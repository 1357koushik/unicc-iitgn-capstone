"""Query side of the C2 lexical index.

    from threat_retrieval_engine.lexical import LexicalIndex
    with LexicalIndex.open() as ix:                      # data/lexical/LATEST (or $TRE_LEXICAL_DIR)
        res = ix.search("log4j jndi remote code execution", k=100)
        res.hits                                         # [(doc_id, score), ...], best first, one per document

Scoring. The column weights are fixed at build time, and FTS5's bm25() is a sum over query terms of one
contribution per (term, document) (k1 = 1.2, b = 0.75, weighted term frequency, whole-document length).
The build computes every such contribution once, exactly as bm25() does, and stores them as a term-major
CSR matrix (``impact``: float64 values, int32 document indices). ``search`` adds the rows of the query's
terms into a float64 accumulator and takes the top k (ties broken by rowid). The ranking equals the plain
FTS5 query ``SELECT rowid, bm25(lex, w...) ... ORDER BY bm25, rowid`` with the build's weights; check_c2
verifies this on every train and dev query. ``search_fts5`` runs that reference query (tests, check_c2 and
tuning of weights, which the matrix cannot change).

Query building (``build_query``) never passes user text to FTS5 as syntax: the text is cut to
``max_query_chars``, tokenized by the shared domain tokenizer, de-duplicated, filtered (stop words, terms
absent from the index, terms above ``max_df_ratio``) and capped at ``max_terms`` rarest terms; every term
passes ``is_valid_token`` and is written as a double-quoted FTS5 string, so the reference MATCH expression is
always ``"t1" OR "t2" ...``. An input with no usable term returns no hits.

The matrix is read fully into memory at open (``np.load`` without memory mapping) and its files are checked
against the manifest's sha256 (startup integrity).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from ..text.tokenizer import ENGLISH_STOP_WORDS, TokenizerConfig, is_valid_token, tokenize
from .config import RankingConfig
from .schema import COLUMNS, IMPACT_FILES, KIND_RANGES, LEXICAL_FORMAT

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "data" / "lexical"
INDEX_FILE = "lexical.sqlite"
MAX_K = 1000


class IndexError_(RuntimeError):
    pass


def default_root() -> Path:
    env = os.environ.get("TRE_LEXICAL_DIR")
    return Path(env) if env else DEFAULT_ROOT


def resolve_build(path: Path | str | None = None) -> Path:
    p = Path(path) if path is not None else default_root()
    if p.is_file() and p.name == INDEX_FILE:
        return p.parent
    if (p / INDEX_FILE).is_file():
        return p
    latest = p / "LATEST"
    if latest.is_file():
        d = p / latest.read_text(encoding="utf-8").strip()
        if (d / INDEX_FILE).is_file():
            return d
    raise FileNotFoundError(f"no lexical index build found at {p}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Query:
    """A built query: the reference MATCH expression and how it was derived (for logging and the parser)."""

    match: str | None
    terms: list[str]
    dropped: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    df: dict[str, int] = field(default_factory=dict)
    tid: dict[str, int] = field(default_factory=dict)


@dataclass
class SearchResult:
    hits: list[tuple[str, float]]
    query: Query
    timings_ms: dict[str, float] = field(default_factory=dict)


class LexicalIndex:
    def __init__(self, build_dir: Path | str, ranking: RankingConfig | None = None, mmap: bool = True,
                 verify: bool = False, load_impact: bool = True):
        self.build_dir = resolve_build(build_dir)
        self.path = self.build_dir / INDEX_FILE
        mp = self.build_dir / "manifest.json"
        self.manifest = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else {}
        self._local = threading.local()
        self._mmap = mmap
        db = self._conn()
        meta = dict(db.execute("SELECT key, value FROM meta"))
        if meta.get("format") != LEXICAL_FORMAT:
            raise IndexError_(f"{self.path}: format {meta.get('format')!r}, expected {LEXICAL_FORMAT!r}")
        if meta.get("columns") != ",".join(COLUMNS):
            raise IndexError_(f"{self.path}: columns {meta.get('columns')!r} differ from the code")
        self.meta = meta
        tok = self.manifest.get("tokenizer") or {}
        self.tokenizer = TokenizerConfig(split_compounds=bool(tok.get("split_compounds", True)),
                                         trailing_digits=bool(tok.get("trailing_digits", True)),
                                         stemmer=tok.get("stemmer", "porter2"))
        if self.tokenizer.key() != meta.get("tokenizer"):
            raise IndexError_(f"{self.path}: built with tokenizer {meta.get('tokenizer')!r}; this code tokenizes as "
                              f"{self.tokenizer.key()!r} (rebuild the index)")
        self.n_docs = int(meta["documents"])
        self.impact_weights = tuple(json.loads(meta["impact_weights"]))
        built = RankingConfig.from_dict(self.manifest["ranking"]) if "ranking" in self.manifest else None
        self.ranking = ranking or built or RankingConfig().with_(weights=dict(zip(COLUMNS, self.impact_weights)))
        if tuple(self.ranking.weights) != self.impact_weights:
            raise IndexError_(f"{self.path}: ranking weights {self.ranking.weights} differ from the weights the impact "
                              f"matrix was built with {self.impact_weights}; rebuild, or use search_fts5")
        self.kind_doc_range = {k: tuple(v) for k, v in json.loads(meta["kind_doc_range"]).items()}
        self.impact_seconds = None
        if load_impact:
            self._load_impact()
        if verify:
            self.verify()

    def _load_impact(self) -> None:
        t0 = time.perf_counter()
        want = (self.manifest.get("impact") or {}).get("sha256", {})
        arrays = {}
        for name in IMPACT_FILES:
            p = self.build_dir / f"impact_{name}.npy"
            if want and _sha256(p) != want.get(name):
                raise IndexError_(f"{p}: sha256 differs from the manifest")
            arrays[name] = np.load(p, mmap_mode=None, allow_pickle=False)
        self.indptr, self.indices, self.data, self.rowids = (arrays["indptr"], arrays["indices"], arrays["data"],
                                                             arrays["rowids"])
        if len(self.rowids) != self.n_docs or len(self.indptr) != int(self.meta["terms"]) + 1 \
                or int(self.indptr[-1]) != len(self.indices) or len(self.indices) != len(self.data):
            raise IndexError_(f"{self.build_dir}: impact matrix shape does not match the index")
        self.impact_seconds = time.perf_counter() - t0

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def open(cls, path: Path | str | None = None, **kw) -> "LexicalIndex":
        return cls(resolve_build(path), **kw)

    def _conn(self) -> sqlite3.Connection:
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
            db.execute("PRAGMA query_only=1")
            db.execute("PRAGMA cache_size=-131072")
            if self._mmap:
                db.execute(f"PRAGMA mmap_size={max(1, self.path.stat().st_size) + (1 << 20)}")
            self._local.db = db
            self.__dict__.setdefault("_all_conns", []).append(db)
        return db

    def close(self) -> None:
        for db in self.__dict__.get("_all_conns", []):
            try:
                db.close()
            except sqlite3.Error:
                pass
        self.__dict__["_all_conns"] = []
        self._local = threading.local()

    def __enter__(self) -> "LexicalIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def build_id(self) -> str:
        return self.manifest.get("build_id", self.build_dir.name)

    def count(self, kind: str | None = None) -> int:
        db = self._conn()
        if kind is None:
            return db.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM docs WHERE doc_kind = ?", (kind,)).fetchone()[0]

    def verify(self) -> None:
        """Startup consistency: documents in docs, meta, the FTS5 table and the impact matrix agree."""
        db = self._conn()
        n_docs = db.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
        n_fts = db.execute("SELECT COUNT(*) FROM lex").fetchone()[0]
        n_imp = len(self.rowids) if hasattr(self, "rowids") else n_docs
        if not (n_docs == n_fts == self.n_docs == n_imp):
            raise IndexError_(f"{self.path}: docs {n_docs}, fts {n_fts}, meta {self.n_docs}, impact {n_imp} differ")

    def warm(self) -> float:
        """Touch the SQLite pages the query builder reads (vocabulary, documents). The impact matrix is
        already in memory. Returns the seconds taken; the service calls this at start-up."""
        t0 = time.perf_counter()
        db = self._conn()
        for sql in ("SELECT SUM(LENGTH(term) + df + tid) FROM vocab", "SELECT SUM(LENGTH(doc_id)) FROM docs"):
            db.execute(sql).fetchone()
        return time.perf_counter() - t0

    def memory_bytes(self) -> int:
        return int(sum(a.nbytes for a in (self.indptr, self.indices, self.data, self.rowids)))

    def info(self) -> dict:
        return {"build_id": self.build_id, "documents": self.n_docs, "tokenizer": self.meta.get("tokenizer"),
                "ranking": self.ranking.as_dict(), "index_sha256": self.manifest.get("index_sha256"),
                "impact_nnz": int(len(self.data)), "impact_bytes": self.memory_bytes()}

    # ------------------------------------------------------------------ query building
    def build_query(self, text: str | None, ranking: RankingConfig | None = None) -> Query:
        r = ranking or self.ranking
        if not isinstance(text, str) or not text:
            return Query(None, [])
        truncated = len(text) > r.max_query_chars
        toks = tokenize(text[: r.max_query_chars], self.tokenizer)
        seen: set[str] = set()
        uniq = []
        for t in toks:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        dropped: dict[str, list[str]] = {}
        if r.stop_words == "english":
            stops = _stop_set(self.tokenizer)
            dropped["stop_word"] = [t for t in uniq if t in stops]
            uniq = [t for t in uniq if t not in stops]
        invalid = [t for t in uniq if not is_valid_token(t)]
        if invalid:  # cannot happen for tokenizer output; kept as the last line of defence
            dropped["invalid"] = invalid
            uniq = [t for t in uniq if is_valid_token(t)]
        df, tid = self._vocab(uniq)
        dropped["not_in_index"] = [t for t in uniq if df.get(t, 0) == 0]
        uniq = [t for t in uniq if df.get(t, 0) > 0]
        if r.max_df_ratio < 1:
            cap = r.max_df_ratio * self.n_docs
            dropped["too_common"] = [t for t in uniq if df[t] > cap]
            uniq = [t for t in uniq if df[t] <= cap]
        if len(uniq) > r.max_terms:
            order = sorted(range(len(uniq)), key=lambda i: (df[uniq[i]], i))
            keep = sorted(order[: r.max_terms])
            dropped["over_max_terms"] = [uniq[i] for i in sorted(order[r.max_terms:])]
            uniq = [uniq[i] for i in keep]
        dropped = {k: v for k, v in dropped.items() if v}
        if not uniq:
            return Query(None, [], dropped, truncated)
        return Query(_or(uniq), uniq, dropped, truncated, {t: df[t] for t in uniq}, {t: tid[t] for t in uniq})

    def _vocab(self, terms: list[str]) -> tuple[dict[str, int], dict[str, int]]:
        df: dict[str, int] = {}
        tid: dict[str, int] = {}
        if not terms:
            return df, tid
        db = self._conn()
        for i in range(0, len(terms), 500):
            part = terms[i:i + 500]
            for t, d, n in db.execute(f"SELECT term, df, tid FROM vocab WHERE term IN ({','.join('?' * len(part))})",
                                      part):
                df[t] = d
                tid[t] = n
        return df, tid

    # ------------------------------------------------------------------ search
    def _check(self, k, kinds) -> tuple[int, list[tuple[int, int]]]:
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise ValueError("k must be a positive integer")
        if kinds is None:
            kinds = tuple(self.kind_doc_range)
        if isinstance(kinds, str):
            kinds = (kinds,)
        bad = [x for x in kinds if x not in KIND_RANGES]
        if bad or not kinds:
            raise ValueError(f"unknown document kinds {bad or kinds}")
        return min(k, MAX_K), [self.kind_doc_range[x] for x in kinds if x in self.kind_doc_range]

    def search(self, text: str | None, k: int = 100, kinds: tuple[str, ...] | None = ("cve",)) -> SearchResult:
        """Top ``k`` documents for ``text`` by BM25 over all query terms (one document once, best first)."""
        k, ranges = self._check(k, kinds)
        t0 = time.perf_counter()
        q = self.build_query(text)
        t1 = time.perf_counter()
        hits: list[tuple[str, float]] = []
        if q.match is not None and ranges:
            acc = np.zeros(self.n_docs, dtype=np.float64)
            ip, ix, dv = self.indptr, self.indices, self.data
            for t in q.terms:  # same order as the phrases of the reference MATCH expression
                n = q.tid[t]
                s, e = int(ip[n]), int(ip[n + 1])
                acc[ix[s:e]] += dv[s:e]
            if len(ranges) != len(self.kind_doc_range):
                mask = np.zeros(self.n_docs, dtype=bool)
                for lo, hi in ranges:
                    mask[lo:hi] = True
                acc[~mask] = 0.0
            nz = np.flatnonzero(acc)
            if len(nz) > k:
                vals = acc[nz]
                kth = np.partition(vals, len(vals) - k)[len(vals) - k]
                nz = nz[vals >= kth]  # every document tied with the k-th score stays for the rowid tie-break
            order = np.lexsort((self.rowids[nz], -acc[nz]))[:k]
            sel = nz[order]
            hits = self._doc_ids([(int(r), -float(s)) for r, s in zip(self.rowids[sel], acc[sel])])
        t2 = time.perf_counter()
        return SearchResult(hits, q, {"build_query": (t1 - t0) * 1000, "score": (t2 - t1) * 1000,
                                      "total": (t2 - t0) * 1000})

    def search_fts5(self, text: str | None, k: int = 100, kinds: tuple[str, ...] | None = ("cve",),
                    ranking: RankingConfig | None = None) -> SearchResult:
        """Reference: one FTS5 OR query over every term, ranked by bm25() with ``ranking``'s weights (any
        weights; slow on common terms). Used by check_c2 for the equality check and by weight tuning."""
        k, _ = self._check(k, kinds)
        r = ranking or self.ranking
        t0 = time.perf_counter()
        q = self.build_query(text, r)
        hits: list[tuple[str, float]] = []
        if q.match is not None:
            kind_sql, kind_params = _kind_filter(kinds)
            weights = ", ".join(_fmt_weight(w) for w in r.weights)
            sql = (f"SELECT rowid, bm25(lex, {weights}) AS s FROM lex WHERE lex MATCH ?{kind_sql} "
                   f"ORDER BY s, rowid LIMIT ?")
            hits = self._doc_ids(self._conn().execute(sql, [q.match, *kind_params, k]).fetchall())
        return SearchResult(hits, q, {"total": (time.perf_counter() - t0) * 1000})

    def _doc_ids(self, rows: list[tuple[int, float]]) -> list[tuple[str, float]]:
        from .schema import cve_id_from_rowid
        other = [rid for rid, _ in rows if not KIND_RANGES["cve"][0] <= rid <= KIND_RANGES["cve"][1]]
        names = {}
        if other:
            names = dict(self._conn().execute(
                f"SELECT rowid, doc_id FROM docs WHERE rowid IN ({','.join('?' * len(other))})", other))
        return [(names.get(rid) or cve_id_from_rowid(rid), -float(s)) for rid, s in rows]


def _or(terms: list[str]) -> str:
    return " OR ".join(_quote(t) for t in terms)


def _quote(term: str) -> str:
    if not is_valid_token(term):
        raise ValueError(f"refusing to place {term!r} in a MATCH expression")
    return '"' + term.replace('"', '""') + '"'


def _kind_filter(kinds: tuple[str, ...] | None) -> tuple[str, list]:
    if kinds is None:
        return "", []
    if isinstance(kinds, str):
        kinds = (kinds,)
    params: list = []
    for x in kinds:
        params += list(KIND_RANGES[x])
    return " AND (" + " OR ".join("rowid BETWEEN ? AND ?" for _ in kinds) + ")", params


def _fmt_weight(w: float) -> str:
    if not math.isfinite(w) or w < 0:
        raise ValueError("invalid weight")
    return repr(float(w))


_STOPS: dict[str, frozenset] = {}


def _stop_set(cfg: TokenizerConfig) -> frozenset:
    """Stop words as they appear after tokenization (stemmed when the index is stemmed)."""
    key = cfg.key()
    if key not in _STOPS:
        out = set()
        for w in ENGLISH_STOP_WORDS:
            out.update(tokenize(w, cfg))
        _STOPS[key] = frozenset(out)
    return _STOPS[key]
