"""Query side of the C2 lexical index.

    from threat_retrieval_engine.lexical import LexicalIndex
    with LexicalIndex.open() as ix:                      # data/lexical/LATEST (or $TRE_LEXICAL_DIR)
        res = ix.search("log4j jndi remote code execution", k=100)
        res.hits                                         # [(doc_id, score), ...], best first, one per document

Query building (``build_query``) never passes user text to FTS5 as syntax. The text is cut to
``max_query_chars``, tokenized by the shared domain tokenizer (the same function that produced the indexed
text), de-duplicated, filtered (stop words, terms absent from the index, terms above ``max_df_ratio``),
capped at ``max_terms`` rarest terms, and every surviving term is checked by ``is_valid_token`` and written
as a double-quoted FTS5 string. The MATCH expression is therefore always ``"t1" OR "t2" OR ...``: operators,
column filters, NEAR, prefix ``*``, ``^``, parentheses and quotes in the input are only ever separators.
An input with no usable term returns no hits without touching FTS5.

Ranking is FTS5's ``bm25()`` with per-column weights; ties are broken by rowid, so the order is
deterministic. Scores are reported as ``-bm25`` (larger is better).
"""
from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..text.tokenizer import ENGLISH_STOP_WORDS, TokenizerConfig, is_valid_token, tokenize
from .config import RankingConfig
from .schema import COLUMNS, KIND_RANGES, LEXICAL_FORMAT, cve_id_from_rowid

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "data" / "lexical"
INDEX_FILE = "lexical.sqlite"
MAX_K = 1000
STRATEGIES = ("budget", "exact", "plain")
BM25_K1 = 1.2  # fixed inside FTS5 bm25()
# Terms in at least this share of documents start on the non-essential side of the MaxScore split.
NON_ESSENTIAL_MIN_DF_RATIO = 0.02


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


@dataclass
class Query:
    """A built query: the MATCH expression and how it was derived (for logging and the parser)."""

    match: str | None
    terms: list[str]
    dropped: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    df: dict[str, int] = field(default_factory=dict)
    max_score: dict[str, float] = field(default_factory=dict)


@dataclass
class SearchResult:
    hits: list[tuple[str, float]]
    query: Query
    timings_ms: dict[str, float] = field(default_factory=dict)


class LexicalIndex:
    def __init__(self, build_dir: Path | str, ranking: RankingConfig | None = None, mmap: bool = True,
                 verify: bool = False):
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
        if ranking is None:
            ranking = RankingConfig.from_dict(self.manifest["ranking"]) if "ranking" in self.manifest else RankingConfig()
        self.ranking = ranking
        msw = meta.get("max_score_weights")
        self.max_score_weights = tuple(json.loads(msw)) if msw else None
        if verify:
            self.verify()

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
            conns = self.__dict__.setdefault("_all_conns", [])
            conns.append(db)
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
        """Startup consistency: document count in docs, meta and the FTS5 table agree."""
        db = self._conn()
        n_docs = db.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
        n_fts = db.execute("SELECT COUNT(*) FROM lex").fetchone()[0]
        if not (n_docs == n_fts == self.n_docs):
            raise IndexError_(f"{self.path}: docs {n_docs}, fts {n_fts}, meta {self.n_docs} differ")

    def info(self) -> dict:
        return {"build_id": self.build_id, "documents": self.n_docs, "tokenizer": self.meta.get("tokenizer"),
                "ranking": self.ranking.as_dict(), "index_sha256": self.manifest.get("index_sha256")}

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
        df, max_score = self._vocab(uniq)
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
        match = _or(uniq)
        return Query(match, uniq, dropped, truncated, {t: df[t] for t in uniq},
                     {t: max_score[t] for t in uniq if max_score.get(t) is not None})

    def _vocab(self, terms: list[str]) -> tuple[dict[str, int], dict[str, float | None]]:
        df: dict[str, int] = {}
        ms: dict[str, float | None] = {}
        if not terms:
            return df, ms
        db = self._conn()
        for i in range(0, len(terms), 500):
            part = terms[i:i + 500]
            for t, d, m in db.execute(f"SELECT term, df, max_score FROM vocab WHERE term IN "
                                      f"({','.join('?' * len(part))})", part):
                df[t] = d
                ms[t] = m
        return df, ms

    # ------------------------------------------------------------------ search
    def search(self, text: str | None, k: int = 100, kinds: tuple[str, ...] | None = ("cve",),
               ranking: RankingConfig | None = None, strategy: str = "budget") -> SearchResult:
        """Top ``k`` documents for ``text``, scored by BM25 over all query terms.

        Strategies (all score a matched document with every query term; they differ in which documents are
        matched):

        * ``budget`` (default): documents containing at least one of the rarest query terms, taken rarest
          first while their summed document frequency stays within ``ranking.candidate_budget`` (at least
          one term). When a single term already exceeds the budget, documents containing both of the two
          rarest terms. The result is exact whenever the MaxScore bound proves it (``timings_ms
          ["plan_exact"]``); otherwise documents that contain only common query terms are not considered.
          The recall cost of this was measured against ``exact`` on train and dev (plan section 12, C2).
        * ``exact``: the plain query's ranking with less work (MaxScore, ``_maxscore``); unbounded work.
        * ``plain``: one FTS5 OR query over every term (reference for tests and measurements).
        """
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise ValueError("k must be a positive integer")
        if strategy not in STRATEGIES:
            raise ValueError(f"strategy must be one of {STRATEGIES}")
        k = min(k, MAX_K)
        kind_sql, kind_params = _kind_filter(kinds)
        r = ranking or self.ranking
        t0 = time.perf_counter()
        q = self.build_query(text, r)
        t1 = time.perf_counter()
        hits: list[tuple[str, float]] = []
        plan: dict = {}
        if q.match is not None:
            weights = ", ".join(_fmt_weight(w) for w in r.weights)
            if strategy == "plain" or len(q.terms) == 1:
                rows = self._run(_or(q.terms), [], k, weights, kind_sql, kind_params)
                plan = {"runs": 1, "essential": len(q.terms), "non_essential": 0, "exact": True}
            elif strategy == "exact":
                rows, plan = self._maxscore(q, k, r, weights, kind_sql, kind_params)
            else:
                rows, plan = self._budget(q, k, r, weights, kind_sql, kind_params)
            hits = self._doc_ids(rows)
        t2 = time.perf_counter()
        return SearchResult(hits, q, {"build_query": (t1 - t0) * 1000, "match": (t2 - t1) * 1000,
                                      "total": (t2 - t0) * 1000, **{f"plan_{a}": b for a, b in plan.items()}})

    def _run(self, essential: str, rest: list[str], k: int, weights: str, kind_sql: str,
             kind_params: list) -> list[tuple[int, float]]:
        """Documents matching the ``essential`` expression, scored by BM25 over its terms plus ``rest``.

        With ``rest`` empty this is one FTS5 query. Otherwise two are combined: documents that also contain a
        ``rest`` term are scored by ``(E) AND (R1 OR R2 ...)`` (all their phrases), the others by ``E`` alone;
        bm25 is a sum over phrases, so each document's best (lowest) bm25 is its full score. A document
        appears at most twice, so the first ``2k`` rows hold the best ``k`` distinct ones."""
        db = self._conn()
        if not rest:
            sql = (f"SELECT rowid, bm25(lex, {weights}) AS s FROM lex WHERE lex MATCH ?{kind_sql} "
                   f"ORDER BY s, rowid LIMIT ?")
            return db.execute(sql, [essential, *kind_params, k]).fetchall()
        m_both = f"({essential}) AND ({_or(rest)})"
        sql = (f"SELECT rowid, s FROM (SELECT rowid, bm25(lex, {weights}) AS s FROM lex WHERE lex MATCH ?{kind_sql} "
               f"UNION ALL SELECT rowid, bm25(lex, {weights}) AS s FROM lex WHERE lex MATCH ?{kind_sql}) "
               f"ORDER BY s, rowid LIMIT ?")
        out, seen = [], set()
        for rid, sc in db.execute(sql, [m_both, *kind_params, essential, *kind_params, 2 * k]):
            if rid not in seen:
                seen.add(rid)
                out.append((rid, sc))
                if len(out) == k:
                    break
        return out

    def _theta_ok(self, rows: list, k: int, rest: list[str], ub: dict[str, float]) -> bool:
        """MaxScore test: no document outside the matched set (it holds only ``rest`` terms) can reach the
        k-th score found."""
        if not rest:
            return True
        theta = -rows[k - 1][1] if len(rows) >= k else 0.0
        return _bound(sum(ub[t] for t in rest)) < theta

    def _budget(self, q: Query, k: int, r: RankingConfig, weights: str, kind_sql: str, kind_params: list
                ) -> tuple[list[tuple[int, float]], dict]:
        order = sorted(q.terms, key=lambda t: (q.df[t], t))
        ub = {t: self._upper_bound(t, q, r) for t in order}
        if q.df[order[0]] > r.candidate_budget and len(order) >= 2:
            essential, rest = order[:2], order[2:]
            expr = f"{_quote(order[0])} AND {_quote(order[1])}"
            rows = self._run(expr, rest, k, weights, kind_sql, kind_params)
            # documents lacking either of the two terms were not considered: never provably exact
            return rows, {"runs": 1, "essential": 2, "non_essential": len(rest), "exact": False, "mode": "and"}
        essential, total = [], 0
        for t in order:
            if essential and total + q.df[t] > r.candidate_budget:
                break
            essential.append(t)
            total += q.df[t]
        rest = order[len(essential):]
        rows = self._run(_or(essential), rest, k, weights, kind_sql, kind_params)
        return rows, {"runs": 1, "essential": len(essential), "non_essential": len(rest),
                      "exact": self._theta_ok(rows, k, rest, ub), "mode": "or"}

    def _maxscore(self, q: Query, k: int, r: RankingConfig, weights: str, kind_sql: str, kind_params: list
                  ) -> tuple[list[tuple[int, float]], dict]:
        """Exact top-k with the MaxScore idea (Turtle and Flood, 1995) on top of FTS5.

        Terms are split into essential (rare) and non-essential (common) ones; only documents containing an
        essential term are scored, with every term. A document containing only non-essential terms scores at
        most UB = sum of their upper bounds (each term's largest contribution to any document: measured at
        build time for the manifest's weights, else the BM25 supremum idf * (k1 + 1)). If UB is below the
        k-th score found, no such document can enter the top k and the result equals the plain query's.
        Otherwise common terms move to the essential side until the bound holds for the k-th score already
        found; the k-th score can only rise when the essential side grows, so the second run is exact."""
        order = sorted(q.terms, key=lambda t: (q.df[t], t))
        ub = {t: self._upper_bound(t, q, r) for t in order}
        cut = NON_ESSENTIAL_MIN_DF_RATIO * self.n_docs
        rest = [t for t in order[1:] if q.df[t] >= cut]
        rest_set = set(rest)
        essential = [t for t in order if t not in rest_set]
        runs = 0
        while True:
            rows = self._run(_or(essential), rest, k, weights, kind_sql, kind_params)
            runs += 1
            if self._theta_ok(rows, k, rest, ub):
                break
            theta = -rows[k - 1][1] if len(rows) >= k else 0.0
            while rest and _bound(sum(ub[t] for t in rest)) >= theta:
                essential.append(rest.pop(0))  # rest is ordered rarest first
        return rows, {"runs": runs, "essential": len(essential), "non_essential": len(rest), "exact": True}

    def _upper_bound(self, term: str, q: Query, r: RankingConfig) -> float:
        ms = q.max_score.get(term)
        if ms is not None and tuple(r.weights) == self.max_score_weights:
            return ms
        df = q.df[term]
        idf = math.log((self.n_docs - df + 0.5) / (df + 0.5))
        if idf <= 0:
            idf = 1e-6  # as FTS5 bm25()
        return idf * (BM25_K1 + 1.0)

    def _doc_ids(self, rows: list[tuple[int, float]]) -> list[tuple[str, float]]:
        out = []
        other = [rid for rid, _ in rows if not KIND_RANGES["cve"][0] <= rid <= KIND_RANGES["cve"][1]]
        names = {}
        if other:
            db = self._conn()
            names = dict(db.execute(f"SELECT rowid, doc_id FROM docs WHERE rowid IN ({','.join('?' * len(other))})",
                                    other))
        for rid, s in rows:
            did = names.get(rid) or cve_id_from_rowid(rid)
            out.append((did, -float(s)))
        return out


def _bound(x: float) -> float:
    """An upper bound inflated past floating-point rounding, so the exactness test stays conservative."""
    return x * (1 + 1e-9) + 1e-12


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
    bad = [x for x in kinds if x not in KIND_RANGES]
    if bad or not kinds:
        raise ValueError(f"unknown document kinds {bad or kinds}")
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
