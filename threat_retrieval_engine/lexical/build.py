"""Build a C2 lexical index from a C1 store build (and, later, further document kinds).

    python -m threat_retrieval_engine.lexical.build [--store <store build or root>] [--out data/lexical]

Writes ``<out>/<build_id>/lexical.sqlite`` and ``manifest.json`` and points ``<out>/LATEST`` at it. The
index file is deterministic: the same inputs, tokenizer and code give a byte-identical file (no timestamps
inside the database; rows are inserted in doc_id order and merged with FTS5 ``optimize`` and ``VACUUM``).

Every term FTS5 stores is checked against the tokenizer's own output (term set and occurrence counts must
be equal), so the claim "query and index are tokenized identically" is verified on the whole index, not
assumed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import platform
import sqlite3
import sys
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..text.tokenizer import TokenizerConfig, fts5_tokenize_option, tokenize
from .config import RANKING, TOKENIZER, RankingConfig
from .schema import COLUMNS, KIND_RANGES, LEXICAL_FORMAT, MAX_SCORE_MIN_DF, cve_id_from_rowid, cve_rowid, ddl
from .sources import CveStoreSource, DocumentSource

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "data" / "lexical"
INDEX_FILE = "lexical.sqlite"
CHUNK = 1000


class BuildError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def code_fingerprint() -> dict:
    from ..store.feeds import git_head
    h = hashlib.sha256()
    pkg = Path(__file__).resolve().parent
    for p in sorted(list(pkg.glob("*.py")) + list((pkg.parent / "text").glob("*.py"))):
        h.update(p.relative_to(pkg.parent).as_posix().encode())
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
    return {"git_commit": git_head(REPO_ROOT), "code_sha256": h.hexdigest(), "format": LEXICAL_FORMAT}


# --------------------------------------------------------------------------- tokenizing workers
_CFG: TokenizerConfig | None = None


def _init_worker(cfg_dict: dict) -> None:
    global _CFG
    _CFG = TokenizerConfig(**cfg_dict)


def _tokenize_chunk(chunk: list[tuple[str, dict[str, str]]]) -> tuple[list[tuple], dict[str, int]]:
    cfg = _CFG or TOKENIZER
    out = []
    cf: Counter = Counter()
    for doc_id, cols in chunk:
        texts, counts = [], []
        for c in COLUMNS:
            toks = tokenize(cols.get(c) or "", cfg)
            cf.update(toks)
            texts.append(" ".join(toks))
            counts.append(len(toks))
        out.append((doc_id, texts, counts))
    return out, dict(cf)


def _chunks(docs: Iterator[tuple[str, dict[str, str]]], n: int) -> Iterator[list]:
    buf = []
    for d in docs:
        buf.append(d)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf


def tokenized_documents(source: DocumentSource, cfg: TokenizerConfig, workers: int
                        ) -> Iterator[tuple[list[tuple], dict[str, int]]]:
    chunks = _chunks(source.iter_documents(), CHUNK)
    if workers <= 1:
        _init_worker(cfg.__dict__)
        for ch in chunks:
            yield _tokenize_chunk(ch)
        return
    ctx = mp.get_context("spawn")
    with ctx.Pool(workers, initializer=_init_worker, initargs=(dict(cfg.__dict__),)) as pool:
        yield from pool.imap(_tokenize_chunk, chunks, chunksize=1)


# --------------------------------------------------------------------------- build
def _rowids_for(kind: str, doc_ids: list[str]) -> list[int]:
    if kind == "cve":
        return [cve_rowid(d) for d in doc_ids]
    lo, hi = KIND_RANGES[kind]
    return [lo + i for i in range(len(doc_ids))]


def build_index(sources: Iterable[DocumentSource], db_path: Path, cfg: TokenizerConfig = TOKENIZER,
                workers: int = 0, progress=print, ranking: RankingConfig = RANKING) -> dict:
    """Write the index to ``db_path`` (must not exist). Returns counts and hashes for the manifest."""
    workers = workers or max(1, min(12, (os.cpu_count() or 2) - 2))
    if db_path.exists():
        raise BuildError(f"{db_path} exists")
    db = sqlite3.connect(str(db_path), isolation_level=None)
    try:
        return _build_into(db, sources, cfg, workers, progress, ranking)
    finally:
        db.close()


def _build_into(db: sqlite3.Connection, sources: Iterable[DocumentSource], cfg: TokenizerConfig, workers: int,
                progress, ranking: RankingConfig) -> dict:
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA page_size=4096")
    db.execute("PRAGMA cache_size=-524288")
    db.executescript(ddl(fts5_tokenize_option()))
    cf_total: Counter = Counter()
    docs_hash = hashlib.sha256()
    counts: dict = {"documents": {}, "tokens_per_column": dict.fromkeys(COLUMNS, 0), "empty_documents": 0}
    described = []
    t0 = time.time()
    n_all = 0
    for source in sources:
        kind = source.kind
        if kind not in KIND_RANGES:
            raise BuildError(f"unknown document kind {kind!r}")
        described.append(source.describe())
        expected = source.count()
        n = 0
        last_id = None
        lo, hi = KIND_RANGES[kind]
        db.execute("BEGIN")
        for rows, cf in tokenized_documents(source, cfg, workers):
            ids = [r[0] for r in rows]
            if kind != "cve":  # ordinal rowids continue across chunks
                rowids = [lo + n + i for i in range(len(rows))]
            else:
                rowids = _rowids_for(kind, ids)
            fts_rows, doc_rows = [], []
            for rid, (doc_id, texts, cnts) in zip(rowids, rows):
                if last_id is not None and doc_id <= last_id:
                    raise BuildError(f"{kind}: documents not in strict doc_id order at {doc_id}")
                last_id = doc_id
                if not lo <= rid <= hi:
                    raise BuildError(f"{doc_id}: rowid {rid} outside the {kind} range")
                if kind == "cve" and cve_id_from_rowid(rid) != doc_id:
                    raise BuildError(f"{doc_id}: rowid {rid} does not map back to the ID")
                th = hashlib.sha256("\x1f".join(texts).encode("utf-8")).hexdigest()
                docs_hash.update(f"{kind}\x1e{doc_id}\x1e{th}\n".encode())
                fts_rows.append((rid, *texts))
                doc_rows.append((rid, doc_id, kind, json.dumps(cnts), th))
                for c, k in zip(COLUMNS, cnts):
                    counts["tokens_per_column"][c] += k
                if not any(cnts):
                    counts["empty_documents"] += 1
            db.executemany(f"INSERT INTO lex(rowid, {', '.join(COLUMNS)}) VALUES ({', '.join('?' * (len(COLUMNS) + 1))})",
                           fts_rows)
            db.executemany("INSERT INTO docs VALUES (?, ?, ?, ?, ?)", doc_rows)
            cf_total.update(cf)
            n += len(rows)
            if n % 50_000 < CHUNK:
                progress(f"[lexical] {kind}: {n:,}/{expected:,} documents ({time.time() - t0:.0f} s)")
        db.execute("COMMIT")
        if n != expected:
            raise BuildError(f"{kind}: source announced {expected} documents but yielded {n}")
        counts["documents"][kind] = n
        n_all += n
    progress(f"[lexical] {n_all:,} documents inserted ({time.time() - t0:.0f} s); optimizing")
    db.execute("INSERT INTO lex(lex) VALUES ('optimize')")

    # Vocabulary, and the identity check: FTS5's terms and counts must equal the tokenizer's.
    db.execute("CREATE VIRTUAL TABLE temp.v USING fts5vocab(main, lex, row)")
    db.execute("BEGIN")
    db.execute("INSERT INTO vocab(term, df, cf, max_score) SELECT term, doc, cnt, NULL FROM temp.v ORDER BY term")
    db.execute("COMMIT")
    mismatch = []
    n_terms = 0
    for term, cnt in db.execute("SELECT term, cf FROM vocab"):
        n_terms += 1
        if cf_total.get(term) != cnt:
            mismatch.append((term, cnt, cf_total.get(term)))
            if len(mismatch) > 20:
                break
    if n_terms != len(cf_total) and not mismatch:
        missing = [t for t in cf_total if db.execute("SELECT 1 FROM vocab WHERE term = ?", (t,)).fetchone() is None]
        mismatch = [(t, None, cf_total[t]) for t in missing[:20]]
    db.execute("DROP TABLE temp.v")
    if mismatch:
        raise BuildError(f"FTS5 tokenization differs from the domain tokenizer (term, fts5 count, tokenizer count): "
                         f"{mismatch[:20]}")
    progress(f"[lexical] MaxScore upper bounds for terms with df >= {MAX_SCORE_MIN_DF}")
    weights_sql = ", ".join(repr(float(w)) for w in ranking.weights)
    common = [t for (t,) in db.execute("SELECT term FROM vocab WHERE df >= ? ORDER BY term", (MAX_SCORE_MIN_DF,))]
    db.execute("BEGIN")
    for t in common:
        (best,) = db.execute(f"SELECT bm25(lex, {weights_sql}) AS s FROM lex WHERE lex MATCH ? ORDER BY s LIMIT 1",
                             ('"' + t + '"',)).fetchone()
        db.execute("UPDATE vocab SET max_score = ? WHERE term = ?", (-best, t))
    db.execute("COMMIT")
    total_tokens = sum(counts["tokens_per_column"].values())
    meta = {
        "max_score_weights": json.dumps([float(w) for w in ranking.weights]),
        "max_score_min_df": str(MAX_SCORE_MIN_DF),
        "format": LEXICAL_FORMAT, "tokenizer": cfg.key(), "fts5_tokenize": fts5_tokenize_option(),
        "columns": ",".join(COLUMNS), "documents": str(n_all), "terms": str(n_terms),
        "tokens": str(total_tokens), "documents_sha256": docs_hash.hexdigest(),
    }
    db.execute("BEGIN")
    db.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
    db.execute("COMMIT")
    progress(f"[lexical] vocabulary {n_terms:,} terms verified against the tokenizer; vacuum")
    db.execute("VACUUM")
    counts.update({"total": n_all, "terms": n_terms, "tokens": total_tokens})
    return {"counts": counts, "sources": described, "documents_sha256": docs_hash.hexdigest(),
            "identity_check": {"terms_compared": n_terms, "mismatches": 0}}


def build(store_path: Path | str | None = None, out_root: Path | str | None = None,
          tokenizer: TokenizerConfig = TOKENIZER, ranking: RankingConfig = RANKING, workers: int = 0,
          extra_sources: Iterable[DocumentSource] = (), progress=print, set_latest: bool = True) -> Path:
    from ..store import Store
    out_root = Path(out_root) if out_root else DEFAULT_OUT
    out_root.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with Store.open(store_path) as store:
        sources = [CveStoreSource(store), *extra_sources]
        key = hashlib.sha256(json.dumps({"store": store.build_id, "tok": tokenizer.key(),
                                         "extra": [s.kind for s in sources[1:]]}).encode()).hexdigest()[:10]
        build_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{key}"
        bdir = out_root / build_id
        bdir.mkdir()
        db_path = bdir / INDEX_FILE
        try:
            info = build_index(sources, db_path, tokenizer, workers, progress, ranking)
        except BaseException:
            if db_path.exists():
                db_path.unlink()
            raise
    manifest = {
        "build_id": build_id,
        "format": LEXICAL_FORMAT,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "index_file": INDEX_FILE,
        "index_sha256": sha256_file(db_path),
        "index_bytes": db_path.stat().st_size,
        "tokenizer": {**tokenizer.as_dict(), "key": tokenizer.key(), "unicodedata_version": unicodedata.unidata_version,
                      "fts5_tokenize": fts5_tokenize_option()},
        "ranking": ranking.as_dict(),
        "columns": list(COLUMNS),
        "kind_rowid_ranges": {k: list(v) for k, v in KIND_RANGES.items()},
        "inputs": info["sources"],
        "documents_sha256": info["documents_sha256"],
        "counts": info["counts"],
        "identity_check": info["identity_check"],
        "code": code_fingerprint(),
        "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                        "platform": platform.platform()},
        "build_seconds": round(time.time() - t0, 1),
    }
    (bdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    if set_latest:
        tmp = out_root / "LATEST.tmp"
        tmp.write_text(build_id + "\n", encoding="utf-8")
        os.replace(tmp, out_root / "LATEST")
    progress(f"[lexical] build {build_id}: {info['counts']['total']:,} documents, "
             f"{manifest['index_bytes'] / 2**20:.0f} MiB, {manifest['build_seconds']} s -> {bdir}")
    return bdir


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", help="C1 store build directory or root (default: data/store, LATEST)")
    ap.add_argument("--out", help=f"output root (default {DEFAULT_OUT})")
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--no-latest", action="store_true", help="do not move the LATEST pointer")
    ap.add_argument("--stemmer", choices=["none", "porter2"], help="override the tuned tokenizer (ablations)")
    ap.add_argument("--no-split", action="store_true", help="ablation: no split forms of compounds")
    ap.add_argument("--no-trailing-digits", action="store_true", help="ablation: no trailing-digit variants")
    a = ap.parse_args(argv)
    tok = TOKENIZER
    if a.stemmer:
        tok = tok.with_(stemmer=a.stemmer)
    if a.no_split:
        tok = tok.with_(split_compounds=False)
    if a.no_trailing_digits:
        tok = tok.with_(trailing_digits=False)
    build(a.store, a.out, tokenizer=tok, workers=a.workers, set_latest=not a.no_latest,
          progress=lambda m: print(m, flush=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
