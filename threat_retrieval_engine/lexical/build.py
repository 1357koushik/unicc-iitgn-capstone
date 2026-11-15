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

import numpy as np
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..text.tokenizer import TokenizerConfig, fts5_tokenize_option, tokenize
from .config import RANKING, TOKENIZER, RankingConfig
from .schema import (BM25_B, BM25_K1, COLUMNS, IMPACT_FILES, KIND_RANGES, LEXICAL_FORMAT, cve_id_from_rowid,
                     cve_rowid, ddl)
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
_WEIGHTS: tuple[float, ...] = tuple(RANKING.weights)


def _init_worker(cfg_dict: dict, weights: tuple[float, ...]) -> None:
    global _CFG, _WEIGHTS
    _CFG = TokenizerConfig(**cfg_dict)
    _WEIGHTS = tuple(weights)


def _tokenize_chunk(chunk: list[tuple[str, dict[str, str]]]) -> tuple[list[tuple], dict[str, int]]:
    """Per document: (doc_id, pre-tokenized text per column, tokens per column, {term: weighted tf}).
    The weighted tf adds the column weight once per occurrence, as FTS5 bm25() accumulates it."""
    cfg = _CFG or TOKENIZER
    out = []
    cf: Counter = Counter()
    for doc_id, cols in chunk:
        texts, counts = [], []
        wtf: dict[str, float] = {}
        for c, w in zip(COLUMNS, _WEIGHTS):
            toks = tokenize(cols.get(c) or "", cfg)
            cf.update(toks)
            texts.append(" ".join(toks))
            counts.append(len(toks))
            for t in toks:
                wtf[t] = wtf.get(t, 0.0) + w
        out.append((doc_id, texts, counts, wtf))
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


def tokenized_documents(source: DocumentSource, cfg: TokenizerConfig, workers: int, weights: tuple[float, ...]
                        ) -> Iterator[tuple[list[tuple], dict[str, int]]]:
    chunks = _chunks(source.iter_documents(), CHUNK)
    if workers <= 1:
        _init_worker(cfg.__dict__, weights)
        for ch in chunks:
            yield _tokenize_chunk(ch)
        return
    ctx = mp.get_context("spawn")
    with ctx.Pool(workers, initializer=_init_worker, initargs=(dict(cfg.__dict__), tuple(weights))) as pool:
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
        info = _build_into(db, sources, cfg, workers, progress, ranking)
    finally:
        db.close()
    arrays = info.pop("impact")
    shas = {}
    for name in IMPACT_FILES:
        p = db_path.parent / f"impact_{name}.npy"
        np.save(p, arrays[name], allow_pickle=False)
        shas[name] = sha256_file(p)
    info["impact"] = {"sha256": shas, "nnz": int(len(arrays["data"])),
                      "bytes": int(sum(a.nbytes for a in arrays.values())),
                      "dtypes": {k: str(v.dtype) for k, v in arrays.items()}}
    return info


def _build_into(db: sqlite3.Connection, sources: Iterable[DocumentSource], cfg: TokenizerConfig, workers: int,
                progress, ranking: RankingConfig) -> dict:
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA page_size=4096")
    db.execute("PRAGMA cache_size=-524288")
    if not all(w > 0 for w in ranking.weights):
        raise BuildError("every column weight must be positive for the impact matrix (a zero-weight column "
                         "would match documents with score 0 in FTS5 but not in the matrix)")
    weights = tuple(float(w) for w in ranking.weights)
    db.executescript(ddl(fts5_tokenize_option()))
    cf_total: Counter = Counter()
    term_pid: dict[str, int] = {}          # provisional term ids, first-seen order
    imp_pid: list[np.ndarray] = []         # per chunk: provisional term id of each (term, doc) pair
    imp_doc: list[np.ndarray] = []         # document position
    imp_wtf: list[np.ndarray] = []         # weighted term frequency
    doc_len: list[int] = []                # tokens in all columns (FTS5's xColumnSize(-1))
    doc_rowid: list[int] = []
    kind_doc_range: dict[str, list[int]] = {}
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
        first_pos = len(doc_rowid)
        db.execute("BEGIN")
        for rows, cf in tokenized_documents(source, cfg, workers, weights):
            ids = [r[0] for r in rows]
            if kind != "cve":  # ordinal rowids continue across chunks
                rowids = [lo + n + i for i in range(len(rows))]
            else:
                rowids = _rowids_for(kind, ids)
            fts_rows, doc_rows = [], []
            c_pid, c_doc, c_wtf = [], [], []
            for rid, (doc_id, texts, cnts, wtf) in zip(rowids, rows):
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
                pos = len(doc_rowid)
                doc_rowid.append(rid)
                doc_len.append(sum(cnts))
                for t, f in wtf.items():
                    i = term_pid.get(t)
                    if i is None:
                        i = term_pid[t] = len(term_pid)
                    c_pid.append(i)
                    c_doc.append(pos)
                    c_wtf.append(f)
            imp_pid.append(np.asarray(c_pid, dtype=np.int64))
            imp_doc.append(np.asarray(c_doc, dtype=np.int32))
            imp_wtf.append(np.asarray(c_wtf, dtype=np.float64))
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
        kind_doc_range[kind] = [first_pos, len(doc_rowid)]
        n_all += n
    progress(f"[lexical] {n_all:,} documents inserted ({time.time() - t0:.0f} s); optimizing")
    db.execute("INSERT INTO lex(lex) VALUES ('optimize')")

    # Vocabulary, and the identity check: FTS5's terms and counts must equal the tokenizer's.
    db.execute("CREATE VIRTUAL TABLE temp.v USING fts5vocab(main, lex, row)")
    db.execute("BEGIN")
    db.execute("INSERT INTO vocab(term, df, cf, tid) SELECT term, doc, cnt, -1 FROM temp.v ORDER BY term")
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
    total_tokens = sum(counts["tokens_per_column"].values())
    progress("[lexical] impact matrix")
    impact = _impact_matrix(db, term_pid, imp_pid, imp_doc, imp_wtf, doc_len, doc_rowid, n_all, total_tokens)
    meta = {
        "impact_weights": json.dumps(list(weights)),
        "kind_doc_range": json.dumps(kind_doc_range, sort_keys=True),
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
            "identity_check": {"terms_compared": n_terms, "mismatches": 0, "document_frequencies_equal": True},
            "impact": impact}


def _impact_matrix(db, term_pid, imp_pid, imp_doc, imp_wtf, doc_len, doc_rowid, n_docs, total_tokens) -> dict:
    """bm25() contribution of every (term, document) pair, as FTS5 computes it:
    idf = ln((N - n + 0.5) / (n + 0.5)), 1e-6 when <= 0; c = idf * (f * (k1 + 1) / (f + k1 * (1 - b + b * D / avgdl)))
    with f the weighted term frequency, D the document's tokens in all columns, avgdl = tokens / N.
    Stored term-major (CSR) with float64 values: float32 values change sums by about 1e-7 relative, enough to
    swap documents whose scores are that close, so the ranking would no longer equal bm25()'s."""
    tid_of = np.full(len(term_pid), -1, dtype=np.int64)
    db.execute("BEGIN")
    rows = db.execute("SELECT term, df FROM vocab ORDER BY term").fetchall()
    df = np.zeros(len(rows), dtype=np.int64)
    for tid, (term, d) in enumerate(rows):
        pid = term_pid.get(term)
        if pid is None:
            raise BuildError(f"term {term!r} in FTS5 but not produced by the tokenizer")
        tid_of[pid] = tid
        df[tid] = d
    db.executemany("UPDATE vocab SET tid = ? WHERE term = ?", ((i, t) for i, (t, _) in enumerate(rows)))
    db.execute("COMMIT")
    if (tid_of < 0).any():
        raise BuildError("tokenizer terms missing from FTS5")
    t = tid_of[np.concatenate(imp_pid)] if imp_pid else np.zeros(0, dtype=np.int64)
    d = np.concatenate(imp_doc) if imp_doc else np.zeros(0, dtype=np.int32)
    f = np.concatenate(imp_wtf) if imp_wtf else np.zeros(0, dtype=np.float64)
    if not np.array_equal(np.bincount(t, minlength=len(df)), df):
        raise BuildError("document frequencies of the impact pairs differ from FTS5's")
    n = float(n_docs)
    idf = np.log((n - df + 0.5) / (df + 0.5))
    idf[idf <= 0.0] = 1e-6
    avgdl = float(total_tokens) / n
    dl = np.asarray(doc_len, dtype=np.float64)
    contrib = idf[t] * ((f * (BM25_K1 + 1.0)) / (f + BM25_K1 * (1.0 - BM25_B + BM25_B * dl[d] / avgdl)))
    order = np.lexsort((d, t))  # term-major, documents ascending inside a term
    indptr = np.zeros(len(df) + 1, dtype=np.int64)
    np.cumsum(df, out=indptr[1:])
    return {"indptr": indptr, "indices": d[order].astype(np.int32), "data": contrib[order],
            "rowids": np.asarray(doc_rowid, dtype=np.int64)}


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
        "impact": info["impact"],
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
    ap.add_argument("--attack", help="C9 ATT&CK build directory or root (adds attack documents)")
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
    from .sources import open_attack
    extra = [open_attack(a.attack)] if a.attack else []
    build(a.store, a.out, tokenizer=tok, workers=a.workers, set_latest=not a.no_latest, extra_sources=extra,
          progress=lambda m: print(m, flush=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
