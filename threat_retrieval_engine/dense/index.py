"""Exact dense search over a C3 build.

    from threat_retrieval_engine.dense import DenseIndex
    ix = DenseIndex.open()                              # data/dense/LATEST (or $TRE_DENSE_DIR)
    hits = ix.search(qvec, k=100, kinds=("cve",))       # [(doc_id, cosine), ...] best first

* The matrix is read fully into process memory at open (``np.load`` without memory mapping): its pages are
  anonymous memory, not a file mapping the kernel can drop under pressure from other users' jobs (plan 4.5,
  11.3). Both files are checked against the manifest's sha256 first, and shape, dtype, row count, kind ranges
  and (optionally) every vector's norm are checked against the manifest.
* One query is one BLAS matrix-vector product (float32) over the rows of the requested kinds (a kind is a
  contiguous row range, so restriction costs nothing), optionally followed by a boolean document mask (rows
  outside it score -inf) for filters.
* Top-k is exact: the k best scores, ties broken by row position (document ID inside a kind, CVE before
  ATT&CK), found with ``argpartition`` keeping every row tied with the k-th score, then a full sort of that
  small set. ``brute_force`` is the reference (float64 scores of every row, complete stable sort) used by
  check_c3 and the tests.
* Multi-row documents (the v1 export with ``collapse = max``): ``groups.npy`` holds each document's first
  row; a document's score is the maximum over its rows.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from .schema import DENSE_FORMAT, DOC_IDS_FILE, KINDS, MANIFEST_FILE, NORM_TOLERANCE, VECTORS_FILE

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "data" / "dense"
GROUPS_FILE = "groups.npy"
MAX_K = 10000


class DenseIndexError(RuntimeError):
    pass


def default_root() -> Path:
    env = os.environ.get("TRE_DENSE_DIR")
    return Path(env) if env else DEFAULT_ROOT


def resolve_build(path: Path | str | None = None) -> Path:
    p = Path(path) if path is not None else default_root()
    if p.is_file() and p.name == VECTORS_FILE:
        return p.parent
    if (p / VECTORS_FILE).is_file() and (p / MANIFEST_FILE).is_file():
        return p
    latest = p / "LATEST"
    if latest.is_file():
        d = p / latest.read_text(encoding="utf-8").strip()
        if (d / VECTORS_FILE).is_file():
            return d
    raise FileNotFoundError(f"no dense index build found at {p}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def set_blas_threads(n: int | None) -> dict:
    """Pin the BLAS thread pool (threadpoolctl). Returns what is in effect, for the record."""
    try:
        from threadpoolctl import threadpool_info, threadpool_limits
    except ImportError:
        return {"mechanism": "environment (threadpoolctl not installed)",
                "OPENBLAS_NUM_THREADS": os.environ.get("OPENBLAS_NUM_THREADS"),
                "OMP_NUM_THREADS": os.environ.get("OMP_NUM_THREADS")}
    if n:
        threadpool_limits(limits=int(n), user_api="blas")
    pools = [{"internal_api": p.get("internal_api"), "num_threads": p.get("num_threads"),
              "version": p.get("version")} for p in threadpool_info() if p.get("user_api") == "blas"]
    return {"mechanism": "threadpoolctl", "requested": n, "blas": pools}


class DenseIndex:
    def __init__(self, build_dir: Path | str, verify: bool = True, check_norms: bool = False):
        self.build_dir = resolve_build(build_dir)
        t0 = time.perf_counter()
        self.manifest = json.loads((self.build_dir / MANIFEST_FILE).read_text(encoding="utf-8"))
        m = self.manifest
        if m.get("format") != DENSE_FORMAT:
            raise DenseIndexError(f"{self.build_dir}: format {m.get('format')!r}, expected {DENSE_FORMAT!r}")
        files = [VECTORS_FILE, DOC_IDS_FILE] + ([GROUPS_FILE] if m.get("row_groups") else [])
        if verify:
            for name in files:
                want = (m.get("files") or {}).get(name)
                got = _sha256(self.build_dir / name)
                if want != got:
                    raise DenseIndexError(f"{self.build_dir / name}: sha256 {got[:16]}... differs from the "
                                          f"manifest's {str(want)[:16]}...")
        vec = np.load(self.build_dir / VECTORS_FILE, mmap_mode=None, allow_pickle=False)
        if vec.dtype != np.float32 or vec.ndim != 2 or not vec.flags["C_CONTIGUOUS"]:
            raise DenseIndexError(f"{self.build_dir}: vectors must be C-contiguous float32 2-d, got {vec.dtype} "
                                  f"{vec.shape}")
        self.vectors = vec
        self.doc_ids = (self.build_dir / DOC_IDS_FILE).read_text(encoding="utf-8").split("\n")
        if self.doc_ids and self.doc_ids[-1] == "":
            self.doc_ids.pop()
        self.n_docs = len(self.doc_ids)
        self.dim = int(vec.shape[1])
        if self.dim != m.get("dim") or self.n_docs != m.get("documents"):
            raise DenseIndexError(f"{self.build_dir}: {self.n_docs} documents x {self.dim} differ from the manifest's "
                                  f"{m.get('documents')} x {m.get('dim')}")
        self.groups = None
        if m.get("row_groups"):
            g = np.load(self.build_dir / GROUPS_FILE, allow_pickle=False)
            if g.dtype != np.int64 or len(g) != self.n_docs or (len(g) and (g[0] != 0 or np.any(np.diff(g) <= 0)
                                                                           or g[-1] >= vec.shape[0])):
                raise DenseIndexError(f"{self.build_dir}: invalid row groups")
            self.groups = g
            if vec.shape[0] != m.get("rows"):
                raise DenseIndexError(f"{self.build_dir}: {vec.shape[0]} rows, manifest {m.get('rows')}")
        elif vec.shape[0] != self.n_docs:
            raise DenseIndexError(f"{self.build_dir}: {vec.shape[0]} vectors for {self.n_docs} documents")
        self.kind_ranges = {k: tuple(v) for k, v in m["kind_ranges"].items()}
        cover = sorted(self.kind_ranges.values())
        if not cover or cover[0][0] != 0 or cover[-1][1] != self.n_docs or any(a[1] != b[0] for a, b in
                                                                               zip(cover, cover[1:])):
            raise DenseIndexError(f"{self.build_dir}: kind ranges {self.kind_ranges} do not tile the documents")
        if any(k not in KINDS for k in self.kind_ranges):
            raise DenseIndexError(f"{self.build_dir}: unknown kinds {list(self.kind_ranges)}")
        if check_norms:
            self.check_norms()
        self._pos = None
        self._lock = threading.Lock()
        self.load_seconds = time.perf_counter() - t0

    @classmethod
    def open(cls, path: Path | str | None = None, **kw) -> "DenseIndex":
        return cls(resolve_build(path), **kw)

    # ------------------------------------------------------------------ metadata
    @property
    def build_id(self) -> str:
        return self.manifest.get("build_id", self.build_dir.name)

    @property
    def model(self) -> dict:
        return self.manifest.get("model") or {}

    def count(self, kind: str | None = None) -> int:
        if kind is None:
            return self.n_docs
        a, b = self.kind_ranges.get(kind, (0, 0))
        return b - a

    def position(self, doc_id: str) -> int | None:
        if self._pos is None:
            with self._lock:
                if self._pos is None:
                    self._pos = {d: i for i, d in enumerate(self.doc_ids)}
        return self._pos.get(doc_id)

    def vector(self, doc_id: str) -> np.ndarray | None:
        p = self.position(doc_id)
        if p is None:
            return None
        if self.groups is None:
            return self.vectors[p]
        return self.vectors[self.groups[p]]

    def memory_bytes(self) -> int:
        return int(self.vectors.nbytes + (self.groups.nbytes if self.groups is not None else 0))

    def check_norms(self) -> float:
        worst = 0.0
        for a in range(0, self.vectors.shape[0], 65536):
            n = np.linalg.norm(self.vectors[a:a + 65536].astype(np.float64), axis=1)
            if not np.isfinite(n).all():
                raise DenseIndexError(f"{self.build_dir}: non-finite vector near row {a}")
            worst = max(worst, float(np.max(np.abs(n - 1.0))) if len(n) else 0.0)
        if worst > NORM_TOLERANCE:
            raise DenseIndexError(f"{self.build_dir}: vector norms deviate from 1 by {worst:.2e}")
        return worst

    def info(self) -> dict:
        m = self.manifest
        return {"build_id": self.build_id, "documents": self.n_docs, "rows": int(self.vectors.shape[0]),
                "dim": self.dim, "counts": m.get("counts"), "source": m.get("source"),
                "model": {k: (m.get("model") or {}).get(k) for k in ("name", "repo", "revision", "config_key")},
                "vectors_sha256": (m.get("files") or {}).get(VECTORS_FILE), "memory_mib": round(self.memory_bytes() / 2**20, 1),
                "load_seconds": round(self.load_seconds, 3), "collapse": m.get("collapse")}

    # ------------------------------------------------------------------ search
    def _ranges(self, kinds) -> list[tuple[int, int]]:
        if kinds is None:
            kinds = tuple(self.kind_ranges)
        if isinstance(kinds, str):
            kinds = (kinds,)
        kinds = tuple(kinds)
        bad = [k for k in kinds if k not in KINDS]
        if bad or not kinds:
            raise ValueError(f"unknown document kinds {bad or kinds}")
        rs = sorted(self.kind_ranges[k] for k in set(kinds) if k in self.kind_ranges)
        merged: list[list[int]] = []
        for a, b in rs:
            if merged and merged[-1][1] == a:
                merged[-1][1] = b
            elif b > a:
                merged.append([a, b])
        return [(a, b) for a, b in merged]

    def _query(self, q) -> np.ndarray:
        q = np.asarray(q)
        if q.ndim != 1 or q.shape[0] != self.dim:
            raise ValueError(f"query vector must have shape ({self.dim},), got {q.shape}")
        if not np.issubdtype(q.dtype, np.floating):
            raise ValueError("query vector must be floating point")
        q = q.astype(np.float32, copy=False)
        if not np.isfinite(q).all():
            raise ValueError("query vector has non-finite values")
        return np.ascontiguousarray(q)

    def scores(self, q, kinds: Iterable[str] | None = ("cve",)) -> tuple[np.ndarray, list[tuple[int, int]]]:
        """Document scores for the requested kinds: (concatenated float32 scores, document ranges)."""
        q = self._query(q)
        ranges = self._ranges(kinds)
        parts = []
        for a, b in ranges:
            if self.groups is None:
                parts.append(self.vectors[a:b] @ q)
            else:
                r0 = int(self.groups[a])
                r1 = int(self.groups[b]) if b < self.n_docs else self.vectors.shape[0]
                rows = self.vectors[r0:r1] @ q
                parts.append(np.maximum.reduceat(rows, self.groups[a:b] - r0))
        return (np.concatenate(parts) if len(parts) != 1 else parts[0]), ranges

    def search(self, q, k: int = 100, kinds: Iterable[str] | None = ("cve",), mask: np.ndarray | None = None
               ) -> list[tuple[str, float]]:
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise ValueError("k must be a positive integer")
        k = min(k, MAX_K)
        s, ranges = self.scores(q, kinds)
        pos = _positions(ranges)
        if mask is not None:
            mask = np.asarray(mask)
            if mask.dtype != bool or mask.shape != (self.n_docs,):
                raise ValueError(f"mask must be a boolean array of shape ({self.n_docs},)")
            keep = mask[pos] if len(ranges) != 1 or ranges[0] != (0, self.n_docs) else mask
            s = np.where(keep, s, np.float32(-np.inf))
        sel = top_k(s, k)
        if mask is not None:
            sel = sel[np.isfinite(s[sel])]
        return [(self.doc_ids[int(pos[i])], float(s[i])) for i in sel]

    def brute_force(self, q, k: int = 100, kinds: Iterable[str] | None = ("cve",)) -> list[tuple[str, float]]:
        """Reference: float64 score of every row of the requested kinds, maximum per document, complete stable
        sort by (score descending, position)."""
        q = self._query(q).astype(np.float64)
        out_s, out_p = [], []
        for a, b in self._ranges(kinds):
            for c in range(a, b, 32768):
                d = min(b, c + 32768)
                if self.groups is None:
                    sc = self.vectors[c:d].astype(np.float64) @ q
                else:
                    r0 = int(self.groups[c])
                    r1 = int(self.groups[d]) if d < self.n_docs else self.vectors.shape[0]
                    rows = self.vectors[r0:r1].astype(np.float64) @ q
                    sc = np.maximum.reduceat(rows, self.groups[c:d] - r0)
                out_s.append(sc)
                out_p.append(np.arange(c, d))
        s = np.concatenate(out_s)
        p = np.concatenate(out_p)
        order = np.lexsort((p, -s))[: min(k, MAX_K)]
        return [(self.doc_ids[int(p[i])], float(s[i])) for i in order]


def _positions(ranges: Sequence[tuple[int, int]]) -> np.ndarray:
    if len(ranges) == 1:
        a, b = ranges[0]
        return np.arange(a, b)
    return np.concatenate([np.arange(a, b) for a, b in ranges])


def top_k(s: np.ndarray, k: int) -> np.ndarray:
    """Indices of the k largest values of ``s`` (ties broken by smaller index), exactly."""
    n = len(s)
    if n == 0:
        return np.zeros(0, dtype=np.int64)
    if k >= n:
        return np.lexsort((np.arange(n), -s.astype(np.float64)))
    kth = np.partition(s, n - k)[n - k]
    cand = np.flatnonzero(s >= kth)  # every value tied with the k-th stays for the tie-break
    order = np.lexsort((cand, -s[cand].astype(np.float64)))
    return cand[order[:k]]
