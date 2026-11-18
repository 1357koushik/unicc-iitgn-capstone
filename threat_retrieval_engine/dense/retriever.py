"""Dense retrieval of a query text: query encoding (one interface per model) + exact search.

    from threat_retrieval_engine.dense import DenseRetriever
    r = DenseRetriever.open()                       # data/dense/LATEST and the model it was built with
    res = r.search("apache struts ognl injection", k=100, kinds=("cve",))
    res.hits, res.timings_ms                        # [(doc_id, cosine)], {"encode": .., "search": .., "total": ..}

The query is encoded by the same model, revision, pooling and documented query format the index's documents
were encoded with; a mismatch refuses to start (plan 5.1, startup integrity). For the exported v1 vectors two
query formats exist: ``documented`` (BGE-M3: no instruction) and ``v1`` (the bge-en instruction and no token
cap, as v1 served it).

Query input: whitespace runs collapsed, then the model's prefix, then truncation at ``query_max_tokens``
(default 256, the plan's model-input cap; identifiers are parsed from the full text by the parser, C4).
Encoded queries are kept in an LRU cache keyed by the exact model input (plan 4.9: a query-embedding cache
that changes no result).
"""
from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

from . import models as M
from .index import DenseIndex, set_blas_threads

MAX_QUERY_CHARS = 20_000


@dataclass
class DenseResult:
    hits: list[tuple[str, float]]
    timings_ms: dict[str, float] = field(default_factory=dict)
    cached: bool = False


class DenseRetriever:
    def __init__(self, index: DenseIndex, encoder=None, query_format: str = "documented",
                 query_max_tokens: int | None = None, cache_size: int = 4096, torch_threads: int | None = None,
                 blas_threads: int | None = None, model_root: str | None = None, disk_cache_dir: str | None = None):
        from .encoder import Encoder
        self.index = index
        im = index.model
        name = im.get("name")
        if name not in M.MODELS:
            raise ValueError(f"index {index.build_id} names no known model ({name!r})")
        spec = M.MODELS[name]
        for key in ("repo", "revision", "pooling", "query_prefix", "passage_prefix", "dim"):
            if im.get(key) != getattr(spec, key):
                raise ValueError(f"index {index.build_id} was built with {key}={im.get(key)!r}; this code has "
                                 f"{getattr(spec, key)!r}")
        if query_format not in ("documented", "v1"):
            raise ValueError("query_format must be 'documented' or 'v1'")
        if query_format == "v1" and index.manifest.get("source") != "v1_export":
            raise ValueError("query_format 'v1' applies only to the exported v1 vectors")
        self.query_format = query_format
        if query_max_tokens is None:
            query_max_tokens = spec.max_position_tokens if query_format == "v1" else M.QUERY_MAX_TOKENS
        self.query_max_tokens = int(min(query_max_tokens, spec.max_position_tokens))
        if torch_threads is None and os.environ.get("TRE_TORCH_THREADS"):
            torch_threads = int(os.environ["TRE_TORCH_THREADS"])
        if blas_threads is None and os.environ.get("TRE_BLAS_THREADS"):
            blas_threads = int(os.environ["TRE_BLAS_THREADS"])
        self.encoder = encoder or Encoder.load(name, model_root=model_root, threads=torch_threads, batch_size=1)
        if self.encoder.spec.name != name:
            raise ValueError(f"encoder {self.encoder.spec.name} differs from the index model {name}")
        self.prefix = M.V1_VECTORS["v1_query_prefix"] if query_format == "v1" else spec.query_prefix
        self.blas = set_blas_threads(blas_threads)
        self._cache: OrderedDict[str, np.ndarray] = OrderedDict()
        self._cache_size = int(cache_size)
        self._lock = threading.Lock()
        self.stats = {"queries": 0, "cache_hits": 0, "disk_cache_hits": 0}
        cdir = disk_cache_dir if disk_cache_dir is not None else os.environ.get("TRE_QUERY_VECTOR_CACHE")
        self.disk = QueryVectorStore(cdir, self.cache_identity()) if cdir else None

    def cache_identity(self) -> str:
        """Everything a query vector depends on besides the model input text."""
        import hashlib
        import json
        s = self.encoder.spec
        return hashlib.sha256(json.dumps({"repo": s.repo, "revision": s.revision, "pooling": s.pooling,
                                          "weights": s.weights_sha256, "prefix": self.prefix,
                                          "max_tokens": self.query_max_tokens}, sort_keys=True).encode()).hexdigest()[:20]

    @classmethod
    def open(cls, path=None, **kw) -> "DenseRetriever":
        return cls(DenseIndex.open(path), **kw)

    def model_input(self, text: str) -> str:
        from .encoder import normalize_text
        if not isinstance(text, str):
            raise TypeError("query must be a string")
        return self.prefix + normalize_text(text[:MAX_QUERY_CHARS], self.query_max_tokens)

    def encode(self, text: str) -> tuple[np.ndarray, bool]:
        key = self.model_input(text)
        with self._lock:
            v = self._cache.get(key)
            if v is not None:
                self._cache.move_to_end(key)
                self.stats["cache_hits"] += 1
                return v, True
        v = self.disk.get(key) if self.disk is not None else None
        if v is not None:
            self.stats["disk_cache_hits"] += 1
        else:
            ids = self.encoder.tokenizer([key], truncation=True, max_length=self.query_max_tokens, padding=False,
                                         return_attention_mask=False, return_token_type_ids=False)["input_ids"]
            v = self.encoder.encode_ids(ids)[0]
            if self.disk is not None:
                self.disk.put(key, v)
        with self._lock:
            self._cache[key] = v
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return v, False

    def search(self, text: str, k: int = 100, kinds: Iterable[str] | None = ("cve",),
               mask: np.ndarray | None = None) -> DenseResult:
        t0 = time.perf_counter()
        v, cached = self.encode(text)
        t1 = time.perf_counter()
        hits = self.index.search(v, k=k, kinds=kinds, mask=mask)
        t2 = time.perf_counter()
        self.stats["queries"] += 1
        return DenseResult(hits, {"encode": (t1 - t0) * 1000, "search": (t2 - t1) * 1000, "total": (t2 - t0) * 1000},
                           cached)

    def info(self) -> dict:
        return {"index": self.index.info(), "encoder": self.encoder.info(), "query_format": self.query_format,
                "query_prefix": self.prefix, "query_max_tokens": self.query_max_tokens, "blas": self.blas,
                "cache_size": self._cache_size,
                "disk_cache": None if self.disk is None else {"path": str(self.disk.path),
                                                              "identity": self.cache_identity()}}


class QueryVectorStore:
    """Offline evaluation aid: query vectors persisted per encoding configuration (SQLite, one file per
    configuration identity), so variants that share an encoder (e.g. several indexes built with one model) encode
    each benchmark query once. A stored vector is the encoder's own output for exactly that model input, so
    results are unchanged (check_c3 verifies that encoding is deterministic); timings of cache hits are not
    latency measurements. Enabled only by ``TRE_QUERY_VECTOR_CACHE`` or ``disk_cache_dir``; the service never
    sets it."""

    def __init__(self, root: str, identity: str):
        import sqlite3
        from pathlib import Path
        Path(root).mkdir(parents=True, exist_ok=True)
        self.path = Path(root) / f"qvec-{identity}.sqlite"
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=60)
        self._db.execute("CREATE TABLE IF NOT EXISTS v (k TEXT PRIMARY KEY, dim INTEGER, vec BLOB)")
        self._db.commit()
        self._lock = threading.Lock()

    def get(self, model_input: str) -> np.ndarray | None:
        import hashlib
        k = hashlib.sha256(model_input.encode("utf-8")).hexdigest()
        with self._lock:
            row = self._db.execute("SELECT dim, vec FROM v WHERE k = ?", (k,)).fetchone()
        if row is None:
            return None
        v = np.frombuffer(row[1], dtype=np.float32)
        return v.copy() if len(v) == row[0] else None

    def put(self, model_input: str, vec: np.ndarray) -> None:
        import hashlib
        k = hashlib.sha256(model_input.encode("utf-8")).hexdigest()
        v = np.ascontiguousarray(vec, dtype=np.float32)
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO v VALUES (?, ?, ?)", (k, len(v), v.tobytes()))
            self._db.commit()
