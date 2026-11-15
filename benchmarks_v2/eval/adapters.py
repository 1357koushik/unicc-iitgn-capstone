"""System adapters: turn one query into one run-file record. Standard library only.

``http_v1`` and ``http_v2`` call a running service; the response field mapping is configuration
(``variants.yaml``), so v2 field changes need no code change. ``runfile`` replays a precomputed run file.
``inprocess`` imports a retrieval component and calls it directly (a component evaluated on its own, such
as the lexical index, before the service exists); the factory returns an object with
``search(text) -> [(doc_id, score), ...]`` and optionally ``info() -> dict``.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .schema import TIER_RANK, ValidationError, load_run

CVE_PREFIX_RE = re.compile(r"^(CVE-\d{4}-\d{4,})(?:_[A-Za-z0-9]+)*$", re.IGNORECASE)
MAX_ERROR_CHARS = 300


class MappingError(RuntimeError):
    """The response does not have the configured shape: a harness configuration problem, so the run stops."""


class TransportError(RuntimeError):
    """The service could not be reached (refused, reset, disconnected). Not recorded; the run stops."""


_MISSING = object()


def get_path(obj: Any, path: str) -> Any:
    """Dotted field path with integer list indices, e.g. ``citations.0.doc_id``. Returns _MISSING if absent."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return cur


def transform_doc_id(raw: str, how: str) -> str | None:
    if how == "identity":
        return raw
    if how == "upper":
        return raw.upper()
    if how == "cve_prefix":
        m = CVE_PREFIX_RE.match(raw.strip())
        return m.group(1).upper() if m else None
    raise MappingError(f"unknown doc_id_transform {how!r}")


class SqliteResolver:
    """Read-only lookup, e.g. v1 hybrid search chunk_id -> corpus doc_id."""

    def __init__(self, path: str, sql: str):
        self.path = os.path.expanduser(path)
        self.sql = sql
        self._db = None
        self._cache: dict[str, str | None] = {}

    def __call__(self, key: str) -> str | None:
        if key in self._cache:
            return self._cache[key]
        if self._db is None:
            self._db = sqlite3.connect(f"file:{Path(self.path).as_posix()}?mode=ro", uri=True, check_same_thread=False)
        row = self._db.execute(self.sql, (key,)).fetchone()
        self._cache[key] = row[0] if row else None
        return self._cache[key]


class HttpAdapter:
    def __init__(self, name: str, cfg: dict, base_url: str | None = None, timeout_s: float | None = None):
        self.name = name
        self.cfg = cfg
        self.base_url = (base_url or cfg["base_url"]).rstrip("/")
        self.endpoint = cfg["endpoint"]
        self.request_extra = dict(cfg.get("request") or {})
        self.timeout_s = float(timeout_s or cfg.get("timeout_s", 120))
        self.retries = int(cfg.get("retries", 2))
        self.retry_wait_s = float(cfg.get("retry_wait_s", 5))
        self.m = dict(cfg["mapping"])
        r = self.m.get("doc_id_resolver")
        self.resolver = SqliteResolver(r["path"], r["sql"]) if r else None

    # -- HTTP
    def _post(self, body: dict) -> tuple[int, bytes, float]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url + self.endpoint, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                payload = resp.read()
                return resp.status, payload, (time.perf_counter() - t0) * 1000.0
        except urllib.error.HTTPError as exc:
            payload = exc.read() if hasattr(exc, "read") else b""
            return exc.code, payload, (time.perf_counter() - t0) * 1000.0
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                return -1, b"", (time.perf_counter() - t0) * 1000.0
            raise TransportError(f"{self.base_url}{self.endpoint}: {exc.reason}") from exc
        except (socket.timeout, TimeoutError):
            return -1, b"", (time.perf_counter() - t0) * 1000.0
        except (ConnectionError, http.client.RemoteDisconnected, http.client.IncompleteRead) as exc:
            raise TransportError(f"{self.base_url}{self.endpoint}: {type(exc).__name__}: {exc}") from exc

    def post_with_retry(self, body: dict) -> tuple[int, bytes, float]:
        last = None
        for attempt in range(self.retries + 1):
            try:
                return self._post(body)
            except TransportError as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(self.retry_wait_s)
        raise last  # type: ignore[misc]

    def service_info(self) -> dict | None:
        hp = self.cfg.get("health_path")
        if not hp:
            return None
        try:
            with urllib.request.urlopen(self.base_url + hp, timeout=10) as resp:
                info = json.loads(resp.read().decode("utf-8", "replace"))
                return info if isinstance(info, dict) else {"health": info}
        except Exception as exc:  # informational only
            return {"health_error": f"{type(exc).__name__}: {exc}"}

    # -- mapping
    def map_response(self, payload: Any) -> tuple[list[dict], bool, dict]:
        results = get_path(payload, self.m["results"])
        if results is _MISSING or not isinstance(results, list):
            raise MappingError(f"{self.name}: response has no list at {self.m['results']!r}")
        ranked, seen, dups = [], set(), 0
        for i, item in enumerate(results, 1):
            raw = get_path(item, self.m["doc_id"])
            if raw is _MISSING or not isinstance(raw, str) or not raw:
                raise MappingError(f"{self.name}: result {i} has no string at {self.m['doc_id']!r}")
            if self.resolver is not None:
                resolved = self.resolver(raw)
                if resolved is None:
                    raise MappingError(f"{self.name}: result {i}: {raw!r} not found by the resolver")
                raw = resolved
            doc = transform_doc_id(raw, self.m.get("doc_id_transform", "identity"))
            if doc is None:
                raise MappingError(f"{self.name}: result {i}: cannot map {raw!r} with "
                                   f"{self.m.get('doc_id_transform')}")
            if doc in seen:
                dups += 1
                continue
            seen.add(doc)
            score = get_path(item, self.m["score"])
            if score is _MISSING or isinstance(score, bool) or not isinstance(score, (int, float)):
                raise MappingError(f"{self.name}: result {i} has no number at {self.m['score']!r}")
            tier = None
            if self.m.get("tier"):
                tier = get_path(item, self.m["tier"])
                if tier is _MISSING:
                    raise MappingError(f"{self.name}: result {i} has no {self.m['tier']!r}")
                if tier is not None and tier not in TIER_RANK:
                    raise MappingError(f"{self.name}: result {i}: unknown tier {tier!r}")
            prob = None
            if self.m.get("probability"):
                prob = get_path(item, self.m["probability"])
                if prob is _MISSING:
                    raise MappingError(f"{self.name}: result {i} has no {self.m['probability']!r}")
                if prob is not None:
                    if isinstance(prob, bool) or not isinstance(prob, (int, float)) or not -1e-9 <= prob <= 1 + 1e-9:
                        raise MappingError(f"{self.name}: result {i}: probability {prob!r} is not in [0, 1]")
                    prob = min(1.0, max(0.0, float(prob)))
            ranked.append({"doc_id": doc, "score": float(score), "tier": tier, "probability": prob})
        abstained = False
        if self.m.get("abstained"):
            a = get_path(payload, self.m["abstained"])
            if a is _MISSING or not isinstance(a, bool):
                raise MappingError(f"{self.name}: response has no boolean at {self.m['abstained']!r}")
            abstained = a
        if self.m.get("abstain_when_empty") and not ranked:
            abstained = True
        return ranked, abstained, {"raw_results": len(results), "duplicates_removed": dups}

    def query(self, text: str) -> dict:
        body = {"query": text, **self.request_extra}
        status, payload, ms = self.post_with_retry(body)
        extra: dict[str, Any] = {"http_status": status}
        if status == -1:
            return {"ranked": [], "abstained": False, "latency_ms": ms,
                    "error": f"timeout: no response within {self.timeout_s:g} s", "extra": extra}
        if status != 200:
            detail = payload.decode("utf-8", "replace")[:MAX_ERROR_CHARS]
            return {"ranked": [], "abstained": False, "latency_ms": ms, "error": f"http_{status}: {detail}",
                    "extra": extra}
        try:
            obj = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {"ranked": [], "abstained": False, "latency_ms": ms, "error": f"invalid_json: {exc}", "extra": extra}
        ranked, abstained, info = self.map_response(obj)
        extra.update(info)
        return {"ranked": ranked, "abstained": abstained, "latency_ms": ms, "error": None, "extra": extra}

    def describe(self) -> dict:
        return {"adapter": self.cfg["adapter"], "base_url": self.base_url, "endpoint": self.endpoint,
                "request": self.request_extra, "timeout_s": self.timeout_s, "mapping": self.m}


class RunfileAdapter:
    """Replays the records of a precomputed run file (validated on load)."""

    def __init__(self, name: str, cfg: dict, path: str | None = None):
        self.name = name
        self.cfg = cfg
        p = Path(path or cfg["path"])
        if not p.is_absolute() and not p.exists():
            p = Path(__file__).resolve().parents[2] / p  # registry paths are relative to the repository root
        self.path = str(p)
        self.run = load_run(p)

    def record_for(self, qid: str) -> dict:
        rec = self.run.records.get(qid)
        if rec is None:
            raise ValidationError(self.path, [f"no record for {qid}"])
        d = rec.to_json()
        d.pop("qid")
        d.pop("variant")
        return d

    def service_info(self) -> dict | None:
        return {"source_run": self.path, "source_variant": self.run.variant, "source_sha256": self.run.sha256}

    def describe(self) -> dict:
        return {"adapter": "runfile", "path": self.path}


class InProcessAdapter:
    """Calls ``factory(**options).search(text)`` in this process. Timing covers the search call only. An
    exception raised by the component is recorded as an error (a miss), like an HTTP 500 from a service."""

    def __init__(self, name: str, cfg: dict):
        import importlib
        self.name = name
        self.cfg = cfg
        mod_name, attr = cfg["factory"].split(":")
        factory = getattr(importlib.import_module(mod_name), attr)
        self.options = dict(cfg.get("options") or {})
        self.system = factory(**self.options)

    def query(self, text: str) -> dict:
        t0 = time.perf_counter()
        try:
            hits = self.system.search(text)
        except Exception as exc:  # the component failed on this input
            ms = (time.perf_counter() - t0) * 1000.0
            return {"ranked": [], "abstained": False, "latency_ms": ms,
                    "error": f"exception: {type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS], "extra": {}}
        ms = (time.perf_counter() - t0) * 1000.0
        ranked, seen, dups = [], set(), 0
        for i, (doc, score) in enumerate(hits, 1):
            if not isinstance(doc, str) or not doc:
                raise MappingError(f"{self.name}: result {i} has no doc_id string")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise MappingError(f"{self.name}: result {i} has no numeric score")
            if doc in seen:
                dups += 1
                continue
            seen.add(doc)
            ranked.append({"doc_id": doc, "score": float(score), "tier": None, "probability": None})
        return {"ranked": ranked, "abstained": False, "latency_ms": ms, "error": None,
                "extra": {"raw_results": len(hits), "duplicates_removed": dups}}

    def service_info(self) -> dict | None:
        info = getattr(self.system, "info", None)
        return info() if callable(info) else None

    def describe(self) -> dict:
        return {"adapter": "inprocess", "factory": self.cfg["factory"], "options": self.options}


def make_adapter(name: str, cfg: dict, base_url: str | None = None, timeout_s: float | None = None,
                 runfile: str | None = None):
    if cfg["adapter"] in ("http_v1", "http_v2"):
        return HttpAdapter(name, cfg, base_url, timeout_s)
    if cfg["adapter"] == "runfile":
        return RunfileAdapter(name, cfg, runfile)
    if cfg["adapter"] == "inprocess":
        return InProcessAdapter(name, cfg)
    raise ValueError(f"unknown adapter {cfg['adapter']!r}")
