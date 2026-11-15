"""Process-wide ATT&CK component for the service: one read-only store, its graph and gazetteer.

The build directory comes from `$TRE_ATTACK_DIR`, else the configured `attack_build_dir` (default
`./data/attack`, which follows `TRE_DATA_DIR`). When no build can be opened the component is `unavailable`
with the reason; callers then find no entities and no relationships, and the service reports the component
as degraded. There is no built-in fallback data.
"""
from __future__ import annotations

import logging
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from .gazetteer import Mention
from .graph import AttackGraph
from .reader import AttackStore

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_state: dict[str, Any] = {"loaded": False, "graph": None, "error": None, "path": None}


def configured_dir() -> Path:
    env = os.environ.get("TRE_ATTACK_DIR", "").strip()
    if env:
        return Path(env)
    from threat_retrieval_engine.config import get_config
    return get_config().attack_build_dir


def get_attack_graph() -> AttackGraph | None:
    """The loaded ATT&CK graph, opening the build on first use; None when unavailable."""
    if _state["loaded"]:
        return _state["graph"]
    with _lock:
        if not _state["loaded"]:
            path = configured_dir()
            _state["path"] = str(path)
            try:
                g = AttackGraph(AttackStore.open(path))
                g.store.gazetteer()  # load names now, not on the first request
                _state["graph"] = g
                logger.info("ATT&CK build %s loaded from %s", g.build_id, g.store.build_dir)
            except Exception as exc:  # missing or unreadable build: reported, never replaced by other data
                _state["error"] = f"{type(exc).__name__}: {exc}"
                logger.error("ATT&CK component unavailable: %s", _state["error"])
            _state["loaded"] = True
    return _state["graph"]


def set_attack_graph(graph: AttackGraph | None, error: str | None = None) -> None:
    """Install a graph (tests, or a service that opened a specific build). None marks it unavailable."""
    with _lock:
        _state.update(loaded=True, graph=graph, error=None if graph else (error or "not configured"),
                      path=str(graph.store.build_dir) if graph else None)
        _match_cached.cache_clear()
        _software_techniques.cache_clear()


def reset() -> None:
    """Forget the loaded build; the next call opens the configured directory again."""
    with _lock:
        if _state["graph"] is not None:
            _state["graph"].store.close()
        _state.update(loaded=False, graph=None, error=None, path=None)
        _match_cached.cache_clear()
        _software_techniques.cache_clear()


def status() -> dict[str, Any]:
    g = get_attack_graph()
    if g is None:
        return {"status": "unavailable", "reason": _state["error"], "path": _state["path"]}
    s = g.store
    return {"status": "available", "build_id": s.build_id, "attack_version": s.attack_version,
            "documents": s.count(), "searchable": s.count(searchable=True), "edges": s.edge_count(),
            "gazetteer_keys": len(s.gazetteer())}


@lru_cache(maxsize=8192)
def _match_cached(text: str, query: bool) -> tuple[Mention, ...]:
    g = _state["graph"]
    return tuple(g.store.gazetteer().match(text, query=query)) if g is not None else ()


def match_entities(text: str, query: bool = True) -> tuple[Mention, ...]:
    """Gazetteer mentions in `text` (cached per text). Empty when the component is unavailable."""
    if not text or get_attack_graph() is None:
        return ()
    return _match_cached(text, query)


def entity_names(text: str, query: bool = True) -> dict[str, list[str]]:
    """v1 pipeline view of the mentions: canonical ATT&CK titles of groups/campaigns (`threat_actors`) and
    software (`malware`), and ATT&CK IDs of techniques named by ID (`technique_ids`). An ambiguous name
    contributes every object it names."""
    g = get_attack_graph()
    out: dict[str, list[str]] = {"threat_actors": [], "malware": [], "technique_ids": [], "doc_ids": []}
    if g is None:
        return out
    for m in match_entities(text, query):
        for c in m.candidates:
            b = g.store.brief(c.doc_id)
            out["doc_ids"].append(c.doc_id)
            if c.doc_kind in ("group", "campaign"):
                out["threat_actors"].append(b["title"])
            elif c.doc_kind == "software":
                out["malware"].append(b["title"])
            elif c.doc_kind == "technique" and m.matched_by == "id":
                out["technique_ids"].append(b["attack_id"])
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


@lru_cache(maxsize=4096)
def _software_techniques(name: str) -> tuple[str, ...]:
    g = _state["graph"]
    if g is None:
        return ()
    return tuple(t for d in g.resolve(name, ("software",)) for t in g.techniques_used_by(d))


def techniques_for_software(names) -> set[str]:
    """ATT&CK IDs of the techniques that the named software (names, aliases or IDs) uses in the graph."""
    if get_attack_graph() is None:
        return set()
    return {t for n in names if n for t in _software_techniques(str(n))}


def canonical_name(name: str, kinds: tuple[str, ...]) -> str | None:
    """ATT&CK title for an exact name/alias/ID of one of `kinds`, when it names exactly one object."""
    g = get_attack_graph()
    if g is None or not name:
        return None
    ids = g.resolve(name, kinds)
    return g.store.brief(ids[0])["title"] if len(ids) == 1 else None
