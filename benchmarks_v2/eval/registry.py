"""Variant registry (``variants.yaml``). Standard library + PyYAML only."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_REGISTRY = Path(__file__).with_name("variants.yaml")
ADAPTERS = ("http_v1", "http_v2", "runfile", "inprocess")
MAPPING_KEYS = ("results", "doc_id", "doc_id_transform", "doc_id_resolver", "score", "tier", "probability",
                "abstained", "abstain_when_empty")
HTTP_KEYS = ("adapter", "description", "base_url", "endpoint", "request", "timeout_s", "health_path", "mapping",
             "retries", "retry_wait_s", "max_transport_failures", "service")
RUNFILE_KEYS = ("adapter", "description", "path")
INPROCESS_KEYS = ("adapter", "description", "factory", "options", "service")


class RegistryError(ValueError):
    pass


def load_registry(path: Path | None = None) -> dict[str, dict]:
    path = Path(path or DEFAULT_REGISTRY)
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("variants"), dict):
        raise RegistryError(f"{path}: expected a mapping with a 'variants' mapping")
    problems = []
    for name, cfg in doc["variants"].items():
        problems.extend(validate_variant(name, cfg))
    if problems:
        raise RegistryError(f"{path}:\n  " + "\n  ".join(problems))
    return doc["variants"]


def validate_variant(name: str, cfg: Any) -> list[str]:
    p = []
    if not isinstance(cfg, dict):
        return [f"{name}: must be a mapping"]
    ad = cfg.get("adapter")
    if ad not in ADAPTERS:
        return [f"{name}: adapter {ad!r} is not one of {', '.join(ADAPTERS)}"]
    allowed = RUNFILE_KEYS if ad == "runfile" else INPROCESS_KEYS if ad == "inprocess" else HTTP_KEYS
    for k in cfg:
        if k not in allowed:
            p.append(f"{name}: unknown key {k!r}")
    if ad == "inprocess":
        f = cfg.get("factory")
        if not isinstance(f, str) or f.count(":") != 1 or not all(f.split(":")):
            p.append(f"{name}: inprocess adapter needs 'factory' as 'package.module:callable'")
        if cfg.get("options") is not None and not isinstance(cfg["options"], dict):
            p.append(f"{name}: options must be a mapping")
        return p
    if ad == "runfile":
        if not isinstance(cfg.get("path"), str):
            p.append(f"{name}: runfile adapter needs 'path'")
        return p
    for k in ("base_url", "endpoint"):
        if not isinstance(cfg.get(k), str):
            p.append(f"{name}: {k} must be a string")
    m = cfg.get("mapping")
    if not isinstance(m, dict):
        p.append(f"{name}: mapping must be a mapping")
        return p
    for k in m:
        if k not in MAPPING_KEYS:
            p.append(f"{name}: mapping: unknown key {k!r}")
    for k in ("results", "doc_id", "score"):
        if not isinstance(m.get(k), str):
            p.append(f"{name}: mapping.{k} must be a field path string")
    if m.get("doc_id_transform", "identity") not in ("identity", "upper", "cve_prefix"):
        p.append(f"{name}: mapping.doc_id_transform must be identity, upper or cve_prefix")
    r = m.get("doc_id_resolver")
    if r is not None and (not isinstance(r, dict) or r.get("kind") != "sqlite" or not r.get("path") or not r.get("sql")):
        p.append(f"{name}: mapping.doc_id_resolver must be {{kind: sqlite, path, sql}}")
    if cfg.get("request") is not None and not isinstance(cfg["request"], dict):
        p.append(f"{name}: request must be a mapping")
    return p


def get_variant(name: str, path: Path | None = None) -> dict:
    reg = load_registry(path)
    if name not in reg:
        raise RegistryError(f"unknown variant {name!r}; registered: {', '.join(sorted(reg))}")
    return dict(reg[name])
