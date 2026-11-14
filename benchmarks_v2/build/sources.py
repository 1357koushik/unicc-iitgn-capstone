"""Access to the B1 collected sources with the role firewall of plan section 6.1.

Every load names the purpose; a source whose manifest role does not permit that purpose is refused.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .common import sha256_file

# purpose -> roles allowed to serve it
PURPOSE_ROLES = {
    "query_text": ("query", "incident"),       # writing or selecting query text
    "ground_truth": ("query", "incident", "attack"),  # relationships / known-item links (never query text)
    "leakage_check": ("expansion", "attack", "query", "incident"),  # read only to test for copying
    "corroboration": ("query", "incident"),
}


class RoleViolation(RuntimeError):
    pass


@dataclass
class Source:
    name: str
    role: str
    status: str
    date: str
    manifest: dict
    records_path: Path | None

    @property
    def licence(self) -> str:
        return (self.manifest.get("license") or {}).get("name", "")

    def records(self) -> list[dict]:
        if self.records_path is None or not self.records_path.is_file():
            return []
        with open(self.records_path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def input_entry(self) -> dict:
        sha = self.manifest.get("records_sha256")
        if sha is None and self.records_path is not None and self.records_path.is_file():
            sha = sha256_file(self.records_path)
        return {"name": f"source/{self.name}", "date": self.date, "role": self.role, "status": self.status,
                "sha256": sha, "records": self.manifest.get("record_count", 0),
                "upstream_version": self.manifest.get("upstream_version") or {}}


class Sources:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._cache: dict[str, Source | None] = {}
        self.used: dict[str, Source] = {}

    def get(self, name: str, purpose: str) -> Source | None:
        if name not in self._cache:
            self._cache[name] = self._load(name)
        s = self._cache[name]
        if s is None:
            return None
        allowed = PURPOSE_ROLES[purpose]
        if s.role not in allowed:
            raise RoleViolation(f"source {name} has role {s.role!r}; not permitted for {purpose}")
        self.used[name] = s
        return s

    def _load(self, name: str) -> Source | None:
        sdir = self.root / name
        latest = sdir / "LATEST"
        if not latest.is_file():
            return None
        day = latest.read_text(encoding="utf-8").strip()
        d = sdir / day
        mp = d / "manifest.json"
        if not mp.is_file():
            return None
        m = json.loads(mp.read_text(encoding="utf-8"))
        rp = d / "records.jsonl"
        return Source(name=name, role=m.get("role", ""), status=m.get("status", ""), date=day, manifest=m,
                      records_path=rp if rp.is_file() else None)

    def available(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.name for p in self.root.iterdir() if (p / "LATEST").is_file())

    def role_of(self, name: str) -> str | None:
        if name not in self._cache:
            self._cache[name] = self._load(name)
        s = self._cache[name]
        return s.role if s else None
