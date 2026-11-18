"""ATT&CK Enterprise objects and STIX relationships (source `attack_enterprise`, role `attack`).

Used only for T9 ground truth and for resolving entity names in Team 3's cases. Description text is
never copied into queries; it is loaded so the leakage test can check that.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .sources import Sources
from .text import name_key

_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_CODE = re.compile(r"</?code>")


def clean_description(s: str) -> str:
    s = _MD_LINK.sub(r"\1", s or "")
    s = _CITATION.sub("", s)
    s = _CODE.sub("", s)
    return re.sub(r"\s+", " ", s).strip()


@dataclass
class AttackKB:
    objects: dict[str, dict] = field(default_factory=dict)          # attack_id -> record (active only)
    all_objects: dict[str, dict] = field(default_factory=dict)      # attack_id -> record (any state)
    stix_to_id: dict[str, str] = field(default_factory=dict)
    rels: list[tuple[str, str, str, str]] = field(default_factory=list)  # (type, src_id, dst_id, rel stix id)
    version: dict = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return bool(self.objects)

    def doc_id(self, attack_id: str) -> str:
        return f"attack:{attack_id}"

    def kind(self, attack_id: str) -> str:
        return self.objects[attack_id]["kind"]

    def name(self, attack_id: str) -> str:
        return self.objects[attack_id]["name"]

    def _adj(self) -> tuple[dict, dict]:
        if not hasattr(self, "_adj_cache"):
            o: dict = defaultdict(set)
            i: dict = defaultdict(set)
            for t, s, d, _ in self.rels:
                o[(s, t)].add(d)
                i[(d, t)].add(s)
            self._adj_cache = (o, i)
        return self._adj_cache

    def out(self, src: str, rtype: str, dst_kind: str | None = None) -> list[str]:
        o, _ = self._adj()
        return sorted(d for d in o.get((src, rtype), ()) if dst_kind is None or self.objects[d]["kind"] == dst_kind)

    def inc(self, dst: str, rtype: str, src_kind: str | None = None) -> list[str]:
        _, i = self._adj()
        return sorted(s for s in i.get((dst, rtype), ()) if src_kind is None or self.objects[s]["kind"] == src_kind)

    def name_index(self) -> dict[str, set[str]]:
        """normalised name or alias -> attack IDs (active objects)."""
        idx: dict[str, set[str]] = defaultdict(set)
        for aid, o in self.objects.items():
            for n in [o["name"]] + list(o.get("aliases") or []):
                k = name_key(n)
                if k:
                    idx[k].add(aid)
        return idx

    def resolve(self, name: str, kinds: tuple[str, ...] = ("group", "software")) -> str | None:
        ids = {a for a in self.name_index().get(name_key(name), set()) if self.objects[a]["kind"] in kinds}
        return next(iter(ids)) if len(ids) == 1 else None

    def description_sentences(self) -> list[tuple[str, str]]:
        from .text import sentences
        out = []
        for aid in sorted(self.all_objects):
            for s in sentences(clean_description(self.all_objects[aid].get("description") or "")):
                out.append((aid, s))
        return out


def load_attack(srcs: Sources, purpose: str = "ground_truth") -> AttackKB:
    kb = AttackKB()
    s = srcs.get("attack_enterprise", purpose)
    if s is None:
        return kb
    kb.version = dict(s.manifest.get("upstream_version") or {})
    recs = s.records()
    rels = []
    for r in recs:
        if r.get("kind") == "relationship":
            rels.append(r)
            continue
        aid = r.get("attack_id")
        if not aid:
            continue
        kb.all_objects[aid] = r
        if not r.get("revoked") and not r.get("deprecated"):
            kb.objects[aid] = r
            kb.stix_to_id[r["stix_id"]] = aid
    for r in rels:
        if r.get("revoked") or r.get("deprecated"):
            continue
        a = kb.stix_to_id.get(r.get("source_ref"))
        b = kb.stix_to_id.get(r.get("target_ref"))
        if a and b:
            kb.rels.append((r["relationship_type"], a, b, r["stix_id"]))
    kb.rels.sort()
    return kb
