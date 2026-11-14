"""Acceptance gate applied to every candidate query: target resolution, overlap filter, leakage pre-filter.

The leakage tests re-check the built files independently; this gate makes the build pass them by
construction and records why every rejected candidate was dropped.
"""
from __future__ import annotations

from collections import defaultdict

from .leakage import TextIndex, attack_sentence_copied
from .model import Item, OverlapFilter, qrel


class Gate:
    def __init__(self, u, eqmap, expansion: TextIndex, attack_sentences: TextIndex | None):
        self.u = u
        self.eqmap = eqmap
        self.overlap = OverlapFilter(u)
        self.expansion = expansion
        self.attack_sentences = attack_sentences
        self.rejects: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.examined: dict[str, int] = defaultdict(int)

    def reject(self, sl: str, why: str) -> bool:
        self.rejects[sl][why] += 1
        return False

    def resolve_cve(self, cid: str) -> tuple[str, str, dict] | None:
        """Map a source-linked CVE to a searchable document: itself, or the live member of its equivalence
        set when it was rejected as a duplicate."""
        if self.u.searchable(cid):
            return cid, "known_item", {}
        if self.u.exists(cid) and self.u.is_rejected(cid):
            canon = self.eqmap.canonical(cid)
            if canon:
                return canon, "equivalence", {"remapped_from": cid}
        return None

    def targets_from(self, cves: list[str]) -> tuple[list[dict], dict]:
        out, meta = [], {}
        seen = set()
        for c in sorted(set(cves)):
            r = self.resolve_cve(c)
            if r is None:
                continue
            doc, origin, m = r
            if doc in seen:
                continue
            seen.add(doc)
            out.append(qrel(doc, 2, origin))
            if m:
                meta.setdefault("remapped_from", []).append(m["remapped_from"])
        return out, meta

    def accept(self, item: Item) -> bool:
        sl = item.slice
        self.examined[sl] += 1
        if item.answerable and not any(q["grade"] == 2 for q in item.qrels):
            return self.reject(sl, "no_searchable_target")
        if not item.text.strip():
            return self.reject(sl, "empty_text")
        if not self.overlap.apply(item):
            return self.reject(sl, "overlap_gt_0.6")
        if self.expansion is not None and self.expansion.collisions(item.text):
            return self.reject(sl, "expansion_text_collision")
        if self.attack_sentences is not None and sl in ("T9", "T0") and \
                attack_sentence_copied(self.attack_sentences, item.text):
            return self.reject(sl, "attack_description_copy")
        return True

    def report(self) -> dict:
        return {"examined": dict(sorted(self.examined.items())),
                "rejected": {k: dict(sorted(v.items())) for k, v in sorted(self.rejects.items())}}
