"""Equivalence sets: CVE documents that describe the same flaw.

Evidence accepted (each set records its reason):

1. ``rejected_duplicate``: a CVE rejected with a reason stating it is a duplicate (or reservation
   duplicate) of another CVE, naming that CVE (NVD rejected description or CVE List rejectedReasons).
   Members: the rejected CVE and the CVE(s) its reason names.
2. ``published_duplicate_statement``: a published CVE whose description states without hedging that it
   is a duplicate of / the same as another CVE ("might", "may", "possibly", "probably", "likely",
   "insufficient information" disqualify the statement).

Chains are merged with union-find. Sets never contain ATT&CK documents.
"""
from __future__ import annotations

import re

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DUP_REASON = re.compile(r"duplicate", re.I)
_PUB_DUP = re.compile(r"\b(?:is|was) (?:a duplicate of|the same (?:issue|vulnerability) as|identical to) (CVE-\d{4}-\d{4,})",
                      re.I)
_HEDGE = re.compile(r"\b(might|may|possibly|probably|likely|insufficient|unclear|perhaps|suggests?)\b", re.I)


def _duplicate_targets(cid: str, reason: str) -> list[str]:
    if not reason or not _DUP_REASON.search(reason):
        return []
    # Prefer IDs after the word "duplicate"; fall back to ConsultIDs.
    m = _DUP_REASON.search(reason)
    after = _CVE.findall(reason[m.start():])
    ids = [x for x in after if x != cid]
    if not ids:
        ids = [x for x in _CVE.findall(reason) if x != cid]
    return sorted(set(ids))


class _UF:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if rb < ra:
                ra, rb = rb, ra
            self.p[rb] = ra


def build_equivalence(u) -> tuple[list[dict], dict]:
    """Return (sets, stats). Each set: {set_id, members, reason}."""
    uf = _UF()
    reasons: dict[tuple[str, str], str] = {}
    stats = {"rejected_total": 0, "rejected_duplicate_reason": 0, "rejected_duplicate_with_target": 0,
             "duplicate_target_missing_from_universe": 0, "published_duplicate_statements": 0}
    for cid in sorted(u.nvd):
        r = u.nvd[cid]
        if r["st"] == "Rejected":
            stats["rejected_total"] += 1
            if _DUP_REASON.search(r["desc"]):
                stats["rejected_duplicate_reason"] += 1
            tg = _duplicate_targets(cid, r["desc"])
            tg_ok = [t for t in tg if t in u.nvd or t in u.kev or t in u.epss]
            stats["duplicate_target_missing_from_universe"] += len(tg) - len(tg_ok)
            if tg_ok:
                stats["rejected_duplicate_with_target"] += 1
            for t in tg_ok:
                uf.union(cid, t)
                reasons[(cid, t)] = "rejected_duplicate"
        else:
            for sent in re.split(r"(?<=[.!?])\s+", r["desc"]):
                m = _PUB_DUP.search(sent)
                if m and not _HEDGE.search(sent) and m.group(1) != cid and m.group(1) in u.nvd:
                    uf.union(cid, m.group(1))
                    reasons[(cid, m.group(1))] = "published_duplicate_statement"
                    stats["published_duplicate_statements"] += 1
    groups: dict[str, set[str]] = {}
    for a, b in reasons:
        root = uf.find(a)
        groups.setdefault(root, set()).update({a, b})
    sets = []
    for root in sorted(groups):
        members = sorted(groups[root])
        kinds = sorted({reasons[k] for k in reasons if k[0] in groups[root]})
        evidence = []
        for (a, b), why in sorted(reasons.items()):
            if a in groups[root]:
                evidence.append(f"{a} {'rejected as duplicate of' if why == 'rejected_duplicate' else 'states it is the same as'} {b}")
        sets.append({"set_id": f"EQ-{members[0]}", "members": members,
                     "reason": "; ".join(kinds) + ": " + "; ".join(evidence[:5])
                     + (f"; (+{len(evidence) - 5} more)" if len(evidence) > 5 else "")})
    stats["sets"] = len(sets)
    stats["members"] = sum(len(s["members"]) for s in sets)
    stats["by_reason"] = {k: sum(1 for s in sets if s["reason"].startswith(k)) for k in
                          ("rejected_duplicate", "published_duplicate_statement")}
    return sets, stats


class EquivalenceMap:
    def __init__(self, sets: list[dict], u):
        self.set_of: dict[str, str] = {}
        self.members: dict[str, list[str]] = {}
        for s in sets:
            self.members[s["set_id"]] = s["members"]
            for m in s["members"]:
                self.set_of[m] = s["set_id"]
        self.u = u

    def canonical(self, cid: str) -> str | None:
        """For a rejected duplicate, the searchable member it maps to (lowest ID if several)."""
        sid = self.set_of.get(cid)
        if sid is None:
            return None
        live = [m for m in self.members[sid] if m != cid and self.u.searchable(m)]
        return live[0] if live else None
