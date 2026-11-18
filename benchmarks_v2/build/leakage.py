"""Leakage detection shared by the builder (pre-filter) and tests/test_benchmark_leakage.py.

A query *collides* with a reference text (an expansion-source record field, or an ATT&CK description
sentence) when any of these hold, with CVE identifiers removed from both sides first:

1. exact: the query text equals the reference text (whitespace-trimmed);
2. normalised: equal after NFKC, lower-casing and collapsing non-alphanumerics;
3. contained: the normalised query (at least 4 tokens) is a substring of the normalised reference;
4. near-duplicate: |Q∩R| / max(|Q|,|R|) >= 0.9 over content tokens;
5. covered-by-title: for short reference fields (titles and names), |Q∩R| / |Q| >= 0.9 with |Q| >= 3.

Queries whose text has no content tokens once CVE identifiers are removed (pure identifier lookups,
slice T1) are skipped: an identifier cannot be derived from a source's wording.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass

from .text import content_tokens, normalize, strip_cve_ids

NEAR_DUP = 0.9
COVER = 0.9

# source -> [(field, short?)]
EXPANSION_FIELDS = {
    "exploitdb": [("title", True)],
    "metasploit_modules": [("name", True), ("description", False)],
    "nuclei_templates": [("name", True)],
    "poc_in_github": [("description", False)],
}


@dataclass
class Collision:
    ref_id: str
    kind: str
    score: float


class TextIndex:
    def __init__(self, refs: list[tuple[str, str, bool]]):
        """refs: (ref_id, text, short_field)."""
        self.ids: list[str] = []
        self.short: list[bool] = []
        self.toks: list[frozenset] = []
        self.norm: list[str] = []
        self.exact: dict[str, list[int]] = defaultdict(list)
        self.normmap: dict[str, list[int]] = defaultdict(list)
        self.post: dict[str, list[int]] = defaultdict(list)
        for rid, text, short in refs:
            if not text or not str(text).strip():
                continue
            text = str(text)
            i = len(self.ids)
            self.ids.append(rid)
            self.short.append(short)
            t = frozenset(content_tokens(text))
            self.toks.append(t)
            n = normalize(strip_cve_ids(text))
            self.norm.append(n)
            self.exact[strip_cve_ids(text).strip()].append(i)
            self.normmap[n].append(i)
            for tok in t:
                self.post[tok].append(i)

    def __len__(self) -> int:
        return len(self.ids)

    def collisions(self, query: str) -> list[Collision]:
        q = frozenset(content_tokens(query))
        if not q:
            return []
        out: list[Collision] = []
        stripped = strip_cve_ids(query).strip()
        qn = normalize(stripped)
        for i in self.exact.get(stripped, []):
            out.append(Collision(self.ids[i], "exact", 1.0))
        for i in self.normmap.get(qn, []):
            out.append(Collision(self.ids[i], "normalised", 1.0))
        # prefix filter: any reference sharing >= ceil(0.9|Q|) tokens holds one of the rarest
        # |Q| - ceil(0.9|Q|) + 1 query tokens.
        need = math.ceil(min(NEAR_DUP, COVER) * len(q) - 1e-9)
        rare = sorted(q, key=lambda t: (len(self.post.get(t, ())), t))[: len(q) - need + 1]
        cand: set[int] = set()
        for t in rare:
            cand.update(self.post.get(t, ()))
        qlen_tokens = len(qn.split())
        for i in sorted(cand):
            r = self.toks[i]
            inter = len(q & r)
            nd = inter / max(len(q), len(r))
            if nd >= NEAR_DUP:
                out.append(Collision(self.ids[i], "near_duplicate", round(nd, 3)))
                continue
            cov = inter / len(q)
            if self.short[i] and len(q) >= 3 and cov >= COVER:
                out.append(Collision(self.ids[i], "covered_by_title", round(cov, 3)))
                continue
            if cov == 1.0 and qlen_tokens >= 4 and qn and qn in self.norm[i]:
                out.append(Collision(self.ids[i], "contained", 1.0))
        return out

    def coverage_max(self, query: str) -> float:
        """Informational: max |Q∩R|/|Q| over all references (directional coverage)."""
        q = frozenset(content_tokens(query))
        if not q:
            return 0.0
        best = 0
        counts: dict[int, int] = defaultdict(int)
        for t in q:
            for i in self.post.get(t, ()):
                counts[i] += 1
        if counts:
            best = max(counts.values())
        return best / len(q)


def expansion_refs(srcs) -> tuple[list[tuple[str, str, bool]], dict[str, dict]]:
    """Load every expansion source's text fields (purpose leakage_check)."""
    refs = []
    used = {}
    for name, fields in EXPANSION_FIELDS.items():
        s = srcs.get(name, "leakage_check")
        if s is None:
            continue
        if s.role != "expansion":
            raise RuntimeError(f"{name} expected role expansion, got {s.role}")
        used[name] = s.input_entry()
        for k, r in enumerate(s.records()):
            for fld, short in fields:
                v = r.get(fld)
                if v:
                    refs.append((f"{name}:{k}:{fld}", v, short))
    return refs, used


def attack_sentence_refs(kb) -> list[tuple[str, str, bool]]:
    return [(f"attack:{aid}:s{k}", s, False) for k, (aid, s) in enumerate(kb.description_sentences())]


def attack_sentence_copied(index: TextIndex, query: str) -> list[Collision]:
    """T9 rule: the query must not copy an ATT&CK description sentence (or a 6+-token run of one)."""
    out = index.collisions(query)
    qn = normalize(strip_cve_ids(query))
    if len(qn.split()) >= 6:
        # 6-token shingles of the query appearing in any sentence
        toks = qn.split()
        shingles = {" ".join(toks[i:i + 6]) for i in range(len(toks) - 5)}
        cand = set()
        q = frozenset(content_tokens(query))
        for t in q:
            cand.update(index.post.get(t, ()))
        for i in sorted(cand):
            if any(sh in index.norm[i] for sh in shingles):
                out.append(Collision(index.ids[i], "shared_6gram", 1.0))
    return out
