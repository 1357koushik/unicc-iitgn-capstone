"""C4 nickname route: a vulnerability name in the question returns every CVE it names as a candidate.

Names come from the C1 store's served aliases (vetted nicknames and vendor bulletin IDs such as MS17-010) and
from Wikidata's named vulnerabilities (``store/wikidata_names``). Matching: the question is split into
alphanumeric tokens, and every run of 1 to ``MAX_TOKENS`` consecutive tokens is normalised the way aliases are
(lower-case alphanumerics, "Dirty COW" -> "dirtycow") and looked up. A hit adds its CVEs to the candidate list
ahead of the fused list; the reranker then orders them (owner decision: no rule picks one CVE of a name).
Only searchable CVEs are returned. A name written only in capitals in every source ("CRIME", "GHOST", "VENOM")
matches only when the question writes it in capitals too, so ordinary words in a narrative ("a crime group")
do not fire it.
"""
from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass

from ..store.text import alias_norm
from ..store import wikidata_names

MAX_TOKENS = 6
MIN_KEY_CHARS = 4
_TOKEN = re.compile(r"[A-Za-z0-9]+")


@dataclass(frozen=True)
class NicknameHit:
    surface: str              # the span of the question
    key: str                  # normalised name
    cves: tuple[str, ...]
    sources: tuple[str, ...]  # store alias sources and/or "wikidata"


def _is_caps(s: str) -> bool:
    letters = [c for c in s if c.isalpha()]
    return bool(letters) and all(c.isupper() for c in letters)


class NicknameRoute:
    def __init__(self, names: dict[str, dict[str, set[str]]]):
        # key -> {"cves": set, "sources": set}
        self.names = names

    @classmethod
    def from_store(cls, store, wikidata_path=None) -> "NicknameRoute":
        names: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"cves": set(), "sources": set(), "forms": set()})
        db = store._db
        q = ("SELECT a.alias_norm, a.cve_id, a.source, a.alias FROM aliases a JOIN cve c ON c.cve_id = a.cve_id "
             "WHERE a.kind IN ('nickname', 'advisory_id') AND c.searchable = 1")
        for key, cve, src, form in db.execute(q):
            if len(key) >= MIN_KEY_CHARS:
                names[key]["cves"].add(cve)
                names[key]["sources"].add(src)
                names[key]["forms"].add(form)
        searchable = None
        for form, key, cves, _item in wikidata_names.load(wikidata_path or wikidata_names.DATA_FILE):
            if searchable is None:
                searchable = set()
            for c in cves:
                if c not in searchable:
                    row = db.execute("SELECT searchable FROM cve WHERE cve_id = ?", (c,)).fetchone()
                    if not row or not row[0]:
                        continue
                    searchable.add(c)
                names[key]["cves"].add(c)
                names[key]["sources"].add("wikidata")
                names[key]["forms"].add(form)
        out = {}
        for k, v in names.items():
            if v["cves"]:
                v["caps_only"] = all(_is_caps(f) for f in v["forms"] if alias_norm(f) == k) and k.isalpha()
                out[k] = v
        return cls(out)

    def __len__(self) -> int:
        return len(self.names)

    def match(self, text: str) -> list[NicknameHit]:
        s = unicodedata.normalize("NFKD", text or "")
        toks = [(m.group(0), m.start(), m.end()) for m in _TOKEN.finditer(s)]
        hits: dict[str, NicknameHit] = {}
        for i in range(len(toks)):
            key = ""
            for n in range(MAX_TOKENS):
                if i + n >= len(toks):
                    break
                key += toks[i + n][0].lower()
                if len(key) < MIN_KEY_CHARS or key in hits:
                    continue
                v = self.names.get(key)
                if v:
                    span = s[toks[i][1]:toks[i + n][2]]
                    if v.get("caps_only") and not _is_caps(span):
                        continue
                    hits[key] = NicknameHit(span, key, tuple(sorted(v["cves"])),
                                            tuple(sorted(v["sources"])))
        return list(hits.values())

    def info(self) -> dict:
        src = defaultdict(int)
        for v in self.names.values():
            for s_ in v["sources"]:
                src[s_] += 1
        return {"names": len(self.names), "names_by_source": dict(sorted(src.items()))}


__all__ = ["NicknameRoute", "NicknameHit", "alias_norm"]
