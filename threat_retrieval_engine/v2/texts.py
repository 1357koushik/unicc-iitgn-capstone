"""Document text for the reranker and the response, from the C1 store (CVEs) and the C9 build (ATT&CK).

CVE text: ``CVE-ID. title. Also known as: aliases. vendor/product. description. weakness.`` (the identifier and
the aliases are visible to the cross-encoder, so a nickname or ID in the question can be read against them).
ATT&CK text: ``ATT&CK-ID title. aliases. description``.
"""
from __future__ import annotations

from typing import Iterable

CVE_COLS = ("cve_id", "title", "aliases", "vendor_product", "description", "weakness", "kev_listed", "epss_score",
            "published", "similar_group", "searchable", "cvss", "provenance", "sources")
MAX_CHARS = 1500


def cve_text(r: dict) -> str:
    parts = [r["cve_id"]]
    if r.get("title"):
        parts.append(r["title"])
    if r.get("aliases"):
        parts.append("Also known as: " + r["aliases"])
    if r.get("vendor_product"):
        parts.append(r["vendor_product"])
    if r.get("description"):
        parts.append(r["description"])
    if r.get("weakness"):
        parts.append(r["weakness"])
    return ". ".join(p.strip().rstrip(".") for p in parts if p)[:MAX_CHARS]


def attack_text(r: dict) -> str:
    head = f"{r.get('attack_id', '')} {r.get('title', '')}".strip()
    parts = [head]
    if r.get("aliases"):
        parts.append("Also known as: " + r["aliases"])
    if r.get("description"):
        parts.append(r["description"])
    return ". ".join(p.strip().rstrip(".") for p in parts if p)[:MAX_CHARS]


class DocTexts:
    def __init__(self, store, attack_store=None):
        self.store = store
        self.attack = attack_store

    def rows(self, doc_ids: Iterable[str]) -> dict[str, dict]:
        ids = list(dict.fromkeys(doc_ids))
        cves = [d for d in ids if d.startswith("CVE-")]
        atk = [d for d in ids if d.startswith("attack:")]
        out: dict[str, dict] = {}
        if cves:
            db = self.store._db
            for i in range(0, len(cves), 500):
                part = cves[i:i + 500]
                cur = db.execute(f"SELECT {', '.join(CVE_COLS)} FROM cve WHERE cve_id IN ({','.join('?' * len(part))})",
                                 part)
                for row in cur.fetchall():
                    r = dict(zip(CVE_COLS, row))
                    r["kind"] = "cve"
                    r["text"] = cve_text(r)
                    out[r["cve_id"]] = r
        if atk and self.attack is not None:
            got = self.attack.get_many(atk, columns=("doc_id", "attack_id", "doc_kind", "title", "aliases",
                                                     "description", "url", "state"))
            for d, r in got.items():
                r["kind"] = "attack"
                r["text"] = attack_text(r)
                out[d] = r
        return out
