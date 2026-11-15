"""Graph expansion over the C9 ATT&CK store for the API's `stix_relationships`.

Every relationship string names both endpoints by ATT&CK ID and comes from a stored STIX relationship:

    "G0016 (APT29) -[uses]-> S0029 (PsExec)"

`EDGE_STRING` parses one back (the C9 check uses it to prove each string in an API response is a stored
edge). `revoked-by` edges are internal revocation bookkeeping and are not surfaced.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .reader import AttackStore, to_doc_id

SURFACED_TYPES_ORDER = ("uses", "attributed-to", "subtechnique-of", "mitigates", "targets")
_KIND_ORDER = {"group": 0, "campaign": 1, "software": 2, "technique": 3, "mitigation": 4}
_ID = r"(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|C\d{4})"
EDGE_STRING = re.compile(rf"^(?P<src>{_ID}) \((?P<src_name>.*?)\) -\[(?P<rel>[a-z-]+)\]-> (?P<dst>{_ID}) "
                         rf"\((?P<dst_name>.*)\)$")
PATH_LIMIT = 25


def format_edge(store: AttackStore, edge: dict) -> str:
    s, d = store.brief(edge["src_doc_id"]), store.brief(edge["dst_doc_id"])
    return f"{s['attack_id']} ({s['title']}) -[{edge['rel_type']}]-> {d['attack_id']} ({d['title']})"


class AttackGraph:
    """Resolves entity names or IDs to ATT&CK documents and lists their relationships."""

    def __init__(self, store: AttackStore):
        self.store = store

    @property
    def build_id(self) -> str:
        return self.store.build_id

    def resolve(self, identifier: str, kinds: Iterable[str] | None = None) -> list[str]:
        """Active doc_ids for an ATT&CK ID (following revocation) or an exact name/alias (every match of the
        allowed kinds; an ambiguous name yields all of them)."""
        if not identifier or not str(identifier).strip():
            return []
        ks = set(kinds) if kinds else None
        if to_doc_id(identifier):
            r = self.store.resolve_id(identifier)
            return [r["doc_id"]] if r and (ks is None or r["doc_kind"] in ks) else []
        return [m["doc_id"] for m in self.store.find_name(identifier, ks)]

    def relationship_paths(self, doc_id: str, limit: int = PATH_LIMIT) -> list[str]:
        """Outgoing relationships of a document, deterministic order: relationship type, then the other
        endpoint's kind and ATT&CK ID."""
        es = [e for e in self.store.edges(doc_id, "out") if e["rel_type"] != "revoked-by"]
        rank = {t: i for i, t in enumerate(SURFACED_TYPES_ORDER)}
        es.sort(key=lambda e: (rank.get(e["rel_type"], len(rank)), e["rel_type"],
                               _KIND_ORDER.get(self.store.brief(e["dst_doc_id"])["doc_kind"], 9),
                               _id_sort(e["dst_attack_id"]), e["rel_stix_id"]))
        out: list[str] = []
        for e in es:
            s = format_edge(self.store, e)
            if s not in out:
                out.append(s)
            if len(out) >= limit:
                break
        return out

    def expand(self, threat_actors: Iterable[str] = (), techniques: Iterable[str] = (),
               malware: Iterable[str] = ()) -> dict[str, Any]:
        """Linked ATT&CK context for entities observed in a query or document: the resolved documents and the
        relationship strings out of each (same contract as the v1 graph hook)."""
        actors = _uniq(d for a in threat_actors for d in self.resolve(a, ("group", "campaign")))
        techs = _uniq(d for t in techniques for d in self.resolve(t, ("technique",)))
        mals = _uniq(d for m in malware for d in self.resolve(m, ("software",)))
        rels: list[str] = []
        for d in actors + techs + mals:
            rels.extend(self.relationship_paths(d))
        name = lambda d: self.store.brief(d)["title"]  # noqa: E731
        return {"actors": sorted(name(d) for d in actors), "techniques": sorted(self.store.brief(d)["attack_id"] for d in techs),
                "malware": sorted(name(d) for d in mals), "doc_ids": actors + techs + mals,
                "relationships": list(dict.fromkeys(rels))}

    def techniques_used_by(self, doc_id: str) -> list[str]:
        """ATT&CK IDs of the techniques a group, campaign or software `uses`."""
        return sorted({e["dst_attack_id"] for e in self.store.edges(doc_id, "out", "uses")
                       if self.store.brief(e["dst_doc_id"])["doc_kind"] == "technique"}, key=_id_sort)


def _uniq(xs: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(xs))


def _id_sort(aid: str) -> tuple:
    head, _, sub = aid.partition(".")
    return head[0], int(head[1:]), int(sub or 0)
