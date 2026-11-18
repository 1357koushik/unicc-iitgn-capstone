"""Reading the ATT&CK Enterprise STIX bundle into document records, edges and CVE-link candidates.

Identity is the ATT&CK ID (the `mitre-attack` external reference), never text similarity. The rules for
objects that cannot be stored, revoked and deprecated objects, and relationships touching them are
here, each with the reason code written to the `rejected` table.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from threat_retrieval_engine.store.text import CVE_IN_TEXT, normalize_cve_id

from .text import alias_norm, clean_description, dense_strip_ids, normalize_attack_id

# STIX type -> document kind. Every other STIX type is read and recorded as not ingested.
TYPE_TO_KIND = {
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "attack-pattern": "technique",
    "course-of-action": "mitigation",
    "campaign": "campaign",
}
KIND_PREFIX = {"group": "G", "software": "S", "technique": "T", "mitigation": "M", "campaign": "C"}
# Why the remaining STIX types are not documents (recorded as the rejection detail).
NOT_INGESTED_DETAIL = {
    "relationship": "graph edge, not a document",
    "x-mitre-tactic": "tactic: used as technique metadata (tactic names on each technique)",
    "x-mitre-detection-strategy": "detection content, outside the T9/ATT&CK document scope of plan 4.4",
    "x-mitre-analytic": "detection content, outside the T9/ATT&CK document scope of plan 4.4",
    "x-mitre-data-component": "detection content, outside the T9/ATT&CK document scope of plan 4.4",
    "x-mitre-data-source": "detection content, outside the T9/ATT&CK document scope of plan 4.4",
    "x-mitre-matrix": "matrix layout object",
    "x-mitre-collection": "bundle collection header (version recorded in the manifest)",
    "identity": "MITRE identity object",
    "marking-definition": "licence marking (copyright statement kept in the manifest)",
}


def attack_ref(obj: dict) -> dict | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def state_of(obj: dict) -> str:
    if obj.get("revoked"):
        return "revoked"
    if obj.get("x_mitre_deprecated"):
        return "deprecated"
    return "active"


@dataclass
class Rejection:
    source: str
    record_id: str
    reason: str
    detail: str | None = None


@dataclass
class Parsed:
    docs: dict[str, dict] = field(default_factory=dict)          # doc_id -> record
    stix_to_doc: dict[str, str] = field(default_factory=dict)    # stored STIX id -> doc_id
    edges: dict[str, dict] = field(default_factory=dict)         # rel stix id -> edge
    rejects: list[Rejection] = field(default_factory=list)
    revoked_chain: dict[str, dict] = field(default_factory=dict)  # revoked doc_id -> {final, chain, problem}
    tactics: dict[str, dict] = field(default_factory=dict)       # shortname -> {name, attack_id}
    collection: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    objects_read: int = 0
    relationships_read: int = 0


# =========================================================================== objects
def _aliases(obj: dict, name: str) -> list[str]:
    raw = list(obj.get("aliases") or []) + list(obj.get("x_mitre_aliases") or [])
    seen = {alias_norm(name)}
    out = []
    for a in raw:
        a = (a or "").strip()
        k = alias_norm(a)
        if a and k and k not in seen:
            seen.add(k)
            out.append(a)
    return out


def _references(obj: dict) -> list[dict]:
    out = []
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            continue
        r = {"source_name": ref.get("source_name") or ""}
        if ref.get("url"):
            r["url"] = ref["url"]
        if ref.get("description"):
            r["description"] = ref["description"].strip()
        if ref.get("external_id"):
            r["external_id"] = ref["external_id"]
        out.append(r)
    return out


def _record(obj: dict, kind: str, attack_id: str, tactics: dict[str, dict]) -> dict:
    name = (obj.get("name") or "").strip()
    st = state_of(obj)
    tl = []
    for ph in obj.get("kill_chain_phases") or []:
        if ph.get("kill_chain_name") == "mitre-attack":
            t = tactics.get(ph.get("phase_name"), {})
            tl.append({"shortname": ph.get("phase_name"), "name": t.get("name") or ph.get("phase_name"),
                       "attack_id": t.get("attack_id")})
    platforms = list(obj.get("x_mitre_platforms") or [])
    attrs: dict[str, Any] = {"domains": obj.get("x_mitre_domains") or [],
                             "contributors": obj.get("x_mitre_contributors") or [],
                             "attack_spec_version": obj.get("x_mitre_attack_spec_version"),
                             "references": _references(obj)}
    if kind == "software":
        attrs["is_family"] = obj.get("is_family")
    if kind == "technique":
        for k in ("x_mitre_impact_type", "x_mitre_remote_support", "x_mitre_effective_permissions",
                  "x_mitre_system_requirements", "x_mitre_permissions_required"):
            if obj.get(k) is not None:
                attrs[k[len("x_mitre_"):]] = obj[k]
    ref = attack_ref(obj) or {}
    return {
        "doc_id": f"attack:{attack_id}", "attack_id": attack_id, "stix_id": obj["id"], "stix_type": obj["type"],
        "doc_kind": kind, "software_type": obj["type"] if kind == "software" else None,
        "is_subtechnique": int(bool(obj.get("x_mitre_is_subtechnique"))), "parent_doc_id": None,
        "name": name, "title": name, "aliases_list": _aliases(obj, name),
        "description_raw": obj.get("description") or "",
        "description": clean_description(obj.get("description")),
        "tactics_list": tl, "platforms_list": platforms,
        "url": ref.get("url"), "version": obj.get("x_mitre_version"), "created": obj.get("created"),
        "modified": obj.get("modified"), "first_seen": obj.get("first_seen"), "last_seen": obj.get("last_seen"),
        "state": st, "searchable": int(st == "active"), "revoked_by": None, "attrs": attrs,
    }


def _pick_duplicate(a: dict, b: dict) -> tuple[dict, dict]:
    """Two objects of one kind with the same ATT&CK ID: keep the active one, else the newer one."""
    rank = {"active": 0, "deprecated": 1, "revoked": 2}
    by_newest = sorted((a, b), key=lambda o: (o.get("modified") or "", o.get("id") or ""), reverse=True)
    keep, drop = sorted(by_newest, key=lambda o: rank[state_of(o)])  # stable: newest wins within a state
    return keep, drop


def parse_bundle(bundle: dict) -> Parsed:
    P = Parsed()
    objs = bundle.get("objects") or []
    by_stix = {o.get("id"): o for o in objs if o.get("id")}
    for o in objs:
        if o.get("type") == "x-mitre-tactic":
            ref = attack_ref(o) or {}
            P.tactics[o.get("x_mitre_shortname")] = {"name": o.get("name"), "attack_id": ref.get("external_id")}
        elif o.get("type") == "x-mitre-collection":
            P.collection = {"name": o.get("name"), "version": o.get("x_mitre_version"), "modified": o.get("modified")}

    # ------------------------------------------------------------------ objects
    candidates: dict[str, dict] = {}   # attack_id -> STIX object
    for o in objs:
        t = o.get("type")
        if t == "relationship":
            continue
        P.objects_read += 1
        sid = o.get("id") or f"<no id #{P.objects_read}>"
        kind = TYPE_TO_KIND.get(t)
        if kind is None:
            P.rejects.append(Rejection("stix_object", sid, f"type_not_ingested:{t}",
                                       NOT_INGESTED_DETAIL.get(t, "STIX type outside the ATT&CK document scope")))
            continue
        ref = attack_ref(o)
        if ref is None:
            P.rejects.append(Rejection("stix_object", sid, "no_attack_id", o.get("name")))
            continue
        aid = normalize_attack_id(ref["external_id"])
        if aid is None or aid != ref["external_id"].strip():
            P.rejects.append(Rejection("stix_object", sid, "malformed_attack_id", ref["external_id"]))
            continue
        if not aid.startswith(KIND_PREFIX[kind]):
            # Pre-2018 ATT&CK modelled mitigations per technique and gave them the technique's ID; they are
            # deprecated and their ID (doc_id) belongs to the technique.
            P.rejects.append(Rejection(
                "stix_object", sid, "id_kind_mismatch",
                f"{t} carries {aid}, an ID of another kind ({state_of(o)}; doc_id attack:{aid} belongs to that object)"))
            continue
        if not (o.get("name") or "").strip():
            P.rejects.append(Rejection("stix_object", sid, "no_name", aid))
            continue
        if aid in candidates:
            keep, drop = _pick_duplicate(candidates[aid], o)
            candidates[aid] = keep
            P.rejects.append(Rejection("stix_object", drop["id"], "duplicate_attack_id",
                                       f"{aid}: kept {keep['id']} ({state_of(keep)}, modified {keep.get('modified')})"))
            continue
        candidates[aid] = o
    for aid in sorted(candidates):
        o = candidates[aid]
        rec = _record(o, TYPE_TO_KIND[o["type"]], aid, P.tactics)
        P.docs[rec["doc_id"]] = rec
        P.stix_to_doc[o["id"]] = rec["doc_id"]
    rejected_stix = {r.record_id: r.reason for r in P.rejects}

    # ------------------------------------------------------------------ revocation map
    rels = sorted((o for o in objs if o.get("type") == "relationship"), key=lambda r: r.get("id") or "")
    P.relationships_read = len(rels)
    revoked_by: dict[str, str] = {}
    for r in rels:
        if r.get("relationship_type") != "revoked-by" or state_of(r) != "active":
            continue
        s, d = P.stix_to_doc.get(r.get("source_ref")), P.stix_to_doc.get(r.get("target_ref"))
        if s and d:
            revoked_by.setdefault(s, d)
    for doc_id, rec in P.docs.items():
        if rec["state"] != "revoked":
            continue
        chain = [doc_id]
        cur = doc_id
        problem = None
        while cur in revoked_by:
            cur = revoked_by[cur]
            if cur in chain:
                problem = "revocation_cycle"
                break
            chain.append(cur)
        if problem is None:
            if len(chain) == 1:
                problem = "no_revoked_by_relationship"
            elif P.docs[cur]["state"] != "active":
                problem = f"replacement_{P.docs[cur]['state']}"
        final = cur if problem is None else None
        rec["revoked_by"] = final
        P.revoked_chain[doc_id] = {"final": final, "chain": chain, "problem": problem}

    # ------------------------------------------------------------------ relationships
    pending_redirects = []
    triples: dict[tuple[str, str, str], str] = {}
    for r in rels:
        rid = r.get("id") or "<no id>"
        rtype = r.get("relationship_type") or ""
        src_o, dst_o = by_stix.get(r.get("source_ref")), by_stix.get(r.get("target_ref"))
        if src_o is None or dst_o is None:
            P.rejects.append(Rejection("stix_relationship", rid, "dangling_reference",
                                       f"{r.get('source_ref')} -> {r.get('target_ref')}"))
            continue
        bad_t = [x["type"] for x in (src_o, dst_o) if x["type"] not in TYPE_TO_KIND]
        if bad_t:
            P.rejects.append(Rejection("stix_relationship", rid, f"endpoint_type_not_ingested:{bad_t[0]}",
                                       f"{src_o['type']} -[{rtype}]-> {dst_o['type']}"))
            continue
        bad_r = [x["id"] for x in (src_o, dst_o) if x["id"] in rejected_stix]
        if bad_r:
            P.rejects.append(Rejection("stix_relationship", rid, "endpoint_not_stored",
                                       f"{bad_r[0]} rejected as {rejected_stix[bad_r[0]]}"))
            continue
        if state_of(r) != "active":
            P.rejects.append(Rejection("stix_relationship", rid, f"relationship_{state_of(r)}", rtype))
            continue
        s, d = P.stix_to_doc[src_o["id"]], P.stix_to_doc[dst_o["id"]]
        edge = {"rel_stix_id": rid, "rel_type": rtype, "src_doc_id": s, "dst_doc_id": d,
                "orig_src_doc_id": s, "orig_dst_doc_id": d, "redirected": None,
                "description_raw": r.get("description") or "", "description": clean_description(r.get("description")),
                "created": r.get("created"), "modified": r.get("modified"), "references": _references(r)}
        if rtype == "revoked-by":
            # the revocation map itself: stored as written, endpoints are the revoked object and its replacement
            P.edges[rid] = edge
            continue
        dep = [x for x in (s, d) if P.docs[x]["state"] == "deprecated"]
        if dep:
            P.rejects.append(Rejection("stix_relationship", rid, "endpoint_deprecated",
                                       f"{P.docs[s]['attack_id']} -[{rtype}]-> {P.docs[d]['attack_id']}: "
                                       f"{P.docs[dep[0]]['attack_id']} is deprecated and has no replacement"))
            continue
        moved = []
        for end in ("src", "dst"):
            cur = edge[f"{end}_doc_id"]
            if P.docs[cur]["state"] == "revoked":
                fin = P.revoked_chain[cur]["final"]
                if fin is None:
                    moved = None
                    P.rejects.append(Rejection("stix_relationship", rid, "endpoint_revoked_without_active_replacement",
                                               f"{P.docs[cur]['attack_id']}: {P.revoked_chain[cur]['problem']}"))
                    break
                edge[f"{end}_doc_id"] = fin
                moved.append(end)
        if moved is None:
            continue
        if moved:
            edge["redirected"] = "both" if len(moved) == 2 else moved[0]
            pending_redirects.append(edge)
            continue
        P.edges[rid] = edge
        triples.setdefault((s, rtype, d), rid)
    for edge in pending_redirects:  # after all direct edges, so a redirect never displaces one
        key = (edge["src_doc_id"], edge["rel_type"], edge["dst_doc_id"])
        orig = f"{P.docs[edge['orig_src_doc_id']]['attack_id']} -[{edge['rel_type']}]-> " \
               f"{P.docs[edge['orig_dst_doc_id']]['attack_id']}"
        if key[0] == key[2]:
            P.rejects.append(Rejection("stix_relationship", edge["rel_stix_id"], "self_loop_after_redirect", orig))
        elif key in triples:
            P.rejects.append(Rejection("stix_relationship", edge["rel_stix_id"], "duplicate_after_redirect",
                                       f"{orig}; same edge already stored as {triples[key]}"))
        else:
            P.edges[edge["rel_stix_id"]] = edge
            triples[key] = edge["rel_stix_id"]

    # ------------------------------------------------------------------ sub-technique parents and titles
    for e in P.edges.values():
        if e["rel_type"] == "subtechnique-of":
            child = P.docs[e["src_doc_id"]]
            child.setdefault("_parents", set()).add(e["dst_doc_id"])
    for rec in P.docs.values():
        if rec["doc_kind"] != "technique" or not rec["is_subtechnique"]:
            continue
        parents = sorted(rec.pop("_parents", set()))
        if not parents:  # no stored subtechnique-of edge: the ID says which technique it belongs to
            pid = "attack:" + rec["attack_id"].split(".")[0]
            parents = [pid] if pid in P.docs else []
            rec["attrs"]["parent_from"] = "attack_id" if parents else "none"
        else:
            rec["attrs"]["parent_from"] = "subtechnique-of"
        if parents:
            rec["parent_doc_id"] = parents[0]
            rec["title"] = f"{P.docs[parents[0]]['name']}: {rec['name']}"
    for rec in P.docs.values():
        rec.pop("_parents", None)
        finish_text(rec)

    P.counts = {
        "objects_by_kind_state": dict(sorted(Counter(f"{r['doc_kind']}/{r['state']}" for r in P.docs.values()).items())),
        "edges_by_type": dict(sorted(Counter(e["rel_type"] for e in P.edges.values()).items())),
        "edges_redirected": sum(1 for e in P.edges.values() if e["redirected"]),
    }
    return P


# =========================================================================== text fields
def finish_text(rec: dict) -> None:
    """Text fields an index reads, with C1's field conventions."""
    rec["aliases"] = "; ".join(rec["aliases_list"]) or None
    rec["tactics"] = "; ".join(t["name"] for t in rec["tactics_list"] if t.get("name")) or None
    rec["platforms"] = "; ".join(rec["platforms_list"]) or None
    rec["description"] = rec["description"] or None
    if rec["searchable"]:
        parts = [rec["title"]]
        if rec["aliases_list"]:
            parts.append(", ".join(rec["aliases_list"]))
        if rec["doc_kind"] == "technique" and rec["tactics"]:
            parts.append(", ".join(t["name"] for t in rec["tactics_list"] if t.get("name")))
        if rec["description"]:
            parts.append(rec["description"])
        txt = " ".join(p if p.rstrip().endswith((".", "!", "?")) else p.rstrip() + "." for p in parts if p)
        rec["dense_text"] = dense_strip_ids(txt)
    else:
        rec["dense_text"] = None
    h = hashlib.sha256()
    for k in ("title", "aliases", "description", "tactics", "platforms", "dense_text"):
        h.update(k.encode())
        h.update(b"\x00")
        h.update((rec.get(k) or "").encode("utf-8"))
        h.update(b"\x01")
    rec["content_hash"] = h.hexdigest()


# =========================================================================== CVE-link candidates
@dataclass
class LinkCandidate:
    record_id: str          # unique: "<stix id>|<field>|<cve>"
    cve_id: str
    evidence_kind: str
    evidence_ref: str       # stix id + field
    targets: list[tuple[str, str]]  # (doc_id, role)
    detail: dict
    reject: tuple[str, str] | None = None  # (reason, detail) when the source cannot carry a link


def _snippet(text: str, cve: str, width: int = 120) -> str:
    i = text.upper().find(cve)
    if i < 0:
        return text[:2 * width]
    a, b = max(0, i - width), min(len(text), i + len(cve) + width)
    return ("..." if a else "") + text[a:b] + ("..." if b < len(text) else "")


def _cves(text: str) -> list[str]:
    return sorted({c for c in (normalize_cve_id(m.group(0)) for m in CVE_IN_TEXT.finditer(text or "")) if c})


def link_candidates(bundle: dict, P: Parsed) -> list[LinkCandidate]:
    """CVE IDs written inside stored ATT&CK objects and relationships (descriptions, external references)."""
    rejected_rel = {r.record_id: r for r in P.rejects if r.source == "stix_relationship"}
    out: list[LinkCandidate] = []
    for o in bundle.get("objects") or []:
        sid = o.get("id")
        is_rel = o.get("type") == "relationship"
        if not is_rel and sid not in P.stix_to_doc:
            continue  # objects not stored are accounted for as objects; their text carries no link
        if is_rel:
            edge = P.edges.get(sid)
        texts: list[tuple[str, str, dict]] = []
        desc = clean_description(o.get("description"))
        for c in _cves(desc):
            texts.append(("description", c, {"snippet": _snippet(desc, c)}))
        for i, ref in enumerate(o.get("external_references") or []):
            if ref.get("source_name") == "mitre-attack":
                continue
            blob = " ".join(str(ref.get(k) or "") for k in ("source_name", "external_id", "description", "url"))
            for c in _cves(blob):
                texts.append((f"external_references[{i}]", c,
                              {"source_name": ref.get("source_name"), "url": ref.get("url"),
                               "description": (ref.get("description") or "").strip()[:300]}))
        for fld, cve, det in texts:
            kind = ("relationship_" if is_rel else "object_") + ("description" if fld == "description"
                                                                   else "external_reference")
            cand = LinkCandidate(record_id=f"{sid}|{fld}|{cve}", cve_id=cve, evidence_kind=kind,
                                 evidence_ref=f"{sid}|{fld}", targets=[], detail=det)
            if is_rel:
                if edge is None:
                    rj = rejected_rel.get(sid)
                    cand.reject = ("relationship_not_stored", f"{rj.reason}: {rj.detail}" if rj else "not stored")
                elif edge["rel_type"] == "revoked-by":
                    cand.reject = ("revocation_relationship", "revoked-by edges carry no CVE evidence")
                else:
                    cand.targets = [(edge["src_doc_id"], "relationship_source"),
                                    (edge["dst_doc_id"], "relationship_target")]
                    cand.detail["relationship"] = (f"{P.docs[edge['src_doc_id']]['attack_id']} -[{edge['rel_type']}]-> "
                                                   f"{P.docs[edge['dst_doc_id']]['attack_id']}")
            else:
                doc = P.docs[P.stix_to_doc[sid]]
                if doc["state"] == "active":
                    cand.targets = [(doc["doc_id"], "self")]
                elif doc["state"] == "revoked" and doc["revoked_by"]:
                    cand.targets = [(doc["revoked_by"], "self")]
                    cand.detail["redirected_from"] = doc["doc_id"]
                elif doc["state"] == "revoked":
                    cand.reject = ("source_object_revoked_without_active_replacement", doc["attack_id"])
                else:
                    cand.reject = ("source_object_deprecated", doc["attack_id"])
            out.append(cand)
    # one candidate per (source, field, CVE); a CVE repeated in one field is one mention
    uniq: dict[str, LinkCandidate] = {}
    for c in out:
        uniq.setdefault(c.record_id, c)
    return [uniq[k] for k in sorted(uniq)]


def resolve_technique(P: Parsed, attack_id: str) -> tuple[str | None, str | None, str | None]:
    """(doc_id, redirected_from, reject_reason) for a technique ID from another ATT&CK version."""
    aid = normalize_attack_id(attack_id)
    if aid is None:
        return None, None, "malformed_attack_id"
    d = P.docs.get(f"attack:{aid}")
    if d is None:
        return None, None, "technique_not_in_build"
    if d["doc_kind"] != "technique":
        return None, None, f"not_a_technique:{d['doc_kind']}"
    if d["state"] == "active":
        return d["doc_id"], None, None
    if d["state"] == "revoked" and d["revoked_by"]:
        return d["revoked_by"], d["doc_id"], None
    return None, None, f"technique_{d['state']}"


def json_dump(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def group_by(items, key):
    d = defaultdict(list)
    for x in items:
        d[key(x)].append(x)
    return d
