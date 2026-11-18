"""T2 nickname slice: corroborated name -> CVE mappings, queries written from templates."""
from __future__ import annotations

import re
from collections import defaultdict

from .common import rng
from .model import GENERATED, Item, qrel
from .nicknames import CANDIDATES
from .text import contains_name, raw_tokens

TEMPLATES = [
    "{n}",
    "what is {n}",
    "are we exposed to {n}?",
    "{n} remediation guidance",
    "{n} patch status for our servers",
    "how serious is {n} and what is affected",
    "need the advisory for the {n} bug",
    "is {n} being exploited right now",
    "{n} vulnerability details",
    "management is asking about {n}, which systems need fixing",
]
PER_NAME = 3   # at most this many accepted queries per name string


def want_ref_ids() -> set[str]:
    return {c for _, cves, _ in CANDIDATES for c in cves}


def query_side_texts(srcs) -> dict[str, list[tuple[str, str, str]]]:
    """CVE -> [(source, record id, text)] from query-role sources (allowed corroboration)."""
    out: dict[str, list] = defaultdict(list)
    s = srcs.get("ghsa_reviewed", "corroboration")
    if s is not None:
        for r in s.records():
            for c in r.get("cve_ids") or []:
                out[c].append(("ghsa_reviewed", r["ghsa_id"], f"{r.get('summary') or ''} {r.get('details') or ''}"))
    s = srcs.get("et_open_rules", "corroboration")
    if s is not None:
        for r in s.records():
            for c in r.get("cve_ids") or []:
                out[c].append(("et_open_rules", str(r["sid"]), r.get("msg") or ""))
    s = srcs.get("sigma_rules", "corroboration")
    if s is not None:
        for r in s.records():
            for c in r.get("cve_ids") or []:
                out[c].append(("sigma_rules", r["rule_id"], f"{r.get('title') or ''} {r.get('description') or ''}"))
    return out


def corroborate(name: str, cid: str, u, qside) -> list[dict]:
    ev = []
    r = u.nvd.get(cid)
    if r is not None and contains_name(name, raw_tokens(r["desc"])):
        ev.append({"source": "nvd_description"})
    if r is not None:
        for url in r.get("refs", []) or []:
            if contains_name(name, raw_tokens(url)):
                ev.append({"source": "nvd_reference", "value": url})
                break
    cl = u.cvelist(cid)
    if cl:
        if contains_name(name, raw_tokens(f"{cl['title']} {cl['desc']}")):
            ev.append({"source": "cve_list_text"})
        for rf in cl["refs"]:
            if contains_name(name, raw_tokens(f"{rf['url']} {rf['name']}")):
                ev.append({"source": "cve_list_reference", "value": rf["url"]})
                break
    for src, rid, text in qside.get(cid, []):
        if contains_name(name, raw_tokens(text)):
            ev.append({"source": src, "value": rid})
            break
    return ev


_BULLETIN = re.compile(r"\bMS\d{2}-\d{3}\b", re.I)


def advisory_chain(name: str, cid: str, candidate_cves: list[str], u, qside) -> list[dict]:
    """Second-hop corroboration: a query-side record (ET Open msg, Sigma title/description, GHSA) attached
    to one of this name's candidate CVEs names the nickname together with a Microsoft bulletin ID
    (e.g. "ETERNALBLUE ... MS17-010"), and this CVE's own NVD references cite that bulletin. Only CVEs
    already on the candidate list can be corroborated this way."""
    r = u.nvd.get(cid)
    if r is None:
        return []
    refs = [x.lower() for x in r.get("refs", []) or []]
    for c in candidate_cves:
        for src, rid, text in qside.get(c, []):
            if not contains_name(name, raw_tokens(text)):
                continue
            for b in sorted({m.group(0).lower() for m in _BULLETIN.finditer(text)}):
                hit = next((x for x in refs if b in x), None)
                if hit:
                    return [{"source": "advisory_chain", "value": f"{src}:{rid} names the nickname with {b.upper()}; "
                                                                   f"NVD reference {hit}"}]
    return []


def build_t2(u, srcs, gate, seed: int, target: int) -> tuple[list[Item], dict]:
    qside = query_side_texts(srcs)
    stats = defaultdict(int)
    mappings = []   # (name, canonical, [(cve, evidence)])
    uncorroborated = []
    for canon, cves, aliases in CANDIDATES:
        for nm in [canon] + aliases:
            stats["name_strings"] += 1
            good = []
            for c in cves:
                stats["pairs"] += 1
                if not u.exists(c):
                    stats["pair_cve_missing"] += 1
                    continue
                ev = corroborate(nm, c, u, qside) or advisory_chain(nm, c, cves, u, qside)
                if not ev:
                    stats["pair_uncorroborated"] += 1
                    continue
                good.append((c, ev))
            if good:
                mappings.append((nm, canon, good))
            else:
                uncorroborated.append(nm)
    stats["names_corroborated"] = len(mappings)
    # Round-robin over names so that every corroborated name contributes before any gets a second query.
    per_name_order = {}
    for nm, canon, good in mappings:
        r = rng(seed, "t2", nm)
        order = list(range(len(TEMPLATES)))
        r.shuffle(order)
        per_name_order[nm] = order
    items: list[Item] = []
    accepted_per_name: dict[str, int] = defaultdict(int)
    cursor: dict[str, int] = defaultdict(int)
    active = [m for m in mappings]
    while active and len(items) < target:
        nxt = []
        for nm, canon, good in active:
            if len(items) >= target:
                break
            order = per_name_order[nm]
            placed = False
            while cursor[nm] < len(order) and not placed:
                tmpl = TEMPLATES[order[cursor[nm]]]
                cursor[nm] += 1
                text = tmpl.format(n=nm)
                qrels, tmeta = gate.targets_from([c for c, _ in good])
                ev = {c: e for c, e in good}
                meta = {"nickname": nm, "canonical_name": canon, "template": tmpl,
                        "corroboration": {q["doc_id"]: ev.get(q["doc_id"]) or ev.get(
                            (tmeta.get("remapped_from") or [None])[0], []) for q in qrels}, **tmeta}
                it = Item(slice="T2", text=text, qrels=qrels, source=dict(GENERATED), meta=meta,
                          link_keys={f"nickname:{canon}"})
                if gate.accept(it):
                    items.append(it)
                    accepted_per_name[nm] += 1
                    placed = True
            if accepted_per_name[nm] < PER_NAME and cursor[nm] < len(order):
                nxt.append((nm, canon, good))
        active = nxt
    stats["names_with_queries"] = sum(1 for v in accepted_per_name.values() if v)
    stats["accepted"] = len(items)
    out = dict(stats)
    out["uncorroborated_names"] = sorted(uncorroborated)
    out["corroborated_names"] = sorted(nm for nm, _, _ in mappings)
    return items, out
