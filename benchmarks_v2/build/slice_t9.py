"""T9 actor / software / technique slice. Question text from templates written here; ground truth from
ATT&CK STIX relationships. ATT&CK description text is never used."""
from __future__ import annotations

from collections import defaultdict

from .common import rng, stable_key
from .model import Item, qrel
from .text import name_key

ID_TEMPLATES = {"group": ["{id}", "what is {id}", "ATT&CK group {id}", "profile of {id}"],
                "software": ["{id}", "what is {id}", "ATT&CK software {id}", "describe {id}"],
                "technique": ["{id}", "what is {id}", "explain ATT&CK technique {id}", "{id} technique details"],
                "mitigation": ["{id}", "what is mitigation {id}", "ATT&CK mitigation {id}"]}
NAME_TEMPLATES = ["{n}"]
ALIAS_TEMPLATES = ["{a}", "who is {a}", "what is {a}", "tell me about the {a} group"]
REL_TEMPLATES = {
    "group_techniques": ["Which techniques does {n} use?", "TTPs of {n}", "{n} techniques", "how does {n} operate - list of techniques",
                         "what ATT&CK techniques are attributed to {n}"],
    "group_software": ["What malware or tools does {n} use?", "software used by {n}", "{n} toolset", "which tools are associated with {n}"],
    "software_groups": ["Which groups use {n}?", "threat actors that have used {n}", "who uses {n}", "{n} operators"],
    "software_techniques": ["What can {n} do?", "techniques implemented by {n}", "{n} capabilities", "behaviour of {n} malware"],
    "technique_mitigations": ["How can {n} be mitigated?", "mitigations for {n}", "defending against {n}", "how to prevent {n}"],
    "technique_subtechniques": ["sub-techniques of {n}", "What are the variants of {n}?", "{n} sub-techniques"],
    "technique_groups": ["Which groups use {n}?", "threat actors known for {n}", "who uses {n}"],
}
PLAN = [("id", 60), ("exact_name", 60), ("alias", 30), ("group_techniques", 30), ("group_software", 25),
        ("software_groups", 25), ("software_techniques", 20), ("technique_mitigations", 20),
        ("technique_subtechniques", 15), ("technique_groups", 15)]
REL_SPEC = {  # family: (subject kind, relationship, direction, answer kind, size range)
    "group_techniques": ("group", "uses", "out", "technique", (3, 80)),
    "group_software": ("group", "uses", "out", "software", (2, 40)),
    "software_groups": ("software", "uses", "in", "group", (2, 30)),
    "software_techniques": ("software", "uses", "out", "technique", (3, 80)),
    "technique_mitigations": ("technique", "mitigates", "in", "mitigation", (1, 15)),
    "technique_subtechniques": ("technique", "subtechnique-of", "in", "technique", (2, 20)),
    "technique_groups": ("technique", "uses", "in", "group", (2, 40)),
}


def build_t9(kb, gate, seed: int, target: int) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    if not kb.available:
        return [], {"available": False}
    lic = "MITRE ATT&CK Terms of Use"
    src_ver = kb.version.get("attack_version") or kb.version.get("commit") or ""
    nidx = kb.name_index()
    unique_name = {aid for aid, o in kb.objects.items() if len(nidx[name_key(o["name"])]) == 1}
    by_kind = defaultdict(list)
    for aid in sorted(kb.objects):
        by_kind[kb.objects[aid]["kind"]].append(aid)
    items: list[Item] = []

    def mk(text, qrels, qtype, subject, extra=None):
        meta = {"query_type": qtype, "subject": f"attack:{subject}", "gate_exact": qtype in ("id", "exact_name"),
                "attack_version": src_ver, **(extra or {})}
        return Item(slice="T9", text=text, qrels=qrels, overlap_exempt=True, link_keys={f"attack:{subject}"},
                    source={"name": "attack_enterprise", "id": subject, "licence": lic}, meta=meta)

    def take(cands, n, family):
        got = 0
        for c in cands:
            if got >= n or len(items) >= target:
                break
            if gate.accept(c):
                items.append(c)
                got += 1
        stats[f"{family}_accepted"] = got

    kinds_cycle = ["group", "software", "technique", "mitigation"]
    # ID queries: balanced over kinds
    cands = []
    per_kind = {k: sorted(by_kind[k], key=lambda a: stable_key(seed, "t9id", a)) for k in kinds_cycle}
    for i in range(200):
        k = kinds_cycle[i % 4]
        if i // 4 < len(per_kind[k]):
            aid = per_kind[k][i // 4]
            t = rng(seed, "t9id", aid).choice(ID_TEMPLATES[k]).format(id=aid)
            cands.append(mk(t, [qrel(f"attack:{aid}", 2, "known_item")], "id", aid, {"kind": k}))
    take(cands, dict(PLAN)["id"], "id")
    # exact names (unique across active objects)
    cands = []
    per_kind = {k: sorted([a for a in by_kind[k] if a in unique_name], key=lambda a: stable_key(seed, "t9n", a))
                for k in kinds_cycle[:3]}
    for i in range(300):
        k = kinds_cycle[i % 3]
        if i // 3 < len(per_kind[k]):
            aid = per_kind[k][i // 3]
            cands.append(mk(kb.name(aid), [qrel(f"attack:{aid}", 2, "known_item")], "exact_name", aid, {"kind": k}))
    take(cands, dict(PLAN)["exact_name"], "exact_name")
    # aliases (unique, different from the name)
    cands = []
    for aid in sorted(by_kind["group"] + by_kind["software"], key=lambda a: stable_key(seed, "t9a", a)):
        o = kb.objects[aid]
        als = [a for a in o.get("aliases") or [] if name_key(a) != name_key(o["name"]) and len(nidx[name_key(a)]) == 1]
        if not als:
            continue
        r = rng(seed, "t9a", aid)
        a = r.choice(sorted(als))
        tm = r.choice(ALIAS_TEMPLATES if o["kind"] == "group" else [t for t in ALIAS_TEMPLATES if "group" not in t])
        cands.append(mk(tm.format(a=a), [qrel(f"attack:{aid}", 2, "known_item")], "alias", aid,
                        {"kind": o["kind"], "alias": a}))
    take(cands, dict(PLAN)["alias"], "alias")
    # relationship questions
    for fam, n in PLAN[3:]:
        sk, rel, direction, ak, (lo, hi) = REL_SPEC[fam]
        cands = []
        for aid in sorted(by_kind[sk], key=lambda a: stable_key(seed, "t9r", fam, a)):
            if fam == "technique_subtechniques" and kb.objects[aid].get("is_subtechnique"):
                continue
            ans = kb.out(aid, rel, ak) if direction == "out" else kb.inc(aid, rel, ak)
            if not (lo <= len(ans) <= hi):
                continue
            r = rng(seed, "t9r", fam, aid)
            o = kb.objects[aid]
            nm = o["name"]
            if aid not in unique_name:
                nm = f"{nm} ({aid})"
            elif sk == "technique" and r.random() < 0.3:
                nm = f"{aid} {nm}"
            text = r.choice(REL_TEMPLATES[fam]).format(n=nm)
            qrels = [qrel(f"attack:{a}", 2, "known_item") for a in ans] + [qrel(f"attack:{aid}", 1, "known_item")]
            cands.append(mk(text, qrels, fam, aid, {"relationship": rel, "answers": len(ans)}))
        take(cands, n, fam)
    stats["accepted"] = len(items)
    return items, dict(stats)
