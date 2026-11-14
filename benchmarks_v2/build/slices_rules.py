"""T3 (advisory wording, reviewed GHSA) and T4 (detection-rule wording, ET Open and Sigma)."""
from __future__ import annotations

import re
from collections import defaultdict

from .common import stable_key
from .model import Item
from .text import CVE_FIND_RE, content_tokens, first_sentence, nfkc, normalize

_CAN = re.compile(r"(?<![A-Za-z0-9])CAN-\d{4}-\d{4,}(?!\d)", re.I)
_BARE_ID = re.compile(r"(?<![A-Za-z0-9.\-])(?:19|20)\d{2}-\d{4,}(?![\d.])")
_ET_PREFIX =re.compile(r"^(ET|GPL)\s+([A-Z][A-Z0-9_]+)\s+")
_VARIANT = re.compile(r"(?<![A-Za-z0-9])M\d{1,2}(?![A-Za-z0-9])")
_TRAIL = {"via", "for", "in", "of", "and", "or", "the", "a", "an", "to", "with", "on", "by", "as", "using",
          "from", "against", "exploits", "exploit", "used", "related", "-", ":", ","}
GENERIC = {"exploit", "exploitation", "exploited", "attempt", "attempted", "possible", "potential", "inbound",
           "outbound", "observed", "detected", "detect", "detection", "suspiciou", "suspicious", "activity",
           "vulnerability", "vuln", "cve", "attack", "rule", "request", "response", "successful", "likely",
           "access", "generic", "scanner", "scan", "poc", "public", "code", "tcp", "udp", "http", "set", "ii",
           "sigma", "hunting", "behavior", "behaviour", "indicator", "variant", "related", "via", "multiple"}


def strip_ids(text: str) -> tuple[str, list[str]]:
    removed = [m.group(0) for m in CVE_FIND_RE.finditer(text)] + [m.group(0) for m in _CAN.finditer(text)]
    text = CVE_FIND_RE.sub(" ", text)
    text = _CAN.sub(" ", text)
    if removed:
        # bare continuation IDs in lists such as "CVE-2025-4427,2025-4428"
        removed += [m.group(0) for m in _BARE_ID.finditer(text)]
        text = _BARE_ID.sub(" ", text)
    return text, removed


def tidy(text: str) -> str:
    t = nfkc(text)
    t = re.sub(r"\(\s*[,/&;-]*\s*\)", " ", t)          # emptied parentheses
    t = re.sub(r"\[\s*\]", " ", t)
    t = re.sub(r"\s*([/,&;])\s*(?=[/,&;)\]]|$)", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    # dangling separators / prepositions at either end
    for _ in range(6):
        words = t.split(" ")
        if words and words[-1].lower().strip(".,:;-") in _TRAIL | {""}:
            words = words[:-1]
        if words and words[0].strip(".,:;-") in ("-", ":", ",", ""):
            words = words[1:]
        t2 = " ".join(words).strip(" -:,;/")
        if t2 == t:
            break
        t = t2
    return t


def informative(text: str) -> bool:
    return len(content_tokens(text) - GENERIC) >= 2


# ----------------------------------------------------------------------------------------------- T3
def build_t3(srcs, gate, seed: int, target: int, per_package: int = 2) -> tuple[list[Item], dict]:
    s = srcs.get("ghsa_reviewed", "query_text")
    stats = defaultdict(int)
    if s is None:
        return [], {"available": False}
    recs = sorted(s.records(), key=lambda r: r["ghsa_id"])
    stats["records"] = len(recs)
    pool = []
    for r in recs:
        if r.get("withdrawn"):
            stats["withdrawn"] += 1
            continue
        if not r.get("cve_ids"):
            stats["no_cve_alias"] += 1
            continue
        if not (r.get("summary") or "").strip():
            stats["no_summary"] += 1
            continue
        pool.append(r)
    stats["eligible"] = len(pool)
    pool.sort(key=lambda r: stable_key(seed, "t3", r["ghsa_id"]))
    per_pkg: dict[str, int] = defaultdict(int)
    items: list[Item] = []
    lic = s.licence
    for r in pool:
        if len(items) >= target:
            break
        pk = r["packages"][0] if r.get("packages") else {"ecosystem": "", "name": ""}
        pkey = f"{pk.get('ecosystem', '')}/{pk.get('name', '')}"
        if per_pkg[pkey] >= per_package:
            stats["package_cap"] += 1
            continue
        qrels, tmeta = gate.targets_from(r["cve_ids"])
        text, removed = strip_ids(r["summary"])
        text = tidy(text)
        variant = "summary"
        if len(content_tokens(text)) < 3 and r.get("details"):
            d, rem2 = strip_ids(first_sentence(r["details"]))
            text = tidy(text + ". " + tidy(d))
            removed += rem2
            variant = "summary+details_first_sentence"
        meta = {"variant": variant, "ecosystem": pk.get("ecosystem", ""), "package": pk.get("name", ""),
                "advisory_published": (r.get("published") or "")[:10], **tmeta}
        if removed:
            meta["stripped"] = sorted(set(removed))
        it = Item(slice="T3", text=text, qrels=qrels,
                  source={"name": "ghsa_reviewed", "id": r["ghsa_id"], "licence": lic}, meta=meta)
        if not gate.accept(it):
            continue
        per_pkg[pkey] += 1
        items.append(it)
    stats["accepted"] = len(items)
    eco = defaultdict(int)
    for it in items:
        eco[it.meta["ecosystem"]] += 1
    stats["by_ecosystem"] = dict(sorted(eco.items()))
    return items, dict(stats)


# ----------------------------------------------------------------------------------------------- T4
def _et_licence(sid: int) -> str:
    if 2000000 <= sid <= 2799999:
        return "BSD (ET Open)"
    return "GPLv2 (ET Open)"


def et_query(msg: str) -> tuple[str, dict]:
    stripped = {}
    m = _ET_PREFIX.match(msg)
    text = msg
    if m:
        stripped["vendor_prefix"] = m.group(0).strip()
        text = text[m.end():]
    text, ids = strip_ids(text)
    if ids:
        stripped["ids"] = ids
    variants = _VARIANT.findall(text)
    if variants:
        stripped["variant_markers"] = variants
        text = _VARIANT.sub(" ", text)
    return tidy(text), stripped


def sigma_query(rec: dict) -> tuple[str, dict, str]:
    title, ids = strip_ids(rec.get("title") or "")
    title = tidy(title)
    stripped = {"ids": ids} if ids else {}
    if informative(title):
        return title, stripped, "title"
    d, ids2 = strip_ids(first_sentence(rec.get("description") or ""))
    d = tidy(d)
    if ids2:
        stripped["ids"] = stripped.get("ids", []) + ids2
    stripped["generic_title_replaced"] = rec.get("title")
    return d, stripped, "description_first_sentence"


def build_t4(srcs, gate, seed: int, target: int, per_cve: int = 2) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    cands = []
    sg = srcs.get("sigma_rules", "query_text")
    if sg is not None:
        for r in sorted(sg.records(), key=lambda r: r["rule_id"]):
            text, stripped, field = sigma_query(r)
            cands.append(("sigma_rules", r["rule_id"], text, stripped, field, r.get("cve_ids") or [],
                          {"rule_author": r.get("author", ""), "rule_status": r.get("status", ""),
                           "rule_path": r.get("path", "")}, sg.licence))
    et = srcs.get("et_open_rules", "query_text")
    if et is not None:
        for r in sorted(et.records(), key=lambda r: r["sid"]):
            text, stripped = et_query(r["msg"])
            cands.append(("et_open_rules", str(r["sid"]), text, stripped, "msg", r.get("cve_ids") or [],
                          {"rule_enabled": bool(r.get("enabled")), "classtype": r.get("classtype", "")},
                          _et_licence(int(r["sid"]))))
    stats["candidates"] = len(cands)
    # Sigma first (smaller, richer wording), each source in a seeded order.
    cands.sort(key=lambda c: (c[0] != "sigma_rules", stable_key(seed, "t4", c[0], c[1])))
    per_target: dict[str, int] = defaultdict(int)
    seen_text: dict[str, set] = defaultdict(set)
    items: list[Item] = []
    for src, rid, text, stripped, fld, cves, extra, lic in cands:
        if len(items) >= target:
            break
        if not informative(text):
            stats["generic_after_stripping"] += 1
            continue
        qrels, tmeta = gate.targets_from(cves)
        tkey = ",".join(sorted(q["doc_id"] for q in qrels))
        if qrels and per_target[tkey] >= per_cve:
            stats["per_target_cap"] += 1
            continue
        nt = normalize(text)
        if nt in seen_text[tkey]:
            stats["duplicate_text_same_target"] += 1
            continue
        meta = {"rule_field": fld, "stripped": stripped, **extra, **tmeta}
        it = Item(slice="T4", text=text, qrels=qrels, source={"name": src, "id": rid, "licence": lic}, meta=meta)
        if not gate.accept(it):
            continue
        per_target[tkey] += 1
        seen_text[tkey].add(nt)
        items.append(it)
    stats["accepted"] = len(items)
    stats["accepted_by_source"] = {k: sum(1 for i in items if i.source["name"] == k)
                                   for k in ("sigma_rules", "et_open_rules")}
    return items, dict(stats)
