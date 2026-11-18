"""Merge the per-source records of one CVE into its store row.

Rules (plan 4.2, 3.1 rows 12-15; Team 1 normalisation guide):

* identity is the CVE ID; NVD, CVE List, KEV and EPSS facts for one ID are merged into one row and every
  field records which source it came from (``provenance``);
* state comes from the CVE List when it has the record (the CNA/MITRE record is authoritative), else NVD;
  disagreements are recorded, not hidden;
* description: the CNA's English description, else NVD's, else the KEV short description;
* vendor_product: NVD CPE pairs with ``vulnerable: true`` whose product is named in the CVE's own
  description or CNA affected block (platform CPEs such as the Red Hat entries NVD lists for a Chrome bug
  are skipped; the platform side of an AND configuration is never vulnerable), else the CNA/ADP
  ``affected`` block, else NVD's copy of it, else KEV; at most 10 distinct humanised pairs;
* CVSS is kept as published: every version, vector, score, severity and source; nothing is derived from
  KEV (no severity override) and EPSS is kept for every scored CVE (no threshold).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .feeds import cpe_parts, reference_key
from .text import (CVE_IN_TEXT, clean_text, description_kind, display_name, find_span, is_na, name_key, slug_tokens,
                   strip_cve_ids, strip_disputed_marker, vendor_product_label)

VENDOR_PRODUCT_CAP = 10
NVD_CWE_CATEGORIES = ("NVD-CWE-Other", "NVD-CWE-noinfo")


def _date(value: Any) -> str | None:
    s = clean_text(value or "")
    return s[:10] if len(s) >= 10 and s[4] == "-" else None


def pick_nvd(records: list[dict]) -> tuple[dict | None, list[tuple[dict, str]]]:
    """Newest NVD record for one CVE; the others with the reason they are not stored."""
    if not records:
        return None, []
    ordered = sorted(records, key=lambda r: (r.get("last_modified") or "", r["file"], -r["index"]), reverse=True)
    keep = ordered[0]
    return keep, [(r, "duplicate_identical_record" if r["sha"] == keep["sha"] else "superseded_by_newer_record")
                  for r in ordered[1:]]


def pick_cvelist(records: list[dict]) -> tuple[dict | None, list[tuple[dict, str]]]:
    if not records:
        return None, []
    ordered = sorted(records, key=lambda r: ((r.get("dates") or {}).get("updated") or "", r["path"]), reverse=True)
    keep = ordered[0]
    return keep, [(r, "duplicate_identical_record" if r["sha"] == keep["sha"] else "superseded_by_newer_record")
                  for r in ordered[1:]]


# --------------------------------------------------------------------------- vendor / product
def _affected_entries(cl: dict | None, nvd: dict | None) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    if cl:
        for a in (cl.get("cna") or {}).get("affected") or []:
            out.append(("cve_list_cna_affected", a))
        for adp in cl.get("adp") or []:
            for a in adp.get("affected") or []:
                out.append(("cve_list_adp_affected", a))
    if nvd:
        for a in nvd.get("aff") or []:
            out.append(("nvd_affected", a))
    return out


def _affected_is_affected(a: dict) -> bool:
    vers = a.get("versions") or []
    if any(str(v.get("status", "")).lower() == "affected" for v in vers):
        return True
    if str(a.get("default_status") or "").lower() == "affected":
        return True
    return not vers


def vendor_product(nvd: dict | None, cl: dict | None, kev: dict | None,
                   texts: list[str]) -> tuple[list[str], str | None, list[dict]]:
    """(humanised 'Vendor Product' labels, method, evidence) for one CVE."""
    labels: list[str] = []
    keys: set[str] = set()
    evidence: list[dict] = []

    def add(label: str, ev: dict) -> bool:
        label = label.replace(";", ",")  # "; " separates pairs in the text column
        k = name_key(label)
        if not k or k in keys:
            return False
        if len(labels) >= VENDOR_PRODUCT_CAP:
            return False
        keys.add(k)
        labels.append(label)
        evidence.append(ev)
        return True

    if nvd:
        seen_pairs: set[tuple[str, str]] = set()
        for m in nvd.get("cpe") or []:
            if not m.get("vulnerable"):
                continue  # not vulnerable, including the platform side of AND configurations
            parts = cpe_parts(m["criteria"])
            if parts is None:
                continue
            part, vslug, pslug, _ = parts
            if (vslug, pslug) in seen_pairs or is_na(pslug):
                continue
            seen_pairs.add((vslug, pslug))
            ptoks = slug_tokens(pslug)
            pspan = next((s for s in (find_span(ptoks, t) for t in texts) if s), None)
            if pspan is None:
                continue  # product not named by the CVE itself: a platform or repackaging CPE
            vtoks = slug_tokens(vslug)
            vspan = next((s for s in (find_span(vtoks, t) for t in texts) if s), None)
            vendor = vspan or " ".join(vtoks)
            add(vendor_product_label(vendor, pspan), {"method": "nvd_cpe_named", "part": part,
                                                       "vendor": vslug, "product": pslug})
        if labels:
            return labels, "nvd_cpe_named", evidence
    for origin, a in _affected_entries(cl, None) + _affected_entries(None, nvd):
        prod = a.get("product") or a.get("package")
        if not prod or is_na(prod) or not _affected_is_affected(a):
            continue
        vend = a.get("vendor") if a.get("vendor") and not is_na(a.get("vendor")) else None
        add(vendor_product_label(vend, prod), {"method": origin, "vendor": vend, "product": prod})
    if labels:
        return labels, evidence[0]["method"], evidence
    if kev and kev.get("product") and not is_na(kev["product"]):
        vend = kev.get("vendor_project") if kev.get("vendor_project") and not is_na(kev["vendor_project"]) else None
        add(vendor_product_label(vend, kev["product"]), {"method": "kev", "vendor": vend, "product": kev["product"]})
        return labels, "kev", evidence
    return [], None, []


def own_names(nvd: dict | None, cl: dict | None, kev: dict | None) -> list[str]:
    """Every vendor/product/package/module name the CVE's own records give (for the alias filter)."""
    names: set[str] = set()
    if nvd:
        for m in nvd.get("cpe") or []:
            p = cpe_parts(m["criteria"])
            if p:
                names.add(display_name(p[1]))
                names.add(display_name(p[2]))
    for _, a in _affected_entries(cl, nvd):
        for k in ("vendor", "product", "package"):
            if a.get(k) and not is_na(a[k]):
                names.add(display_name(a[k]))
        for mod in a.get("modules") or []:
            names.add(display_name(mod))
    if kev:
        for k in ("vendor_project", "product"):
            if kev.get(k) and not is_na(kev[k]):
                names.add(display_name(kev[k]))
    return sorted(n for n in names if n)


# --------------------------------------------------------------------------- weaknesses, CVSS, references
def weaknesses(nvd: dict | None, cl: dict | None, kev: dict | None, cwe_names: dict[str, str],
               cve_id: str = "") -> tuple[list[str], list[dict], str, list[dict]]:
    """(sorted CWE IDs, weakness entries with names and sources, weakness text, related CVEs).

    CNA problem-type text sometimes names other CVEs ("incomplete fix for CVE-2008-5313"); those IDs are
    moved to the related-CVE list and removed from the weakness text, so an ID query cannot match the wrong
    CVE through it."""
    by_id: dict[str, dict] = {}
    related: list[dict] = []

    def take_ids(text: str, origin: str) -> str:
        for m in CVE_IN_TEXT.finditer(text or ""):
            rid = m.group(0).upper()
            if rid != cve_id and not any(r["cve_id"] == rid and r["source"] == origin for r in related):
                related.append({"cve_id": rid, "source": origin, "text": text[:300]})
        return strip_cve_ids(text) if CVE_IN_TEXT.search(text or "") else text
    free_text: dict[str, dict] = {}
    nvd_categories: set[str] = set()

    def add_id(cid: str, origin: str, text: str | None) -> None:
        e = by_id.setdefault(cid, {"id": cid, "name": cwe_names.get(cid), "sources": []})
        if origin not in e["sources"]:
            e["sources"].append(origin)
        if e["name"] is None and text:
            t = take_ids(clean_text(text), origin)
            if t.upper().startswith(cid.upper()):
                t = t[len(cid):].strip(" :-")
            if t:
                e["name"] = t
                e["name_source"] = origin

    if nvd:
        for w in nvd.get("weak") or []:
            if w.get("id"):
                add_id(w["id"], "nvd", None)
            elif w.get("nvd_category"):
                nvd_categories.add(w["nvd_category"])
    if cl:
        groups = [("cve_list_cna", (cl.get("cna") or {}).get("problems") or [])]
        groups += [(f"cve_list_adp:{a.get('provider')}", a.get("problems") or []) for a in cl.get("adp") or []]
        for origin, probs in groups:
            for p in probs:
                if p.get("id"):
                    add_id(p["id"], origin, p.get("text"))
                elif p.get("text") and not is_na(p["text"]):
                    text = take_ids(p["text"], origin)
                    k = name_key(text)
                    if not k:
                        continue
                    e = free_text.setdefault(k, {"id": None, "name": text, "sources": []})
                    if origin not in e["sources"]:
                        e["sources"].append(origin)
    if kev:
        for cid in kev.get("cwes") or []:
            add_id(cid, "kev", None)
    for e in by_id.values():
        if e["name"] and "name_source" not in e:
            e["name_source"] = "cwe_catalog"
    ids = sorted(by_id, key=lambda s: int(s[4:]))
    named_keys = {name_key(by_id[i]["name"]) for i in ids if by_id[i]["name"]}
    extra = [e for k, e in sorted(free_text.items()) if k and k not in named_keys]
    entries = [by_id[i] for i in ids] + extra
    for cat in sorted(nvd_categories):
        entries.append({"id": None, "nvd_category": cat, "sources": ["nvd"]})
    parts = []
    for i in ids:
        e = by_id[i]
        parts.append(f"{i} {e['name']}" if e["name"] else i)
    parts += [e["name"] for e in extra]
    return ids, entries, "; ".join(parts), related


def weakness_names(entries: list[dict]) -> list[str]:
    return [e["name"] for e in entries if e.get("name")]


def merge_cvss(*groups: list[dict]) -> list[dict]:
    out: dict[tuple, dict] = {}
    for g in groups:
        for e in g:
            key = (e["version"], e.get("vector"), e.get("score"))
            cur = out.get(key)
            src = {k: e[k] for k in ("provider", "origin", "type") if e.get(k)}
            if cur is None:
                cur = out[key] = {"version": e["version"], "vector": e.get("vector"), "score": e.get("score"),
                                  "severity": e.get("severity"), "sources": []}
            elif cur["severity"] is None and e.get("severity"):
                cur["severity"] = e["severity"]
            elif e.get("severity") and cur["severity"] != e["severity"]:
                src["severity"] = e["severity"]  # keep a disagreeing severity label with its source
            if src not in cur["sources"]:
                cur["sources"].append(src)
    return sorted(out.values(), key=lambda e: (e["version"], e.get("vector") or "", e.get("score") or -1))


def merge_references(*groups: list[dict]) -> list[dict]:
    out: dict[str, dict] = {}
    order: list[str] = []
    for g in groups:
        for r in g:
            k = reference_key(r["url"])
            cur = out.get(k)
            if cur is None:
                cur = out[k] = {"url": r["url"], "origins": [], "tags": []}
                order.append(k)
            elif cur["url"].startswith("http://") and r["url"].startswith("https://"):
                cur["url"] = r["url"]
            if r["origin"] not in cur["origins"]:
                cur["origins"].append(r["origin"])
            for t in r.get("tags") or []:
                if t not in cur["tags"]:
                    cur["tags"].append(t)
            if r.get("name") and "name" not in cur:
                cur["name"] = r["name"]
    res = []
    for k in order:
        e = out[k]
        if not e["tags"]:
            del e["tags"]
        res.append(e)
    return res


# --------------------------------------------------------------------------- dense text
def _sentence(s: str) -> str:
    s = s.strip()
    return s if not s or s[-1] in ".!?" else s + "."


def dense_text(title: str | None, vp_labels: list[str], description: str, wnames: list[str]) -> str:
    """`title. vendor product. description. weakness.` with no labels, no boilerplate and no CVE IDs.

    The title is left out when the description already contains it, and so is the vendor/product part when
    every pair is already named in the description (no repeated text). Weakness names only (no CWE IDs)."""
    desc = strip_cve_ids(strip_disputed_marker(description))
    low = desc.casefold()
    parts = []
    t = strip_cve_ids(title or "")
    if t and t.casefold().rstrip(". ") not in low:
        parts.append(_sentence(t))
    vp = [strip_cve_ids(x) for x in vp_labels if x.casefold() not in low]
    vp = [x for x in vp if x]
    if vp:
        parts.append(_sentence(", ".join(vp)))
    parts.append(_sentence(desc))
    w = [strip_cve_ids(x) for x in wnames if x.casefold() not in low]
    w = [x for x in w if x and x.casefold() not in low]
    if w:
        parts.append(_sentence("; ".join(w)))
    return " ".join(p for p in parts if p)


def content_hash(row: dict) -> str:
    payload = [row.get(k) for k in ("searchable", "title", "description", "vendor_product", "weakness",
                                    "aliases", "kev_text", "dense_text")]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- the row
def build_row(cid: str, nvd: dict | None, cl: dict | None, kev: dict | None, epss: tuple[float, float] | None,
              ctx: dict) -> tuple[dict, dict]:
    """(store row, side information for the alias filter) for one CVE.

    ctx: cwe_names, kev_file, epss_file, epss_meta, store_version."""
    cna = (cl or {}).get("cna") or {}
    prov_sources: dict[str, Any] = {}
    fields: dict[str, Any] = {}
    conflicts: dict[str, Any] = {}
    if nvd:
        prov_sources["nvd"] = {"file": nvd["file"], "index": nvd["index"], "record_sha256": nvd["sha"],
                               "status": nvd.get("status"), "last_modified": nvd.get("last_modified")}
    if cl:
        prov_sources["cve_list"] = {"path": cl["path"], "record_sha256": cl["sha"], "state": cl.get("state"),
                                    "data_version": cl.get("data_version"), "updated": cl["dates"].get("updated")}
    if kev:
        prov_sources["kev"] = {"file": ctx.get("kev_file"), "row": kev["row"], "record_sha256": kev["sha"]}
    if epss:
        prov_sources["epss"] = {"file": ctx.get("epss_file"), "model_version": ctx["epss_meta"].get("model_version"),
                                "score_date": ctx["epss_meta"].get("score_date")}

    # ---- state
    nvd_desc = (nvd or {}).get("desc_en") or ""
    cna_desc = cna.get("desc_en") or ""
    nvd_kind = description_kind(nvd_desc)
    if cl:
        s = (cl.get("state") or "").upper()
        state = {"REJECTED": "rejected", "RESERVED": "reserved"}.get(s, "published")
        if state == "published" and description_kind(cna_desc) in ("reserved", "rejected"):
            state = description_kind(cna_desc)
        fields["state"] = "cve_list"
        if nvd and (nvd.get("status") == "Rejected") != (state == "rejected"):
            conflicts["state"] = {"cve_list": cl.get("state"), "nvd": nvd.get("status")}
    elif nvd:
        if nvd.get("status") == "Rejected" or nvd_kind == "rejected":
            state = "rejected"
        elif nvd.get("status") == "Reserved" or nvd_kind == "reserved":
            state = "reserved"
        else:
            state = "published"
        fields["state"] = "nvd"
    else:
        state = "published"
        fields["state"] = "kev_listed" if kev else "epss_scored"

    # ---- description
    description, dsrc = "", None
    if state == "rejected":
        for src, text in (("cve_list_cna_rejected_reason", cna.get("rejected_reason")), ("nvd", nvd_desc),
                          ("cve_list_cna", cna_desc)):
            if text:
                description, dsrc = text, src
                break
    else:
        options = [("cve_list_cna", cna_desc), ("nvd", nvd_desc), ("kev", (kev or {}).get("short_description") or "")]
        for src, text in options:
            if text and description_kind(text) == "ok":
                description, dsrc = text, src
                break
        if not dsrc:
            for src, text in options:
                if text:
                    description, dsrc = text, src
                    break
    dkind = description_kind(description)
    searchable = state == "published" and dkind == "ok"
    fields["description"] = dsrc
    if cna_desc and nvd_desc and dsrc == "cve_list_cna" and cna_desc != nvd_desc:
        fields["description_nvd_differs"] = True

    title = cna.get("title") or None
    if title and is_na(title):
        title = None
    fields["title"] = "cve_list_cna" if title else None

    # ---- vendor/product
    texts = [t for t in (description, nvd_desc, cna_desc, title or "") if t]
    for _, a in _affected_entries(cl, nvd):
        v, p = a.get("vendor") or "", a.get("product") or a.get("package") or ""
        if p and not is_na(p):
            texts.append(f"{v} {p}" if v and not is_na(v) else p)
            texts.append(p)
    vp_labels, vp_method, vp_evidence = vendor_product(nvd, cl, kev, texts)
    fields["vendor_product"] = {"method": vp_method, "pairs": vp_evidence} if vp_method else None

    # ---- weakness, CVSS, CPE, references, affected
    cwe_ids, wentries, wtext, related = weaknesses(nvd, cl, kev, ctx["cwe_names"], cid)
    fields["weakness"] = sorted({s for e in wentries for s in e.get("sources", [])})
    cvss_groups = [(nvd or {}).get("cvss") or [], cna.get("cvss") or []]
    cvss_groups += [a.get("cvss") or [] for a in (cl or {}).get("adp") or []]
    cvss = merge_cvss(*cvss_groups)
    fields["cvss"] = sorted({s["origin"] for e in cvss for s in e["sources"] if s.get("origin")})
    ref_groups = [(nvd or {}).get("refs") or [], cna.get("refs") or []]
    ref_groups += [a.get("refs") or [] for a in (cl or {}).get("adp") or []]
    refs = merge_references(*ref_groups)
    affected = [a for _, a in _affected_entries(cl, nvd)]
    tags = sorted(set((nvd or {}).get("tags") or []) | set(cna.get("tags") or []))

    # ---- KEV / EPSS
    kev_json = None
    kev_text = None
    if kev:
        kev_json = {"listed": True, **{k: kev.get(k) for k in ("vendor_project", "product", "vulnerability_name",
                                                                "date_added", "short_description", "required_action",
                                                                "due_date", "ransomware_use", "notes", "cwes",
                                                                "forensic_triage")}}
        kev_text = " ".join(_sentence(x) for x in (kev.get("vulnerability_name"), kev.get("short_description")) if x)
        fields["kev"] = "kev"
    epss_json = None
    if epss:
        epss_json = {"score": epss[0], "percentile": epss[1], "date": _date(ctx["epss_meta"].get("score_date")),
                     "score_date": ctx["epss_meta"].get("score_date"), "model_version": ctx["epss_meta"].get("model_version")}
        fields["epss"] = "epss"
    if nvd and nvd.get("nvd_kev"):
        fields["nvd_kev_fields"] = nvd["nvd_kev"]

    # ---- dates, assigner
    cl_dates = (cl or {}).get("dates") or {}
    dates: dict[str, Any] = {}
    if cl_dates:
        dates["cve_list"] = dict(cl_dates)
    if nvd:
        dates["nvd"] = {k: v for k, v in (("published", nvd.get("published")), ("last_modified", nvd.get("last_modified"))) if v}
    if kev:
        dates["kev"] = {k: v for k, v in (("date_added", kev.get("date_added")), ("due_date", kev.get("due_date"))) if v}
    published = _date(cl_dates.get("published")) or _date((nvd or {}).get("published"))
    fields["published"] = "cve_list" if _date(cl_dates.get("published")) else ("nvd" if published else None)
    modified = max([d for d in (cl_dates.get("updated"), (nvd or {}).get("last_modified")) if d] or [""]) or None
    assigner = dict((cl or {}).get("assigner") or {})
    if nvd and nvd.get("source_identifier"):
        assigner["nvd_source_identifier"] = nvd["source_identifier"]

    dense = dense_text(title, vp_labels, description, weakness_names(wentries)) if searchable else None
    sources = [s for s, present in (("nvd", nvd), ("cve_list", cl), ("kev", kev), ("epss", epss)) if present]
    provenance = {"sources": prov_sources, "fields": fields}
    if conflicts:
        provenance["conflicts"] = conflicts
    row = {
        "cve_id": cid,
        "state": state,
        "searchable": 1 if searchable else 0,
        "description_kind": dkind,
        "title": title,
        "description": description or None,
        "description_source": dsrc,
        "vendor_product": "; ".join(vp_labels) or None,
        "weakness": wtext or None,
        "aliases": None,
        "kev_text": kev_text,
        "dense_text": dense,
        "published": published,
        "modified": modified,
        "nvd_status": (nvd or {}).get("status"),
        "sources": ",".join(sources),
        "kev_listed": 1 if kev else 0,
        "epss_score": epss[0] if epss else None,
        "epss_percentile": epss[1] if epss else None,
        "cvss": cvss,
        "cwe_ids": cwe_ids,
        "weaknesses": wentries,
        "related_cves": related,
        "cpe": (nvd or {}).get("cpe") or [],
        "affected": affected,
        "kev": kev_json,
        "epss": epss_json,
        "references": refs,
        "tags": tags,
        "dates": dates,
        "assigner": assigner,
        "provenance": provenance,
        "store_version": ctx["store_version"],
    }
    side = {"own_names": own_names(nvd, cl, kev),
            "desc_texts": [t for t in dict.fromkeys((description, nvd_desc, cna_desc)) if t],
            "title": title or ""}
    return row, side
