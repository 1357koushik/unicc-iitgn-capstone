"""Readers for the four raw CVE feeds (NVD yearly JSON 2.0, CVE List V5, CISA KEV CSV, EPSS CSV).

Each reader turns a source record into a compact, source-faithful dict (no merging, no invented values)
and reports every record it cannot use as a `Reject(source, record_id, reason)`; the build reconciles
records read against records stored plus records rejected.

Normalisation follows Team 1's rules (knowledge_foundation/NORMALIZED_CVE_DATA_GUIDE.md and
cve_normalized_lookup.py): join by CVE ID, keep the source and provider with every fact, null instead of
invented values, keep genuine disagreements (different CVSS assessments), deduplicate references by URL key.
It is a streaming bulk pass instead of Team 1's per-CVE lookup, which scans a year file per CVE.
"""
from __future__ import annotations

import codecs
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

from .text import clean_text, normalize_cve_id

NVD_SOURCE = "nvd"
CVELIST_SOURCE = "cve_list"
KEV_SOURCE = "kev"
EPSS_SOURCE = "epss"

_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)


@dataclass(frozen=True)
class Reject:
    source: str
    record_id: str
    reason: str
    detail: str = ""


# --------------------------------------------------------------------------- references (Team 1 rules)
def clean_url(value: Any) -> str:
    url = clean_text(value or "")
    url = re.sub(r"^(?:https?://)+(https?://)", r"\1", url, flags=re.IGNORECASE)
    if url.lower().startswith("http://https://"):
        url = "https://" + url[len("http://https://"):]
    if url.lower().startswith("https://http://"):
        url = "http://" + url[len("https://http://"):]
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() in {"http", "https"}:
            url = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
    except ValueError:
        pass
    return url


def reference_key(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.netloc:
            return urlunsplit(("", parts.netloc.casefold(), parts.path.rstrip("/"), parts.query, parts.fragment))
    except ValueError:
        pass
    return url.casefold().rstrip("/")


def _ref(ref: dict, origin: str, provider: str | None) -> dict | None:
    if not isinstance(ref, dict):
        return None
    url = clean_url(ref.get("url"))
    if not url:
        return None
    out = {"url": url, "origin": origin}
    src = ref.get("source") or provider
    if src:
        out["provider"] = str(src)
    tags = [clean_text(t) for t in (ref.get("tags") or []) if isinstance(t, str) and clean_text(t)]
    if tags:
        out["tags"] = tags
    name = clean_text(ref.get("name") or "")
    if name and name != url:
        out["name"] = name
    return out


# --------------------------------------------------------------------------- CVSS
_NVD_METRIC_KEYS = {"cvssMetricV2": "2.0", "cvssMetricV30": "3.0", "cvssMetricV31": "3.1", "cvssMetricV40": "4.0"}
_CL_METRIC_KEYS = {"cvssV2_0": "2.0", "cvssV3_0": "3.0", "cvssV3_1": "3.1", "cvssV4_0": "4.0"}


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _cvss_entry(data: dict, version_hint: str, severity: Any, provider: Any, origin: str,
                mtype: Any = None) -> dict | None:
    if not isinstance(data, dict):
        return None
    vector = clean_text(data.get("vectorString") or "") or None
    score = _num(data.get("baseScore"))
    if vector is None and score is None:
        return None
    sev = clean_text(severity or data.get("baseSeverity") or "").upper() or None
    out = {"version": clean_text(data.get("version") or version_hint) or version_hint, "vector": vector,
           "score": score, "severity": sev, "provider": clean_text(provider or "") or None, "origin": origin}
    if mtype:
        out["type"] = clean_text(mtype)
    return out


def nvd_cvss(metrics: Any) -> list[dict]:
    out = []
    if not isinstance(metrics, dict):
        return out
    for key, version in _NVD_METRIC_KEYS.items():
        for m in metrics.get(key) or []:
            if not isinstance(m, dict):
                continue
            e = _cvss_entry(m.get("cvssData") or {}, version, m.get("baseSeverity"), m.get("source"),
                            "nvd", m.get("type"))
            if e:
                out.append(e)
    return out


def cvelist_cvss(metrics: Any, provider: str | None, origin: str) -> list[dict]:
    out = []
    for m in metrics or []:
        if not isinstance(m, dict):
            continue
        for key, version in _CL_METRIC_KEYS.items():
            d = m.get(key)
            if isinstance(d, dict):
                e = _cvss_entry(d, version, d.get("baseSeverity"), provider, origin)
                if e:
                    out.append(e)
    return out


# --------------------------------------------------------------------------- affected / CPE
def _versions(versions: Any) -> list[dict]:
    out = []
    for v in versions or []:
        if not isinstance(v, dict):
            continue
        d = {k: v[k] for k in ("version", "status", "lessThan", "lessThanOrEqual", "versionType") if k in v}
        if d:
            out.append(d)
    return out


def _affected_item(item: Any, origin: str, provider: str | None) -> dict | None:
    if not isinstance(item, dict):
        return None
    out = {"vendor": clean_text(item.get("vendor") or "") or None,
           "product": clean_text(item.get("product") or "") or None,
           "origin": origin}
    if provider:
        out["provider"] = provider
    for src, dst in (("packageName", "package"), ("collectionURL", "collection_url"), ("defaultStatus", "default_status"),
                     ("repo", "repo"), ("packageURL", "purl")):
        val = clean_text(item.get(src) or "")
        if val:
            out[dst] = val
    vers = _versions(item.get("versions"))
    if vers:
        out["versions"] = vers
    for key in ("cpes", "platforms", "modules", "programFiles"):
        vals = [clean_text(x) for x in item.get(key) or [] if isinstance(x, str) and clean_text(x)]
        if vals:
            out[key] = vals
    if out["vendor"] is None and out["product"] is None and "package" not in out:
        return None
    return out


def nvd_cpe_matches(configurations: Any) -> list[dict]:
    """Flatten NVD configurations, keeping the AND/OR structure needed for the platform rule.

    role: 'vulnerable' (vulnerable: true), 'platform' (vulnerable: false inside an AND configuration, the
    running-on side) or 'not_vulnerable' (vulnerable: false elsewhere)."""
    out = []
    for ci, cfg in enumerate(configurations or []):
        if not isinstance(cfg, dict):
            continue
        cfg_op = cfg.get("operator") or ("AND" if len(cfg.get("nodes") or []) > 1 else "OR")
        for ni, node in enumerate(cfg.get("nodes") or []):
            if not isinstance(node, dict):
                continue
            for m in node.get("cpeMatch") or []:
                if not isinstance(m, dict) or not isinstance(m.get("criteria"), str):
                    continue
                vuln = m.get("vulnerable") is True
                e = {"criteria": m["criteria"], "vulnerable": vuln, "config": ci, "config_operator": cfg_op,
                     "node": ni, "node_operator": node.get("operator") or "OR",
                     "role": "vulnerable" if vuln else ("platform" if cfg_op == "AND" else "not_vulnerable")}
                if node.get("negate"):
                    e["negate"] = True
                for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                          "versionEndExcluding"):
                    if m.get(k):
                        e[k] = m[k]
                out.append(e)
    return out


def cpe_parts(criteria: str) -> tuple[str, str, str, str] | None:
    """(part, vendor slug, product slug, version) of a CPE 2.3 string; None if malformed.
    Escaped colons (\\:) inside fields are honoured."""
    if not criteria.startswith("cpe:2.3:"):
        return None
    fields = re.split(r"(?<!\\):", criteria)
    if len(fields) < 6:
        return None
    return fields[2], fields[3], fields[4], fields[5]


# --------------------------------------------------------------------------- weaknesses
def _cwe_id(value: Any) -> str | None:
    m = _CWE_RE.search(str(value or ""))
    return f"CWE-{int(m.group(1))}" if m else None


def nvd_weaknesses(weaknesses: Any) -> list[dict]:
    out = []
    for w in weaknesses or []:
        if not isinstance(w, dict):
            continue
        for d in w.get("description") or []:
            val = clean_text((d or {}).get("value") or "")
            if not val:
                continue
            e = {"origin": "nvd", "provider": w.get("source"), "type": w.get("type")}
            if val.upper().startswith("CWE-"):
                e["id"] = _cwe_id(val)
            else:
                e["nvd_category"] = val  # NVD-CWE-Other / NVD-CWE-noinfo
            out.append(e)
    return out


def cvelist_problems(problem_types: Any, origin: str, provider: str | None) -> list[dict]:
    out = []
    for p in problem_types or []:
        for d in (p or {}).get("descriptions") or []:
            if not isinstance(d, dict):
                continue
            lang = str(d.get("lang") or "en").lower()
            text = clean_text(d.get("description") or "")
            cid = _cwe_id(d.get("cweId")) or (_cwe_id(text) if text.upper().startswith("CWE-") else None)
            if not cid and (not text or not lang.startswith("en")):
                continue
            e = {"origin": origin, "provider": provider}
            if cid:
                e["id"] = cid
            if text:
                e["text"] = text
            out.append(e)
    return out


def _english(descs: Any) -> str:
    """First English description: lang 'en' exactly, else the first 'en-*'."""
    exact = other = ""
    for d in descs or []:
        if not isinstance(d, dict):
            continue
        lang = str(d.get("lang") or "").lower()
        val = clean_text(d.get("value") or "")
        if not val:
            continue
        if lang == "en" and not exact:
            exact = val
        elif lang.startswith("en") and not other:
            other = val
    return exact or other


# --------------------------------------------------------------------------- NVD
def iter_json_array(path: Path, key: str, hasher: Any | None = None,
                    chunk: int = 1 << 24) -> Iterator[tuple[int, Any, str | None]]:
    """Stream the elements of the top-level array `key` of a large JSON file.

    Yields (element index, decoded value or None, raw element text or error message). Undecodable
    trailing content yields one (index, None, message) item and stops. `hasher` sees every byte."""
    dec = json.JSONDecoder()
    udec = codecs.getincrementaldecoder("utf-8")()
    with open(path, "rb") as f:
        eof = False

        def more() -> str:
            nonlocal eof
            b = f.read(chunk)
            if not b:
                eof = True
                return udec.decode(b"", final=True)
            if hasher is not None:
                hasher.update(b)
            return udec.decode(b)

        buf = more()
        marker = f'"{key}"'
        while marker not in buf:
            if eof:
                raise ValueError(f"{path.name}: no '{key}' array")
            buf += more()
        i = buf.index(marker) + len(marker)
        while buf.find("[", i) < 0:
            if eof:
                raise ValueError(f"{path.name}: '{key}' is not an array")
            buf += more()
        i = buf.index("[", i) + 1
        n = 0
        while True:
            while True:
                while i < len(buf) and buf[i] in " \t\r\n,":
                    i += 1
                if i < len(buf) or eof:
                    break
                buf = buf[i:] + more()
                i = 0
            if i >= len(buf):
                yield n, None, "truncated: array not closed"
                return
            if buf[i] == "]":
                while not eof:
                    more()
                return
            try:
                v, j = dec.raw_decode(buf, i)
            except json.JSONDecodeError as e:
                if not eof:
                    buf = buf[i:] + more()
                    i = 0
                    continue
                yield n, None, f"unparseable JSON element: {e.msg}"
                return
            yield n, v, buf[i:j]
            n += 1
            i = j
            if i > (1 << 23):
                buf = buf[i:]
                i = 0


def compact_nvd(wrapper: Any, raw: str, file_name: str, index: int) -> tuple[dict | None, Reject | None]:
    rid = f"{file_name}#{index}"
    if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
        return None, Reject(NVD_SOURCE, rid, "malformed_record", "element has no 'cve' object")
    c = wrapper["cve"]
    raw_id = c.get("id")
    cid = normalize_cve_id(raw_id)
    if cid is None:
        reason = "missing_cve_id" if not raw_id else "malformed_cve_id"
        return None, Reject(NVD_SOURCE, rid, reason, str(raw_id)[:80])
    rec = {
        "id": cid,
        "file": file_name,
        "index": index,
        "sha": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "status": clean_text(c.get("vulnStatus") or "") or None,
        "published": c.get("published"),
        "last_modified": c.get("lastModified"),
        "source_identifier": c.get("sourceIdentifier"),
        "desc_en": _english(c.get("descriptions")),
        "cvss": nvd_cvss(c.get("metrics")),
        "weak": nvd_weaknesses(c.get("weaknesses")),
        "cpe": nvd_cpe_matches(c.get("configurations")),
        "aff": [a for blk in c.get("affected") or [] if isinstance(blk, dict)
                for a in (_affected_item(x, "nvd_affected", blk.get("source"))
                          for x in blk.get("affectedData") or []) if a],
        "refs": [r for r in (_ref(x, "nvd", None) for x in c.get("references") or []) if r],
        "tags": sorted({t for g in c.get("cveTags") or [] if isinstance(g, dict)
                        for t in g.get("tags") or [] if isinstance(t, str)}),
    }
    kev = {k: c[k] for k in ("cisaExploitAdd", "cisaActionDue", "cisaRequiredAction", "cisaVulnerabilityName")
           if c.get(k)}
    if kev:
        rec["nvd_kev"] = kev
    return rec, None


# --------------------------------------------------------------------------- CVE List V5
def compact_cvelist(data: Any, relpath: str, sha: str) -> tuple[dict | None, Reject | None]:
    if not isinstance(data, dict):
        return None, Reject(CVELIST_SOURCE, relpath, "malformed_record", "top level is not an object")
    meta = data.get("cveMetadata")
    if not isinstance(meta, dict):
        return None, Reject(CVELIST_SOURCE, relpath, "malformed_record", "no cveMetadata")
    raw_id = meta.get("cveId")
    cid = normalize_cve_id(raw_id)
    if cid is None:
        reason = "missing_cve_id" if not raw_id else "malformed_cve_id"
        return None, Reject(CVELIST_SOURCE, relpath, reason, str(raw_id)[:80])
    stem = relpath.rsplit("/", 1)[-1].rsplit(".", 1)[0].upper()
    if stem != cid:
        return None, Reject(CVELIST_SOURCE, relpath, "cve_id_filename_mismatch", f"file {stem} holds {cid}")
    containers = data.get("containers") if isinstance(data.get("containers"), dict) else {}
    rec: dict[str, Any] = {
        "id": cid, "path": relpath, "sha": sha,
        "state": clean_text(meta.get("state") or "").upper() or None,
        "data_version": data.get("dataVersion"),
        "dates": {k: meta[v] for k, v in (("reserved", "dateReserved"), ("published", "datePublished"),
                                          ("updated", "dateUpdated"), ("rejected", "dateRejected")) if meta.get(v)},
        "assigner": {k: meta[v] for k, v in (("org_id", "assignerOrgId"), ("short_name", "assignerShortName"))
                     if meta.get(v)},
    }
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else None
    if cna is not None:
        pm = cna.get("providerMetadata") or {}
        prov = pm.get("shortName") or pm.get("orgId")
        rec["cna"] = {
            "provider": prov,
            "title": clean_text(cna.get("title") or ""),
            "desc_en": _english(cna.get("descriptions")),
            "affected": [a for a in (_affected_item(x, "cna", prov) for x in cna.get("affected") or []) if a],
            "problems": cvelist_problems(cna.get("problemTypes"), "cna", prov),
            "cvss": cvelist_cvss(cna.get("metrics"), prov, "cna"),
            "refs": [r for r in (_ref(x, "cna", prov) for x in cna.get("references") or []) if r],
            "tags": sorted({t for t in cna.get("tags") or [] if isinstance(t, str)}),
            "rejected_reason": _english(cna.get("rejectedReasons")),
        }
    adps = []
    for adp in containers.get("adp") or []:
        if not isinstance(adp, dict):
            continue
        pm = adp.get("providerMetadata") or {}
        prov = pm.get("shortName") or pm.get("orgId")
        origin = f"adp:{prov}" if prov else "adp"
        entry = {
            "provider": prov,
            "affected": [a for a in (_affected_item(x, origin, prov) for x in adp.get("affected") or []) if a],
            "problems": cvelist_problems(adp.get("problemTypes"), origin, prov),
            "cvss": cvelist_cvss(adp.get("metrics"), prov, origin),
            "refs": [r for r in (_ref(x, origin, prov) for x in adp.get("references") or []) if r],
        }
        if any(entry[k] for k in ("affected", "problems", "cvss", "refs")):
            adps.append(entry)
    if adps:
        rec["adp"] = adps
    return rec, None


def read_cvelist_file(path: Path, relpath: str) -> tuple[dict | None, Reject | None]:
    try:
        raw = path.read_bytes()
    except OSError as e:
        return None, Reject(CVELIST_SOURCE, relpath, "unreadable_file", str(e)[:120])
    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, Reject(CVELIST_SOURCE, relpath, "unparseable_json", str(e)[:120])
    return compact_cvelist(data, relpath, sha)


# --------------------------------------------------------------------------- KEV
KEV_FIELDS = {"cveID": "cve_id", "vendorProject": "vendor_project", "product": "product",
              "vulnerabilityName": "vulnerability_name", "dateAdded": "date_added",
              "shortDescription": "short_description", "requiredAction": "required_action", "dueDate": "due_date",
              "knownRansomwareCampaignUse": "ransomware_use", "notes": "notes", "cwes": "cwes",
              "forensicTriage": "forensic_triage"}


def read_kev(path: Path) -> tuple[dict[str, dict], list[Reject], int]:
    """KEV rows by CVE ID. Returns (rows, rejects, rows read)."""
    rows: dict[str, dict] = {}
    rejects: list[Reject] = []
    n = 0
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_no, row in enumerate(reader, start=2):
            n += 1
            rid = f"{path.name}:{line_no}"
            cid = normalize_cve_id(row.get("cveID"))
            if cid is None:
                rejects.append(Reject(KEV_SOURCE, rid, "malformed_cve_id", str(row.get("cveID"))[:80]))
                continue
            rec: dict[str, Any] = {"row": line_no}
            for src, dst in KEV_FIELDS.items():
                if src == "cveID":
                    continue
                val = clean_text(row.get(src) or "")
                rec[dst] = val or None
            rec["cwes"] = sorted({f"CWE-{int(x)}" for x in _CWE_RE.findall(row.get("cwes") or "")},
                                 key=lambda s: int(s[4:]))
            sha = hashlib.sha256(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest()
            rec["sha"] = sha
            if cid in rows:
                same = rows[cid]["sha"] == sha
                rejects.append(Reject(KEV_SOURCE, rid, "duplicate_identical_row" if same else "duplicate_conflicting_row",
                                      f"{cid} already read from line {rows[cid]['row']}"))
                continue
            rows[cid] = rec
    return rows, rejects, n


# --------------------------------------------------------------------------- EPSS
def read_epss(path: Path) -> tuple[dict[str, tuple[float, float]], dict[str, str], list[Reject], int]:
    """EPSS (score, percentile) by CVE ID plus the file metadata (model_version, score_date)."""
    scores: dict[str, tuple[float, float]] = {}
    meta: dict[str, str] = {}
    rejects: list[Reject] = []
    n = 0
    with open(path, encoding="utf-8-sig", newline="") as f:
        first = f.readline()
        if first.startswith("#"):
            for item in first[1:].strip().split(","):
                if ":" in item:
                    k, v = item.split(":", 1)
                    meta[k.strip()] = v.strip()
        else:
            f.seek(0)
        reader = csv.DictReader(f)
        line_no = 2 if meta else 1
        for row in reader:
            line_no += 1
            n += 1
            rid = f"{path.name}:{line_no}"
            cid = normalize_cve_id(row.get("cve"))
            if cid is None:
                rejects.append(Reject(EPSS_SOURCE, rid, "malformed_cve_id", str(row.get("cve"))[:80]))
                continue
            s, p = _num(row.get("epss")), _num(row.get("percentile"))
            if s is None or p is None or not (0.0 <= s <= 1.0) or not (0.0 <= p <= 1.0):
                rejects.append(Reject(EPSS_SOURCE, rid, "invalid_score", f"{row.get('epss')},{row.get('percentile')}"))
                continue
            if cid in scores:
                same = scores[cid] == (s, p)
                rejects.append(Reject(EPSS_SOURCE, rid, "duplicate_identical_row" if same else "duplicate_conflicting_row", cid))
                continue
            scores[cid] = (s, p)
    return scores, meta, rejects, n


def latest_dated(feeds_dir: Path, prefix: str) -> Path | None:
    files = sorted(feeds_dir.glob(f"{prefix}-*.csv"))
    return files[-1] if files else None


def git_head(repo: Path) -> str | None:
    """HEAD commit of a git checkout, read from .git without running git."""
    g = repo / ".git"
    try:
        head = (g / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref:"):
        return head or None
    ref = head.split(":", 1)[1].strip()
    p = g / ref
    if p.is_file():
        return p.read_text(encoding="utf-8").strip() or None
    packed = g / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


# one CPE field character: plain, or a JSON-escaped CPE escape (raw bytes \\: or \\!), or another JSON escape
_CPE_FIELD = rb'((?:\\\\.|\\.|[^:"\\])+)'
_CPE_VOCAB = re.compile(rb'"criteria"\s*:\s*"cpe:2\.3:[aoh]:' + _CPE_FIELD + rb':' + _CPE_FIELD + rb':')


def scan_cpe_vocabulary(path: Path) -> tuple[set[str], set[str]]:
    """(vendor slugs, product slugs) named anywhere in an NVD file's CPE criteria (raw byte scan)."""
    vendors: set[str] = set()
    products: set[str] = set()
    tail = b""
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 24), b""):
            data = tail + chunk
            for m in _CPE_VOCAB.finditer(data):
                vendors.add(m.group(1).decode("utf-8", "replace"))
                products.add(m.group(2).decode("utf-8", "replace"))
            tail = data[-512:]
    return vendors, products
