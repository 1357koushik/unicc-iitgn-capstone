"""The CVE universe: a streaming bulk pass over the raw feeds (NVD yearly JSON, KEV, EPSS) plus
on-demand reads of CVE List V5 records.

The universe is the set of CVE IDs the corpus can contain (NVD, CVE List, KEV, EPSS). A CVE is
*searchable* when it is not rejected in NVD or the CVE List and has an English description.
"""
from __future__ import annotations

import codecs
import csv
import hashlib
import json
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .common import sha256_file

CPE_PAIR_CAP = 40        # distinct (part, vendor, product) pairs kept per CVE
CPE_VERSION_CAP = 120    # version specs kept per pair
AFF_CAP = 20
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_DOMAIN = re.compile(r"(?<![a-z0-9.-])[a-z0-9][a-z0-9-]{1,40}(?:\.[a-z0-9-]{1,40})*\.(?:com|net|org|info|biz|xyz|top|ru|cn|io|online|site|club|live)(?![a-z0-9])")
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}")


def _iter_nvd(path: Path, hasher) -> Iterator[dict]:
    dec = json.JSONDecoder()
    udec = codecs.getincrementaldecoder("utf-8")()
    with open(path, "rb") as f:
        def more() -> str:
            b = f.read(1 << 24)
            if not b:
                return ""
            hasher.update(b)
            return udec.decode(b)
        buf = more()
        while '"vulnerabilities"' not in buf:
            nxt = more()
            if not nxt:
                return
            buf += nxt
        i = buf.index('"vulnerabilities"')
        while buf.find("[", i) < 0:
            buf += more()
        i = buf.index("[", i) + 1
        while True:
            while True:
                while i < len(buf) and buf[i] in " \t\r\n,":
                    i += 1
                if i < len(buf):
                    break
                buf = more()
                i = 0
                if not buf:
                    return
            if buf[i] == "]":
                # drain the remainder so the hash covers the whole file
                while more():
                    pass
                return
            try:
                v, j = dec.raw_decode(buf, i)
            except json.JSONDecodeError:
                nxt = more()
                if not nxt:
                    raise ValueError(f"truncated JSON in {path}")
                buf = buf[i:] + nxt
                i = 0
                continue
            yield v
            i = j
            if i > (1 << 23):
                buf = buf[i:]
                i = 0


def _cpe_entries(configurations: list) -> tuple[dict[str, list], bool]:
    out: dict[str, list] = {}
    trunc = False

    def visit(node: Any) -> None:
        nonlocal trunc
        if isinstance(node, dict):
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                key = f"{parts[2]}:{parts[3]}:{parts[4]}"
                spec = [parts[5], m.get("versionStartIncluding", ""), m.get("versionStartExcluding", ""),
                        m.get("versionEndIncluding", ""), m.get("versionEndExcluding", "")]
                lst = out.get(key)
                if lst is None:
                    if len(out) >= CPE_PAIR_CAP:
                        trunc = True
                        continue
                    lst = out[key] = []
                if spec in lst:
                    continue
                if len(lst) >= CPE_VERSION_CAP:
                    trunc = True
                    continue
                lst.append(spec)
            for ch in node.get("nodes", []) or []:
                visit(ch)
            for ch in node.get("children", []) or []:
                visit(ch)
        elif isinstance(node, list):
            for x in node:
                visit(x)

    visit(configurations or [])
    return out, trunc


def _affected(blocks: list) -> list[dict]:
    out = []
    for b in blocks or []:
        for a in b.get("affectedData", []) or []:
            vers = []
            for v in a.get("versions", []) or []:
                vers.append([str(v.get("version", "")), str(v.get("status", "")), str(v.get("lessThan", "")),
                             str(v.get("lessThanOrEqual", "")), str(v.get("versionType", ""))])
            item = {"v": str(a.get("vendor", "")), "p": str(a.get("product", "")), "ver": vers[:60],
                    "dflt": str(a.get("defaultStatus", ""))}
            if item not in out:
                out.append(item)
            if len(out) >= AFF_CAP:
                return out
    return out


def parse_nvd_file(args: tuple[str, frozenset]) -> dict:
    """Worker: compact records for one NVD yearly file."""
    path_s, want_refs = args
    path = Path(path_s)
    h = hashlib.sha256()
    recs = []
    iocs: set[str] = set()
    mentioned: set[str] = set()
    for w in _iter_nvd(path, h):
        c = w.get("cve") or {}
        cid = str(c.get("id", "")).upper()
        if not cid.startswith("CVE-"):
            continue
        desc = ""
        for d in c.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value") or ""
                break
        cwes = set()
        for wk in c.get("weaknesses", []) or []:
            for d in wk.get("description", []) or []:
                v = d.get("value", "")
                if v.startswith("CWE-"):
                    cwes.add(v)
        cpe, trunc = _cpe_entries(c.get("configurations") or [])
        rec = {"id": cid, "st": c.get("vulnStatus", ""), "pub": (c.get("published") or "")[:10], "desc": desc,
               "cwe": sorted(cwes), "cpe": cpe, "cpe_trunc": trunc, "aff": _affected(c.get("affected") or []),
               "tags": sorted({t for tg in c.get("cveTags", []) or [] for t in tg.get("tags", [])})}
        if cid in want_refs:
            rec["refs"] = [r.get("url", "") for r in c.get("references", []) or []]
        recs.append(rec)
        low = desc.lower()
        iocs.update(_IPV4.findall(desc))
        iocs.update(x.lower() for x in _HEX.findall(desc))
        iocs.update(_DOMAIN.findall(low))
        mentioned.update(m.upper() for m in _CVE_IN_TEXT.findall(desc.upper()))
    return {"file": path.name, "sha256": h.hexdigest(), "bytes": path.stat().st_size, "records": recs,
            "iocs": sorted(iocs), "mentioned": sorted(mentioned)}


@dataclass
class Universe:
    feeds_dir: Path
    nvd: dict[str, dict] = field(default_factory=dict)
    kev: dict[str, dict] = field(default_factory=dict)
    epss: set[str] = field(default_factory=set)
    corpus_iocs: set[str] = field(default_factory=set)
    mentioned_ids: set[str] = field(default_factory=set)
    inputs: list[dict] = field(default_factory=list)
    _cvelist_cache: dict[str, dict | None] = field(default_factory=dict)
    cvelist_reads: dict[str, str] = field(default_factory=dict)   # relative path -> sha256

    # ---------------------------------------------------------------- CVE List
    @property
    def cvelist_root(self) -> Path:
        return self.feeds_dir / "cvelistV5-live" / "cves"

    def cvelist_path(self, cid: str) -> Path:
        _, year, num = cid.split("-")
        return self.cvelist_root / year / f"{int(num) // 1000}xxx" / f"{cid}.json"

    def cvelist(self, cid: str) -> dict | None:
        if cid in self._cvelist_cache:
            return self._cvelist_cache[cid]
        p = self.cvelist_path(cid)
        out = None
        if p.is_file():
            raw = p.read_bytes()
            self.cvelist_reads[p.relative_to(self.cvelist_root).as_posix()] = hashlib.sha256(raw).hexdigest()
            d = json.loads(raw)
            meta = d.get("cveMetadata", {}) or {}
            cna = (d.get("containers", {}) or {}).get("cna", {}) or {}
            adps = (d.get("containers", {}) or {}).get("adp", []) or []
            desc = ""
            for x in cna.get("descriptions", []) or []:
                if str(x.get("lang", "")).startswith("en"):
                    desc = x.get("value") or ""
                    break
            reasons = " ".join(x.get("value", "") for x in cna.get("rejectedReasons", []) or [])
            refs = [{"url": r.get("url", ""), "name": r.get("name", "")} for r in cna.get("references", []) or []]
            for a in adps:
                refs += [{"url": r.get("url", ""), "name": r.get("name", "")} for r in a.get("references", []) or []]
            aff = []
            for blk in [cna] + list(adps):
                for a in blk.get("affected", []) or []:
                    vers = [[str(v.get("version", "")), str(v.get("status", "")), str(v.get("lessThan", "")),
                             str(v.get("lessThanOrEqual", "")), str(v.get("versionType", ""))]
                            for v in a.get("versions", []) or []]
                    aff.append({"v": str(a.get("vendor", "")), "p": str(a.get("product", "")), "ver": vers[:60],
                                "dflt": str(a.get("defaultStatus", ""))})
            out = {"state": meta.get("state", ""), "pub": (meta.get("datePublished") or "")[:10],
                   "title": cna.get("title") or "", "desc": desc, "rejected_reasons": reasons, "refs": refs,
                   "aff": aff[:AFF_CAP]}
        self._cvelist_cache[cid] = out
        return out

    # ---------------------------------------------------------------- queries
    def exists(self, cid: str) -> bool:
        return cid in self.nvd or cid in self.kev or cid in self.epss or self.cvelist(cid) is not None

    def is_rejected(self, cid: str) -> bool:
        r = self.nvd.get(cid)
        if r is not None and r["st"] == "Rejected":
            return True
        cl = self.cvelist(cid)
        return cl is not None and cl["state"] == "REJECTED"

    def searchable(self, cid: str) -> bool:
        """In the corpus, not rejected, with an English description (NVD, or the CVE List when NVD lacks it)."""
        if not self.exists(cid) or self.is_rejected(cid):
            return False
        return bool(self.description(cid))

    def description(self, cid: str) -> str:
        r = self.nvd.get(cid)
        if r is not None and r["desc"]:
            return r["desc"]
        cl = self.cvelist(cid)
        return cl["desc"] if cl else ""

    def published(self, cid: str) -> str:
        r = self.nvd.get(cid)
        if r is not None and r["pub"]:
            return r["pub"]
        cl = self.cvelist(cid)
        return cl["pub"] if cl else ""

    def corpus_text(self, cid: str) -> str:
        """Text a CVE document is indexed with: NVD and CVE List descriptions, CVE List title, KEV name."""
        parts = [self.description(cid)]
        cl = self.cvelist(cid)
        if cl:
            if cl["desc"] and cl["desc"] != parts[0]:
                parts.append(cl["desc"])
            if cl["title"]:
                parts.append(cl["title"])
        k = self.kev.get(cid)
        if k:
            parts.append(k["name"])
        return "\n".join(p for p in parts if p)


def load_universe(feeds_dir: Path, want_refs: set[str] | frozenset = frozenset(), workers: int = 6) -> Universe:
    feeds_dir = Path(feeds_dir)
    u = Universe(feeds_dir=feeds_dir)
    nvd_dir = feeds_dir / "nvd_cve_data"
    files = sorted(nvd_dir.glob("*.json"))
    if not files:
        raise FileNotFoundError(f"no NVD yearly files in {nvd_dir}")
    want = frozenset(want_refs)
    # largest first for load balance; results re-sorted below
    jobs = [(str(p), want) for p in sorted(files, key=lambda p: -p.stat().st_size)]
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(parse_nvd_file, jobs))
    else:
        results = [parse_nvd_file(j) for j in jobs]
    results.sort(key=lambda r: r["file"])
    for res in results:
        u.inputs.append({"name": f"nvd/{res['file']}", "sha256": res["sha256"], "bytes": res["bytes"],
                         "records": len(res["records"])})
        for rec in res["records"]:
            prev = u.nvd.get(rec["id"])
            if prev is None or (prev["st"] == "Rejected" and rec["st"] != "Rejected"):
                u.nvd[rec["id"]] = rec
        u.corpus_iocs.update(res["iocs"])
        u.mentioned_ids.update(res["mentioned"])
    kev_files = sorted(feeds_dir.glob("cisa_kev-*.csv"))
    if kev_files:
        kp = kev_files[-1]
        with open(kp, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                cid = (row.get("cveID") or "").strip().upper()
                if cid:
                    u.kev[cid] = {"name": row.get("vulnerabilityName", ""), "vendor": row.get("vendorProject", ""),
                                  "product": row.get("product", ""), "added": row.get("dateAdded", "")}
        u.inputs.append({"name": f"kev/{kp.name}", "sha256": sha256_file(kp), "bytes": kp.stat().st_size,
                         "records": len(u.kev)})
    epss_files = sorted(feeds_dir.glob("epss_scores-*.csv"))
    if epss_files:
        ep = epss_files[-1]
        with open(ep, encoding="utf-8") as f:
            for line in f:
                if line.startswith("CVE-"):
                    u.epss.add(line.split(",", 1)[0].strip().upper())
        u.inputs.append({"name": f"epss/{ep.name}", "sha256": sha256_file(ep), "bytes": ep.stat().st_size,
                         "records": len(u.epss)})
    return u


def cvelist_version(feeds_dir: Path) -> str | None:
    from .common import git_head
    return git_head(Path(feeds_dir) / "cvelistV5-live")


def scan_universe_ids(feeds_dir: Path) -> set[str]:
    """Fast ID-only scan of NVD + KEV + EPSS (used by the leakage tests; independent of the builder)."""
    ids: set[str] = set()
    pat = re.compile(rb'"id"\s*:\s*"(CVE-\d{4}-\d{4,})"')
    for p in sorted((Path(feeds_dir) / "nvd_cve_data").glob("*.json")):
        with open(p, "rb") as f:
            tail = b""
            for chunk in iter(lambda: f.read(1 << 24), b""):
                data = tail + chunk
                ids.update(m.decode() for m in pat.findall(data))
                tail = data[-64:]
    for p in sorted(Path(feeds_dir).glob("cisa_kev-*.csv"))[-1:]:
        with open(p, encoding="utf-8", newline="") as f:
            ids.update((r.get("cveID") or "").strip().upper() for r in csv.DictReader(f))
    for p in sorted(Path(feeds_dir).glob("epss_scores-*.csv"))[-1:]:
        with open(p, encoding="utf-8") as f:
            ids.update(line.split(",", 1)[0].strip().upper() for line in f if line.startswith("CVE-"))
    ids.discard("")
    return ids


def cvelist_file_exists(feeds_dir: Path, cid: str) -> bool:
    _, year, num = cid.split("-")
    return (Path(feeds_dir) / "cvelistV5-live" / "cves" / year / f"{int(num) // 1000}xxx" / f"{cid}.json").is_file()


def env_workers() -> int:
    try:
        return max(1, int(os.environ.get("B2_WORKERS", "6")))
    except ValueError:
        return 6
