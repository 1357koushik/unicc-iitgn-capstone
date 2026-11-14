"""B1 acceptance check: prints PASS/FAIL per item, exit 1 if any FAIL.

    python scripts/collect/check_b1.py [--root DIR]   (--out is an alias)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_all import SOURCES  # noqa: E402
from collect_common import ROLES, default_out_dir  # noqa: E402

REQUIRED = ["source", "role", "status", "upstream_urls", "upstream_version", "retrieved_at_utc", "license",
            "record_count", "records_sha256", "collector_version", "malformed_cve_ids_dropped"]
EXPECTED_ROLE = {"ghsa_reviewed": "query", "et_open_rules": "query", "sigma_rules": "query",
                 "cisa_advisories": "incident", "acsc_advisories": "incident",
                 "ncsc_uk_advisories": "incident", "exploitdb": "expansion", "metasploit_modules": "expansion",
                 "nuclei_templates": "expansion", "poc_in_github": "expansion",
                 "attack_enterprise": "attack", "kev_attack_mappings": "attack"}
fails = 0


def report(ok: bool, label: str, detail: str = "") -> None:
    global fails
    fails += (not ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def check_source(out: Path, name: str, roles_seen: dict[str, str]) -> None:
    sdir = out / name
    latest = sdir / "LATEST"
    if not latest.exists():
        report(False, f"{name}: LATEST present", "source never collected")
        return
    day = latest.read_text().strip()
    d = sdir / day
    mp = d / "manifest.json"
    if not mp.exists():
        report(False, f"{name}: manifest.json present", str(mp))
        return
    m = json.loads(mp.read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED if k not in m]
    report(not missing, f"{name}: manifest has all fields", f"missing {missing}" if missing else f"date {day}")
    report(m.get("source") == name, f"{name}: manifest source name matches")
    role = m.get("role")
    report(role in ROLES and role == EXPECTED_ROLE[name], f"{name}: role valid", f"role={role}")
    roles_seen.setdefault(name, role)
    lic = m.get("license") or {}
    report(all(lic.get(k) for k in ("name", "url", "permits")), f"{name}: licence name/url/permits filled")
    report(bool(m.get("retrieved_at_utc")) and bool(m.get("upstream_urls")), f"{name}: retrieval time and URLs filled")
    status = m.get("status")
    if status in ("unavailable", "licence_blocked"):
        report(bool(m.get("reason")), f"{name}: status {status} has a reason", m.get("reason") or "")
        return
    report(status == "ok", f"{name}: status ok", f"status={status}")
    uv = m.get("upstream_version") or {}
    report(any(uv.get(k) for k in ("commit", "etag", "last_modified", "sha256")), f"{name}: upstream version recorded",
           json.dumps({k: uv.get(k) for k in ("commit", "etag") if uv.get(k)}))
    rp = d / "records.jsonl"
    if not rp.exists():
        report(False, f"{name}: records.jsonl present")
        return
    n = 0
    try:
        with open(rp, encoding="utf-8") as f:
            for line in f:
                json.loads(line)
                n += 1
        report(True, f"{name}: records.jsonl parses", f"{n} lines")
    except Exception as e:
        report(False, f"{name}: records.jsonl parses", str(e)[:100])
    report(n == m.get("record_count") and n > 0, f"{name}: record count matches manifest", f"{n} vs {m.get('record_count')}")
    report(sha(rp) == m.get("records_sha256"), f"{name}: records sha256 matches manifest")
    if name in WEB_INCIDENT:
        check_web_incident(name, d, m)
    report(isinstance(m.get("malformed_cve_ids_dropped"), int), f"{name}: malformed CVE count recorded",
           str(m.get("malformed_cve_ids_dropped")))


WEB_INCIDENT = ("acsc_advisories", "ncsc_uk_advisories")


def check_web_incident(name: str, d: Path, m: dict) -> None:
    """B1b: national-CERT advisory collectors record robots.txt, licence verification, rule and enumeration."""
    ex = m.get("extra") or {}
    rb = ex.get("robots_txt") or {}
    report(bool(rb.get("url")) and rb.get("http_status") in (200, 404), f"{name}: robots.txt result recorded",
           f"status {rb.get('http_status')}: {rb.get('result')}")
    lv = ex.get("licence_verified") or {}
    report(bool(lv.get("page")) and bool(lv.get("statement")), f"{name}: licence verification page recorded", lv.get("page", ""))
    report(bool(ex.get("keep_rule")) and bool(ex.get("enumeration")), f"{name}: keep rule and enumeration method recorded",
           (ex.get("enumeration") or "")[:90])
    n = with_cve = bad = fffd = 0
    cves: set[str] = set()
    dates = []
    with open(d / "records.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            n += 1
            fffd += any("\ufffd" in str(v) for v in r.values())
            ok = all(r.get(k) for k in ("url", "title", "text", "advisory_id", "keep_reason", "published"))
            ok = ok and r["keep_reason"] in ("cve", "actor", "cve+actor") and bool(r["cve_ids"]) == ("cve" in r["keep_reason"])
            ok = ok and all(re.fullmatch(r"CVE-\d{4}-\d{4,}", c) for c in r["cve_ids"])
            bad += (not ok)
            if r["cve_ids"]:
                with_cve += 1
                cves.update(r["cve_ids"])
            dates.append(r.get("published", ""))
    report(bad == 0, f"{name}: every record has url/title/date/text/keep_reason and consistent CVE ids",
           f"{bad} bad of {n}")
    report(fffd == 0, f"{name}: no U+FFFD replacement characters in any record", f"{fffd} records affected")
    report(n > 0 and with_cve > 0 and dates == sorted(dates, reverse=True), f"{name}: newest first, CVE-bearing records exist",
           f"{n} records, {with_cve} with CVE, {len(cves)} distinct CVEs")


def check_tests() -> None:
    root = Path(__file__).resolve().parents[2]
    p = subprocess.run([sys.executable, "-m", "pytest", "tests/test_collectors.py", "-q"], cwd=root,
                       capture_output=True, text=True)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    report(p.returncode == 0, "unit tests (tests/test_collectors.py)", last)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", "--out", dest="out", type=Path, default=default_out_dir(),
                    help="sources directory holding <source>/LATEST (default data/sources)")
    ap.add_argument("--skip-tests", action="store_true")
    a = ap.parse_args()
    roles: dict[str, str] = {}
    for name in SOURCES:
        check_source(a.out, name, roles)
    report(len(roles) == len(set(SOURCES)) and all(r in ROLES for r in roles.values()),
           "every source has exactly one valid role", f"{len(roles)} sources, roles {sorted(set(roles.values()))}")
    gi = Path(__file__).resolve().parents[2] / ".gitignore"
    report(bool(re.search(r"^data/sources/\s*$", gi.read_text(encoding="utf-8"), re.M)), "data/sources/ is gitignored")
    if not a.skip_tests:
        check_tests()
    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
