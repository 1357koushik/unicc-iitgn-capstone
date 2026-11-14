"""Emerging Threats Open Suricata ruleset (role: query)."""
from __future__ import annotations

import re

from collect_common import Context, SourceSpec, http_download

BASE = "https://rules.emergingthreats.net/open/suricata-7.0.3/"
SPEC = SourceSpec(
    name="et_open_rules",
    role="query",
    urls=[BASE + "emerging-all.rules", BASE + "LICENSE"],
    license_name="BSD (sid 2000000-2799999) / GPLv2 (sid 1-3464, 100000000-100000908) per rule",
    license_url=BASE + "LICENSE",
    license_note=("Open rules are BSD-licensed (redistribution with copyright notice); some low-sid rules are "
                  "GPLv2. We store the file and derive only rule titles/CVE links as queries; do not "
                  "redistribute rule bodies without the LICENSE notice."),
    description="emerging-all.rules for Suricata 7.0.3; one record per rule carrying a CVE reference.",
)

_RULE_START = re.compile(r"^\s*(#\s*)?(alert|drop|reject|pass)\s", re.IGNORECASE)
_SID = re.compile(r"\bsid:\s*(\d+)\s*;")
_MSG = re.compile(r'\bmsg:\s*"((?:[^"\\]|\\.)*)"\s*;')
_CVE_REF = re.compile(r"\breference:\s*cve\s*,\s*([^;\s]+)\s*;", re.IGNORECASE)
_CLASS = re.compile(r"\bclasstype:\s*([^;\s]+)\s*;")


def parse_rule_line(line: str, cve_normalizer) -> dict | None:
    """Parse one Suricata rule line. Returns None unless it is a rule with >=1 valid CVE reference.

    `cve_normalizer(list)->list` drops malformed references. Commented-out rules get enabled=False.
    """
    m = _RULE_START.match(line)
    if not m:
        return None
    sid = _SID.search(line)
    if not sid:
        return None
    refs = []
    for r in _CVE_REF.findall(line):
        refs.append(r if r.upper().startswith("CVE") else "CVE-" + r)
    if not refs:
        return None
    cves = cve_normalizer(refs)
    if not cves:
        return None
    msg = _MSG.search(line)
    cls = _CLASS.search(line)
    return {
        "sid": int(sid.group(1)),
        "msg": (msg.group(1).replace('\\"', '"') if msg else ""),
        "cve_ids": cves,
        "classtype": cls.group(1) if cls else None,
        "enabled": m.group(1) is None,
    }


def collect(ctx: Context):
    info = http_download(BASE + "emerging-all.rules", ctx.raw_dir / "emerging-all.rules")
    http_download(BASE + "LICENSE", ctx.raw_dir / "LICENSE")
    ctx.upstream.update({"etag": info["etag"], "last_modified": info["last_modified"],
                         "ruleset": "suricata-7.0.3", "sha256": info["sha256"]})
    seen: dict[int, dict] = {}
    total = 0
    with open(ctx.raw_dir / "emerging-all.rules", encoding="utf-8", errors="replace") as f:
        for line in f:
            total += 1
            rec = parse_rule_line(line, ctx.cves)
            if rec:
                seen[rec["sid"]] = rec  # last one wins on duplicate sid
    ctx.extra["lines_scanned"] = total
    ctx.extra["disabled_rules_included"] = sum(1 for r in seen.values() if not r["enabled"])
    for sid in sorted(seen):
        yield seen[sid]
