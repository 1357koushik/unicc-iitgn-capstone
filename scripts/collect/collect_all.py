"""Run the B1 source collectors.

    python scripts/collect/collect_all.py [--only a,b] [--out DIR] [--date YYYY-MM-DD]

Layout: <out>/<source>/<date>/{raw/, records.jsonl, manifest.json} and <out>/<source>/LATEST.
Exit status 0 when every selected source is ok or recorded as unavailable/licence_blocked,
non-zero when any collector failed hard (network or parse error); other sources still run.
"""
from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_common import CollectError, default_out_dir, run_source  # noqa: E402

SOURCES = [
    "ghsa_reviewed", "et_open_rules", "sigma_rules", "cisa_advisories", "acsc_advisories",
    "ncsc_uk_advisories", "exploitdb",
    "metasploit_modules", "nuclei_templates", "poc_in_github", "attack_enterprise", "kev_attack_mappings",
    "cwe_catalog",
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated source names")
    ap.add_argument("--out", type=Path, default=default_out_dir(), help="output root (default data/sources)")
    ap.add_argument("--date", help="override the UTC date directory (testing)")
    args = ap.parse_args(argv)
    names = SOURCES
    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
        bad = [n for n in names if n not in SOURCES]
        if bad:
            ap.error(f"unknown source(s) {bad}; choose from {SOURCES}")
    args.out.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    for name in names:
        print(f"=== {name}", flush=True)
        try:
            m = run_source(importlib.import_module(name), args.out, args.date)
            print(f"    {m['status']}: {m['record_count']} records, "
                  f"{m['malformed_cve_ids_dropped']} malformed CVE ids dropped", flush=True)
        except CollectError as e:
            print(f"    FAILED: {e}", file=sys.stderr, flush=True)
            failures.append(name)
        except Exception:
            traceback.print_exc()
            print(f"    FAILED: unexpected error in {name}", file=sys.stderr, flush=True)
            failures.append(name)
    if failures:
        print(f"\nFAILED sources: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
