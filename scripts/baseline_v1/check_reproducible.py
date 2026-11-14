"""Acceptance check: both baseline runs have identical ranks and match plan section 2.2.

Usage: python check_reproducible.py [results/baseline_v1]
"""
import json
import sys
from pathlib import Path

d = Path(sys.argv[1] if len(sys.argv) > 1 else "results/baseline_v1")
r1 = json.loads((d / "quality_run1.json").read_text())
r2 = json.loads((d / "quality_run2.json").read_text())
ok = True


def key(r):
    return {x["query"]: x for x in r["q1"]}


a, b = key(r1), key(r2)
if set(a) != set(b):
    print("FAIL: query sets differ")
    ok = False
for q in a:
    if q in b and a[q]["rank"] != b[q]["rank"]:
        print(f"FAIL: rank differs for {q!r}: run1={a[q]['rank']} run2={b[q]['rank']}")
        ok = False

for name, r in (("run1", r1), ("run2", r2)):
    s = r["summary"]["all"]
    good = s["hit1"] == 11 and s["hit10"] == 19 and abs(s["mrr"] - 0.47) < 0.005
    print(f"{name}: n={s['n']} hit@1={s['hit1']} hit@10={s['hit10']} MRR={s['mrr']} vs plan 11/19/0.47 -> {'ok' if good else 'MISMATCH'}")
    ok = ok and good

# informational: do the top-10 lists match exactly?
diff10 = [q for q in a if q in b and a[q]["top10_doc_ids"] != b[q]["top10_doc_ids"]]
print(f"queries whose full top-10 differ between runs (informational): {len(diff10)}")
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
