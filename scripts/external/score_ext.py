"""Score the public-benchmark run. Two orders per question: served v2 (routes + fused) and fused search alone.
Ranked list is restricted to the benchmark's target kind (CVE or ATT&CK), as each benchmark's corpus holds only
candidates of that kind. Text2TTP is scored at top-level technique (sub-technique hits count for the parent, the
list is de-duplicated). Bootstrap 95% intervals over questions (10,000 resamples, seed 20261118)."""
import json, random, sys, collections, statistics

qf, outs, md = sys.argv[1], sys.argv[2:-1], sys.argv[-1]
Q = {json.loads(l)["qid"]: json.loads(l) for l in open(qf, encoding="utf-8")}
R = {}
for f in outs:
    for l in open(f, encoding="utf-8"):
        r = json.loads(l)
        R[r["qid"]] = r


def ranked(q, r, order):
    hits = r["hits"]
    if order == "fused":
        hits = sorted([h for h in hits if h[2]], key=lambda h: h[2])
    ids = [h[0] for h in hits]
    if q["target"] == "cve":
        ids = [d for d in ids if d.startswith("CVE-")]
    else:
        ids = [d for d in ids if d.startswith("attack:T")]
        if q["level"] == "top":
            ids = list(dict.fromkeys(d.split(".")[0] for d in ids))
    return ids


def per_q(q, ids):
    gold = set(q["gold_docs"])
    if q["level"] == "top":
        gold = {g.split(".")[0] for g in gold}
    ranks = [i + 1 for i, d in enumerate(ids) if d in gold]
    first = ranks[0] if ranks else None
    n = max(len(gold), 1)
    return {"hit1": float(bool(first and first <= 1)), "hit3": float(bool(first and first <= 3)),
            "hit5": float(bool(first and first <= 5)), "hit10": float(bool(first and first <= 10)),
            "mrr10": (1 / first if first and first <= 10 else 0.0),
            "recall3": len([x for x in ranks if x <= 3]) / n, "recall10": len([x for x in ranks if x <= 10]) / n}


def boot(v, B=10000, seed=20261118):
    rnd = random.Random(seed)
    n = len(v)
    m = sorted(sum(v[rnd.randrange(n)] for _ in range(n)) / n for _ in range(B))
    return statistics.fmean(v), m[int(0.025 * B)], m[int(0.975 * B) - 1]


groups = collections.defaultdict(list)
for qid, q in Q.items():
    b = q["bench"]
    groups[b].append(qid)
    if b.startswith("text2ttp"):
        groups["text2ttp_all"].append(qid)
missing = [q for q in Q if q not in R]
metrics = ["hit1", "hit3", "hit5", "hit10", "mrr10", "recall3", "recall10"]
res = {}
lines = ["# v2 on public cybersecurity retrieval benchmarks", "",
         f"Questions {len(Q)}, answered {len(Q) - len(missing)}. Values: mean [95% bootstrap interval]. "
         "Questions whose answer is not in our corpus count as misses.", ""]
for g in sorted(groups):
    qs = [q for q in groups[g] if q in R]
    lines += [f"## {g} (n={len(qs)}, answer not in corpus: {sum(not Q[q]['gold_docs'] for q in qs)}, "
              f"text found in our ATT&CK descriptions: {sum(bool(Q[q].get('leak')) for q in qs)})", "",
              "| order | " + " | ".join(metrics) + " |", "|---|" + "---|" * len(metrics)]
    for order in ("served", "fused"):
        rows = [per_q(Q[q], ranked(Q[q], R[q], order)) for q in qs]
        cell = {}
        for m in metrics:
            mean, lo, hi = boot([r[m] for r in rows])
            cell[m] = {"value": mean, "ci": [lo, hi]}
        res.setdefault(g, {})[order] = cell
        lines.append(f"| {order} | " + " | ".join(f"{cell[m]['value']:.3f} [{cell[m]['ci'][0]:.3f}, {cell[m]['ci'][1]:.3f}]" for m in metrics) + " |")
    lines.append("")
ms = [R[q]["ms"] for q in R]
lines.append(f"Retrieval time per question (12 parallel workers x 4 threads): p50 {statistics.median(ms):.0f} ms, "
             f"p95 {sorted(ms)[int(0.95 * len(ms))]:.0f} ms; skipped stages: "
             f"{collections.Counter(s for q in R for s in R[q]['skipped'])}")
open(md, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
json.dump(res, open(md.replace(".md", ".json"), "w"), indent=1)
print("\n".join(lines))
