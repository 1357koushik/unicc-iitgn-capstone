"""Score technique rankings: every fusion of the lists (from `tech_eval.py lists`) and reranked runs.

    python score_tech.py <tech_queries.jsonl> <cti_corpus.json> <tech dir> <out.md> [--select dev]

Metrics per question set (the benchmark's own): Text2TTP Recall@10 at top-level technique, CTID KEV Hits@10 and
MRR@10, CTIConnect Hit@5 over the benchmark's own ATT&CK corpus, dev (our benchmark) Recall@10, MRR@10, Hit@1.
Model choices are made on dev only (56 dev questions whose answers are ATT&CK techniques); the public sets are
reported for the chosen setting.
"""
import itertools
import json
import random
import statistics
import sys
from pathlib import Path

RRF_K = 60.0
LISTS = ["keyword", "bge-large", "sentsecbert", "securebert2", "qwen3-emb"]


def load(qf, corpus_f, tdir):
    Q = {json.loads(l)["qid"]: json.loads(l) for l in open(qf, encoding="utf-8")}
    cti = set(json.load(open(corpus_f))["attack"])
    L = {}
    for f in sorted(Path(tdir).glob("lists[0-9]*.jsonl")):
        for l in open(f):
            r = json.loads(l)
            L[r["qid"]] = r
    R = {}
    for f in sorted(Path(tdir).glob("rerank_*.jsonl")):
        name = f.stem.split("_", 1)[1][:-2]
        for l in open(f):
            r = json.loads(l)
            R.setdefault(name, {})[r["qid"]] = r
    return Q, cti, L, R


def group(q):
    b = q["bench"]
    return "text2ttp" if b.startswith("text2ttp") else ("dev" if b.startswith("dev_") else b)


def fuse(lists, names):
    sc = {}
    for n in names:
        for r, d in enumerate(lists[n], 1):
            sc[d] = sc.get(d, 0.0) + 1.0 / (RRF_K + r)
    return sorted(sc, key=lambda d: -sc[d])


def view(q, ranked, cti):
    g = group(q)
    if g == "text2ttp":
        return list(dict.fromkeys(d.split(".")[0] for d in ranked)), {x.split(".")[0] for x in q["gold_docs"]}
    if g.startswith("cticonnect"):
        return [d for d in ranked if d in cti], set(q["gold_docs"])
    return ranked, set(q["gold_docs"])


def metrics(q, ranked, cti):
    ids, gold = view(q, ranked, cti)
    hits = [i + 1 for i, d in enumerate(ids) if d in gold]
    f = hits[0] if hits else None
    return {"hit1": float(bool(f and f <= 1)), "hit5": float(bool(f and f <= 5)), "hit10": float(bool(f and f <= 10)),
            "mrr10": 1 / f if f and f <= 10 else 0.0,
            "recall10": len([h for h in hits if h <= 10]) / max(len(gold), 1)}


MAIN = {"dev": ["recall10", "mrr10", "hit1"], "text2ttp": ["recall10"], "ctid_kev": ["hit10", "mrr10"],
        "cticonnect_atd": ["hit5"], "cticonnect_ata": ["hit5"]}


def table(Q, cti, ranked_by_q, qids):
    out = {}
    for g in MAIN:
        qs = [q for q in qids if group(Q[q]) == g and q in ranked_by_q]
        if not qs:
            continue
        rows = [metrics(Q[q], ranked_by_q[q], cti) for q in qs]
        out[g] = {m: statistics.fmean(r[m] for r in rows) for m in MAIN[g]}
        out[g]["n"] = len(qs)
    return out


def ci(Q, cti, ranked_by_q, g, m, B=10000, seed=20261118):
    qs = [q for q in ranked_by_q if group(Q[q]) == g]
    v = [metrics(Q[q], ranked_by_q[q], cti)[m] for q in qs]
    rnd = random.Random(seed)
    s = sorted(sum(v[rnd.randrange(len(v))] for _ in v) / len(v) for _ in range(B))
    return s[int(0.025 * B)], s[int(0.975 * B) - 1]


def main():
    qf, corpus_f, tdir, md = sys.argv[1:5]
    Q, cti, L, R = load(qf, corpus_f, tdir)
    qids = [q for q in Q if q in L]
    lines = ["# Technique route: list fusions and rerankers", "",
             f"Questions with rankings: {len(qids)} of {len(Q)}. Choice made on dev only.", "",
             "## Fusions (no reranker)", "", "| lists | dev R@10 | dev MRR | dev Hit@1 | Text2TTP R@10 | KEV Hits@10 |"
             " KEV MRR | CTIC ATD Hit@5 | CTIC ATA Hit@5 |", "|---|---|---|---|---|---|---|---|---|"]
    res = {}
    for k in range(1, len(LISTS) + 1):
        for combo in itertools.combinations(LISTS, k):
            rk = {q: fuse(L[q]["lists"], combo) for q in qids}
            t = table(Q, cti, rk, qids)
            res["+".join(combo)] = t
            lines.append("| " + "+".join(combo) + " | " + " | ".join(
                f"{t.get(g, {}).get(m, float('nan')):.3f}" for g, m in
                [("dev", "recall10"), ("dev", "mrr10"), ("dev", "hit1"), ("text2ttp", "recall10"),
                 ("ctid_kev", "hit10"), ("ctid_kev", "mrr10"), ("cticonnect_atd", "hit5"),
                 ("cticonnect_ata", "hit5")]) + " |")
    best = max(res, key=lambda c: (round(res[c]["dev"]["recall10"], 3), round(res[c]["dev"]["mrr10"], 3),
                                   -c.count("+")))
    lines += ["", f"Best fusion on dev (Recall@10, then MRR, then fewer lists): **{best}**", ""]
    if R:
        lines += ["## Rerankers on the first 20 of a fusion", "",
                  "| reranker | fusion | dev R@10 | dev MRR | dev Hit@1 | Text2TTP R@10 | KEV Hits@10 | KEV MRR |"
                  " CTIC ATD Hit@5 | CTIC ATA Hit@5 | ms/question p50 |", "|---|---|---|---|---|---|---|---|---|---|---|"]
        for name, runs in sorted(R.items()):
            rk = {}
            for q, r in runs.items():
                head = r["fused"][:len(r["head_scores"])]
                order = [d for _, d in sorted(zip(r["head_scores"], head), key=lambda x: -x[0])]
                rk[q] = order + r["fused"][len(head):]
            t = table(Q, cti, rk, list(runs))
            res["rerank:" + name] = t
            ms = statistics.median(r["ms"] for r in runs.values())
            fusion_name = name.split("@", 1)[1] if "@" in name else ""
            lines.append(f"| {name.split('@')[0]} | {fusion_name} | " + " | ".join(
                f"{t.get(g, {}).get(m, float('nan')):.3f}" for g, m in
                [("dev", "recall10"), ("dev", "mrr10"), ("dev", "hit1"), ("text2ttp", "recall10"),
                 ("ctid_kev", "hit10"), ("ctid_kev", "mrr10"), ("cticonnect_atd", "hit5"),
                 ("cticonnect_ata", "hit5")]) + f" | {ms:.0f} |")
    overlap = sum(bool(L[q].get("kb_overlap")) for q in qids if group(Q[q]) == "text2ttp")
    lines += ["", f"Text2TTP questions whose text contains a whole knowledge-base entry: {overlap}"]
    Path(md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    json.dump(res, open(Path(md).with_suffix(".json"), "w"), indent=1)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
