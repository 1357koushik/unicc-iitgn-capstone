"""Re-order v2_full run files offline with a blend of the pre-rerank order and the reranker's order.

    python scripts/v2/blend_sim.py <run.jsonl> <features.jsonl> <queries.jsonl> <alpha> <out.jsonl>

Inside the reranked head (the results that carry a rerank logit), each result scores
    1 / (K + pre_position) + alpha / (K + rerank_position)
where pre_position is its place in the candidate list the reranker received (route candidates first, then the
fused order) and rerank_position its place by logit. alpha = inf is the reranker's order alone (what v2_full
ran), alpha = 0 the order without reranking. Results outside the head and identifier (EXACT) results keep
their place. The output is a run file in the harness format, so the harness scores it like any run.
"""
import json
import math
import sys

K = 2.0


def blend(head, alpha):
    pre = sorted(head, key=lambda h: (h["route"] == "fused", h["fused_rank"] if h["fused_rank"] else 10**6))
    rr = sorted(head, key=lambda h: -h["rerank_logit"])
    pp = {h["doc_id"]: i + 1 for i, h in enumerate(pre)}
    rp = {h["doc_id"]: i + 1 for i, h in enumerate(rr)}
    if math.isinf(alpha):
        return [h["doc_id"] for h in rr]
    sc = {d: 1 / (K + pp[d]) + alpha / (K + rp[d]) for d in pp}
    return sorted(sc, key=lambda d: (-sc[d], pp[d]))


def main():
    run_p, feat_p, q_p, alpha, out_p = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
    text2qid = {}
    for l in open(q_p, encoding="utf-8"):
        q = json.loads(l)
        text2qid.setdefault(q["text"], q["qid"])
    feats = {}
    for l in open(feat_p, encoding="utf-8"):
        r = json.loads(l)
        if r["query"] in text2qid:
            feats[text2qid[r["query"]]] = r
    with open(out_p, "w", encoding="utf-8") as o:
        for l in open(run_p, encoding="utf-8"):
            r = json.loads(l)
            f = feats.get(r["qid"])
            if f:
                hits = f["hits"]
                head = [h for h in hits if h["rerank_logit"] is not None]
                if head:
                    ids = [x["doc_id"] for x in r["ranked"]]
                    pos = sorted(ids.index(h["doc_id"]) for h in head if h["doc_id"] in ids)
                    order = blend([h for h in head if h["doc_id"] in ids], alpha)
                    ranked = list(r["ranked"])
                    by = {x["doc_id"]: x for x in ranked}
                    for p_, d in zip(pos, order):
                        ranked[p_] = by[d]
                    n = len(ranked)
                    r["ranked"] = [dict(x, score=float(n - i)) for i, x in enumerate(ranked)]
            o.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
