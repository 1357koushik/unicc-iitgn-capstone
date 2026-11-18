"""Technique route evaluation on the server.

    lists  i n thr      per question: technique ranking of every list (keyword + each encoder), top 100
    rerank i n thr R F  per question: reranker R scores for the first 20 techniques of fusion F (F: list names
                        joined by '+'), written with the fused order
Inputs in $EXT_DIR: tech_queries.jsonl ({qid, bench, text, gold_docs, ...}). Technique KB: $TRE_TECH_DIR/LATEST.
Gold IDs are resolved to active ATT&CK documents (revoked -> replacement); a question whose text contains a whole KB
entry (procedure example or description) is marked `kb_overlap`.
"""
import json
import os
import re
import sys
import time
from pathlib import Path

import numpy as np

D = Path(os.path.expanduser(os.environ.get("EXT_DIR", "~/team2/ext")))
TECH = Path(os.path.expanduser(os.environ.get("TRE_TECH_DIR", "~/team2/techniques/builds")))
ENCODERS = ["bge-large", "sentsecbert", "securebert2", "qwen3-emb"]
TOP = 100


def norm(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def setup():
    from threat_retrieval_engine.v2 import techniques as T
    build = TECH / (TECH / "LATEST").read_text().strip()
    rows = [json.loads(l) for l in open(build / "entries.jsonl", encoding="utf-8")]
    ents = [T.Entry(r["doc_id"], r["kind"], r["text"]) for r in rows]
    red = T._Reducer([e.doc_id for e in ents])
    return T, build, ents, red


def main():
    mode, i, n, thr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    import torch
    torch.set_num_threads(thr)
    T, build, ents, red = setup()
    Q = [json.loads(l) for l in open(D / "tech_queries.jsonl", encoding="utf-8")][i::n]
    out = open(D / "tech" / f"{mode}{'_' + sys.argv[5] if mode == 'rerank' else ''}{i:02d}.jsonl", "w")
    if mode == "lists":
        bm = T.BM25([e.text for e in ents])
        encs = {e: T.Encoder(e, threads=thr) for e in ENCODERS}
        embs = {e: np.load(build / f"emb_{e}.npy") for e in ENCODERS}
        kbn = [norm(e.text) for e in ents]
        long_kb = [(k, e.doc_id) for k, e in zip(kbn, ents) if len(k) > 40]
        for q in Q:
            rec = {"qid": q["qid"], "lists": {}, "ms": {}}
            t0 = time.perf_counter()
            s = bm.scores(q["text"])
            best = red.best(s)
            o = np.argsort(-best, kind="stable")[:TOP]
            rec["lists"]["keyword"] = [red.techs[j] for j in o if best[j] > 0]
            rec["ms"]["keyword"] = (time.perf_counter() - t0) * 1000
            for e in ENCODERS:
                t0 = time.perf_counter()
                best = red.best(embs[e] @ encs[e].query(q["text"]))
                rec["lists"][e] = [red.techs[j] for j in np.argsort(-best, kind="stable")[:TOP]]
                rec["ms"][e] = (time.perf_counter() - t0) * 1000
            qn = norm(q["text"])
            rec["kb_overlap"] = sorted({d for k, d in long_kb if k in qn or (len(qn) > 40 and qn in k)})
            out.write(json.dumps(rec) + "\n")
    else:
        rname, fusion = sys.argv[5], sys.argv[6].split("+")
        L = {}
        for f in sorted((D / "tech").glob("lists*.jsonl")):
            for l in open(f):
                r = json.loads(l)
                L[r["qid"]] = r
        rr = T.load_reranker(rname, threads=thr)
        dtext = {e.doc_id: e.text[:T.RERANK_CHARS] for e in ents if e.kind == "description"}
        for q in Q:
            lists = L[q["qid"]]["lists"]
            sc = {}
            for name in fusion:
                for r, d in enumerate(lists[name], 1):
                    sc[d] = sc.get(d, 0.0) + 1.0 / (T.RRF_K + r)
            fused = sorted(sc, key=lambda d: -sc[d])[:TOP]
            head = fused[:T.RERANK_DEPTH]
            t0 = time.perf_counter()
            s = rr.score(q["text"], [dtext.get(d, d) for d in head])
            out.write(json.dumps({"qid": q["qid"], "fused": fused, "head_scores": [float(x) for x in s],
                                  "ms": (time.perf_counter() - t0) * 1000}) + "\n")
    out.close()
    print("done", mode, i, len(Q), flush=True)


if __name__ == "__main__":
    main()
