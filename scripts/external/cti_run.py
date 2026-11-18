"""CTIConnect on its own corpus: candidates restricted to the benchmark's KB IDs (dense: exact mask; keyword: top
1000 then filter). run i n thr."""
import json, os, sys, time
import numpy as np
D = os.path.expanduser(os.environ.get("EXT_DIR", "~/team2/ext"))
i, n, thr = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
from threat_retrieval_engine.v2.system import open_system
r = open_system(rerank=False, torch_threads=thr)
C = json.load(open(f"{D}/cti_corpus.json"))
ix = r.dense.index
masks, allow = {}, {}
for kind, ids in C.items():
    m = np.zeros(ix.n_docs, dtype=bool)
    pos = [ix.position(d) for d in ids]
    m[[p for p in pos if p is not None]] = True
    masks[kind], allow[kind] = m, set(ids)
    print(kind, "corpus", len(ids), "in our index", int(m.sum()), flush=True)
lex_s, den_s, cur = r.lexical.search, r.dense.search, {}
def lex(text, k=100, kinds=None):
    res = lex_s(text, k=1000, kinds=(cur["kind"],))
    res.hits = [h for h in res.hits if h[0] in allow[cur["kind"]]][:k]
    return res
r.lexical.search = lex
r.dense.search = lambda text, k=100, kinds=None, **kw: den_s(text, k=k, kinds=(cur["kind"],), mask=masks[cur["kind"]])
Q = [json.loads(l) for l in open(f"{D}/ext_queries_ready.jsonl")]
Q = [q for q in Q if q["bench"].startswith("cticonnect")][i::n]
with open(f"{D}/out/cti{i:02d}.jsonl", "w") as o:
    for q in Q:
        cur["kind"] = q["target"]
        t0 = time.perf_counter()
        res = r.retrieve(q["text"], k=200)
        hits = [[h.doc_id, h.route, h.fused_rank] for h in res.hits if h.doc_id in allow[q["target"]]]
        o.write(json.dumps({"qid": q["qid"], "ms": (time.perf_counter() - t0) * 1000, "skipped": res.skipped, "hits": hits}) + "\n")
print("done", len(Q))
