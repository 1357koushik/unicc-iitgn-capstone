"""prep: resolve KEV texts, check gold presence and leakage.  run i n thr: retrieve shard i of n."""
import json, os, re, sys, time

mode = sys.argv[1]
D = os.path.expanduser(os.environ.get("EXT_DIR", "~/team2/ext"))


def norm(t):
    return re.sub(r"\s+", " ", (t or "").lower()).strip()


if mode == "prep":
    from threat_retrieval_engine.store import Store
    from threat_retrieval_engine.v2.system import _attack_store
    st = Store.open(None)
    atk = _attack_store(None)
    Q = [json.loads(l) for l in open(f"{D}/ext_queries.jsonl")]
    searchable = {r["doc_id"]: norm(r.get("description")) for r in atk.iter_searchable(columns=("doc_id", "description"))}
    blob = "\n".join(searchable.values())
    cves = sorted({g for q in Q for g in q["valid"] if g.startswith("CVE-")} | {q["cve"] for q in Q if q.get("cve")})
    desc, srch = {}, {}
    for i in range(0, len(cves), 500):
        p = cves[i:i + 500]
        for c, d, s in st._db.execute(
                f"SELECT cve_id, description, searchable FROM cve WHERE cve_id IN ({','.join('?' * len(p))})", p):
            desc[c], srch[c] = d, s
    stats = {"questions": len(Q), "gold_ids": 0, "gold_missing": 0, "gold_redirected": 0,
             "questions_no_gold_in_corpus": 0, "kev_no_text": 0, "leak": 0}
    with open(f"{D}/ext_queries_ready.jsonl", "w") as out:
        for q in Q:
            if q.get("cve"):
                q["text"] = desc.get(q["cve"])
                if not q["text"]:
                    stats["kev_no_text"] += 1
                    q["text"] = q["cve"]
            gold = []
            for g in q["valid"]:
                stats["gold_ids"] += 1
                if g.startswith("CVE-"):
                    if srch.get(g):
                        gold.append(g)
                    else:
                        stats["gold_missing"] += 1
                    continue
                r = atk.resolve_id(g)
                if r and r["doc_id"] in searchable:
                    gold.append(r["doc_id"])
                    stats["gold_redirected"] += bool(r.get("resolved_from"))
                else:
                    stats["gold_missing"] += 1
            q["gold_docs"] = sorted(set(gold))
            stats["questions_no_gold_in_corpus"] += not gold
            t = norm(q["text"])
            if len(t) > 40 and t[:150] in blob:
                q["leak"] = True
                stats["leak"] += 1
            out.write(json.dumps(q) + "\n")
    print(json.dumps(stats))
else:
    i, n, thr = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    from threat_retrieval_engine.v2.system import open_system
    r = open_system(rerank=False, torch_threads=thr)
    restrict = len(sys.argv) > 5 and sys.argv[5] == "kind"
    lex_s, den_s, cur = r.lexical.search, r.dense.search, {}
    if restrict:     # candidate search over the benchmark's target kind only (the corpus the benchmark defines)
        r.lexical.search = lambda text, k=100, kinds=None: lex_s(text, k=k, kinds=cur["kinds"])
        r.dense.search = lambda text, k=100, kinds=None, **kw: den_s(text, k=k, kinds=cur["kinds"], **kw)
    Q = [json.loads(l) for l in open(f"{D}/ext_queries_ready.jsonl")][i::n]
    tag = "kind" if restrict else "shard"
    with open(f"{D}/out/{tag}{i:02d}.jsonl", "w") as o:
        for q in Q:
            cur["kinds"] = (q["target"],)
            t0 = time.perf_counter()
            res = r.retrieve(q["text"], k=200)
            o.write(json.dumps({"qid": q["qid"], "ms": (time.perf_counter() - t0) * 1000, "skipped": res.skipped,
                                "hits": [[h.doc_id, h.route, h.fused_rank] for h in res.hits]}) + "\n")
    print("shard", i, "done", len(Q))
