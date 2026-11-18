"""Public benchmarks -> one query file. gold IDs: CVE-... or ATT&CK IDs (T1190, T1574.010)."""
import csv, json, re, sys, collections
B = sys.argv[1]; out = open(sys.argv[2], "w", encoding="utf-8", newline="\n")
n = collections.Counter()
def w(**r):
    out.write(json.dumps(r) + "\n"); n[r["bench"]] += 1
for task, path in (("wim", "entity_linking/wim.jsonl"), ("atd", "entity_linking/atd.jsonl"), ("ata", "entity_attribution/ata.jsonl")):
    for l in open(f"{B}/CTIConnect/data/{path}", encoding="utf-8"):
        d = json.loads(l); g = d["ground_truth"]
        if task == "wim":
            gold, valid = [g["target_id"]], g.get("valid_target_ids") or [g["target_id"]]
        elif task == "atd":
            gold = valid = [g["target_id"]]
        else:
            gold = valid = g["target_ids"]
        w(qid=d["id"], bench=f"cticonnect_{task}", target="cve" if task == "wim" else "attack", level="full",
          text=d["question"], gold=gold, valid=valid)
for i, r in enumerate(csv.DictReader(open(f"{B}/Text2TTP/data/sentences.sanitized.csv", encoding="utf-8"))):
    w(qid=f"t2t-{i:05d}", bench=f"text2ttp_{r['dataset']}", target="attack", level="top", text=r["clean"] or r["text"],
      gold=[r["top_tech_id"] or r["tech_id"].split(".")[0]], valid=[r["top_tech_id"] or r["tech_id"].split(".")[0]])
k = json.load(open(f"{B}/mappings-explorer/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json", encoding="utf-8"))
by = collections.defaultdict(list)
for m in k["mapping_objects"]:
    if m.get("attack_object_id"):
        by[m["capability_id"]].append(m["attack_object_id"])
for c, ts in sorted(by.items()):
    ts = list(dict.fromkeys(ts))
    w(qid=f"kev-{c}", bench="ctid_kev", target="attack", level="full", text=None, cve=c, gold=ts, valid=ts)
print(dict(n), sum(n.values()))
