"""Retrieval-quality edge cases with known correct answers.

Scores where the expected CVE lands in the results (hit@1/@5/@10, MRR) for
nicknames, plain-English descriptions, typos, near-miss IDs, vendor queries,
and checks that off-topic queries are NOT given high confidence.
Read-only: queries the API and reads SQLite in read-only mode.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=None, help="write all results to this JSON file")
ARGS = ap.parse_args()
OUT = {"q1": [], "summary": {}, "q2": [], "q4": []}
BASE = "http://127.0.0.1:8765"
DB = os.path.expanduser("~/data/sqlite/corpus_store.db")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)

# (category, query, expected CVE ids - any one counts as a hit)
CASES = [
    ("nickname", "Log4Shell", {"CVE-2021-44228"}),
    ("nickname", "Heartbleed OpenSSL", {"CVE-2014-0160"}),
    ("nickname", "EternalBlue SMBv1", {"CVE-2017-0144"}),
    ("nickname", "Shellshock bash", {"CVE-2014-6271", "CVE-2014-7169"}),
    ("nickname", "BlueKeep RDP", {"CVE-2019-0708"}),
    ("nickname", "Zerologon Netlogon", {"CVE-2020-1472"}),
    ("nickname", "PrintNightmare print spooler", {"CVE-2021-34527", "CVE-2021-1675"}),
    ("nickname", "ProxyLogon Exchange", {"CVE-2021-26855"}),
    ("nickname", "Follina MSDT", {"CVE-2022-30190"}),
    ("nickname", "Dirty COW", {"CVE-2016-5195"}),
    ("nickname", "Citrix Bleed", {"CVE-2023-4966"}),
    ("nickname", "regreSSHion OpenSSH", {"CVE-2024-6387"}),
    ("nickname", "xz utils backdoor", {"CVE-2024-3094"}),
    ("nickname", "Spring4Shell", {"CVE-2022-22965"}),
    ("description", "JNDI lookup in a Java logging library lets attackers load remote code via LDAP",
     {"CVE-2021-44228", "CVE-2021-45046"}),
    ("description", "TLS heartbeat extension bug leaks server memory contents", {"CVE-2014-0160"}),
    ("description", "bash processes trailing commands after function definitions in environment variables",
     {"CVE-2014-6271", "CVE-2014-7169"}),
    ("description", "race condition in the Linux kernel copy-on-write lets a local user write to read-only memory",
     {"CVE-2016-5195"}),
    ("description", "signal handler race condition in sshd allows unauthenticated remote code execution as root",
     {"CVE-2024-6387"}),
    ("description", "Word document uses the ms-msdt URL protocol to run PowerShell code", {"CVE-2022-30190"}),
    ("description", "MOVEit Transfer web application SQL injection exploited by Cl0p ransomware",
     {"CVE-2023-34362"}),
    ("typo", "log4shel remote code exectuion", {"CVE-2021-44228"}),
    ("typo", "heartbleeed open ssl", {"CVE-2014-0160"}),
    ("typo", "eternal blue smb exploit", {"CVE-2017-0144"}),
    ("vendor", "Fortinet FortiOS SSL-VPN heap overflow unauthenticated remote code execution",
     {"CVE-2022-42475", "CVE-2023-27997", "CVE-2024-21762"}),
    ("vendor", "Ivanti Connect Secure authentication bypass and command injection",
     {"CVE-2023-46805", "CVE-2024-21887"}),
    ("vendor", "Palo Alto PAN-OS GlobalProtect command injection", {"CVE-2024-3400"}),
    ("exact-id", "CVE-2021-45046", {"CVE-2021-45046"}),
    ("exact-id", "cve-2014-0160", {"CVE-2014-0160"}),
]

OFF_TOPIC = ["how to bake a chocolate cake", "weather in Gandhinagar today",
             "best football players of all time"]


def post(path, body, timeout=120.0):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, text = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        status, text = err.code, err.read().decode("utf-8", "replace")
    except Exception as err:
        status, text = -1, str(err)
    el = time.perf_counter() - start
    try:
        return status, json.loads(text), el
    except ValueError:
        return status, text, el


def doc_of(chunk_id):
    row = db.execute("select doc_id, source_org from corpus where chunk_id=?", (chunk_id,)).fetchone()
    return row if row else ("?", "?")


def cve_of(doc_id):
    m = CVE_RE.search(doc_id or "")
    return m.group(0).upper() if m else None


def in_corpus(cve):
    return db.execute("select count(*) from corpus where doc_id like ?", (cve + "%",)).fetchone()[0]


print("=== Q1: hybrid search, top 10 — where does the right CVE rank? ===")
rows = []
for cat, query, expected in CASES:
    present = {c: in_corpus(c) for c in expected}
    status, p, el = post("/api/v1/search/hybrid", {"query": query, "top_k": 10})
    ranked = []
    if status == 200 and isinstance(p, dict):
        for h in p.get("results", []):
            doc, src = doc_of(h["chunk_id"])
            ranked.append((cve_of(doc), src, doc))
    rank = next((i + 1 for i, (c, _, _) in enumerate(ranked) if c in expected), None)
    rows.append({"cat": cat, "query": query, "expected": sorted(expected), "rank": rank,
                 "in_corpus": sum(present.values()) > 0, "status": status})
    OUT["q1"].append({"category": cat, "query": query, "expected": sorted(expected), "rank": rank,
                      "in_corpus": sum(present.values()) > 0, "top10_doc_ids": [d for _, _, d in ranked],
                      "latency_s": round(el, 3), "http_status": status})
    top3 = [f"{c}({s})" for c, s, _ in ranked[:3]]
    flag = "HIT@1" if rank == 1 else (f"rank {rank}" if rank else ("MISS" if any(present.values()) else "NOT IN DATA"))
    print(f"  [{flag:<11}] {cat:<11} {query[:58]:<58} {el:5.1f}s top3={top3}", flush=True)

scored = [r for r in rows if r["in_corpus"] and r["status"] == 200]
for cat in ["all", "nickname", "description", "typo", "vendor", "exact-id"]:
    sub = scored if cat == "all" else [r for r in scored if r["cat"] == cat]
    if not sub:
        continue
    h1 = sum(1 for r in sub if r["rank"] == 1)
    h5 = sum(1 for r in sub if r["rank"] and r["rank"] <= 5)
    h10 = sum(1 for r in sub if r["rank"])
    mrr = sum(1 / r["rank"] for r in sub if r["rank"]) / len(sub)
    OUT["summary"][cat] = {"n": len(sub), "hit1": h1, "hit5": h5, "hit10": h10, "mrr": round(mrr, 4)}
    print(f"  {cat:<11} n={len(sub):<3} hit@1={h1}/{len(sub)}  hit@5={h5}/{len(sub)}  hit@10={h10}/{len(sub)}  MRR={mrr:.2f}")
skipped = [r["query"] for r in rows if not r["in_corpus"]]
if skipped:
    print(f"  (not scored — expected CVE not in the corpus: {skipped})")

print("\n=== Q2: full /threats/match — confidence tier, KEV and EPSS on the top hit ===")
for query, expect_cve in [("Log4Shell", "CVE-2021-44228"), ("CVE-2021-44228", "CVE-2021-44228"),
                          ("CVE-2017-0144", "CVE-2017-0144"), ("Heartbleed OpenSSL", "CVE-2014-0160"),
                          ("CVE-2021-44229", None)]:
    status, p, el = post("/api/v1/threats/match", {"query": query, "top_k": 5})
    if status != 200 or not isinstance(p, dict):
        print(f"  {query:<22} HTTP {status} {el:.1f}s {str(p)[:100]}")
        OUT["q2"].append({"query": query, "http_status": status, "latency_s": round(el, 3), "matches": []})
        continue
    OUT["q2"].append({"query": query, "http_status": status, "latency_s": round(el, 3),
                      "matches": [{"rank": m.get("rank"), "doc_id": doc_of(m["chunk_id"])[0],
                                   "confidence_tier": m.get("confidence_tier"), "match_type": m.get("match_type")}
                                  for m in p.get("top_matches", [])[:3]]})
    for m in p.get("top_matches", [])[:3]:
        doc, src = doc_of(m["chunk_id"])
        print(f"  {query:<22} #{m['rank']} {doc:<28} tier={m.get('confidence_tier'):<11} type={m.get('match_type'):<18} "
              f"kev={m.get('cisa_kev')!s:<5} epss={m.get('epss_score')} ({el:.1f}s)")

print("\n=== Q3: ground truth from the corpus for those CVEs (sources, KEV record present?) ===")
for cve in ["CVE-2021-44228", "CVE-2017-0144", "CVE-2014-0160"]:
    docs = [r[0] for r in db.execute("select distinct doc_id from corpus where doc_id like ?", (cve + "%",))]
    print(f"  {cve}: {docs}")

print("\n=== Q4: off-topic queries — should get LOW confidence, not STRONG/EXACT ===")
for q in OFF_TOPIC:
    status, p, el = post("/api/v1/threats/match", {"query": q, "top_k": 3})
    if status == 200 and isinstance(p, dict) and p.get("top_matches"):
        t = p["top_matches"][0]
        doc, _ = doc_of(t["chunk_id"])
        OUT["q4"].append({"query": q, "http_status": status, "latency_s": round(el, 3),
                          "tier": t.get("confidence_tier"), "composite_score": t.get("composite_score"), "top": doc})
        print(f"  {q:<40} tier={t.get('confidence_tier'):<11} score={t.get('composite_score'):.3f} top={doc} ({el:.1f}s)")
    else:
        OUT["q4"].append({"query": q, "http_status": status, "latency_s": round(el, 3)})
        print(f"  {q:<40} HTTP {status} {el:.1f}s {str(p)[:100]}")

if ARGS.out:
    with open(ARGS.out, "w") as fh:
        json.dump(OUT, fh, indent=2)
