"""Call POST /api/v1/threats/match for 10 fixed queries x 3 reps; record pipeline_profile and top 5."""
import argparse
import json
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8765"
QUERIES = [
    "Palo Alto PAN-OS GlobalProtect command injection", "Log4Shell",
    "Heartbleed OpenSSL", "Fortinet FortiOS SSL-VPN heap overflow", "Citrix Bleed",
    "CVE-2014-0160", "CVE-2021-44228", "CVE-2017-0144", "CVE-2024-3400", "CVE-2021-45046",
]
REPS = 3

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
args = ap.parse_args()

calls = []
for q in QUERIES:
    for rep in range(1, REPS + 1):
        req = urllib.request.Request(BASE + "/api/v1/threats/match",
                                     data=json.dumps({"query": q, "top_k": 5}).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                status, text = r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            status, text = -1, str(e)
        el = time.perf_counter() - t0
        try:
            body = json.loads(text)
        except ValueError:
            body = None
        top, prof = [], None
        if isinstance(body, dict):
            prof = body.get("pipeline_profile")
            for m in (body.get("top_matches") or [])[:5]:
                top.append({"doc_id": m.get("doc_id") or m.get("chunk_id"),
                            "confidence_tier": m.get("confidence_tier"),
                            "composite_score": m.get("composite_score")})
        calls.append({"query": q, "rep": rep, "http_status": status, "latency_s": round(el, 3),
                      "pipeline_profile": prof, "top5": top})
        print(f"{q[:50]:<50} rep{rep} HTTP {status} {el:.1f}s", flush=True)

with open(args.out, "w") as fh:
    json.dump({"calls": calls}, fh, indent=2)
