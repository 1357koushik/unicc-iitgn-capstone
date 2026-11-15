# B6: v1 baseline on benchmark v2.0 (dev)

v1 (tag `v1-baseline`) served on the IITGN server, CPU only, port 8765, one request at a time, 30 s pause after
each error (see `benchmarks_v2/eval/server/B6_RUNBOOK.md`). Scored with the B4 harness, `--allow-unjudged`:
judgement round 1 has not run, so these reports are **provisional**. An unjudged document counts as no gain, and the
sensitivity table in each report shows the other extreme.

| Run | Queries | Errors | Latency p50 / p95 | macro nDCG@10 | overall S@1 |
|---|---|---|---|---|---|
| `/threats/match` (what Team 3 calls), dev | 1,489 | 1,351 (HTTP 504 at 15 s) | 15.0 s / 15.1 s | 0.040 | 0.035 |
| `/search/hybrid` (retrieval only), dev | 1,489 | 0 | 3.9 s / 5.8 s | 0.277 | see report |

Main findings:

- `/threats/match` times out on 91% of queries, so its quality on the benchmark is close to zero; this is the
  number v2 replaces in production.
- Even `/search/hybrid`, which always answers, ranks the queried CVE first for only 1.3% of exact CVE-ID queries
  (T1 S@1 0.013) and finds no ATT&CK object (T9 = 0; v1 has none).
- The train run of `/search/hybrid` is kept for reference; v1 is compared with v2 on dev here and on the sealed test
  in E1.

Files: `runs/*.jsonl` (run files with `.meta.json` sidecars, copied from `~/team2/eval/runs` on the server),
`v1_hybrid-dev-20261116.md`, `v1_hybrid-train-20261116.md`, and `v1_match-dev-vs-hybrid-20261116.md` (all v1_match
metrics plus the paired comparison against v1_hybrid).
