# Load and latency results (work package B5)

Produced by `scripts/bench/run_load.sh <v1|v2> [levels]`. Statistics are the median of the repetitions
(`scripts/bench/summarize_load.py` prints the table; `scripts/bench/check_b5.sh` verifies the medians against the raw records).

## v1 demonstration run, 2026-11-14 (file `v1-20261114-192052.json`)

Frozen v1 (`~/threat_retrieval_engine`, port 8765), IITGN server (Intel Xeon Gold 6136, CPU only, shared with other users),
`scripts/bench/queries/latency_smoke.jsonl` (60 queries, run in the same order each time), 15 requests per repetition,
3 repetitions, 2 unrecorded warm-up requests per level, client timeout 60 s. Harness commit `repo-411ba11` plus the B5 changes.

| | concurrency 1 | concurrency 4 |
|---|---|---|
| latency p50 / p95 / p99 / max (HTTP 200) | 8334 / 11383 / 11945 / 12140 ms | no successful response |
| latency of all responses p50 / p95 | 8334 / 11383 ms | 15048 / 15066 ms (all were 504) |
| throughput, HTTP 200 per second | 0.113 | 0.000 |
| responses per second (any status) | 0.113 | 0.249 |
| HTTP 200 / 503 / 504 / other per repetition | 15 / 0 / 0 / 0 | 0 / 0 / 15 / 0 |
| transport errors, `Retry-After` seen | 0, 0 | 0, 0 |
| dominant stage `vector_database_ms` p50 / p95 | 8324 / 11340 ms | n/a (no 200 response, so no profile) |
| `scoring_ms` p50 / p95 | 3.9 / 5.2 ms | n/a |
| RSS peak / steady | 30348 / 27636 MB | 39968 / 30740 MB |
| load average (1 min) before -> after level | 2.8 -> 9.5 | 9.5 -> 75.7 |

Whole service: cold start 111.5 s to first healthy `/api/v1/health`, 122.1 s to first successful query. RSS before load 27269 MB, peak 40759 MB.

Reading the numbers:

- One request at a time takes 8 to 12 s; at 4 concurrent requests every request hit v1's 15 s deadline and returned 504 (15 of 15 in each repetition). v1 has no admission control: it never answers 503 and sends no `Retry-After`.
- v1 at concurrency 4 drove the server load average to about 76 on a 48-core machine, so this level disturbs other users; do not repeat it needlessly.
- Level 16 was not run for v1 (the brief allowed skipping it: at 15 s per request with all requests timing out, a 16-way level was not informative and would have added load); v2 must be run at 1, 4 and 16.
- The server is shared, so load averages are recorded before and after each level and each repetition (in the JSON).
- v1 has no build identifier in its health payload; the file records the harness repo commit as a note.
- A response cache in v2 will lower latency in repetitions 2 and 3 for the same queries; this is part of the v2 design, and per-repetition statistics are in the JSON for inspection.
