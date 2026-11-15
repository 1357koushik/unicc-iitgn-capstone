# B6 runbook: v1 baseline on the server

Runs `v1_match` then `v1_hybrid` over the train and dev splits of benchmark v2.0 (920 + 1,489 = 2,409 queries
each). The test split is not on the server and must not be copied. Concurrency 1, `--pause-after-error 30`,
CPU only, one `server_lock.sh` acquisition, v1 service stopped at the end.

Server paths (all under `~/team2`, nothing under `~/data`):

| What | Path |
|---|---|
| Open benchmark files | `~/team2/benchmark/v2.0/` |
| Run files | `~/team2/eval/runs/{v1_match,v1_hybrid}-{train,dev}.jsonl` (+ `.meta.json`) |
| Job log | `~/team2/eval/out/b6.log` (exit code in `b6.exit` when the job has ended) |
| v1 service log | `~/team2/run/eval-v1.log` |

SSH shorthand: `S="ssh -o BatchMode=yes -p 2022 koushik.moram@10.0.62.212"` (post-quantum warnings can be ignored).

## Check progress

```bash
$S 'tail -5 ~/team2/eval/out/b6.log; cat ~/team2/run/bench.lock.info; cat ~/team2/eval/out/b6.exit 2>/dev/null'
$S 'cd ~/team2/eval/runs && wc -l *.jsonl'          # lines = queries recorded (errors included)
$S 'tail -1 ~/team2/eval/runs/v1_match-train.jsonl'  # latest record
$S 'grep -c "\"error\": *\"" ~/team2/eval/runs/v1_match-train.jsonl'   # rough error count
$S 'pgrep -af "benchmarks_v2.eval|uvicorn|b6_server"'
```

A run file is complete when its line count equals the split size (train 920, dev 1,489); the job log then says
`[run] complete` for it. `b6.exit` containing `0` means all four runs of the job finished.

## Resume after an interruption

Run files are append-only and resumable; queries already recorded are skipped. After a portal login, reboot or
killed process:

1. Check nothing is still running: `$S 'pgrep -af "benchmarks_v2.eval|uvicorn|b6_server"; ss -ltn | grep 876[56]'`.
   If the job is alive, do nothing. If a stray `uvicorn` on 8765 is left behind, stop it
   (`$S 'kill $(cat ~/team2/run/eval-v1.pid)'`); the launcher refuses to start while 8765 or 8766 is occupied.
2. Restart from the repository on the PC (Git Bash), with the open benchmark files path:
   `B6_BENCH_DIR="D:/Project Course/unicc-iitgn-capstone/data/benchmark/v2.0" benchmarks_v2/eval/server/b6_start.sh`
   This re-copies the harness and open files (never `sealed/`) and starts the same job detached. Finished run
   files are skipped quickly; the unfinished one continues.
3. If the network (portal login) was the cause, log in to the portal first so the PC can reach the server. The
   job itself needs no network; it runs entirely on the server.
4. After a reboot the server loses the nohup job but not the run files; step 2 is the same. A stale
   `bench.lock.info` is removed by `server_lock.sh` when the lock is released; if the lock holder is dead the
   lock is free automatically (flock).

## Copy run files back

```bash
mkdir -p results/eval/runs
scp -P 2022 'koushik.moram@10.0.62.212:team2/eval/runs/*' results/eval/runs/
```

Copy only after the job ended (`b6.exit` present). Partial copies are fine for a look but not for scoring.

## Part 2: score commands

Run from the repository root, with the open v2.0 data in `data/benchmark/v2.0`. Judging round 1 has not happened
yet, so unjudged top-10 documents are expected: `--allow-unjudged`. Reports go to `results/eval/`.

```bash
D=data/benchmark/v2.0
for V in v1_match v1_hybrid; do
  for S in train dev; do
    python -m benchmarks_v2.eval score --run results/eval/runs/$V-$S.jsonl --dataset $D --split $S \
      --allow-unjudged --out-dir results/eval
  done
done

# paired comparison on dev: v1_match (this) against v1_hybrid (reference), this - reference
python -m benchmarks_v2.eval score --run results/eval/runs/v1_match-dev.jsonl --dataset $D --split dev \
  --compare results/eval/runs/v1_hybrid-dev.jsonl --allow-unjudged --out-dir results/eval
```

If `score` is unhappy about a flag, `python -m benchmarks_v2.eval score --help` lists them
(`--allow-incomplete` only for a run that is knowingly partial). Errors (504, timeouts) are recorded as misses
by design; that is the true v1 result.


## Run order (coordinator decision, 2026-11-15)

v1 `/threats/match` times out (HTTP 504 at 15 s) on most queries, and the harness waits 30 s after each error so that work v1 abandons after a timeout cannot slow the next query (the pause is kept: removing it would bias v1 downwards). Running every variant on train and dev would take about 28 hours. v1 is only compared on dev (and on test in E1); the train split is only used to fit v2. The default order is therefore:

1. `v1_hybrid` train, 2. `v1_hybrid` dev, 3. `v1_match` dev.

`v1_match` train is not run. The 25 `v1_match-train` records from the first start are kept but not used. Override with `B6_RUNS="variant:split ..."`.

Note: the process to stop is the `b6_server.sh` process (check with `ps -u $USER -o pid,ppid,cmd | grep b6_server`), not the nohup wrapper PID printed at start.
