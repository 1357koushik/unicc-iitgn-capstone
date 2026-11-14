#!/usr/bin/env bash
# Exclusive-use lock for benchmark runs on the server (work package B5).
# Usage (on the server):   server_lock.sh <command...>
# Takes flock on ~/team2/run/bench.lock, waits if another benchmark holds it (message every
# 60 s), runs the command, releases the lock when the command ends. Exit code is the command's.
# The lock file descriptor is closed for the child, so a daemon started by the command
# cannot keep the lock after this script exits.
set -u
[ $# -ge 1 ] || { echo "usage: $0 <command...>" >&2; exit 2; }
LOCK="${BENCH_LOCK:-$HOME/team2/run/bench.lock}"
mkdir -p "$(dirname "$LOCK")"
exec 9>>"$LOCK"
waited=0
until flock -w 60 9; do
  waited=$((waited + 60))
  echo "[server_lock] $(date '+%F %T') waiting for $LOCK (held by: $(cat "$LOCK.info" 2>/dev/null || echo unknown)); waited ${waited}s"
done
echo "[server_lock] $(date '+%F %T') acquired $LOCK (pid $$)"
echo "pid $$ since $(date '+%F %T'): $*" > "$LOCK.info"
"$@" 9>&-
rc=$?
rm -f "$LOCK.info"
echo "[server_lock] $(date '+%F %T') releasing $LOCK (command exit $rc)"
exit $rc
