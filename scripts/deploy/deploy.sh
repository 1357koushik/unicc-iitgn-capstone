#!/usr/bin/env bash
# Deploy a git ref of this repository to the IITGN server (work package A2).
#
# Usage (run on the PC, from anywhere inside the repository):
#   scripts/deploy/deploy.sh <git-ref>
#
# Steps:
#   1. push the ref to the `server` remote (bare repo ~/team2/repo.git)
#   2. over ssh: export it to ~/team2/releases/<short-sha>
#   3. create/update that release's venv from requirements-retrieval.lock, fully
#      offline from the wheel mirror ~/wheels, and `pip install -e` the package
#   4. repoint the symlink ~/team2/current at the release
# Idempotent: re-running with the same ref repeats nothing that is already done.
#
# Environment:
#   TRE_SERVER_REMOTE  git remote name (default: server)
#   TRE_SSH_TARGET     user@host (default: koushik.moram@10.0.62.212)
#   TRE_SSH_PORT       ssh port (default: 2022)
#   TRE_WAIT_FILE      if set: before the heavy venv step, wait (60 s poll) while
#                      this file exists on the server (shared-machine etiquette)
set -euo pipefail

REF="${1:-}"
if [ -z "$REF" ]; then
  echo "usage: $0 <git-ref>" >&2
  exit 2
fi

REMOTE="${TRE_SERVER_REMOTE:-server}"
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
WAIT_FILE="${TRE_WAIT_FILE:-}"

cd "$(git rev-parse --show-toplevel)"
SHA="$(git rev-parse --verify "${REF}^{commit}")"
SHORT="${SHA:0:9}"
echo "[deploy] ref=$REF sha=$SHA short=$SHORT"

echo "[deploy] pushing to remote '$REMOTE' as refs/releases/$SHORT"
git push --quiet "$REMOTE" "$SHA:refs/releases/$SHORT"

echo "[deploy] building release on the server"
ssh -o BatchMode=yes -p "$PORT" "$TARGET" bash -s -- "$SHA" "$SHORT" "$WAIT_FILE" <<'REMOTE'
set -euo pipefail
SHA="$1"; SHORT="$2"; WAIT_FILE="${3:-}"
WAIT_FILE="${WAIT_FILE/#\$HOME/$HOME}"   # allow a literal $HOME prefix
T="$HOME/team2"
REL="$T/releases/$SHORT"
PY="$HOME/py312/bin/python"
WHEELS="$HOME/wheels"

# --- 1. export the commit ---------------------------------------------------
if [ -f "$REL/.release_sha" ] && [ "$(cat "$REL/.release_sha")" = "$SHA" ]; then
  echo "[server] release $SHORT already exported"
else
  rm -rf "$REL.tmp"; mkdir -p "$REL.tmp"
  git --git-dir="$T/repo.git" archive "$SHA" | tar -x -C "$REL.tmp"
  echo "$SHA" > "$REL.tmp/.release_sha"
  # keep an existing venv if only the export is being redone
  if [ -d "$REL/.venv" ]; then mv "$REL/.venv" "$REL.tmp/.venv-old"; fi
  rm -rf "$REL"; mv "$REL.tmp" "$REL"
  if [ -d "$REL/.venv-old" ]; then rm -rf "$REL/.venv"; mv "$REL/.venv-old" "$REL/.venv"; fi
  echo "[server] exported $SHA to $REL"
fi

# --- 2. venv from the lock file, offline -------------------------------------
LOCK="$REL/requirements-retrieval.lock"
[ -f "$LOCK" ] || { echo "[server] ERROR: $LOCK missing in this commit" >&2; exit 1; }
LOCK_HASH="$(sha256sum "$LOCK" | cut -d' ' -f1)"
STAMP="$REL/.venv/.lock_sha256"
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$LOCK_HASH" ] && [ -x "$REL/.venv/bin/python" ]; then
  echo "[server] venv up to date (lock $LOCK_HASH)"
else
  if [ -n "$WAIT_FILE" ]; then
    while [ -e "$WAIT_FILE" ]; do echo "[server] waiting: $WAIT_FILE exists"; sleep 60; done
  fi
  echo "[server] creating venv from the lock file (offline)"
  rm -rf "$REL/.venv"
  "$PY" -m venv "$REL/.venv"
  "$REL/.venv/bin/python" -m pip install --quiet --no-index --find-links "$WHEELS" -r "$LOCK"
  "$REL/.venv/bin/python" -m pip install --quiet --no-index --no-deps --no-build-isolation -e "$REL"
  echo "$LOCK_HASH" > "$STAMP"
fi
# the editable install must point at this release (cheap; refreshes after an export redo)
"$REL/.venv/bin/python" -m pip install --quiet --no-index --no-deps --no-build-isolation -e "$REL"

# --- 3. switch the symlink atomically ----------------------------------------
ln -sfn "$REL" "$T/current.new"
mv -Tf "$T/current.new" "$T/current"
echo "[server] current -> $(readlink "$T/current")"
REMOTE

echo "[deploy] done: $SHORT"
