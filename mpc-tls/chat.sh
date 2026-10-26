#!/bin/zsh
# Chat with Claude where every message is a borrowed request through the pool.
#
# Starts a pool in the background holding your subscription token (read from
# state.json, never printed), then opens the chat as the borrower. The pool
# lends the token to each request but cannot read what you type or what comes
# back. Quit with an empty line or Ctrl-D; the pool is stopped on exit.
#
# Usage: mpc-tls/chat.sh [user-in-state.json] [--model claude-sonnet-5-5]
set -euo pipefail

here=${0:A:h}
repo=${here:h}
bin=${LEMBAS_MPC_BIN:-$here/lembas-mpc/target/release/lembas-mpc}
user=${1:-alessandro}
shift $(( $# > 0 ? 1 : 0 ))
port=${LEMBAS_MPC_PORT:-7700}

if [[ ! -x $bin ]]; then
  echo "build it first: (cd $here/lembas-mpc && cargo build --release)" >&2
  echo "or set LEMBAS_MPC_BIN to a lembas-mpc binary (the app bundle has one)" >&2
  exit 1
fi

export LEMBAS_TOKEN=$(python3 -I - "$repo/state.json" "$user" <<'PY'
import json, sys, time
state = json.load(open(sys.argv[1]))
o = state["oauth"][sys.argv[2]]
if o["expiresAt"] / 1000 < time.time():
    sys.exit(f"{sys.argv[2]}'s access token has expired; open the lembas app to refresh it")
print(o["accessToken"])
PY
)

# A pool left over from an earlier run (possibly an older build) would answer
# instead of ours; stop it first.
pkill -f "lembas-mpc pool --listen 127.0.0.1:$port" 2>/dev/null && sleep 0.3
if lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $port is in use by another program; set LEMBAS_MPC_PORT to pick another" >&2
  exit 1
fi

RUST_LOG=${RUST_LOG:-warn} "$bin" pool --listen 127.0.0.1:$port &
pool=$!
trap 'kill $pool 2>/dev/null; wait $pool 2>/dev/null' EXIT INT TERM
unset LEMBAS_TOKEN

# Wait for our pool to listen (without connecting to it: a probe connection
# would look like a borrower that left).
for _ in {1..50}; do
  lsof -nP -a -p $pool -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1 && break
  kill -0 $pool 2>/dev/null || { echo "the pool failed to start" >&2; exit 1; }
  sleep 0.1
done

RUST_LOG=${RUST_LOG:-warn} "$bin" chat --pool 127.0.0.1:$port "$@"
