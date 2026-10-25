#!/bin/bash
# Add a new member to the pool. Usage: ./add-user.sh <name>
set -e
cd "$(dirname "$0")"

if [ -z "$1" ]; then
  echo "usage: ./add-user.sh <name>"
  exit 1
fi
NAME=$1
TOKEN="pool-$(openssl rand -hex 24)"

node -e "
const fs = require('fs');
const c = JSON.parse(fs.readFileSync('config.json', 'utf8'));
if (c.users[process.argv[1]]) { console.error('user already exists'); process.exit(1); }
c.users[process.argv[1]] = { token: process.argv[2], claudeToken: 'PASTE-' + process.argv[1] + '-sk-ant-oat01-HERE' };
fs.writeFileSync('config.json', JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
" "$NAME" "$TOKEN"

IP=$(node -e "console.log(require('./config.json').host)")
cat <<EOF

added $NAME. Two more steps:

1. send them this pool token privately (not in a group chat):
   $TOKEN

2. send them this one-liner to run (they must already be on your tailnet):
   curl -fsSL http://$IP:8787/join.sh | sh -s -- http://$IP:8787 $TOKEN

When they run the one-liner, Claude Code keeps their normal claude.ai login and only
gains a local fallback agent. Ask them to click "Connect subscription…" in the menu bar
app; that is the preferred setup and lets the pool read usage windows.

A 'claude setup-token' token is only a legacy fallback (it cannot read usage windows).
If they prefer that path, they can send it to you, then run:
  ./set-token.sh $NAME
and restart the pool.

EOF
