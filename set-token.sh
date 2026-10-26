#!/bin/bash
# Update a user's claudeToken in config.json without echoing it.
# Usage: ./set-token.sh <username>
set -e
cd "$(dirname "$0")"

if [ -z "$1" ]; then
  echo "usage: ./set-token.sh <username>   (users in config.json: $(node -e "console.log(Object.keys(require('./config.json').users).join(', '))"))"
  exit 1
fi

printf "paste the sk-ant-oat01-... token for %s (input hidden): " "$1"
read -rs TOKEN
echo

node -e "
const fs = require('fs');
const c = JSON.parse(fs.readFileSync('config.json', 'utf8'));
if (!c.users[process.argv[1]]) { console.error('no such user: ' + process.argv[1]); process.exit(1); }
if (!process.argv[2].startsWith('sk-ant-oat01-')) { console.error('that does not look like a setup token (should start with sk-ant-oat01-)'); process.exit(1); }
c.users[process.argv[1]].claudeToken = process.argv[2];
fs.writeFileSync('config.json', JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
console.log('saved.');
" "$1" "$TOKEN"

# The running pool keeps config.json in memory and writes it back whenever a member
# changes something, which would drop this edit: restart it so it reads the new file.
if launchctl print "gui/$(id -u)/com.lembas.pool" >/dev/null 2>&1; then
  launchctl kickstart -k "gui/$(id -u)/com.lembas.pool" && echo "restarted the pool"
else
  echo "restart the pool now, or this change is overwritten the next time it saves its config." >&2
fi
