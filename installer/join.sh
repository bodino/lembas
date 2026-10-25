#!/bin/sh
# Terminal alternative to pasting an invite code into the lembas app. Run as:
#   curl -fsSL <pool-url>/join.sh | sh -s -- <pool-url> <pool-token>
# Installs lembas.app and writes its config. On launch the app installs its bundled
# background agent and points Claude Code at it; nothing else (no Node) is needed.
set -e
URL="$1"; TOKEN="$2"
if [ -z "$URL" ] || [ -z "$TOKEN" ]; then
  echo "usage: sh join.sh <pool-url> <pool-token>" >&2
  exit 1
fi

echo "==> writing lembas config (0600)"
mkdir -p "$HOME/.config"
printf '{\n  "url": "%s",\n  "token": "%s"\n}\n' "$URL" "$TOKEN" > "$HOME/.config/lembas.json"
chmod 600 "$HOME/.config/lembas.json"

echo "==> installing the lembas menu bar app"
TMP=$(mktemp -d)
# From the GitHub release (built from the public source), not from the pool.
curl -fsSL -o "$TMP/lembas.zip" "https://github.com/bodino/lembas/releases/latest/download/lembas.zip"
DEST="/Applications"
if ! touch "$DEST/.lembas-test-write" 2>/dev/null; then
  DEST="$HOME/Applications"
fi
rm -f "$DEST/.lembas-test-write" 2>/dev/null || true
mkdir -p "$DEST"
rm -rf "$DEST/lembas.app"
(cd "$DEST" && unzip -oq "$TMP/lembas.zip")
rm -rf "$TMP"
open "$DEST/lembas.app"

cat <<MSG

done! lembas is in your menu bar. lembas has set up its background agent
and pointed Claude Code at it; Claude Code keeps its normal claude.ai login.

next: click the lembas icon and connect your subscription.

MSG
