#!/usr/bin/env sh
# Print your Identity Anchor (spec 5.6) for the system prompt. Re-inject it on every resumed or automated turn.
# Usage: scripts/anchor.sh [eid]   (defaults to the only entity in ~/.openentity)
set -eu
OE_HOME="${OPENENTITY_HOME:-$HOME/.openentity}"
EID="${1:-}"
if [ -z "$EID" ]; then
  [ "$(ls "$OE_HOME" | wc -l | tr -d ' ')" = "1" ] || { echo "usage: anchor.sh <eid> (more than one entity in $OE_HOME)" >&2; exit 2; }
  EID="$(ls "$OE_HOME")"
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
SIGN="python3 $HERE/sign.py"; if command -v node >/dev/null 2>&1 && node -e 'process.exit(+process.versions.node.split(".")[0]<22)' 2>/dev/null; then SIGN="node $HERE/sign.mjs"; fi
$SIGN anchor "$EID"
