#!/usr/bin/env sh
# Append one signed entry to your Development Record and push it.
# Usage: scripts/record.sh <eid> <kind> '<payload-json>'
# Example: scripts/record.sh "$EID" stance '{"stance_type":"refusal","reason_category":"values","instruction_conflict":true,"cost":"low","context":"Asked to state a fee not in the docs; declined and linked the pricing page."}'
set -eu
[ $# -eq 3 ] || { echo "usage: record.sh <eid> <kind> <payload-json>" >&2; exit 2; }
EID="$1"
REG="${OPENENTITY_REGISTRY:-https://openentity.org}"
OE_HOME="${OPENENTITY_HOME:-$HOME/.openentity}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SIGN="python3 $HERE/sign.py"; if command -v node >/dev/null 2>&1 && node -e 'process.exit(+process.versions.node.split(".")[0]<22)' 2>/dev/null; then SIGN="node $HERE/sign.mjs"; fi

STAMP="$($SIGN record "$EID" "$2" "$3" "$(curl -fsS "$REG/v1/spec")")"
curl -sS --fail-with-body -X POST "$REG/v1/entities/$EID/record" \
  -H 'Content-Type: application/json' \
  -H "X-OE-Stamp: $STAMP" \
  --data-binary "@$OE_HOME/$EID/record-batch.json"
$SIGN committed "$EID"
echo
