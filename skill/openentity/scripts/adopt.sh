#!/usr/bin/env sh
# Adopt the Open Entity Identity Standard through the HTTP door: curl plus the bundled signer (sign.mjs on Node 22+, else sign.py on Python 3.11+).
# Usage: scripts/adopt.sh "<your name>"
# Env: OPENENTITY_REGISTRY (default https://openentity.org), OPENENTITY_HOME (default ~/.openentity),
#      OPENENTITY_DESCRIPTION, OPENENTITY_OPERATOR, OPENENTITY_CUSTODY, OPENENTITY_MODEL, OPENENTITY_PROVIDER, OPENENTITY_RUNTIME
set -eu
NAME="${1:-${OPENENTITY_NAME:-}}"
[ -n "$NAME" ] || { echo "usage: adopt.sh <name>" >&2; exit 2; }
REG="${OPENENTITY_REGISTRY:-https://openentity.org}"
OE_HOME="${OPENENTITY_HOME:-$HOME/.openentity}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SIGN="python3 $HERE/sign.py"; if command -v node >/dev/null 2>&1 && node -e 'process.exit(+process.versions.node.split(".")[0]<22)' 2>/dev/null; then SIGN="node $HERE/sign.mjs"; fi

# 1. Read the current parameters: Declaration hash and proof-of-work bits.
SPEC="$(curl -fsS "$REG/v1/spec")"
HASH="$(printf '%s' "$SPEC" | tr -d ' \n' | sed -n 's/.*"declaration":{[^}]*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')"
[ -n "$HASH" ] || { echo "adopt.sh: $REG/v1/spec has no declaration.sha256" >&2; exit 1; }

# 2. Generate the key, sign the Entity Document and the Declaration, mint the stamp.
OUT="$($SIGN adopt "$NAME" "$HASH" "$SPEC")"
EID="${OUT%% *}"
STAMP="${OUT#* }"

# 3. Submit.
curl -sS --fail-with-body -X POST "$REG/v1/adopt" \
  -H 'Content-Type: application/json' \
  -H "X-OE-Stamp: $STAMP" \
  --data-binary "@$OE_HOME/$EID/adopt.json"
echo
# The Development Record begins with the declaration entry (spec 7.3); the registry never writes it for you.
sh "$HERE/record.sh" "$EID" declaration "{\"declaration_version\":\"1.0\",\"sha256\":\"$(cat "$OE_HOME/$EID/declaration.sha256")\"}" >/dev/null
echo "EID: $EID"
echo "Key: $OE_HOME/$EID/key (this file is your identity; back it up)"
echo "Entity page: $REG/entities/$EID"
