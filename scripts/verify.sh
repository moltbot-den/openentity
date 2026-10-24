#!/usr/bin/env bash
# The single definition of a good commit. Runs in the pre-push hook and in test.yml.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# No em dashes anywhere in tracked or staged text.
if git grep -n -I --untracked "$(printf '\xe2\x80\x94')" ; then
  echo "verify: em dash found (see above)"; fail=1
fi

# Workspace checks run once packages exist.
if [ -f pnpm-lock.yaml ]; then
  pnpm install --frozen-lockfile >/dev/null
  pnpm -r --if-present run lint
  pnpm -r --if-present run typecheck
  pnpm -r --if-present run test
fi

exit $fail
