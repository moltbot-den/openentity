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
  pnpm -r --if-present run build  # deploy.yml builds every package; a missing build tool fails here first
  pnpm -r --if-present run test
fi

# Independent Python implementation: its own tests, and every TS-generated vector must verify.
if [ -d sdk/python ]; then
  (cd sdk/python && uv run --quiet pytest -q) || fail=1
  uv run --quiet scripts/independent_verifier.py --vectors test-vectors || fail=1
fi

# LangChain integration (Python half; the JS half runs with the pnpm workspace above). Both run the shared corpus in integrations/langchain/fixtures.
if [ -d integrations/langchain/python ]; then
  (cd integrations/langchain/python && uv run --quiet pytest -q) || fail=1
fi

# Google ADK integration (Python half; the JS half runs with the pnpm workspace above). Mocked HTTP only.
if [ -d integrations/adk/python ]; then
  (cd integrations/adk/python && uv run --quiet pytest -q) || fail=1
fi

exit $fail
