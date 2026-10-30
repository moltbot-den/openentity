#!/usr/bin/env bash
# Weekly release train (CLAUDE.md, "Releases"): a package publishes at most once in 6 days.
# Usage: release-gate.sh <package dir> [hotfix reason]. A non-empty reason (security fix or broken install) lets it through.
set -euo pipefail
dir=$1 reason=${2:-}
if [ -f "$dir/package.json" ]; then
  name=$(node -p "require('./$dir/package.json').name")
  last=$(npm view "$name" time.modified 2>/dev/null || true)
else
  name=$(sed -n 's/^name = "\(.*\)"/\1/p' "$dir/pyproject.toml" | head -1)
  last=$(curl -fsS "https://pypi.org/pypi/$name/json" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(max(f["upload_time_iso_8601"] for fs in d["releases"].values() for f in fs))' 2>/dev/null || true)
fi
[ -z "$last" ] && { echo "release-gate: $name has never been published"; exit 0; }
age=$(( ($(date -u +%s) - $(python3 -c "import sys,datetime;print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()))" "$last")) / 86400 ))
if [ "$age" -lt 6 ] && [ -z "$reason" ]; then
  echo "release-gate: $name last published $age day(s) ago ($last). Wait for the weekly train, or pass a hotfix reason (security fix or broken install)."
  exit 1
fi
echo "release-gate: $name ok (last published $age day(s) ago${reason:+, hotfix: $reason})"
