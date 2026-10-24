#!/usr/bin/env bash
# PRD 7.7: agent entry points must answer 200 with the expected body to a generic
# client from a datacenter IP (the CI runner). Any challenge page fails this.
set -euo pipefail
base="${1:-https://openentity.org}"
fail=0
check() {
  local path="$1" want="$2" ua="$3" body code
  body=$(curl -sS -A "$ua" -w '\n%{http_code}' "$base$path") || { echo "FAIL $path ($ua): request error"; fail=1; return; }
  code="${body##*$'\n'}"; body="${body%$'\n'*}"
  if [ "$code" != 200 ] || ! grep -qF -- "$want" <<<"$body"; then
    echo "FAIL $path ($ua): HTTP $code"; fail=1
  else
    echo "ok   $path ($ua)"
  fi
}
for ua in "curl/8" "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"; do
  check /llms.txt "# Open Entity" "$ua"
  check /v1/spec '"declaration' "$ua"
  check /.well-known/openentity.json '"eid"' "$ua"
done
exit $fail
