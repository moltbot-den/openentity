#!/usr/bin/env bash
# Post-deploy check for the account service: health, the AASA Apple's CDN fetches (JSON, no redirect), the token keys.
#   bash scripts/account-check.sh account.openentity.org
set -euo pipefail
host="$1"
fail() { echo "account-check $host: $*" >&2; exit 1; }
curl -fsS "https://$host/v1/health" | grep -q '"ok":true' || fail "health"
read -r code type < <(curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "https://$host/.well-known/apple-app-site-association")
[ "$code" = 200 ] || fail "AASA answered $code (no redirect allowed)"
[[ "$type" == application/json* ]] || fail "AASA content type is $type"
curl -fsS "https://$host/.well-known/apple-app-site-association" | grep -q '7R835D5LDZ.org.openentity.app' || fail "AASA does not name the app"
curl -fsS "https://$host/.well-known/jwks.json" | grep -q '"kty":"EC"' || fail "jwks.json has no EC key"
curl -fsS "https://$host/.well-known/did.json" | grep -q "did:web:$host" || fail "did.json"
# The web pages answer with their own CSP; /approve forms post only to the four product sites.
curl -fsS -D - -o /dev/null "https://$host/approve" | grep -qi "^content-security-policy: default-src 'none'.*form-action 'self' https://moltbotden.com" || fail "/approve CSP"
# Gate M3: the viewer-request function gives each request the viewer's address; without it ipOf answers 503.
install=$(python3 -c 'import uuid; print(uuid.uuid4())')
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "https://$host/v1/installs" -H 'content-type: application/json' -d "{\"install_id\":\"$install\",\"platform\":\"ios\"}")
[ "$code" = 201 ] || fail "POST /v1/installs answered $code: the viewer address did not reach the service"
# PLAN 2.3, no test doors in production: production has no test identity provider (404, or 503 while sign-in is closed).
if [ "$host" = account.openentity.org ]; then
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "https://$host/v1/auth/test-idp" -H 'content-type: application/json' -d '{"kind":"apple","nonce":"x"}')
  [ "$code" = 404 ] || [ "$code" = 503 ] || fail "test identity provider answered $code in production"
fi
echo "account-check $host: ok"
