#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { printf '\033[1;32m[pass]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }
json_get() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

curl -kfsS https://localhost:9443/oauth2/jwks >/dev/null || fail "WSO2 JWKS is unavailable"
pass "WSO2 Identity Server JWKS"

curl -fsS http://localhost:8081/realms/corporate/.well-known/openid-configuration >/dev/null || fail "Corporate OIDC discovery is unavailable"
pass "Corporate OIDC discovery"

CONFIG="$(curl -fsS http://localhost:4000/api/config)"
VERSION="$(printf '%s' "$CONFIG" | json_get 'd["product"]["version"]')"
[[ "$VERSION" == "7.3.0" ]] || fail "Expected WSO2 IS 7.3.0, got $VERSION"
pass "Runtime configuration targets WSO2 IS 7.3.0"

M2M="$(curl -fsS -X POST http://localhost:4000/api/demo/m2m)"
DECISION="$(printf '%s' "$M2M" | json_get 'd["protectedApiResult"]["decision"]')"
SCOPE="$(printf '%s' "$M2M" | json_get 'd["token"]["decoded"]["scope"]')"
[[ "$DECISION" == "allow" ]] || fail "Client Credentials protected API decision was not allow"
[[ "$SCOPE" == *"orders.read"* ]] || fail "M2M token does not include orders.read"
pass "Client Credentials, JWT issuance, scope, and protected API validation"

AGENT_ROLE="$(printf '%s' "$CONFIG" | json_get 'd["agent"]["role"]')"
[[ "$AGENT_ROLE" == "inventory-agent" ]] || fail "Agent role was not configured"
pass "Agent identity and role metadata"

STATUS="$(curl -fsS http://localhost:4000/api/status)"
TRUST="$(printf '%s' "$STATUS" | json_get 'd["components"]["trustedTokenIssuer"]')"
[[ "$TRUST" == "CONFIGURED" ]] || fail "Trusted token issuer is missing"
pass "Trusted token issuer configuration"

printf '\nSmoke validation passed. Interactive Authorization Code, RBAC deny/allow, federation, token exchange, and agent execution are demonstrated from http://localhost:3000.\n'
