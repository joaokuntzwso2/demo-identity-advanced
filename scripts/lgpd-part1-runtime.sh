#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

echo "============================================================"
echo "LGPD PART 1 — runtime + Consent Management v2 foundation"
echo "============================================================"

for f in \
  docker-compose.yml \
  docker-compose.lgpd-consent.yml \
  platform/wso2/deployment-lgpd.toml \
  scripts/start-lgpd-consent.sh \
  scripts/validate-lgpd-consent.sh
do
  [[ -f "$f" ]] || {
    echo "ERROR: missing $f"
    echo "Expected the earlier LGPD installer/repair to have created it."
    exit 1
  }
done

[[ -f .lgpd-consent.env ]] || {
  echo "ERROR: missing .lgpd-consent.env"
  exit 1
}

set -a
# shellcheck disable=SC1091
source .lgpd-consent.env
set +a

: "${WSO2_IS_IMAGE:?Missing WSO2_IS_IMAGE}"
: "${WSO2_IS_UPDATE_LEVEL:?Missing WSO2_IS_UPDATE_LEVEL}"
: "${CONSENT_WEBHOOK_SECRET:?Missing CONSENT_WEBHOOK_SECRET}"

if ! [[ "$WSO2_IS_UPDATE_LEVEL" =~ ^[0-9]+$ ]] || \
   (( WSO2_IS_UPDATE_LEVEL < 12 )); then
  echo "ERROR: WSO2_IS_UPDATE_LEVEL must be 12 or later."
  exit 1
fi

grep -q 'enable_v2_api = true' platform/wso2/deployment-lgpd.toml || {
  echo "ERROR: Consent Management v2 is not enabled."
  exit 1
}

grep -q 'ConsentEventHook.properties.enable = true' \
  platform/wso2/deployment-lgpd.toml || {
  echo "ERROR: ConsentEventHook is not enabled."
  exit 1
}

grep -q 'ConsentPurposeEventHook.properties.enable = true' \
  platform/wso2/deployment-lgpd.toml || {
  echo "ERROR: ConsentPurposeEventHook is not enabled."
  exit 1
}

echo
echo "Resolved WSO2 image:"
docker compose \
  --env-file .lgpd-consent.env \
  -f docker-compose.yml \
  -f docker-compose.lgpd-consent.yml \
  config |
awk '
  /^  wso2is:$/ { in_service=1; next }
  in_service && /^    image:/ { print "  " $0; exit }
'

echo
echo "Starting/reconciling LGPD stack..."
./scripts/start-lgpd-consent.sh

echo
echo "Validating LGPD runtime..."
./scripts/validate-lgpd-consent.sh

echo
echo "Checking Consent Management v2 API..."
http_code="$(
  curl -ksS \
    -u "${WSO2_ADMIN_USER:-admin}:${WSO2_ADMIN_PASSWORD:-admin}" \
    -o /tmp/lgpd-consent-v2-probe.json \
    -w '%{http_code}' \
    "https://localhost:9443/api/identity/consent-mgt/v2.0/purposes?limit=1" \
    || true
)"

case "$http_code" in
  200|201)
    echo "PASS: Consent Management v2 purposes API is reachable (HTTP $http_code)"
    ;;
  401|403)
    echo "PASS: Consent Management v2 endpoint exists (HTTP $http_code); authentication/authorization is enforced."
    ;;
  404)
    echo "ERROR: Consent Management v2 purposes endpoint returned 404."
    echo "The updated runtime/configuration is not exposing the expected v2 API."
    cat /tmp/lgpd-consent-v2-probe.json || true
    exit 1
    ;;
  *)
    echo "ERROR: unexpected Consent Management v2 probe response: HTTP $http_code"
    cat /tmp/lgpd-consent-v2-probe.json || true
    exit 1
    ;;
esac

echo
echo "Checking My Account..."
curl -kfsS https://localhost:9443/myaccount >/dev/null
echo "PASS: My Account is reachable"

echo
echo "Checking LGPD notice..."
curl -fsS http://localhost:8300/policy/lgpd >/dev/null
echo "PASS: LGPD notice is reachable"

echo
echo "Checking downstream consent audit..."
curl -fsS http://localhost:8300/health | python3 -m json.tool

echo
echo "============================================================"
echo "PART 1 COMPLETE"
echo "============================================================"
echo "WSO2 IS update level : 7.3.0.${WSO2_IS_UPDATE_LEVEL}"
echo "Consent Management v2: enabled"
echo "My Account            : available"
echo "Consent event hooks   : enabled"
echo "LGPD notice           : available"
echo "Consent audit service : available"
echo
echo "Part 2 will provision, with no Console work:"
echo "  - MarketSphere LGPD policy"
echo "  - optional marketing/preferences"
echo "  - Portal Corporativo assignment"
echo "  - seeded consent records for demo users"
echo "  - bootstrap verification of those objects"
