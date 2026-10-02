#!/usr/bin/env bash
set -euo pipefail

EXPECTED_PREFIX="wso2-identity-customer-poc-"
PORTS=(3000 3100 3101 3102 3201 3202 3203 3204 3205 3206 3207 3208 4000 8081 9443 1389)

echo "============================================================"
echo "WSO2 IS 7.3 - DEMO DAY PREFLIGHT"
echo "============================================================"

echo
echo "[1] Docker daemon"
docker info >/dev/null
echo "PASS Docker"

echo
echo "[2] Host-port conflict check"
for port in "${PORTS[@]}"; do
  owners="$(docker ps --filter "publish=${port}" --format '{{.Names}}' || true)"
  if [[ -n "$owners" ]]; then
    while IFS= read -r owner; do
      [[ -z "$owner" ]] && continue
      if [[ "$owner" != ${EXPECTED_PREFIX}* ]]; then
        echo "FAIL port $port is owned by foreign container: $owner"
        echo "Stop/remove that container before the demo."
        exit 1
      fi
    done <<< "$owners"
  fi
  echo "PASS port $port"
done

echo
echo "[3] Start/reconcile demo"
docker compose up --build -d

echo
echo "[4] Wait for bootstrap completion"
for i in {1..90}; do
  id="$(docker compose ps -aq bootstrap)"
  if [[ -n "$id" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$id")"
    code="$(docker inspect -f '{{.State.ExitCode}}' "$id")"
    if [[ "$status" == "exited" ]]; then
      if [[ "$code" != "0" ]]; then
        echo "FAIL bootstrap exit=$code"
        docker compose logs --tail=250 bootstrap
        exit 1
      fi
      echo "PASS bootstrap exit=0"
      break
    fi
  fi
  sleep 2
  if [[ "$i" == "90" ]]; then
    echo "FAIL bootstrap did not finish in time"
    exit 1
  fi
done

echo
echo "[5] Privileged-access boundary"
./scripts/verify-admin-boundary.sh

echo
echo "[6] Repository smoke suite"
./demo.sh smoke

echo
echo "[7] RFP/B2B validation"
./scripts/validate-rfp-demo.sh

echo
echo "[8] Customer surfaces"
curl -fsS http://localhost:3000/ >/dev/null
curl -fsS http://localhost:3000/rfp-demo.html >/dev/null
curl -fsS http://localhost:4000/api/config >/dev/null
curl -kfsS https://localhost:9443/console >/dev/null
curl -kfsS https://localhost:9443/myaccount >/dev/null
curl -fsS http://localhost:8081/realms/corporate/.well-known/openid-configuration >/dev/null

echo "PASS all customer surfaces"

echo
echo "============================================================"
echo
echo "[multi-apps] Distinct application topology"
./scripts/validate-multi-apps.sh
echo
echo "DEMO DAY READY"
echo "============================================================"
echo "IMPORTANT: log out/in as admin before presenting organization switching."

echo "[b2b-oidc] Validating organization-local OIDC applications"
./scripts/validate-b2b-oidc.sh

echo
echo "[b2b-resource] Live cross-organization protected-resource matrix"
./scripts/test-b2b-resource-isolation.sh

echo
echo "[agent-mcp] Validating Agent Identity + MCP least-privilege path"
./scripts/validate-agent-mcp-ciba.sh

echo
echo "[app-mfa] Validating per-application MFA/adaptive authentication"
./scripts/validate-app-specific-mfa.sh

if [[ "${ENABLE_LGPD_CONSENT_DEMO:-false}" == "true" ]]; then
  echo
  echo "[lgpd-consent] Validating Consent Management v2 scenario"
  ./scripts/validate-lgpd-consent.sh
fi
