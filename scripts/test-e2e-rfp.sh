#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"

echo
echo "[0] Bootstrap idempotency"
./scripts/test-bootstrap-idempotency.sh
echo "WSO2 IDENTITY SERVER 7.3 - COMPLETE E2E PRE-FLIGHT"
echo "============================================================"

docker info >/dev/null

bootstrap_id="$(docker compose ps -aq bootstrap)"
if [[ -z "$bootstrap_id" ]]; then
  echo "FAIL: bootstrap container not found"
  exit 1
fi

status="$(docker inspect -f '{{.State.Status}}' "$bootstrap_id")"
exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$bootstrap_id")"

echo "bootstrap status=$status exit=$exit_code"

if [[ "$status" != "exited" || "$exit_code" != "0" ]]; then
  echo "FAIL: bootstrap must be exited with code 0"
  docker compose logs --tail=300 bootstrap
  exit 1
fi

echo
echo "[1/3] Repository smoke suite"
./demo.sh smoke

echo
echo "[2/3] Customer B2B/RFP suite"
./scripts/validate-rfp-demo.sh

echo
echo "[3/3] Bootstrap evidence"
docker compose logs bootstrap | grep -F "Published runtime configuration for API, agent, and UI" >/dev/null
docker compose logs bootstrap | grep -F "CUSTOMER RFP DEMO READY" >/dev/null

echo
echo "[admin-boundary] Verifying root-admin/least-privilege boundary"
./scripts/verify-admin-boundary.sh

echo
echo "[multi-apps] Distinct application topology"
./scripts/validate-multi-apps.sh
echo
echo "ALL NON-INTERACTIVE E2E CHECKS PASSED"
echo "Continue with docs/CUSTOMER_RFP_DEMO.md for interactive browser flows."

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
