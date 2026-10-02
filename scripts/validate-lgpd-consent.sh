#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

ENV_FILE=".lgpd-consent.env"
[[ -f "$ENV_FILE" ]] || {
  echo "FAIL: missing $ENV_FILE"
  exit 1
}

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${WSO2_IS_IMAGE:?Missing WSO2_IS_IMAGE}"
: "${WSO2_IS_UPDATE_LEVEL:?Missing WSO2_IS_UPDATE_LEVEL}"
: "${CONSENT_WEBHOOK_SECRET:?Missing CONSENT_WEBHOOK_SECRET}"

if ! [[ "$WSO2_IS_UPDATE_LEVEL" =~ ^[0-9]+$ ]] || \
   (( WSO2_IS_UPDATE_LEVEL < 12 )); then
  echo "FAIL: WSO2_IS_UPDATE_LEVEL must be >= 12"
  exit 1
fi

COMPOSE=(
  docker compose
  --env-file "$ENV_FILE"
  -f docker-compose.yml
  -f docker-compose.lgpd-consent.yml
)

resolved_image="$("${COMPOSE[@]}" config | awk '
  /^  wso2is:$/ { in_service=1; next }
  in_service && /^    image:/ {
    sub(/^    image:[[:space:]]*/, "")
    print
    exit
  }
')"

if [[ "$resolved_image" != "$WSO2_IS_IMAGE" ]]; then
  echo "FAIL: Compose resolved a different WSO2 image."
  echo "expected: $WSO2_IS_IMAGE"
  echo "actual  : $resolved_image"
  exit 1
fi

case "$resolved_image" in
  wso2/wso2is:7.3.0|wso2/wso2is:latest)
    echo "FAIL: LGPD scenario is still using the public GA image"
    exit 1
    ;;
esac

grep -q 'enable_v2_api = true' platform/wso2/deployment-lgpd.toml
grep -q 'ConsentEventHook.properties.enable = true' platform/wso2/deployment-lgpd.toml
grep -q 'ConsentPurposeEventHook.properties.enable = true' platform/wso2/deployment-lgpd.toml
grep -q 'disabled_channels = \[\]' platform/wso2/deployment-lgpd.toml

echo "== Resolved runtime =="
echo "WSO2 image   : $resolved_image"
echo "Update level : 7.3.0.$WSO2_IS_UPDATE_LEVEL"

echo
echo "== Running containers =="
"${COMPOSE[@]}" ps

echo
echo "== Consent audit =="
curl -fsS http://localhost:8300/health | python3 -m json.tool

echo
echo "== WSO2 Console =="
curl -kfsSI https://localhost:9443/console | head -n 1

echo
echo "PASS: LGPD consent runtime prerequisites are active"
echo "  image selection      : owned by docker-compose.yml"
echo "  consent v2           : enabled"
echo "  consent webhooks     : enabled"
echo "  webhook HMAC receiver: healthy"
echo
echo "Next: follow docs/LGPD_CONSENT_DEMO.md for the WSO2 Console objects and Flow Builder."
