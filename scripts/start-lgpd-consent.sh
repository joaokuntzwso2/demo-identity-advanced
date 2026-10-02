#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

ENV_FILE=".lgpd-consent.env"

[[ -f "$ENV_FILE" ]] || {
  echo "ERROR: missing $ENV_FILE"
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
  echo "ERROR: Consent Management v2 requires WSO2 IS 7.3.0 update level 12 or later."
  echo "WSO2_IS_UPDATE_LEVEL=$WSO2_IS_UPDATE_LEVEL"
  exit 1
fi

case "$WSO2_IS_IMAGE" in
  wso2/wso2is:7.3.0|wso2/wso2is:latest)
    echo "ERROR: LGPD consent scenario cannot use the public GA image:"
    echo "  $WSO2_IS_IMAGE"
    echo "Use an updated WSO2 subscription image at 7.3.0.12 or later."
    exit 1
    ;;
esac

tag="${WSO2_IS_IMAGE##*:}"
if [[ "$tag" =~ ^7[.]3[.]0[.]([0-9]+)$ ]]; then
  image_level="${BASH_REMATCH[1]}"
  if (( image_level < 12 )); then
    echo "ERROR: image tag update level is below 12: $WSO2_IS_IMAGE"
    exit 1
  fi
  if (( image_level != WSO2_IS_UPDATE_LEVEL )); then
    echo "ERROR: image tag and WSO2_IS_UPDATE_LEVEL disagree."
    echo "  image                : $WSO2_IS_IMAGE"
    echo "  WSO2_IS_UPDATE_LEVEL : $WSO2_IS_UPDATE_LEVEL"
    exit 1
  fi
fi

export ENABLE_LGPD_CONSENT_DEMO=true

COMPOSE=(
  docker compose
  --env-file "$ENV_FILE"
  -f docker-compose.yml
  -f docker-compose.lgpd-consent.yml
)

echo
echo "== LGPD consent stack =="
echo "WSO2 image        : $WSO2_IS_IMAGE"
echo "Update level      : 7.3.0.$WSO2_IS_UPDATE_LEVEL"
echo "Target application: ${LGPD_CONSENT_APP:-Portal Corporativo}"
echo

echo "Resolved Compose image:"
"${COMPOSE[@]}" config | awk '
  /^  wso2is:$/ { in_service=1; next }
  in_service && /^    image:/ { print "  " $0; exit }
'

echo
echo "Pulling the WSO2 image through Docker Compose..."
if ! "${COMPOSE[@]}" pull wso2is; then
  echo
  echo "ERROR: Docker could not pull:"
  echo "  $WSO2_IS_IMAGE"
  echo
  echo "If the registry reports UNAUTHORIZED, authenticate Docker once to"
  echo "registry.wso2.com using your WSO2 subscription credentials, then rerun:"
  echo
  echo "  docker login registry.wso2.com"
  echo "  ./scripts/start-lgpd-consent.sh"
  echo
  echo "If it reports MANIFEST UNKNOWN, use an available 7.3.0.N image where N >= 12"
  echo "and set WSO2_IS_UPDATE_LEVEL=N in .lgpd-consent.env."
  exit 1
fi

echo
echo "Starting the stack..."
"${COMPOSE[@]}" up --build -d

echo
echo "Waiting for consent-audit..."
for _ in $(seq 1 45); do
  if curl -fsS http://localhost:8300/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

curl -fsS http://localhost:8300/health | python3 -m json.tool

echo
echo "Waiting for WSO2 Identity Server..."
for _ in $(seq 1 90); do
  if curl -kfsS https://localhost:9443/console >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

echo
echo "Running bootstrap against the consent-capable runtime..."
"${COMPOSE[@]}" up --build --force-recreate bootstrap

echo
echo "============================================================"
echo "LGPD CONSENT STACK READY"
echo "============================================================"
echo "Console        : https://localhost:9443/console"
echo "My Account     : https://localhost:9443/myaccount"
echo "Consent audit  : http://localhost:8300"
echo "Privacy notice : http://localhost:8300/policy/lgpd"
echo
echo "Next:"
echo "  ./scripts/validate-lgpd-consent.sh"
echo "  cat docs/LGPD_CONSENT_DEMO.md"
