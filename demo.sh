#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

COMPOSE=(docker compose)
ACTION="${1:-up}"

log() { printf '\033[1;35m[demo]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

preflight() {
  command -v docker >/dev/null 2>&1 || fail "Docker is required. Install Docker Desktop or a compatible Docker Engine."
  docker info >/dev/null 2>&1 || fail "Docker is installed but the daemon is not reachable."
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."
  command -v curl >/dev/null 2>&1 || fail "curl is required for readiness checks."
  if [[ ! -f .env ]]; then
    cp .env.example .env
    log "Created .env from .env.example"
  fi
}

wait_http() {
  local name="$1" url="$2" attempts="${3:-120}"
  for ((i=1; i<=attempts; i++)); do
    if curl -kfsS --max-time 5 "$url" >/dev/null 2>&1; then
      log "$name is ready"
      return 0
    fi
    sleep 3
  done
  "${COMPOSE[@]}" ps
  fail "$name did not become ready: $url"
}

show_urls() {
  cat <<'TXT'

Environment ready
-----------------
Demo UI:            http://localhost:3000
Protected API:      http://localhost:4000/health
WSO2 Console:       https://localhost:9443/console
Corporate OIDC IdP: http://localhost:8081
LDAP:               ldap://localhost:1389

Primary demo users
------------------
alice / Alice@123    Portal allowed; finance user
bob   / Bob@123      Valid login; Portal denied
carol / Carol@123    Portal admin; agent and token-exchange demos
CORP/diana / Corporate@123   External LDAP; Portal allowed
CORP/eduardo / Corporate@123 External LDAP; Portal denied
federated.user / Federated@123  Corporate OIDC login

The WSO2 endpoint uses a local self-signed certificate. Accept it once in the
browser before starting the OIDC login flow.
TXT
}

case "$ACTION" in
  up)
    preflight
    log "Building and starting WSO2 IS 7.3, LDAP, corporate OIDC, bootstrap, APIs, agent, and UI"
    "${COMPOSE[@]}" up -d --build --force-recreate --remove-orphans
    wait_http "WSO2 Identity Server" "https://localhost:9443/oauth2/jwks" 180
    wait_http "Protected API" "http://localhost:4000/health" 180
    wait_http "Demo UI" "http://localhost:3000" 120
    show_urls
    ;;
  bootstrap)
    preflight
    log "Re-running the idempotent WSO2 configuration bootstrap"
    "${COMPOSE[@]}" up -d ldap keycloak wso2is
    "${COMPOSE[@]}" run --rm --build bootstrap
    "${COMPOSE[@]}" up -d --build --force-recreate marketplace-api inventory-agent ui
    wait_http "Protected API" "http://localhost:4000/health" 120
    ;;
  smoke)
    preflight
    exec "$ROOT_DIR/scripts/smoke.sh"
    ;;
  status)
    preflight
    "${COMPOSE[@]}" ps
    printf '\nRuntime status:\n'
    curl -fsS http://localhost:4000/api/status | { command -v jq >/dev/null 2>&1 && jq . || cat; }
    ;;
  logs)
    preflight
    shift || true
    exec "${COMPOSE[@]}" logs -f --tail=200 "$@"
    ;;
  down)
    preflight
    "${COMPOSE[@]}" down --remove-orphans
    ;;
  reset)
    preflight
    log "Removing containers and demo data volumes"
    "${COMPOSE[@]}" down -v --remove-orphans
    exec "$0" up
    ;;
  *)
    cat >&2 <<EOF_USAGE
Usage: ./demo.sh {up|bootstrap|smoke|status|logs [service]|down|reset}
EOF_USAGE
    exit 2
    ;;
esac
