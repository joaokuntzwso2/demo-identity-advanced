#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [[ -f .lgpd-consent.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .lgpd-consent.env
  set +a
fi

docker compose \
  -f docker-compose.yml \
  -f docker-compose.lgpd-consent.yml \
  down
