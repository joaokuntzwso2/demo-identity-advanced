#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile bootstrap/bootstrap.py
python3 -m json.tool platform/keycloak/realm.json >/dev/null
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose config --quiet
else
  printf 'Docker Compose is unavailable; skipped Compose schema validation.
' >&2
fi

node --check services/marketplace-api/src/server.js
node --check services/inventory-agent/src/server.js
bash -n demo.sh scripts/smoke.sh scripts/validate-static.sh

if command -v npm >/dev/null 2>&1; then
  (
    cd ui
    npm install --no-audit --no-fund
    npm run build
  )
else
  printf 'npm is unavailable; skipped the UI dependency build.
' >&2
fi

printf 'Static validation passed.
'
