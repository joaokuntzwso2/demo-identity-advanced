#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "BOOTSTRAP IDEMPOTENCY TEST"
echo "============================================================"

run_bootstrap() {
  local run="$1"
  echo
  echo "== bootstrap run ${run} =="
  docker compose up --build --force-recreate bootstrap

  local id
  id="$(docker compose ps -aq bootstrap)"
  [[ -n "$id" ]] || { echo "FAIL: bootstrap container not found"; exit 1; }

  local status exit_code
  status="$(docker inspect -f '{{.State.Status}}' "$id")"
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$id")"

  echo "status=${status} exit=${exit_code}"
  [[ "$status" == "exited" && "$exit_code" == "0" ]] || {
    echo "FAIL: bootstrap run ${run}"
    docker compose logs --tail=250 bootstrap
    exit 1
  }

  docker compose logs bootstrap | grep -F "CUSTOMER RFP DEMO READY" >/dev/null || {
    echo "FAIL: RFP completion marker missing on run ${run}"
    exit 1
  }

  echo "PASS: bootstrap run ${run}"
}

run_bootstrap 1
run_bootstrap 2

echo
echo "PASS: bootstrap is idempotent across consecutive executions"
