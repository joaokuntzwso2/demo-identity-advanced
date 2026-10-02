#!/usr/bin/env bash
set -euo pipefail

echo "== Live B2B cross-organization protected-resource matrix =="

docker compose run --rm --no-deps \
  bootstrap python -u b2b_resource_isolation_test.py
