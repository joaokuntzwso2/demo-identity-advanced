#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm --no-deps bootstrap python -u admin_boundary.py --verify-only
