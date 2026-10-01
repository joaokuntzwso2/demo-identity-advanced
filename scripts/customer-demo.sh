#!/usr/bin/env bash
set -euo pipefail
case "${1:-help}" in
  urls)
    cat <<'EOF'
Main demo:       http://localhost:3000/
RFP Demo Center: http://localhost:3000/rfp-demo.html
Application Portal: http://localhost:3100/
Finance Workspace:  http://localhost:3101/
Security Operations:http://localhost:3102/
B2B applications:   http://localhost:3201/ ... http://localhost:3208/
WSO2 Console:    https://localhost:9443/console
WSO2 My Account: https://localhost:9443/myaccount
Keycloak:        http://localhost:8081/
EOF
    ;;
  preflight) ./scripts/test-e2e-rfp.sh ;;
  logs) docker compose logs --tail=300 bootstrap ;;
  start) docker compose up --build -d ;;
  stop) docker compose down --remove-orphans ;;
  *)
    echo "Usage: ./scripts/customer-demo.sh {start|preflight|urls|logs|stop}"
    ;;
esac
