#!/usr/bin/env bash
set -euo pipefail

echo "== Agent/MCP/CIBA provisioning diagnostics =="
echo

echo "[1] Current MCP client function"
python3 - <<'PY'
from pathlib import Path
import ast

p=Path("bootstrap/agent_mcp_ciba_extension.py")
src=p.read_text()
tree=ast.parse(src)
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name=="ensure_ciba_mcp_client":
        lines=src.splitlines()
        print("\n".join(lines[node.lineno-1:node.end_lineno]))
        break
else:
    raise SystemExit("ensure_ciba_mcp_client not found")
PY

echo
echo "[2] CIBA discovery metadata"
curl -ks https://localhost:9443/oauth2/token/.well-known/openid-configuration \
  | python3 -m json.tool \
  | grep -E '"backchannel_authentication_endpoint"|"grant_types_supported"|"urn:openid:params:grant-type:ciba"' \
  || true

echo
echo "[3] Recent WSO2 CIBA/OAuth errors"
docker compose logs --no-color --tail=350 wso2is \
  | grep -Ei -A12 -B8 'CIBA|SE-50000|OAuth|Unexpected Processing Error' \
  | tail -220 \
  || true
