#!/usr/bin/env bash
set -euo pipefail

./scripts/validate-mcp-server-registration.sh

echo "============================================================"
echo "AGENT IDENTITY + MCP + CIBA/OBO NON-INTERACTIVE VALIDATION"
echo "============================================================"

curl -fsS http://localhost:8200/health >/tmp/agent-mcp-health.json
curl -fsS http://localhost:8200/policy >/tmp/agent-mcp-policy.json
curl -fsS http://localhost:5002/health >/tmp/agent-mcp-agent-health.json
curl -fsS http://localhost:5002/config >/tmp/agent-mcp-public-config.json

echo "PASS MCP server health"
echo "PASS Agent MCP runner health"

python3 - <<'PY'
import json

policy=json.load(open("/tmp/agent-mcp-policy.json"))
cfg=json.load(open("/tmp/agent-mcp-public-config.json"))

assert cfg["ready"] is True
assert cfg["resource"]["scopes"]["read"]=="inventory.mcp.read"
assert cfg["resource"]["scopes"]["adjust"]=="inventory.mcp.adjust"
assert cfg["ciba"]["actorToken"] is True
assert cfg["ciba"]["notificationChannel"]=="external"

roles={r["name"]:set(r["permissions"]) for r in cfg["roles"]}
assert roles["inventory-mcp-agent-reader"] == {"inventory.mcp.read"}
assert roles["inventory-mcp-human-approver"] == {
    "inventory.mcp.read",
    "inventory.mcp.adjust",
    "inventory.mcp.audit",
}

tools={t["name"]:t for t in policy["tools"]}
assert tools["inventory_get_snapshot"]["requiresOBO"] is False
assert tools["inventory_adjust_stock"]["requiresOBO"] is True
assert tools["inventory_get_audit"]["requiresOBO"] is True

serialized=json.dumps(cfg).lower()
for forbidden in ("clientsecret","client_secret","agentsecret","password"):
    assert forbidden not in serialized, f"public Agent/MCP metadata exposes {forbidden}"

print("PASS MCP scopes and role permissions")
print("PASS sensitive tools require OBO")
print("PASS public Agent/MCP metadata contains no secrets")
PY

curl -fsS \
  -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:5002/demo/preflight \
  -d '{}' \
  >/tmp/agent-mcp-preflight.json

python3 - <<'PY'
import json

r=json.load(open("/tmp/agent-mcp-preflight.json"))
assert r.get("ok") is True, r
claims=r["agentToken"]
assert claims.get("aut")=="AGENT", claims
scope=set(claims.get("scope") or [])
assert "inventory.mcp.read" in scope, scope
assert "inventory.mcp.adjust" not in scope, scope

assert r["readResult"]["ok"] is True
denied=r["sensitiveMutation"]["result"]
assert denied["ok"] is False
assert denied["status"]==403
assert denied["code"] in {"insufficient_scope","human_approval_required"}

print("PASS native Agent token has aut=AGENT")
print("PASS autonomous Agent has inventory.mcp.read")
print("PASS autonomous Agent does NOT have inventory.mcp.adjust")
print("PASS real MCP read tool succeeds with Agent identity")
print("PASS real MCP mutation is denied pending human approval")
PY

echo
echo "NON-INTERACTIVE AGENT/MCP VALIDATION PASSED"
echo "Interactive CIBA/OBO approval:"
echo "  ./scripts/agent-mcp-ciba-demo.sh"
