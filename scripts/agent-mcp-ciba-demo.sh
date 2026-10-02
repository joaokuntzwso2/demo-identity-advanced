#!/usr/bin/env bash
set -euo pipefail

BASE="${AGENT_MCP_DEMO_URL:-http://localhost:5002}"
START_FILE="$(mktemp)"
DONE_FILE="$(mktemp)"
trap 'rm -f "$START_FILE" "$DONE_FILE"' EXIT

echo "============================================================"
echo "INVENTORY AGENT + MCP + CIBA/OBO EXPERT DEMO"
echo "============================================================"
echo
echo "Phase 1:"
echo "  Inventory Agent obtains its own WSO2 Agent token."
echo "  It reads inventory through MCP."
echo "  It attempts a mutation and is denied."
echo

curl -fsS \
  -X POST \
  -H 'Content-Type: application/json' \
  "$BASE/demo/start" \
  -d '{
    "sku":"SKU-LAPTOP-001",
    "delta":-7,
    "reason":"Human-approved cycle count correction for demo"
  }' >"$START_FILE"

python3 - "$START_FILE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if not d.get("ok"):
    raise SystemExit(json.dumps(d,indent=2))

print("AGENT TOKEN")
print("-----------")
print(json.dumps(d["agentToken"],indent=2))
print()
print("MCP READ")
print("--------")
print(json.dumps(d["readResult"],indent=2))
print()
print("SENSITIVE MCP MUTATION - EXPECTED DENIAL")
print("----------------------------------------")
print(json.dumps(d["sensitiveMutation"],indent=2))
print()
print("CIBA REQUEST")
print("------------")
print("Binding message :",d["ciba"]["bindingMessage"])
print("Channel         :",d["ciba"]["notificationChannel"])
print("Approval URL    :",d["ciba"]["authUrl"])
print("Request ID      :",d["requestId"])
PY

AUTH_URL="$(
python3 - "$START_FILE" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["ciba"]["authUrl"])
PY
)"

REQUEST_ID="$(
python3 - "$START_FILE" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["requestId"])
PY
)"

echo
echo "============================================================"
echo "HUMAN APPROVAL REQUIRED"
echo "============================================================"
echo
echo "Open this URL in a PRIVATE / INCOGNITO browser:"
echo
echo "  $AUTH_URL"
echo
echo "Authenticate as:"
echo
echo "  carol / Carol@123"
echo
echo "Review the binding message and approve the CIBA request."
echo
echo "The agent cannot continue until WSO2 issues the OBO token."
echo
read -r -p "Press ENTER after Carol has approved the request... "

echo
echo "Phase 2:"
echo "  Poll CIBA token endpoint."
echo "  Verify OBO token: sub=Carol, act.sub=Inventory Agent."
echo "  Retry sensitive MCP mutation."
echo "  Read MCP audit showing BOTH identities."
echo

curl -fsS \
  -X POST \
  -H 'Content-Type: application/json' \
  "$BASE/demo/complete" \
  -d "{\"requestId\":\"$REQUEST_ID\",\"timeoutSeconds\":120}" \
  >"$DONE_FILE"

python3 - "$DONE_FILE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if not d.get("ok"):
    raise SystemExit(json.dumps(d,indent=2))

print("OBO TOKEN CLAIMS")
print("----------------")
print(json.dumps(d["oboToken"],indent=2))
print()
print("DUAL IDENTITY")
print("-------------")
print("Human sub :",d["dualIdentity"]["humanSub"])
print("Agent act.sub :",d["dualIdentity"]["agentSub"])
print()
print("APPROVED MCP MUTATION")
print("---------------------")
print(json.dumps(d["mutationResult"],indent=2))
print()
print("MCP AUDIT")
print("---------")
print(json.dumps(d["audit"],indent=2))
print()
print("============================================================")
print("DEMO COMPLETE")
print("Agent-only token       -> READ ALLOWED")
print("Agent-only mutation    -> DENIED")
print("Carol CIBA approval    -> OBO TOKEN")
print("OBO sub                -> HUMAN")
print("OBO act.sub            -> AGENT")
print("Sensitive MCP mutation -> ALLOWED + AUDITED")
print("============================================================")
PY
