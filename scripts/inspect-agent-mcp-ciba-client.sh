#!/usr/bin/env bash
set -euo pipefail

docker compose run --rm --no-deps bootstrap python - <<'PY'
import json
import bootstrap as core

NAME = "Inventory MCP Agent Client"
CIBA = "urn:openid:params:grant-type:ciba"

app = core.find_application(NAME)
app_id = app["id"]
path = f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc"

oidc = core.request("GET", path).json()
client_id = oidc.get("clientId")

if not client_id:
    raise SystemExit("FAIL: Inventory MCP Agent Client has no clientId")

dcr = core.request(
    "GET",
    f"/api/identity/oauth2/dcr/v1.1/register/{client_id}",
).json()

print("Application:", NAME)
print("Application ID:", app_id)
print("Client ID:", client_id)
print("App Management grantTypes:", json.dumps(oidc.get("grantTypes")))
print("DCR grant_types:", json.dumps(dcr.get("grant_types")))
print("Callback URLs:", json.dumps(oidc.get("callbackURLs")))

for key in (
    "cibaAuthReqExpiryTime",
    "cibaNotificationChannels",
    "cibaSkipUserValidation",
    "cibaAllowFederatedUsers",
):
    if key in oidc:
        print(f"{key}:", json.dumps(oidc.get(key)))

assert CIBA in (oidc.get("grantTypes") or []), \
    "FAIL: CIBA absent from Application Management"
assert CIBA in (dcr.get("grant_types") or []), \
    "FAIL: CIBA absent from DCR"

print("PASS: CIBA grant is enabled and visible through both management APIs")
PY
