#!/usr/bin/env bash
set -euo pipefail

echo "== Agent MCP/CIBA client verification =="

docker compose run --rm --no-deps bootstrap python - <<'PY'
import json
import bootstrap as core

payload = core.request(
    "GET",
    "/api/server/v1/applications?limit=100",
).json()

apps = payload.get("applications") or payload.get("Applications") or []
matches = []

for app in apps:
    app_id = app.get("id")
    if not app_id:
        continue

    response = core.session.get(
        f"{core.WSO2}/api/server/v1/applications/{app_id}/inbound-protocols/oidc",
        timeout=45,
    )
    if response.status_code != 200:
        continue

    oidc = response.json()
    grants = set(oidc.get("grantTypes") or [])

    if "urn:openid:params:grant-type:ciba" in grants:
        matches.append((app, oidc))

if not matches:
    raise SystemExit("FAIL: no application with CIBA grant configured")

print(f"Found {len(matches)} CIBA application(s)")

good = []
for app, oidc in matches:
    name = app.get("name")
    public = oidc.get("publicClient")
    grants = oidc.get("grantTypes") or []
    client_id = oidc.get("clientId")

    print()
    print("Application :", name)
    print("Client ID   :", client_id)
    print("Public      :", public)
    print("Grant types :", ", ".join(grants))

    if public is False:
        good.append((app, oidc))

if not good:
    raise SystemExit(
        "FAIL: CIBA exists only on public clients; "
        "WSO2 CIBA requires confidential client authentication in this demo"
    )

print()
print("PASS: at least one CIBA client is confidential")
PY
