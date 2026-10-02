#!/usr/bin/env bash
set -euo pipefail

echo "== First-class MCP Server registration =="

docker compose run --rm --no-deps bootstrap python - <<'PY'
import json
import bootstrap as core

NAME = "MarketSphere Inventory MCP"
IDENTIFIER = "https" + "://mcp.marketsphere.local/inventory"
APP = "Inventory MCP Agent Client"
EXPECTED_SCOPES = {
    "inventory.mcp.read",
    "inventory.mcp.adjust",
    "inventory.mcp.audit",
}
EXPECTED_ROLES = {
    "inventory-mcp-agent-reader": {"inventory.mcp.read"},
    "inventory-mcp-human-approver": EXPECTED_SCOPES,
}

response = core.session.get(
    f"{core.WSO2}/api/server/v1/api-resources",
    params={
        "filter": f"identifier eq {IDENTIFIER}",
        "limit": 100,
    },
    timeout=45,
)
assert response.status_code == 200, response.text

payload = response.json()
items = (
    payload
    if isinstance(payload, list)
    else payload.get("apiResources")
    or payload.get("APIResources")
    or payload.get("resources")
    or payload.get("items")
    or []
)

matches = []
for item in items:
    resource_id = item.get("id")
    if not resource_id:
        continue
    details = core.request(
        "GET",
        f"/api/server/v1/api-resources/{resource_id}",
    ).json()
    if details.get("identifier") == IDENTIFIER:
        matches.append(details)

assert len(matches) == 1, matches
resource_id = matches[0]["id"]

resource = core.request(
    "GET",
    f"/api/server/v1/api-resources/{resource_id}",
).json()
resource_type = str(
    resource.get("type") or resource.get("resourceType") or ""
).upper()
assert resource_type == "MCP", resource
assert resource.get("name") == NAME, resource

scope_names = {
    x.get("name") for x in resource.get("scopes", []) if isinstance(x, dict)
}
assert EXPECTED_SCOPES.issubset(scope_names), (EXPECTED_SCOPES, scope_names)

app = core.find_application(APP)
authorized = core.request(
    "GET",
    f"/api/server/v1/applications/{app['id']}/authorized-apis",
).json()
if isinstance(authorized, dict):
    authorized = (
        authorized.get("authorizedAPIs")
        or authorized.get("apiResources")
        or authorized.get("items")
        or []
    )
entry = next((x for x in authorized if x.get("id") == resource_id), None)
assert entry, authorized
authorized_scopes = {
    (x.get("name") if isinstance(x, dict) else x)
    for x in (entry.get("authorizedScopes") or entry.get("scopes") or [])
}
assert EXPECTED_SCOPES.issubset(authorized_scopes), authorized_scopes

roles_payload = core.request(
    "GET",
    "/scim2/v2/Roles?count=100",
    headers={"Accept": "application/scim+json"},
).json()
roles = roles_payload.get("Resources") or []
for role_name, expected_permissions in EXPECTED_ROLES.items():
    role = next(
        (
            x for x in roles
            if x.get("displayName") == role_name
            and str((x.get("audience") or {}).get("value") or "") == app["id"]
        ),
        None,
    )
    assert role, f"Missing application role {role_name}"
    full = core.request(
        "GET",
        f"/scim2/v2/Roles/{role['id']}",
        headers={"Accept": "application/scim+json"},
    ).json()
    permissions = {
        x.get("value") for x in (full.get("permissions") or []) if isinstance(x, dict)
    }
    assert expected_permissions.issubset(permissions), (
        role_name,
        expected_permissions,
        permissions,
    )

print(json.dumps({
    "mcpServer": {
        "id": resource_id,
        "name": resource.get("name"),
        "identifier": resource.get("identifier"),
        "type": resource_type,
        "scopes": sorted(scope_names),
    },
    "application": {
        "id": app["id"],
        "name": APP,
        "authorizedScopes": sorted(authorized_scopes),
    },
    "roles": {k: sorted(v) for k, v in EXPECTED_ROLES.items()},
}, indent=2))
print()
print("PASS: MCP Server is first-class, app-authorized, and role-bound")
PY
