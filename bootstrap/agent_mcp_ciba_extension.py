#!/usr/bin/env python3
"""Provision the expert Agent Identity + MCP + CIBA/OBO demo.

This extension runs AFTER the normal bootstrap so it can reuse:
- Carol (human approver)
- Inventory Reconciliation Agent (first-class Agent Identity)
- the published runtime configuration and JWKS/issuer metadata

It creates a dedicated MCP resource and a dedicated confidential MCP client
application that is used for BOTH:
  1) App-Native Agent authentication (actor token)
  2) CIBA with actor_token (human-approved OBO token)

Least privilege is intentional:
- Agent role: inventory.mcp.read only
- Carol approver role: inventory.mcp.read + inventory.mcp.adjust + inventory.mcp.audit
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import bootstrap as core

RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
RUNTIME_PATH = RUNTIME_DIR / "runtime-config.json"
UI_RUNTIME_PATH = RUNTIME_DIR / "ui-config.json"
PRIVATE_PATH = RUNTIME_DIR / "agent-mcp-private.json"

CIBA_GRANT = "urn:openid:params:grant-type:ciba"
MCP_RESOURCE_TYPE = "MCP"
MCP_NAME = "MarketSphere Inventory MCP"
MCP_IDENTIFIER = "https://mcp.marketsphere.local/inventory"
MCP_APP_NAME = "Inventory MCP Agent Client"
MCP_CLIENT_NAME = "marketsphere-inventory-mcp-agent-client"

SCOPE_READ = "inventory.mcp.read"
SCOPE_ADJUST = "inventory.mcp.adjust"
SCOPE_AUDIT = "inventory.mcp.audit"
ALL_SCOPES = [SCOPE_READ, SCOPE_ADJUST, SCOPE_AUDIT]


def log(message: str) -> None:
    print(f"[agent-mcp] {message}", flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_runtime() -> dict[str, Any]:
    if not RUNTIME_PATH.exists():
        fail("runtime-config.json is missing; run the base bootstrap first")
    return json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))


def exact_user(username: str) -> dict[str, Any]:
    users = core.scim_filter("Users", "userName", username)
    exact = [
        user for user in users
        if str(user.get("userName") or "").split("/", 1)[-1] == username
    ]
    if len(exact) != 1:
        fail(f"Expected exactly one user {username!r}; found {len(exact)}")
    return exact[0]


def inventory_agent() -> dict[str, Any]:
    response = core.request(
        "GET",
        "/scim2/Agents?count=100",
        headers={"Accept": "application/scim+json"},
    )
    for agent in response.json().get("Resources", []):
        details = agent.get(core.AGENT_SCHEMA, {})
        if details.get("DisplayName") == "Inventory Reconciliation Agent":
            return agent
    fail("Inventory Reconciliation Agent was not found")


def enable_app_native_authentication(app_id: str) -> None:
    """Use a PATCH-specific payload; never echo GET advancedConfigurations.

    IS 7.3 may return internal/read-only advanced-configuration fields. Sending
    the full GET object back is what caused the original 400 in the legacy demo.
    """
    app = core.request(
        "GET", f"/api/server/v1/applications/{app_id}"
    ).json()
    if (
        app.get("advancedConfigurations", {})
        .get("enableAPIBasedAuthentication")
        is True
    ):
        log("App-Native Authentication already enabled.")
        return

    core.request(
        "PATCH",
        f"/api/server/v1/applications/{app_id}",
        expected=(200, 204),
        json={
            "advancedConfigurations": {
                "enableAPIBasedAuthentication": True,
            }
        },
    )

    updated = core.request(
        "GET", f"/api/server/v1/applications/{app_id}"
    ).json()
    if (
        updated.get("advancedConfigurations", {})
        .get("enableAPIBasedAuthentication")
        is not True
    ):
        fail("App-Native Authentication was not persisted")

    log("Enabled App-Native Authentication with a minimal PATCH payload.")


def configure_ciba(app_id: str) -> None:
    path = (
        f"/api/server/v1/applications/{app_id}"
        "/inbound-protocols/oidc"
    )
    oidc = core.request("GET", path).json()
    oidc.pop("state", None)
    oidc.pop("issuer", None)

    grants = list(dict.fromkeys(
        list(oidc.get("grantTypes") or [])
        + ["authorization_code", CIBA_GRANT]
    ))
    oidc["grantTypes"] = grants

    # These names are the native WSO2 OAuth application properties used by IS.
    oidc["cibaAuthReqExpiryTime"] = 300
    oidc["cibaNotificationChannels"] = "external"
    oidc["cibaSkipUserValidation"] = False
    oidc["cibaAllowFederatedUsers"] = False

    oidc.setdefault("accessToken", {})
    oidc["accessToken"]["type"] = "JWT"

    validators = set(oidc.get("scopeValidators") or [])
    validators.add("Role based scope validator")
    oidc["scopeValidators"] = sorted(validators)

    core.request(
        "PUT",
        path,
        expected=(200, 201),
        json=oidc,
    )

    saved = core.request("GET", path).json()
    saved_grants = set(saved.get("grantTypes") or [])
    if CIBA_GRANT not in saved_grants:
        fail("CIBA grant was not persisted on Inventory MCP Agent Client")

    channels = saved.get("cibaNotificationChannels")
    if isinstance(channels, list):
        external = any(str(x).lower() == "external" for x in channels)
    else:
        external = "external" in str(channels or "").lower()
    if not external:
        fail(
            "External CIBA notification channel was not persisted: "
            f"{channels!r}"
        )

    expiry = saved.get("cibaAuthReqExpiryTime")
    if expiry is not None and int(expiry) < 120:
        fail(f"Unexpected CIBA auth request expiry: {expiry}")

    log("Configured CIBA: 300s expiry + External notification channel.")



def _api_resource_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("apiResources", "APIResources", "resources", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _find_api_resource_by_identifier(identifier: str) -> dict[str, Any] | None:
    # Resolve by identifier using server-side filtering. The tenant contains
    # many built-in resources, so first-page enumeration is not reliable.
    response = core.session.get(
        f"{core.WSO2}/api/server/v1/api-resources",
        params={
            "filter": f"identifier eq {identifier}",
            "limit": 100,
        },
        timeout=45,
    )
    if response.status_code != 200:
        raise RuntimeError(
            "Could not query API resource by identifier "
            f"{identifier!r}: HTTP {response.status_code} "
            f"{response.text[:2000]}"
        )

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

        if details.get("identifier") == identifier:
            matches.append(details)

    if len(matches) > 1:
        fail(
            f"Multiple API resources use identifier {identifier!r}: "
            f"{[(x.get('id'), x.get('name'), x.get('type')) for x in matches]!r}"
        )

    return matches[0] if matches else None

def _find_application_optional(display_name: str) -> dict[str, Any] | None:
    payload = core.request(
        "GET",
        "/api/server/v1/applications?limit=100",
    ).json()
    applications = (
        payload.get("applications")
        or payload.get("Applications")
        or []
    )
    exact = [
        app for app in applications
        if isinstance(app, dict) and app.get("name") == display_name
    ]
    if len(exact) > 1:
        fail(f"Multiple applications found with name {display_name!r}")
    return exact[0] if exact else None


def _detach_authorized_resource_if_present(
    application_name: str,
    resource_id: str,
) -> None:
    application = _find_application_optional(application_name)
    if not application:
        return

    app_id = application.get("id")
    if not app_id:
        return

    path = f"/api/server/v1/applications/{app_id}/authorized-apis"
    payload = core.request("GET", path).json()
    if isinstance(payload, list):
        authorized = payload
    elif isinstance(payload, dict):
        authorized = (
            payload.get("authorizedAPIs")
            or payload.get("apiResources")
            or payload.get("items")
            or []
        )
    else:
        authorized = []

    if any(
        isinstance(item, dict) and item.get("id") == resource_id
        for item in authorized
    ):
        core.request(
            "DELETE",
            f"{path}/{resource_id}",
            expected=(204,),
        )
        log(
            f"Removed legacy authorization for {application_name} "
            "before MCP resource migration."
        )


def ensure_mcp_server_resource(
    name: str,
    identifier: str,
    scopes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create/reconcile a first-class WSO2 MCP Server resource.

    The Console's Resources > MCP Servers view uses the same API Resource
    Management API as normal business API resources, but creation must include
    resourceType=MCP. Existing BUSINESS resources cannot be converted through
    the normal update model, so this helper migrates this demo's legacy
    resource by deleting and recreating only the exact known identifier.
    """
    existing = _find_api_resource_by_identifier(identifier)

    if existing:
        resource_id = existing.get("id")
        if not resource_id:
            fail(f"Existing resource {identifier!r} has no id")

        details = core.request(
            "GET",
            f"/api/server/v1/api-resources/{resource_id}",
        ).json()
        resource_type = str(
            details.get("type")
            or details.get("resourceType")
            or existing.get("type")
            or existing.get("resourceType")
            or ""
        ).upper()

        if resource_type == MCP_RESOURCE_TYPE:
            reconciled = core.ensure_api_resource(name, identifier, scopes)
            persisted = core.request(
                "GET",
                f"/api/server/v1/api-resources/{reconciled['id']}",
            ).json()
            persisted_type = str(
                persisted.get("type")
                or persisted.get("resourceType")
                or ""
            ).upper()
            if persisted_type != MCP_RESOURCE_TYPE:
                fail(
                    "MCP resource lost its resource type during reconciliation: "
                    f"{persisted_type!r}"
                )
            log("First-class MCP Server resource is configured.")
            return persisted

        if existing.get("name") != name and details.get("name") != name:
            fail(
                "Refusing to migrate an unrelated API resource that happens "
                f"to use {identifier!r}: {details!r}"
            )

        log(
            f"Migrating legacy {resource_type or 'BUSINESS'} resource "
            f"{name!r} to first-class MCP Server resource."
        )

        _detach_authorized_resource_if_present(MCP_APP_NAME, resource_id)
        core.request(
            "DELETE",
            f"/api/server/v1/api-resources/{resource_id}",
            expected=(204,),
        )

    response = core.request(
        "POST",
        "/api/server/v1/api-resources",
        expected=(200, 201),
        json={
            "name": name,
            "identifier": identifier,
            "description": (
                "Inventory MCP Server protected by WSO2 Identity Server; "
                "read is autonomous, while adjust/audit use human-approved OBO."
            ),
            "requiresAuthorization": True,
            "scopes": scopes,
            "resourceType": MCP_RESOURCE_TYPE,
        },
    )

    created = response.json() if response.content else {}
    resource_id = created.get("id")
    if not resource_id:
        found = _find_api_resource_by_identifier(identifier)
        resource_id = (found or {}).get("id")
    if not resource_id:
        fail("MCP Server was created but its resource id could not be resolved")

    persisted = core.request(
        "GET",
        f"/api/server/v1/api-resources/{resource_id}",
    ).json()
    persisted_type = str(
        persisted.get("type")
        or persisted.get("resourceType")
        or ""
    ).upper()
    if persisted_type != MCP_RESOURCE_TYPE:
        fail(
            "WSO2 did not persist the MCP resource type; "
            f"expected MCP, got {persisted_type!r}: {persisted!r}"
        )

    persisted_scopes = {
        item.get("name")
        for item in (persisted.get("scopes") or [])
        if isinstance(item, dict)
    }
    expected_scopes = {item["name"] for item in scopes}
    if not expected_scopes.issubset(persisted_scopes):
        fail(
            "MCP scopes were not persisted. "
            f"expected={sorted(expected_scopes)!r} "
            f"actual={sorted(x for x in persisted_scopes if x)!r}"
        )

    log("Created first-class MCP Server resource with resourceType=MCP.")
    return persisted


def write_runtime(
    runtime: dict[str, Any],
    mcp_resource: dict[str, Any],
    app: dict[str, Any],
    oauth: dict[str, Any],
    agent: dict[str, Any],
) -> None:
    agent_secret = (
        runtime.get("agent", {}).get("secret")
        or agent.get("password")
        or agent.get("secret")
    )
    if not agent_secret:
        fail(
            "Managed Agent secret is unavailable. The secret is returned only "
            "when the Agent is created; preserve the runtime volume or recreate "
            "the demo environment."
        )

    client_secret = oauth.get("client_secret")
    if not client_secret:
        fail("Inventory MCP Agent Client has no client secret")

    agent_id = (
        runtime.get("agent", {}).get("id")
        or agent.get("userName")
        or agent.get("id")
    )
    resource_id = (
        runtime.get("agent", {}).get("resourceId")
        or agent.get("id")
    )

    expected_subjects = list(dict.fromkeys(
        str(x) for x in (agent_id, resource_id) if x
    ))

    public = {
        "ready": True,
        "architecture": "Agent Identity -> MCP -> CIBA actor_token -> OBO",
        "resource": {
            "id": mcp_resource["id"],
            "name": MCP_NAME,
            "identifier": MCP_IDENTIFIER,
            "type": MCP_RESOURCE_TYPE,
            "scopes": {
                "read": SCOPE_READ,
                "adjust": SCOPE_ADJUST,
                "audit": SCOPE_AUDIT,
            },
        },
        "mcpServer": {
            "publicUrl": "http://localhost:8200/mcp",
            "healthUrl": "http://localhost:8200/health",
            "policyUrl": "http://localhost:8200/policy",
            "transport": "Streamable HTTP",
            "tools": [
                {
                    "name": "inventory_get_snapshot",
                    "requiredScopes": [SCOPE_READ],
                    "requiresOBO": False,
                },
                {
                    "name": "inventory_adjust_stock",
                    "requiredScopes": [SCOPE_READ, SCOPE_ADJUST],
                    "requiresOBO": True,
                    "humanApproval": "CIBA",
                },
                {
                    "name": "inventory_get_audit",
                    "requiredScopes": [SCOPE_AUDIT],
                    "requiresOBO": True,
                },
            ],
        },
        "client": {
            "applicationId": app["id"],
            "displayName": MCP_APP_NAME,
            "clientId": oauth["client_id"],
            "grantTypes": ["authorization_code", CIBA_GRANT],
            "appNativeAuthentication": True,
            "redirectUri": "http://inventory-agent-mcp:5002/callback",
        },
        "agent": {
            "id": agent_id,
            "resourceId": resource_id,
            "displayName": "Inventory Reconciliation Agent",
            "expectedSubjects": expected_subjects,
            "role": "inventory-mcp-agent-reader",
            "permissions": [SCOPE_READ],
            "tokenSemantics": {
                "sub": "Inventory Agent identity",
                "aut": "AGENT",
                "act": None,
            },
        },
        "humanApprover": {
            "username": "carol",
            "role": "inventory-mcp-human-approver",
            "permissions": ALL_SCOPES,
        },
        "ciba": {
            "grantType": CIBA_GRANT,
            "notificationChannel": "external",
            "authRequestExpirySeconds": 300,
            "loginHint": "carol",
            "publicEndpoint": f"{core.WSO2_PUBLIC}/t/carbon.super/oauth2/ciba",
            "publicTokenEndpoint": f"{core.WSO2_PUBLIC}/t/carbon.super/oauth2/token",
            "requestedScopes": ["openid", *ALL_SCOPES],
            "actorToken": True,
            "oboClaims": {
                "sub": "human approver",
                "act.sub": "Inventory Agent identity",
            },
        },
        "roles": [
            {
                "name": "inventory-mcp-agent-reader",
                "principal": "Inventory Reconciliation Agent",
                "permissions": [SCOPE_READ],
            },
            {
                "name": "inventory-mcp-human-approver",
                "principal": "carol",
                "permissions": ALL_SCOPES,
            },
        ],
        "demo": {
            "agentService": "http://localhost:5002",
            "interactiveScript": "./scripts/agent-mcp-ciba-demo.sh",
            "validationScript": "./scripts/validate-agent-mcp-ciba.sh",
        },
    }

    runtime["agentMcp"] = public
    RUNTIME_PATH.write_text(
        json.dumps(runtime, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Secrets needed only by the agent process are deliberately stored outside
    # runtime-config.json so /api/config and ui-config can never accidentally
    # expose the CIBA client secret.
    private = {
        "clientId": oauth["client_id"],
        "clientSecret": client_secret,
        "agentId": agent_id,
        "agentSecret": agent_secret,
        "authorizationEndpointInternal": (
            f"{core.WSO2}/oauth2/authorize"
        ),
        "authnEndpointInternal": f"{core.WSO2}/oauth2/authn",
        "tokenEndpointInternal": f"{core.WSO2}/oauth2/token",
        "cibaEndpointInternal": (
            f"{core.WSO2}/t/carbon.super/oauth2/ciba"
        ),
        "cibaTokenEndpointInternal": (
            f"{core.WSO2}/t/carbon.super/oauth2/token"
        ),
    }
    PRIVATE_PATH.write_text(
        json.dumps(private, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        PRIVATE_PATH.chmod(0o600)
    except OSError:
        pass

    if UI_RUNTIME_PATH.exists():
        ui = json.loads(UI_RUNTIME_PATH.read_text(encoding="utf-8"))
        ui["agentMcp"] = public
        UI_RUNTIME_PATH.write_text(
            json.dumps(ui, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    log("Published public Agent/MCP metadata and separate private credentials.")



def _oidc_meta_options(payload, *path):
    current = payload
    for key in path:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    return current if isinstance(current, list) else []


def _discover_ciba_grant_type():
    meta = core.request(
        "GET",
        "/api/server/v1/applications/meta/inbound-protocols/oidc",
        expected=(200,),
    ).json()

    options = _oidc_meta_options(
        meta,
        "allowedGrantTypes",
        "options",
    )

    candidates = []
    for option in options:
        if not isinstance(option, dict):
            continue
        name = str(option.get("name") or "")
        display = str(option.get("displayName") or "")
        haystack = f"{name} {display}".lower()
        if "ciba" in haystack or "backchannel" in haystack:
            candidates.append(option)

    if len(candidates) != 1:
        available = [
            {
                "name": option.get("name"),
                "displayName": option.get("displayName"),
            }
            for option in options
            if isinstance(option, dict)
        ]
        raise RuntimeError(
            "Could not uniquely discover the CIBA grant type from "
            "WSO2 OIDC application metadata. Candidates="
            f"{candidates}; available={available}"
        )

    grant_type = candidates[0].get("name")
    if not grant_type:
        raise RuntimeError(
            f"CIBA metadata option has no name: {candidates[0]}"
        )

    print(
        "[agent-mcp] Application Management CIBA grant identifier: "
        f"{grant_type}",
        flush=True,
    )
    return grant_type


def ensure_ciba_mcp_client(client_name, display_name):
    """
    Reconcile the dedicated confidential MCP CIBA client using the
    Application Management representation exposed by this IS 7.3 runtime.

    IS 7.3 represents CIBA configuration as:

        cibaAuthenticationRequest:
            authReqExpiryTime
            notificationChannels
            skipUserValidation
            allowFederatedUsers
    """
    import copy

    ciba_grant = "urn:openid:params:grant-type:ciba"

    # OAuth redirect used by the app-native Authorization Code flow.
    # This is distinct from any CIBA human-approval callback/notification.
    oauth_redirect_uri = os.getenv(
        "MCP_AGENT_REDIRECT_URI",
        "http://inventory-agent-mcp:5002/callback",
    )

    ciba_callback_url = os.getenv(
        "MCP_APPROVAL_CALLBACK_URL",
        "http://localhost:5001/callback",
    )

    ciba_expiry_seconds = int(
        os.getenv("MCP_CIBA_AUTH_REQ_EXPIRY", "300")
    )

    if ciba_expiry_seconds <= 0:
        raise RuntimeError(
            "MCP_CIBA_AUTH_REQ_EXPIRY must be greater than zero"
        )

    log(f"MCP OAuth redirect URI: {oauth_redirect_uri}")
    log(f"MCP CIBA approval callback URL: {ciba_callback_url}")
    log(
        "Application Management CIBA grant identifier: "
        f"{ciba_grant}"
    )
    log(
        "CIBA authentication request expiry: "
        f"{ciba_expiry_seconds}s"
    )

    # Seed the application with a conventional confidential OAuth client.
    # CIBA is added below using the server's actual Application Management
    # representation.
    oauth = core.ensure_client(
        client_name,
        display_name,
        ["authorization_code"],
        redirect_uris=[oauth_redirect_uri],
        public=False,
        pkce=False,
    )

    application = core.find_application(display_name)

    if not application:
        raise RuntimeError(
            f"Could not find application {display_name!r}"
        )

    application_id = application.get("id")

    if not application_id:
        raise RuntimeError(
            f"Application {display_name!r} has no id"
        )

    oidc_path = (
        f"/api/server/v1/applications/{application_id}"
        "/inbound-protocols/oidc"
    )

    # Read the exact representation returned by this server.
    response = core.session.get(
        f"{core.WSO2}{oidc_path}",
        timeout=45,
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Could not read Inventory MCP Agent Client OIDC configuration. "
            f"GET {oidc_path} -> HTTP "
            f"{response.status_code}: {response.text}"
        )

    current = response.json()

    #
    # Build the update from the server-returned representation rather than
    # inventing an OIDC payload. Remove known response-only properties.
    #
    payload = copy.deepcopy(current)

    # clientId is required when updating an existing OIDC inbound
    # configuration. Preserve the server-returned clientId.
    #
    # clientSecret/state are response-side values and are not needed
    # for this configuration update.
    for response_only in (
        "clientSecret",
        "state",
    ):
        payload.pop(response_only, None)

    if not payload.get("clientId"):
        raise RuntimeError(
            "OIDC configuration returned no clientId; refusing update"
        )

    #
    # Preserve Authorization Code for bootstrap compatibility and add CIBA.
    #
    grants = list(payload.get("grantTypes") or [])

    if "authorization_code" not in grants:
        grants.append("authorization_code")

    if ciba_grant not in grants:
        grants.append(ciba_grant)

    payload["grantTypes"] = grants

    # Authorization Code redirect_uri validation is exact. Ensure the
    # app-native Agent redirect URI is registered on this OAuth client.
    callback_urls = list(payload.get("callbackURLs") or [])

    if oauth_redirect_uri not in callback_urls:
        callback_urls.append(oauth_redirect_uri)

    payload["callbackURLs"] = callback_urls

    #
    # Dedicated CIBA client remains confidential.
    #
    payload["publicClient"] = False

    payload["clientAuthentication"] = (
        payload.get("clientAuthentication")
        or {}
    )

    payload["clientAuthentication"][
        "tokenEndpointAuthMethod"
    ] = "client_secret_post"

    #
    # THIS IS THE IMPORTANT IS 7.3 SHAPE.
    #
    payload["cibaAuthenticationRequest"] = {
        "authReqExpiryTime": ciba_expiry_seconds,
        "notificationChannels": ["external"],
        "skipUserValidation": False,
        "allowFederatedUsers": False,
    }

    log(
        "Updating Inventory MCP Agent Client using "
        "nested cibaAuthenticationRequest configuration"
    )

    update = core.session.put(
        f"{core.WSO2}{oidc_path}",
        json=payload,
        timeout=45,
    )

    if update.status_code not in (200, 201):
        raise RuntimeError(
            "Could not enable CIBA on Inventory MCP Agent Client. "
            f"PUT {oidc_path} -> HTTP "
            f"{update.status_code}: {update.text}"
        )

    #
    # Verify what IS actually persisted.
    #
    verify = core.session.get(
        f"{core.WSO2}{oidc_path}",
        timeout=45,
    )

    if verify.status_code != 200:
        raise RuntimeError(
            "CIBA update succeeded but verification failed. "
            f"GET {oidc_path} -> HTTP "
            f"{verify.status_code}: {verify.text}"
        )

    saved = verify.json()

    saved_grants = saved.get("grantTypes") or []

    if ciba_grant not in saved_grants:
        raise RuntimeError(
            "WSO2 did not persist the CIBA grant. "
            f"grantTypes={saved_grants!r}"
        )

    ciba = saved.get("cibaAuthenticationRequest") or {}

    expiry = ciba.get("authReqExpiryTime")

    try:
        expiry_value = int(expiry)
    except (TypeError, ValueError):
        expiry_value = 0

    if expiry_value <= 0:
        raise RuntimeError(
            "WSO2 persisted an invalid CIBA auth request expiry: "
            f"{expiry!r}"
        )

    channels = ciba.get("notificationChannels") or []

    if isinstance(channels, str):
        channels = [
            value.strip()
            for value in channels.split(",")
            if value.strip()
        ]

    normalized_channels = {
        str(value).strip().lower()
        for value in channels
    }

    if "external" not in normalized_channels:
        raise RuntimeError(
            "WSO2 did not persist the external CIBA "
            "notification channel. "
            f"notificationChannels={channels!r}"
        )

    if saved.get("publicClient") is not False:
        raise RuntimeError(
            "Inventory MCP Agent Client must remain confidential"
        )

    log(
        "CIBA client reconciled successfully: "
        f"expiry={expiry_value}s, "
        f"notificationChannels={channels!r}, "
        f"client_id={saved.get('clientId') or oauth.get('client_id')}"
    )

    return {
        **oauth,
        "application_id": application_id,
        "client_id": (
            saved.get("clientId")
            or oauth.get("client_id")
        ),
        "client_secret": oauth.get("client_secret"),
        "ciba_auth_req_expiry_time": expiry_value,
        "ciba_notification_channels": channels,
    }

def main() -> None:
    runtime = load_runtime()
    carol = exact_user("carol")
    agent = inventory_agent()

    mcp_resource = ensure_mcp_server_resource(
        MCP_NAME,
        MCP_IDENTIFIER,
        [
            {
                "name": SCOPE_READ,
                "displayName": "Read inventory through MCP",
                "description": (
                    "Permit the Inventory Agent to inspect inventory state."
                ),
            },
            {
                "name": SCOPE_ADJUST,
                "displayName": "Adjust inventory through MCP",
                "description": (
                    "Permit a sensitive stock mutation after human delegation."
                ),
            },
            {
                "name": SCOPE_AUDIT,
                "displayName": "Read inventory MCP audit trail",
                "description": (
                    "Read the user+agent attribution recorded for mutations."
                ),
            },
        ],
    )

    oauth = ensure_ciba_mcp_client(MCP_CLIENT_NAME, MCP_APP_NAME)
    app = core.find_application(MCP_APP_NAME)

    core.set_application_role_audience(app["id"])
    core.configure_oidc_protocol(app["id"])
    enable_app_native_authentication(app["id"])

    # The client is allowed to request the resource. Principal permissions are
    # still constrained by the application-audience roles below.
    core.authorize_api(app["id"], mcp_resource, ALL_SCOPES)

    # Stronger than the generic tutorial: the autonomous Agent receives ONLY
    # read. It cannot simply ask for the mutation scope with its own identity.
    core.ensure_role(
        "inventory-mcp-agent-reader",
        app["id"],
        [SCOPE_READ],
        users=[agent],
    )

    # Carol is the human approval principal. Her role is what allows the CIBA
    # OBO token to receive the elevated permissions after approval.
    core.ensure_role(
        "inventory-mcp-human-approver",
        app["id"],
        ALL_SCOPES,
        users=[carol],
    )

    write_runtime(runtime, mcp_resource, app, oauth, agent)

    print("", flush=True)
    log("==================================================")
    log("AGENT IDENTITY + MCP + CIBA/OBO READY")
    log("MCP Server resource: MarketSphere Inventory MCP [type=MCP]")
    log("Agent role: inventory-mcp-agent-reader -> read only")
    log("Human role: inventory-mcp-human-approver -> read/adjust/audit")
    log("Agent-only mutation: DENIED")
    log("CIBA actor_token -> OBO sub=user + act.sub=agent")
    log("MCP server: http://localhost:8200/mcp")
    log("Agent demo: http://localhost:5002")
    log("==================================================")
    print("", flush=True)


if __name__ == "__main__":
    main()
