#!/usr/bin/env python3
"""
Second-stage bootstrap for the customer RFP demo.

Runs only after the repository's existing bootstrap.py has completed successfully.

What is materialized in WSO2 IS 7.3:
- a dedicated M2M management application using Client Credentials + Organization Switch;
- a multi-level B2B organization hierarchy;
- resident users in multiple organization contexts;
- organization-local applications in multiple hierarchy levels;
- deliberately repeated user/app names in different organizations to demonstrate isolation.

The module uses supported WSO2 management/SCIM APIs and fails hard if the B2B
scenario cannot be verified. It does not replace or weaken the existing bootstrap.
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests
import urllib3

import bootstrap as core

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RUNTIME = Path("/runtime/runtime-config.json")
UI_RUNTIME = Path("/runtime/ui-config.json")
RFP_REPORT = Path("/runtime/rfp-bootstrap-report.json")

PUBLIC_WSO2 = os.getenv("PUBLIC_WSO2_BASE", "https://localhost:9443").rstrip("/")
VERIFY_TLS = False

MANAGEMENT_APP = "MarketSphere B2B Bootstrap Client"

ROOT_SCOPES = [
    "internal_organization_create",
    "internal_organization_view",
    "internal_org_organization_create",
    "internal_org_organization_view",
    "internal_org_user_mgt_create",
    "internal_org_user_mgt_list",
    "internal_org_user_mgt_view",
    "internal_org_application_mgt_create",
    "internal_org_application_mgt_view",
    "internal_org_application_mgt_update",
]

ORG_SCOPES = [
    "internal_org_organization_create",
    "internal_org_organization_view",
    "internal_org_user_mgt_create",
    "internal_org_user_mgt_list",
    "internal_org_user_mgt_view",
    "internal_org_application_mgt_create",
    "internal_org_application_mgt_view",
    "internal_org_application_mgt_update",
]

ORG_HIERARCHY_SCOPES = [
    "internal_org_organization_create",
    "internal_org_organization_view",
]

ORG_USER_SCOPES = [
    "internal_org_user_mgt_create",
    "internal_org_user_mgt_list",
    "internal_org_user_mgt_view",
]

ORG_APP_SCOPES = [
    "internal_org_application_mgt_create",
    "internal_org_application_mgt_view",
    "internal_org_application_mgt_update",
]

REPORT: dict[str, Any] = {"operations": [], "warnings": [], "verified": []}


def op(message: str) -> None:
    print(f"[rfp-bootstrap] {message}", flush=True)
    REPORT["operations"].append(message)


def warn(message: str) -> None:
    print(f"[rfp-bootstrap] WARNING: {message}", flush=True)
    REPORT["warnings"].append(message)


def fail(message: str) -> None:
    raise RuntimeError(message)


def payload_items(payload: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def bearer_request(
    method: str,
    path: str,
    token: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> requests.Response:
    url = f"{core.WSO2}{path}"
    headers = kwargs.pop("headers", {})
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **headers,
    }
    response = requests.request(
        method,
        url,
        headers=headers,
        verify=VERIFY_TLS,
        timeout=30,
        **kwargs,
    )
    if response.status_code not in expected:
        body = response.text[:1800]
        fail(f"{method} {path} -> HTTP {response.status_code}: {body}")
    return response


def find_scope_owners(scope_names: list[str]) -> dict[str, tuple[str, str]]:
    """Return {scope_name: (api_resource_id, api_resource_name)}."""
    response = core.request(
        "GET",
        "/api/server/v1/api-resources?limit=1000",
        expected=(200,),
    )
    resources = payload_items(response.json(), ("APIResources", "apiResources", "resources", "Resources", "items"))
    owners: dict[str, tuple[str, str]] = {}

    for item in resources:
        rid = item.get("id")
        if not rid:
            continue
        sresp = core.request(
            "GET",
            f"/api/server/v1/api-resources/{rid}/scopes",
            expected=(200, 404),
        )
        if sresp.status_code == 404:
            continue
        scopes = payload_items(sresp.json(), ("Scopes", "scopes", "Resources", "items"))
        for scope in scopes:
            name = scope.get("name")
            if name in scope_names:
                owners[name] = (rid, item.get("name") or item.get("identifier") or rid)

    return owners


def authorize_management_scopes(app_id: str) -> None:
    all_scopes = list(dict.fromkeys(ROOT_SCOPES))
    owners = find_scope_owners(all_scopes)
    missing = [scope for scope in all_scopes if scope not in owners]
    if missing:
        fail(
            "Could not locate the following WSO2 organization-management scopes: "
            + ", ".join(missing)
        )

    grouped: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}
    for scope, (rid, rname) in owners.items():
        grouped[rid].append(scope)
        names[rid] = rname

    for rid, scopes in grouped.items():
        core.authorize_api(app_id, {"id": rid}, sorted(scopes))
        op(f"Authorized {MANAGEMENT_APP} for {names[rid]}: {', '.join(sorted(scopes))}")


def ensure_management_client(grant_types: list[str]) -> dict[str, Any]:
    oauth = core.ensure_client(
        "marketsphere-b2b-bootstrap",
        MANAGEMENT_APP,
        grant_types,
        redirect_uris=[],
        public=False,
        pkce=False,
    )
    application = core.find_application(MANAGEMENT_APP)
    client = {
        "application_id": application.get("id"),
        "client_id": oauth.get("client_id"),
        "client_secret": oauth.get("client_secret"),
    }
    if not all(client.values()):
        fail("Management application did not return application/client credentials.")
    authorize_management_scopes(client["application_id"])
    return client


def token_client_credentials(client: dict[str, Any]) -> str:
    response = requests.post(
        f"{core.WSO2}/oauth2/token",
        auth=(client["client_id"], client["client_secret"]),
        data={
            "grant_type": "client_credentials",
            "scope": " ".join(ROOT_SCOPES),
        },
        verify=VERIFY_TLS,
        timeout=30,
    )
    if response.status_code != 200:
        fail(f"Client Credentials for B2B management app failed: {response.status_code} {response.text[:1800]}")
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        fail("No access_token returned for B2B management app.")
    granted = set((payload.get("scope") or "").split())
    missing = [s for s in ROOT_SCOPES if s not in granted]
    if missing:
        fail("B2B management token is missing required scopes: " + ", ".join(missing))
    op("Obtained scoped root management token using Client Credentials.")
    return token


def organization_switch(
    client: dict[str, Any],
    root_token: str,
    org_id: str,
    scopes: list[str] | None = None,
) -> str:
    requested = scopes or ORG_SCOPES
    last_error = ""
    for attempt in range(1, 11):
        response = requests.post(
            f"{core.WSO2}/oauth2/token",
            auth=(client["client_id"], client["client_secret"]),
            data={
                "grant_type": "organization_switch",
                "token": root_token,
                "switching_organization": org_id,
                "scope": " ".join(requested),
            },
            verify=VERIFY_TLS,
            timeout=30,
        )
        if response.status_code == 200:
            payload = response.json()
            token = payload.get("access_token")
            granted = set((payload.get("scope") or "").split())
            missing = [scope for scope in requested if scope not in granted]
            if token and not missing:
                op(f"Organization Switch token obtained for organization {org_id}.")
                return token
            last_error = "token missing scopes: " + ", ".join(missing)
        else:
            last_error = f"{response.status_code} {response.text[:1200]}"
        time.sleep(min(attempt, 3))
    fail(f"Organization Switch failed for {org_id}: {last_error}")


def list_child_orgs(token: str, *, root: bool = False) -> list[dict[str, Any]]:
    path = "/api/server/v1/organizations" if root else "/o/api/server/v1/organizations"
    response = bearer_request(
        "GET",
        path,
        token,
        expected=(200,),
        params={"limit": 100},
    )
    return payload_items(
        response.json(),
        ("organizations", "Organizations", "items"),
    )


def ensure_org(
    token: str,
    name: str,
    description: str,
    *,
    root: bool = False,
) -> dict[str, Any]:
    for org in list_child_orgs(token, root=root):
        if org.get("name") == name:
            op(f"Organization already exists: {name} ({org.get('id')})")
            return org

    path = "/api/server/v1/organizations" if root else "/o/api/server/v1/organizations"
    response = bearer_request(
        "POST",
        path,
        token,
        expected=(201,),
        headers={"Content-Type": "application/json"},
        json={
            "name": name,
            "description": description,
        },
    )
    created = response.json() if response.text.strip() else {}
    if created.get("id"):
        op(f"Created organization: {name} ({created.get('id')})")
        return created

    for org in list_child_orgs(token, root=root):
        if org.get("name") == name:
            op(f"Created organization: {name} ({org.get('id')})")
            return org

    fail(f"Organization '{name}' was created but could not be resolved.")


def share_management_app(app_id: str) -> None:
    response = core.request(
        "POST",
        "/api/server/v1/applications/share-with-all",
        expected=(200, 202, 400, 409),
        json={
            "applicationId": app_id,
            "policy": "ALL_EXISTING_AND_FUTURE_ORGS",
            "roleSharing": {"mode": "ALL"},
        },
    )

    if response.status_code in (200, 202):
        op(
            "Shared B2B management application with all existing "
            "and future organizations."
        )
        return

    check = core.request(
        "GET",
        f"/api/server/v1/applications/{app_id}/share?attributes=sharingMode",
        expected=(200, 404),
    )

    if check.status_code == 200:
        payload = check.json()
        sharing_mode = payload.get("sharingMode") or {}
        if sharing_mode.get("policy") == "ALL_EXISTING_AND_FUTURE_ORGS":
            op(
                "B2B management application is already shared with all "
                "existing and future organizations."
            )
            return

    fail(
        "Application share-with-all failed: "
        f"HTTP {response.status_code} {response.text[:1500]}"
    )


def scim_filter_username(username: str) -> str:
    # Requests takes care of URL encoding through params.
    return f'userName eq "{username}"'


def ensure_org_user(
    token: str,
    *,
    username: str,
    password: str,
    given_name: str,
    family_name: str,
    email: str,
) -> dict[str, Any]:
    response = bearer_request(
        "GET",
        "/o/scim2/Users",
        token,
        expected=(200,),
        params={"filter": scim_filter_username(username), "count": 20},
    )
    existing = payload_items(response.json(), ("Resources",))
    if existing:
        op(f"Resident user already exists: {username}")
        return existing[0]

    response = bearer_request(
        "POST",
        "/o/scim2/Users",
        token,
        expected=(201,),
        headers={"Content-Type": "application/scim+json"},
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "password": password,
            "name": {
                "givenName": given_name,
                "familyName": family_name,
            },
            "emails": [
                {
                    "value": email,
                    "type": "work",
                    "primary": True,
                }
            ],
            "active": True,
        },
    )
    user = response.json()
    op(f"Created resident user: {username} ({user.get('id')})")
    return user


def list_org_apps(token: str) -> list[dict[str, Any]]:
    response = bearer_request(
        "GET",
        "/o/api/server/v1/applications",
        token,
        expected=(200,),
        params={"limit": 100},
    )
    return payload_items(response.json(), ("applications", "items"))


def ensure_org_application(token: str, name: str, description: str) -> dict[str, Any]:
    for app in list_org_apps(token):
        if app.get("name") == name:
            op(f"Organization-local application already exists: {name} ({app.get('id')})")
            return app

    response = bearer_request(
        "POST",
        "/o/api/server/v1/applications",
        token,
        expected=(200, 201),
        headers={"Content-Type": "application/json"},
        json={
            "name": name,
            "description": description,
            "associatedRoles": {"allowedAudience": "APPLICATION"},
        },
    )
    created = response.json() if response.text.strip() else {}
    if created.get("id"):
        op(f"Created organization-local application: {name} ({created.get('id')})")
        return created

    for app in list_org_apps(token):
        if app.get("name") == name:
            op(f"Created organization-local application: {name} ({app.get('id')})")
            return app
    fail(f"Application '{name}' was created but could not be resolved.")


def publicize(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace(core.WSO2, PUBLIC_WSO2)
    if isinstance(value, list):
        return [publicize(v) for v in value]
    if isinstance(value, dict):
        return {k: publicize(v) for k, v in value.items()}
    return value


def validate_oidc_discovery() -> dict[str, Any]:
    candidates = [
        f"{core.WSO2}/oauth2/token/.well-known/openid-configuration",
        f"{core.WSO2}/oauth2/.well-known/openid-configuration",
        f"{core.WSO2}/.well-known/openid-configuration",
    ]
    result = {"validated": False, "url": None, "issuer": None, "jwks_uri": None}
    for url in candidates:
        try:
            response = requests.get(url, verify=VERIFY_TLS, timeout=10)
            if response.status_code == 200:
                payload = response.json()
                if payload.get("authorization_endpoint") and payload.get("token_endpoint"):
                    result = {
                        "validated": True,
                        "url": url.replace(core.WSO2, PUBLIC_WSO2),
                        "issuer": publicize(payload.get("issuer")),
                        "jwks_uri": publicize(payload.get("jwks_uri")),
                    }
                    op(f"OIDC Discovery validated: {result['url']}")
                    return result
        except Exception:
            pass
    warn("OIDC Discovery could not be auto-validated from the known local endpoint candidates.")
    return result


def rfp_matrix(discovery: dict[str, Any]) -> dict[str, Any]:
    # Status values deliberately distinguish what the laptop demo proves from
    # what must be shown as product/architecture/contractual evidence.
    requirements = [
        {"id":"RF-01","name":"Authorization Code + PKCE","status":"LIVE","evidence":"Portal Corporativo uses Authorization Code with PKCE (S256)."},
        {"id":"RF-02","name":"Client Credentials","status":"LIVE","evidence":"Orders M2M Client and the B2B bootstrap client use Client Credentials."},
        {"id":"RF-03","name":"Refresh Token + revocation","status":"CONFIGURED","evidence":"OIDC clients are provisioned with refresh_token and renew-refresh-token configuration; revocation is a platform endpoint rather than a staged UI action."},
        {"id":"RF-04","name":"Token Exchange RFC 8693","status":"LIVE","evidence":"External Keycloak subject token is exchanged by WSO2 for a reduced-scope downstream token."},
        {"id":"RF-05","name":"JWT Bearer RFC 7521/7523","status":"PLATFORM","evidence":"Supported by IS 7.3, but not synthesized as a fake live path in this POC."},
        {"id":"RF-06","name":"OpenID Connect","status":"LIVE","evidence":"Interactive login produces OIDC ID/access tokens."},
        {"id":"RF-07","name":"OIDC Discovery","status":"LIVE" if discovery.get("validated") else "PLATFORM","evidence":"Discovery endpoint was automatically validated at bootstrap." if discovery.get("validated") else "Supported by IS 7.3; local bootstrap could not auto-resolve the discovery URL."},
        {"id":"RF-08","name":"OIDC Back-Channel Logout","status":"PLATFORM","evidence":"Native capability; the current Portal demo exercises logout but not a second RP receiving a live back-channel Logout Token."},
        {"id":"RF-09","name":"External IdP federation","status":"LIVE","evidence":"Keycloak corporate OIDC IdP, JIT/correlation path, and optional Entra integration."},
        {"id":"RF-10","name":"SAML 2.0 + Passkeys","status":"PLATFORM","evidence":"Native capabilities; a hardware/browser passkey and an external SAML IdP are intentionally not fabricated by bootstrap."},
        {"id":"RF-11","name":"OTP / MFA resilience","status":"PLATFORM","evidence":"TOTP/SMS/Email/FIDO2 and adaptive authentication are platform capabilities. Provider failure/fallback needs an explicit provider/script, as stated in the submitted response."},
        {"id":"RF-12","name":"Business scopes","status":"LIVE","evidence":"API Resources, scopes, descriptions and application-scoped RBAC are provisioned by bootstrap. Advanced governance metadata remains an extension area."},
        {"id":"RF-13","name":"Tenant-scoped consent","status":"PLATFORM","evidence":"Consent Management is a native API/capability; this POC does not invent a consent audit history."},
        {"id":"RF-14","name":"Delegated scope approval workflow","status":"PLATFORM","evidence":"Workflow/policy configuration is required; this is kept as evidence rather than a hard-coded approval screen."},
        {"id":"RF-15","name":"Multi-tenancy / B2B isolation","status":"LIVE","evidence":"Multi-level organizations, resident users, organization-local applications and Organization Switch are created and verified at bootstrap."},
        {"id":"RF-16","name":"Operational API Keys","status":"COMPLEMENTARY","evidence":"API-key lifecycle is a WSO2 API Manager capability; the IS demo uses OAuth credentials and does not misrepresent IS as APIM."},
        {"id":"RF-17","name":"Service Accounts","status":"LIVE","evidence":"M2M clients plus a distinct managed Agent identity/workload credential."},
        {"id":"RF-18","name":"Scale / 99.99% availability","status":"ARCHITECTURE","evidence":"Self-contained JWT/non-persistent token and HA deployment architecture are product capabilities; contractual SLA and Black-Friday load cannot be proven by a laptop demo."},
        {"id":"RF-19","name":"LGPD / GDPR","status":"PLATFORM","evidence":"Privacy/self-service APIs and product controls are evidence items; a complete enterprise DSAR workflow requires process/integration."},
        {"id":"RF-20","name":"Developer Experience / APIs / SDKs","status":"LIVE","evidence":"The entire POC is API-bootstrapped; REST/SCIM usage is visible in code. SDK language coverage remains as stated in the submitted response."},
        {"id":"RF-21","name":"Enterprise support","status":"CONTRACTUAL","evidence":"Subscription/support SLA is contractual evidence, not a runtime feature."},
    ]

    extended = [
        {"name":"Multiple authentication methods","status":"PLATFORM","evidence":"Passkeys, Magic Link, OTP/TOTP, federation/social and X.509 are native options; external channels/authenticators are not simulated."},
        {"name":"Per-application login flows","status":"CONFIGURED","evidence":"Applications have independent authentication configuration; Portal also has an explicit federated sequence."},
        {"name":"Conditional / adaptive authentication","status":"PLATFORM","evidence":"Adaptive Authentication supports risk/context-driven step-up; no fake SMS/risk provider is introduced."},
        {"name":"Multiple login attributes","status":"PLATFORM","evidence":"IS supports alternative login identifiers; current deterministic demo keeps usernames visually clear."},
        {"name":"Multiple user stores","status":"LIVE","evidence":"Primary WSO2 store plus CORP OpenLDAP secondary store; no migration is required."},
        {"name":"SCIM / JIT provisioning","status":"LIVE","evidence":"Bootstrap provisions identities using SCIM and federation is configured for JIT/correlation."},
        {"name":"Approval workflows","status":"PLATFORM","evidence":"Workflow support is shown as platform evidence; no cosmetic approval UI is substituted for a real workflow."},
        {"name":"User journeys / self-service","status":"CONFIGURED","evidence":"Native My Account/application catalog is used; registration/recovery/invite are product journeys."},
        {"name":"Multi-level B2B hierarchy","status":"LIVE","evidence":"Root -> business unit/partner -> sub-organization tree is provisioned and verified."},
        {"name":"Delegated B2B administration","status":"PLATFORM","evidence":"Organization-aware management APIs and Organization Switch are exercised by bootstrap; human delegated-console privileges remain a governed role assignment."},
        {"name":"Agent lifecycle / unique identity","status":"LIVE","evidence":"Managed Agent identity is created, owned, authorized and reported by bootstrap."},
        {"name":"Agent RBAC","status":"LIVE","evidence":"Agent-specific application role grants inventory.read/inventory.write rather than inheriting the human owner's token."},
        {"name":"Agent OBO / CIBA","status":"PLATFORM","evidence":"CIBA/OBO patterns are product capabilities. The live POC uses RFC 8693 delegation and an independent workload identity; it does not relabel that flow as CIBA."},
        {"name":"MCP authorization","status":"PLATFORM","evidence":"IS 7.3 documents MCP authorization; no MCP server is invented inside this identity-only repository."},
        {"name":"Branding / notification templates / localization","status":"PLATFORM","evidence":"Per-application/organization branding and notification/localization are native configuration capabilities; customer assets and real SMS/email providers are prerequisites."},
        {"name":"Management APIs and connectors","status":"LIVE","evidence":"Management, Organization and SCIM APIs drive bootstrap. Third-party fraud/verification connectors remain integration evidence."},
    ]
    return {
        "title": "Customer RFP Coverage",
        "generatedBy": "rfp_extension.py",
        "requirements": requirements,
        "extendedRequirements": extended,
        "oidcDiscovery": discovery,
        "legend": {
            "LIVE": "Materialized and executable/inspectable in this demo.",
            "CONFIGURED": "Materialized configuration; not necessarily a dedicated UI button.",
            "PLATFORM": "Native IS capability shown as product evidence, not simulated.",
            "COMPLEMENTARY": "Requires the complementary WSO2 product named in the response.",
            "ARCHITECTURE": "Architecture/scale property, not meaningfully proven on one laptop.",
            "CONTRACTUAL": "Contractual/support evidence, not a runtime capability.",
        },
    }


def build_tree(flat: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_parent: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    for item in flat:
        by_parent[item.get("parentKey")].append(item)

    def node(item: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in item.items() if k != "parentKey"}
        out["children"] = [node(child) for child in by_parent.get(item["key"], [])]
        return out

    return [node(item) for item in by_parent.get(None, [])]


def main() -> None:
    if not RUNTIME.exists():
        fail("runtime-config.json does not exist. The original bootstrap must run first.")

    runtime = json.loads(RUNTIME.read_text())

    client = ensure_management_client(["client_credentials"])
    root_token = token_client_credentials(client)

    # --- Hierarchy -----------------------------------------------------------
    # Root
    # ├── MarketSphere Retail Brazil
    # │   ├── Seller Alpha Commerce
    # │   │   └── Seller Alpha Logistics
    # │   └── Partner Fintech LATAM
    # └── MarketSphere International
    #     └── Marketplace Mexico

    flat_orgs: list[dict[str, Any]] = []

    def record(key: str, org: dict[str, Any], parent_key: str | None, depth: int) -> None:
        flat_orgs.append({
            "key": key,
            "id": org.get("id"),
            "name": org.get("name"),
            "description": org.get("description"),
            "parentKey": parent_key,
            "depth": depth,
        })

    retail = ensure_org(
        root_token,
        "MarketSphere Retail Brazil",
        "Brazilian retail business unit and parent organization for B2B sellers and partners.",
        root=True,
    )

    international = ensure_org(
        root_token,
        "MarketSphere International",
        "International business unit used to demonstrate a separate first-level hierarchy.",
        root=True,
    )

    # Share once with all current and future organizations.
    share_management_app(client["application_id"])

    # Organization Switch is enabled only after sharing.
    client = ensure_management_client(["client_credentials", "organization_switch"])
    root_token = token_client_credentials(client)

    record("retail-br", retail, None, 1)
    record("international", international, None, 1)

    retail_token = organization_switch(client, root_token, retail["id"], scopes=ORG_HIERARCHY_SCOPES)
    international_token = organization_switch(client, root_token, international["id"], scopes=ORG_HIERARCHY_SCOPES)

    seller = ensure_org(
        retail_token,
        "Seller Alpha Commerce",
        "Independent marketplace seller isolated inside the Retail Brazil organization.",
    )
    record("seller-alpha", seller, "retail-br", 2)

    fintech = ensure_org(
        retail_token,
        "Partner Fintech LATAM",
        "Financial-services B2B partner with its own resident identities and applications.",
    )
    record("fintech-latam", fintech, "retail-br", 2)

    seller_token = organization_switch(client, root_token, seller["id"], scopes=ORG_HIERARCHY_SCOPES)

    logistics = ensure_org(
        seller_token,
        "Seller Alpha Logistics",
        "Third-level logistics sub-organization delegated beneath Seller Alpha Commerce.",
    )
    record("seller-logistics", logistics, "seller-alpha", 3)

    mexico = ensure_org(
        international_token,
        "Marketplace Mexico",
        "Mexico marketplace organization, isolated from the Brazilian hierarchy.",
    )
    record("mexico", mexico, "international", 2)

    # Give app-sharing propagation a short deterministic window before using
    # Organization Switch against all newly-created child organizations.
    org_tokens = {
        "retail-br": retail_token,
        "seller-alpha": seller_token,
        "fintech-latam": organization_switch(client, root_token, fintech["id"]),
        "seller-logistics": organization_switch(client, root_token, logistics["id"]),
        "international": international_token,
        "mexico": organization_switch(client, root_token, mexico["id"]),
    }

    org_by_key = {item["key"]: item for item in flat_orgs}

    # --- Resident users ------------------------------------------------------
    user_specs = [
        ("retail-br", "retail.admin", "Retail@1234", "Renata", "Admin", "renata.admin@retail.example"),
        ("seller-alpha", "seller.admin", "Seller@1234", "Sofia", "Seller Admin", "sofia@seller-alpha.example"),
        ("seller-alpha", "operator", "Seller@1234", "Alex", "Seller Operator", "operator@seller-alpha.example"),
        ("fintech-latam", "fintech.admin", "Fintech@1234", "Fernando", "Fintech Admin", "fernando@fintech.example"),
        ("seller-logistics", "logistics.operator", "Logistics@1234", "Lucas", "Logistics Operator", "lucas@logistics.example"),
        ("international", "intl.admin", "International@1234", "Isabela", "International Admin", "isabela@international.example"),
        # Deliberately same username as Seller Alpha, but a different resident
        # identity in another organization tree.
        ("mexico", "operator", "Mexico@1234", "Olivia", "Mexico Operator", "operator@marketplace-mx.example"),
        ("mexico", "mexico.admin", "Mexico@1234", "Mariana", "Mexico Admin", "mariana@marketplace-mx.example"),
    ]
    # Refresh root management authorization before resident-user validation.
    root_token = token_client_credentials(client)
    users_public = []
    for org_key, username, password, given, family, email in user_specs:
        # Obtain a fresh organization-scoped token immediately before the
        # SCIM operation. Organization Switch access tokens are intentionally
        # treated as short-lived context tokens and are not cached across the
        # complete bootstrap.
        root_token = token_client_credentials(client)
        operation_token = organization_switch(
            client,
            root_token,
            org_by_key[org_key]["id"],
            scopes=ORG_USER_SCOPES,
        )
        user = ensure_org_user(
            operation_token,
            username=username,
            password=password,
            given_name=given,
            family_name=family,
            email=email,
        )
        users_public.append({
            "organizationKey": org_key,
            "organization": org_by_key[org_key]["name"],
            "organizationId": org_by_key[org_key]["id"],
            "id": user.get("id"),
            "username": username,
            "email": email,
        })

    # --- Organization-local applications -----------------------------------
    # "Partner Storefront" intentionally exists in two isolated orgs.
    app_specs = [
        ("retail-br", "Retail Governance Console", "Application owned by the Retail Brazil organization."),
        ("seller-alpha", "Partner Storefront", "Seller Alpha resident marketplace application."),
        ("seller-alpha", "Seller Backoffice", "Seller-specific administration application."),
        ("fintech-latam", "Settlement Service", "Fintech partner settlement application."),
        ("seller-logistics", "Logistics Integration", "Application owned by the third-level logistics organization."),
        ("international", "International Partner Console", "Application owned by the international business unit."),
        ("mexico", "Partner Storefront", "Mexico resident marketplace application with the same display name as Seller Alpha."),
        ("mexico", "Mexico Operations", "Mexico organization operations application."),
    ]
    # Refresh root management authorization before application validation.
    root_token = token_client_credentials(client)
    apps_public = []
    for org_key, name, description in app_specs:
        # Re-acquire the organization context immediately before the
        # application-management operation for deterministic reruns.
        root_token = token_client_credentials(client)
        operation_token = organization_switch(
            client,
            root_token,
            org_by_key[org_key]["id"],
            scopes=ORG_APP_SCOPES,
        )
        app = ensure_org_application(operation_token, name, description)
        apps_public.append({
            "organizationKey": org_key,
            "organization": org_by_key[org_key]["name"],
            "organizationId": org_by_key[org_key]["id"],
            "id": app.get("id"),
            "name": name,
            "description": description,
        })

    # --- Verify materialized state ------------------------------------------
    if len(flat_orgs) != 6:
        fail(f"Expected 6 organizations, found {len(flat_orgs)}")
    if len(users_public) != 8:
        fail(f"Expected 8 resident users, found {len(users_public)}")
    if len(apps_public) != 8:
        fail(f"Expected 8 organization-local applications, found {len(apps_public)}")

    repeated_users = [u for u in users_public if u["username"] == "operator"]
    repeated_apps = [a for a in apps_public if a["name"] == "Partner Storefront"]
    if len({u["organizationId"] for u in repeated_users}) != 2 or len({u.get("id") for u in repeated_users}) != 2:
        fail("Isolation proof failed: repeated 'operator' users were not isolated into distinct objects.")
    if len({a["organizationId"] for a in repeated_apps}) != 2 or len({a.get("id") for a in repeated_apps}) != 2:
        fail("Isolation proof failed: repeated 'Partner Storefront' apps were not isolated into distinct objects.")

    REPORT["verified"] += [
        "6 B2B organizations across three hierarchy levels",
        "8 resident organization users",
        "8 organization-local applications",
        "same username 'operator' exists in two isolated organizations",
        "same application name 'Partner Storefront' exists in two isolated organizations",
        "Organization Switch used to administer organization contexts",
    ]

    discovery = validate_oidc_discovery()

    runtime["b2b"] = {
        "ready": True,
        "managementPattern": "Client Credentials + Organization Switch + Organization APIs",
        "managementApplication": {
            "name": MANAGEMENT_APP,
            "applicationId": client["application_id"],
            "clientId": client["client_id"],
            # Deliberately do not write the management client secret into the public B2B block.
        },
        "hierarchy": build_tree(flat_orgs),
        "organizations": [{k: v for k, v in o.items() if k != "parentKey"} for o in flat_orgs],
        "residentUsers": users_public,
        "organizationApplications": apps_public,
        "isolationProof": {
            "sameUsername": "operator",
            "userOrganizations": [u["organization"] for u in repeated_users],
            "sameApplicationName": "Partner Storefront",
            "applicationOrganizations": [a["organization"] for a in repeated_apps],
            "statement": "The repeated names resolve to different WSO2 object IDs in different organization contexts.",
        },
    }
    runtime["rfp"] = rfp_matrix(discovery)

    RUNTIME.write_text(json.dumps(runtime, indent=2, ensure_ascii=False) + "\n")

    # Rebuild the browser-safe file from the already-sanitized file generated
    # by the original bootstrap, adding only B2B/RFP blocks that contain no
    # OAuth client secrets.
    if UI_RUNTIME.exists():
        ui_runtime = json.loads(UI_RUNTIME.read_text())
    else:
        ui_runtime = {}
    ui_runtime["b2b"] = runtime["b2b"]
    ui_runtime["rfp"] = runtime["rfp"]
    UI_RUNTIME.write_text(json.dumps(ui_runtime, indent=2, ensure_ascii=False) + "\n")

    RFP_REPORT.write_text(json.dumps(REPORT, indent=2, ensure_ascii=False) + "\n")

    print("\n[rfp-bootstrap] ==================================================", flush=True)
    print("[rfp-bootstrap] CUSTOMER RFP DEMO READY", flush=True)
    print("[rfp-bootstrap] 6 organizations / 3 levels", flush=True)
    print("[rfp-bootstrap] 8 resident users", flush=True)
    print("[rfp-bootstrap] 8 organization-local applications", flush=True)
    print("[rfp-bootstrap] B2B isolation proof populated", flush=True)
    print("[rfp-bootstrap] ==================================================\n", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        REPORT["fatal"] = str(exc)
        try:
            RFP_REPORT.write_text(json.dumps(REPORT, indent=2, ensure_ascii=False) + "\n")
        except Exception:
            pass
        print(f"[rfp-bootstrap] FATAL: {exc}", flush=True)
        raise
