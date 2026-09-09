#!/usr/bin/env python3
"""Idempotent bootstrap for the WSO2 Identity Server 7.3 customer POC.

The bootstrap intentionally uses only supported WSO2 management/SCIM/DCR APIs.
Where product builds expose optional properties with different names (agent-login
flag or federated sequence metadata), the bootstrap probes the resource metadata
and records a visible warning instead of silently pretending that it succeeded.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WSO2 = os.getenv("WSO2_BASE_URL", "https://wso2is:9443").rstrip("/")
WSO2_PUBLIC = os.getenv("WSO2_PUBLIC_BASE_URL", "https://localhost:9443").rstrip("/")
ADMIN = os.getenv("WSO2_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("WSO2_ADMIN_PASSWORD", "admin")
RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
STRICT = os.getenv("BOOTSTRAP_STRICT", "false").lower() == "true"
KEYCLOAK = os.getenv("KEYCLOAK_BASE_URL", "http://keycloak:8080").rstrip("/")
KEYCLOAK_PUBLIC = os.getenv("KEYCLOAK_PUBLIC_BASE_URL", "http://localhost:8081").rstrip("/")

SCIM = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_ROLE = "urn:ietf:params:scim:schemas:extension:2.0:Role"
AGENT_SCHEMA = "urn:scim:wso2:agent:schema"


def load_previous_runtime() -> dict[str, Any]:
    path = RUNTIME_DIR / "runtime-config.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


PREVIOUS_RUNTIME = load_previous_runtime()


@dataclass
class Report:
    completed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def ok(self, text: str) -> None:
        self.completed.append(text)
        print(f"[ok] {text}")

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        print(f"[warning] {text}")


report = Report()
session = requests.Session()
session.auth = (ADMIN, ADMIN_PASSWORD)
session.verify = False
session.headers.update({"Accept": "application/json"})


def request(method: str, path: str, *, expected: Iterable[int] = (200,), **kwargs: Any) -> requests.Response:
    url = path if path.startswith("http") else f"{WSO2}{path}"
    response = session.request(method, url, timeout=45, **kwargs)
    if response.status_code not in set(expected):
        body = response.text[:1000]
        raise RuntimeError(f"{method} {url} -> {response.status_code}: {body}")
    return response


def wait_for(url: str, label: str, timeout: int = 600) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code < 500:
                report.ok(f"{label} is ready")
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    raise TimeoutError(f"Timed out waiting for {label}: {url}")


def scim_filter(resource: str, attribute: str, value: str) -> list[dict[str, Any]]:
    expression = quote(f'{attribute} eq "{value}"')
    data = request(
        "GET",
        f"/scim2/{resource}?filter={expression}",
        headers={"Accept": "application/scim+json"},
    ).json()
    return data.get("Resources", [])


def ensure_user(username: str, password: str, given: str, family: str, email: str, department: str) -> dict[str, Any]:
    existing = scim_filter("Users", "userName", username)
    if existing:
        report.ok(f"Local user {username} already exists")
        return existing[0]
    payload = {
        "schemas": [SCIM, SCIM_ENTERPRISE],
        "userName": username,
        "password": password,
        "name": {"givenName": given, "familyName": family},
        "displayName": f"{given} {family}",
        "emails": [{"value": email, "type": "work", "primary": True}],
        "active": True,
        SCIM_ENTERPRISE: {"department": department, "employeeNumber": username.upper()},
    }
    created = request(
        "POST", "/scim2/Users", expected=(201,), json=payload,
        headers={"Content-Type": "application/scim+json", "Accept": "application/scim+json"},
    ).json()
    report.ok(f"Created local user {username}")
    return created


def ensure_group(name: str, member_ids: list[str]) -> dict[str, Any]:
    existing = scim_filter("Groups", "displayName", name)
    payload_members = [{"value": member_id} for member_id in member_ids]
    if existing:
        group = existing[0]
        current = {item.get("value") for item in group.get("members", [])}
        missing = [member for member in payload_members if member["value"] not in current]
        if missing:
            request(
                "PATCH", f"/scim2/Groups/{group['id']}", expected=(200, 204),
                json={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "add", "path": "members", "value": missing}],
                },
                headers={"Content-Type": "application/scim+json"},
            )
        report.ok(f"Group {name} is configured")
        return group
    created = request(
        "POST", "/scim2/Groups", expected=(201,),
        json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": name, "members": payload_members},
        headers={"Content-Type": "application/scim+json", "Accept": "application/scim+json"},
    ).json()
    report.ok(f"Created group {name}")
    return created


def _api_resource_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    for key in (
        "APIResources",
        "apiResources",
        "resources",
        "Resources",
        "items",
    ):
        value = payload.get(key)

        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    return []


def _resource_matches(
    item: dict[str, Any],
    identifier: str,
    name: str,
) -> bool:
    actual_identifier = str(
        item.get("identifier") or ""
    ).rstrip("/")

    expected_identifier = identifier.rstrip("/")

    return (
        actual_identifier == expected_identifier
        or item.get("name") == name
    )


def _absolute_management_url(href: str) -> str:
    if href.startswith("http://") or href.startswith("https://"):
        return (
            href
            .replace(WSO2_PUBLIC, WSO2)
            .replace("https://localhost:9443", WSO2)
        )

    if href.startswith("/"):
        return f"{WSO2}{href}"

    return f"{WSO2}/{href.lstrip('/')}"


def find_api_resource(
    identifier: str,
    name: str,
) -> dict[str, Any] | None:
    host_part = identifier.split("://", 1)[-1]

    expressions = [
        f"identifier eq {identifier}",
        f'identifier eq "{identifier}"',
        f"identifier co {host_part}",
        f"name eq {name}",
    ]

    for expression in expressions:
        response = session.get(
            f"{WSO2}/api/server/v1/api-resources",
            params={
                "filter": expression,
                "limit": 1000,
            },
            timeout=45,
        )

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError:
                payload = {}

            for item in _api_resource_items(payload):
                if _resource_matches(item, identifier, name):
                    return item

        elif response.status_code not in (400, 404):
            raise RuntimeError(
                f"GET {response.url} -> "
                f"{response.status_code}: "
                f"{response.text[:1000]}"
            )

    url = f"{WSO2}/api/server/v1/api-resources"
    params: dict[str, Any] | None = {"limit": 1000}
    visited: set[str] = set()

    for _ in range(100):
        response = session.get(
            url,
            params=params,
            timeout=45,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"GET {response.url} -> "
                f"{response.status_code}: "
                f"{response.text[:1000]}"
            )

        payload = response.json()

        for item in _api_resource_items(payload):
            if _resource_matches(item, identifier, name):
                return item

        next_url = None

        links = (
            payload.get("links", [])
            if isinstance(payload, dict)
            else []
        )

        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict):
                    continue

                href = str(link.get("href") or "")
                rel = str(link.get("rel") or "").lower()

                if (
                    href
                    and (
                        rel in {"next", "after"}
                        or "after=" in href
                    )
                ):
                    candidate = _absolute_management_url(href)

                    if candidate not in visited:
                        next_url = candidate
                        break

        if not next_url:
            break

        visited.add(next_url)
        url = next_url
        params = None

    return None


def ensure_api_resource(
    name: str,
    identifier: str,
    scopes: list[dict[str, str]],
) -> dict[str, Any]:
    summary = find_api_resource(identifier, name)
    created_now = False

    if summary is None:
        payload = {
            "name": name,
            "identifier": identifier,
            "description": (
                "Preloaded business API for the "
                f"customer POC: {name}"
            ),
            "requiresAuthorization": True,
            "scopes": scopes,
        }

        response = session.post(
            f"{WSO2}/api/server/v1/api-resources",
            json=payload,
            timeout=45,
        )

        if response.status_code in (200, 201):
            created_now = True

            if response.content:
                try:
                    summary = response.json()
                except ValueError:
                    summary = None

            if not summary or not summary.get("id"):
                summary = find_api_resource(identifier, name)

        elif response.status_code == 409:
            summary = find_api_resource(identifier, name)

        else:
            raise RuntimeError(
                f"POST {response.url} -> "
                f"{response.status_code}: "
                f"{response.text[:1000]}"
            )

    if summary is None or not summary.get("id"):
        raise RuntimeError(
            "API resource exists but could not be retrieved: "
            f"{identifier} ({name})"
        )

    resource_id = summary["id"]

    resource = request(
        "GET",
        f"/api/server/v1/api-resources/{resource_id}",
    ).json()

    scope_response = request(
        "GET",
        (
            f"/api/server/v1/api-resources/"
            f"{resource_id}/scopes"
        ),
        expected=(200, 404),
    )

    existing_scopes = (
        scope_response.json()
        if scope_response.status_code == 200
        else []
    )

    existing_names = {
        scope.get("name")
        for scope in existing_scopes
        if (
            isinstance(scope, dict)
            and scope.get("name")
        )
    }

    missing_scopes = [
        scope
        for scope in scopes
        if scope["name"] not in existing_names
    ]

    if missing_scopes:
        request(
            "PUT",
            (
                f"/api/server/v1/api-resources/"
                f"{resource_id}/scopes"
            ),
            expected=(200, 204),
            json=missing_scopes,
        )

        existing_scopes = request(
            "GET",
            (
                f"/api/server/v1/api-resources/"
                f"{resource_id}/scopes"
            ),
        ).json()

    resource["scopes"] = existing_scopes

    if created_now:
        report.ok(f"Created API resource {name}")
    else:
        report.ok(f"API resource {name} is configured")

    return resource


def _find_application_optional(
    display_name: str,
) -> dict[str, Any] | None:
    response = session.get(
        f"{WSO2}/api/server/v1/applications",
        params={
            "limit": 100,
            "filter": f"name eq {display_name}",
        },
        timeout=45,
    )

    if response.status_code == 200:
        payload = response.json()
        applications = (
            payload.get("applications")
            or payload.get("Applications")
            or []
        )

        for application in applications:
            if application.get("name") == display_name:
                return application

    payload = request(
        "GET",
        "/api/server/v1/applications?limit=100",
    ).json()

    applications = (
        payload.get("applications")
        or payload.get("Applications")
        or []
    )

    for application in applications:
        if application.get("name") == display_name:
            return application

    return None


def _application_id_from_create(
    response: requests.Response,
    display_name: str,
) -> str:
    if response.content:
        try:
            payload = response.json()
            application_id = (
                payload.get("id")
                or payload.get("applicationId")
            )

            if application_id:
                return application_id
        except ValueError:
            pass

    location = response.headers.get("Location", "").rstrip("/")

    if location:
        candidate = location.rsplit("/", 1)[-1]

        if candidate:
            return candidate

    application = _find_application_optional(display_name)

    if application and application.get("id"):
        return application["id"]

    raise RuntimeError(
        "Application was created but its id could not "
        f"be resolved: {display_name}"
    )


def _normalize_callback_urls(
    redirect_uris: list[str],
) -> list[str]:
    import re

    unique_uris = list(dict.fromkeys(
        uri.strip()
        for uri in redirect_uris
        if uri and uri.strip()
    ))

    if len(unique_uris) <= 1:
        return unique_uris

    alternatives = "|".join(
        re.escape(uri)
        for uri in unique_uris
    )

    return [f"regexp=({alternatives})"]


def _origins_from_redirects(
    redirect_uris: list[str],
) -> list[str]:
    origins: set[str] = set()

    for uri in redirect_uris:
        if "://" not in uri:
            continue

        scheme, remainder = uri.split("://", 1)
        authority = remainder.split("/", 1)[0]

        if authority:
            origins.add(f"{scheme}://{authority}")

    return sorted(origins)


def ensure_client(
    client_name: str,
    display_name: str,
    grant_types: list[str],
    *,
    redirect_uris: list[str] | None = None,
    public: bool = False,
    pkce: bool = False,
) -> dict[str, Any]:
    redirect_uris = redirect_uris or []

    application = _find_application_optional(display_name)
    created_application = application is None

    if application is None:
        response = request(
            "POST",
            "/api/server/v1/applications",
            expected=(201,),
            json={
                "name": display_name,
                "description": (
                    "Preloaded OAuth/OIDC application for "
                    f"the customer POC: {client_name}"
                ),
                "associatedRoles": {
                    "allowedAudience": "APPLICATION"
                },
            },
        )

        application_id = _application_id_from_create(
            response,
            display_name,
        )

        application = {
            "id": application_id,
            "name": display_name,
        }
    else:
        application_id = application["id"]

    oidc_path = (
        f"/api/server/v1/applications/{application_id}"
        "/inbound-protocols/oidc"
    )

    current_response = session.get(
        f"{WSO2}{oidc_path}",
        timeout=45,
    )

    if current_response.status_code == 200:
        oidc = current_response.json()
        oidc.pop("state", None)
        oidc.pop("issuer", None)

    elif current_response.status_code == 404:
        oidc = {}

    else:
        raise RuntimeError(
            f"GET {WSO2}{oidc_path} -> "
            f"{current_response.status_code}: "
            f"{current_response.text[:1000]}"
        )

    oidc["grantTypes"] = grant_types
    oidc["callbackURLs"] = _normalize_callback_urls(redirect_uris)
    oidc["allowedOrigins"] = _origins_from_redirects(
        redirect_uris
    )
    oidc["publicClient"] = public

    oidc["pkce"] = {
        "mandatory": pkce,
        "supportPlainTransformAlgorithm": False,
    }

    oidc["accessToken"] = {
        **oidc.get("accessToken", {}),
        "type": "JWT",
        "userAccessTokenExpiryInSeconds": 3600,
        "applicationAccessTokenExpiryInSeconds": 3600,
    }

    oidc["refreshToken"] = {
        **oidc.get("refreshToken", {}),
        "expiryInSeconds": 86400,
        "renewRefreshToken": True,
    }

    oidc["idToken"] = {
        **oidc.get("idToken", {}),
        "expiryInSeconds": 3600,
    }

    update_response = request(
        "PUT",
        oidc_path,
        expected=(200, 201),
        json=oidc,
    )

    if update_response.content:
        try:
            updated = update_response.json()
        except ValueError:
            updated = request("GET", oidc_path).json()
    else:
        updated = request("GET", oidc_path).json()

    if not public and not updated.get("clientSecret"):
        secret_response = request(
            "POST",
            f"{oidc_path}/regenerate-secret",
            expected=(200,),
        )

        if secret_response.content:
            secret_payload = secret_response.json()
            updated["clientSecret"] = (
                secret_payload.get("clientSecret")
                or secret_payload.get("client_secret")
            )

    if not updated.get("clientId"):
        refreshed = request("GET", oidc_path).json()
        updated.update(refreshed)

    result = {
        "client_id": updated.get("clientId"),
        "client_secret": updated.get("clientSecret"),
    }

    if not result["client_id"]:
        raise RuntimeError(
            f"OIDC client id was not returned for {display_name}"
        )

    if not public and not result["client_secret"]:
        raise RuntimeError(
            f"OIDC client secret was not returned for {display_name}"
        )

    action = "Created" if created_application else "Configured"
    report.ok(f"{action} OAuth client {display_name}")

    return result



def _discoverable_group_payload(
    groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    # Convert SCIM groups into the IS 7.3 Application Management API shape.
    by_store: dict[str, list[dict[str, str]]] = {}

    for group in groups:
        group_id = group.get("id")
        display_name = group.get("displayName") or group.get("name")
        if not group_id or not display_name:
            continue

        if "/" in display_name:
            store, group_name = display_name.split("/", 1)
        else:
            store, group_name = "PRIMARY", display_name

        by_store.setdefault(store.upper(), []).append({
            "id": group_id,
            "name": group_name,
        })

    return [
        {"userStore": store, "groups": values}
        for store, values in sorted(by_store.items())
    ]


def ensure_discoverable_application(
    app_id: str,
    access_url: str,
    groups: list[dict[str, Any]],
) -> None:
    # Configure the shipped My Account application catalog. This is not a
    # custom launcher: discoverability and group filtering are native IS 7.3.
    path = f"/api/server/v1/applications/{app_id}"
    # IMPORTANT: build a PATCH-specific payload instead of copying the full
    # advancedConfigurations object returned by GET. IS 7.3 may return
    # read-only/internal fields such as additionalSpProperties, and the
    # Application Management PATCH API rejects those fields with APP-60506.
    advanced = {
        "discoverableByEndUsers": True,
        "discoverableGroups": _discoverable_group_payload(groups),
        # These users are pre-assigned demo users. Authorization is still
        # enforced separately through application roles and API scopes.
        "skipLoginConsent": True,
        "skipLogoutConsent": True,
    }

    request(
        "PATCH",
        path,
        expected=(200, 204),
        json={
            "accessUrl": access_url,
            "advancedConfigurations": advanced,
        },
    )

    updated = request("GET", path).json()
    persisted = updated.get("advancedConfigurations") or {}

    if not persisted.get("discoverableByEndUsers"):
        raise RuntimeError(
            f"Discoverability was not persisted for application {app_id}"
        )

    expected_group_ids = {
        group["id"]
        for group in groups
        if group.get("id")
    }
    persisted_group_ids = {
        group.get("id")
        for store in persisted.get("discoverableGroups", [])
        for group in store.get("groups", [])
        if group.get("id")
    }
    if expected_group_ids and not expected_group_ids.issubset(persisted_group_ids):
        raise RuntimeError(
            "Discoverable Groups were not persisted as expected for "
            f"{updated.get('name') or app_id}"
        )

    report.ok(
        "Configured native My Account discovery for "
        f"{updated.get('name') or app_id}"
    )


def find_application(display_name: str) -> dict[str, Any]:
    response = session.get(
        f"{WSO2}/api/server/v1/applications?limit=100&filter={quote(f'name eq {display_name}')}",
        timeout=45,
    )
    apps = []
    if response.status_code == 200:
        data = response.json()
        apps = data.get("applications") or data.get("Applications") or []
    for app in apps:
        if app.get("name") == display_name:
            return app
    # Fall back to a full list because filter handling can vary by update level,
    # especially for names that contain spaces.
    data = request("GET", "/api/server/v1/applications?limit=100").json()
    apps = data.get("applications") or data.get("Applications") or []
    for app in apps:
        if app.get("name") == display_name:
            return app
    raise RuntimeError(f"Application not found after DCR: {display_name}")

def authorize_api(
    app_id: str,
    api: dict[str, Any],
    scopes: list[str],
) -> None:
    path = (
        f"/api/server/v1/applications/"
        f"{app_id}/authorized-apis"
    )

    def read_authorizations() -> list[dict[str, Any]]:
        payload = request("GET", path).json()

        if isinstance(payload, list):
            return payload

        return (
            payload.get("authorizedAPIs")
            or payload.get("AuthorizedAPIs")
            or []
        )

    def find_authorization(
        entries: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        return next(
            (
                entry
                for entry in entries
                if entry.get("id") == api["id"]
            ),
            None,
        )

    def scope_names(
        authorization: dict[str, Any],
    ) -> set[str]:
        values = (
            authorization.get("authorizedScopes")
            or authorization.get("scopes")
            or []
        )

        return {
            (
                item.get("name")
                if isinstance(item, dict)
                else item
            )
            for item in values
            if (
                item.get("name")
                if isinstance(item, dict)
                else item
            )
        }

    entries = read_authorizations()
    matching = find_authorization(entries)

    if matching is None:
        request(
            "POST",
            path,
            expected=(200, 201),
            json={
                "id": api["id"],
                "policyIdentifier": "RBAC",
                "scopes": scopes,
            },
        )

        entries = read_authorizations()
        matching = find_authorization(entries)

        if matching is None:
            raise RuntimeError(
                "WSO2 accepted the API authorization request "
                "but the authorization was not persisted: "
                f"application={app_id}, api={api['id']}"
            )

    current_scopes = scope_names(matching)
    missing_scopes = [
        scope
        for scope in scopes
        if scope not in current_scopes
    ]

    if missing_scopes:
        request(
            "PATCH",
            f"{path}/{api['id']}",
            expected=(200, 204),
            json={
                "addedScopes": missing_scopes,
                "removedScopes": [],
            },
        )

        entries = read_authorizations()
        matching = find_authorization(entries)

        if matching is None:
            raise RuntimeError(
                "Authorized API disappeared after scope update: "
                f"application={app_id}, api={api['id']}"
            )

        current_scopes = scope_names(matching)
        still_missing = [
            scope
            for scope in scopes
            if scope not in current_scopes
        ]

        if still_missing:
            raise RuntimeError(
                "WSO2 completed the authorization update but "
                "the following scopes remain absent: "
                f"{still_missing}"
            )

    api_name = (
        api.get("name")
        or api.get("displayName")
        or api["id"]
    )

    report.ok(
        f"Authorized {api_name} for application {app_id}"
    )


def ensure_role(name: str, app_id: str, permissions: list[str], groups: list[dict[str, Any]] | None = None, users: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    # Application-audience roles are used so the role claim and scope grants remain
    # isolated to the application that owns the protected resource.
    role_filter = quote(f'displayName eq "{name}"')
    response = request("GET", f"/scim2/v2/Roles?filter={role_filter}&count=100", headers={"Accept": "application/scim+json"})
    resources = response.json().get("Resources", [])
    role = next((item for item in resources if item.get("audience", {}).get("value") == app_id), None)
    desired_permissions = {permission for permission in permissions}
    desired_groups = {group["id"] for group in (groups or [])}
    desired_users = {user["id"] for user in (users or [])}
    if role:
        role = request("GET", f"/scim2/v2/Roles/{role['id']}", headers={"Accept": "application/scim+json"}).json()
        operations = []
        current_permissions = {item.get("value") for item in role.get("permissions", [])}
        current_groups = {item.get("value") for item in role.get("groups", [])}
        current_users = {item.get("value") for item in role.get("users", [])}
        if desired_permissions - current_permissions:
            operations.append({"op": "add", "path": "permissions", "value": [{"value": value, "display": value} for value in sorted(desired_permissions - current_permissions)]})
        if desired_groups - current_groups:
            operations.append({"op": "add", "path": "groups", "value": [{"value": value} for value in sorted(desired_groups - current_groups)]})
        if desired_users - current_users:
            operations.append({"op": "add", "path": "users", "value": [{"value": value} for value in sorted(desired_users - current_users)]})
        if operations:
            request(
                "PATCH", f"/scim2/v2/Roles/{role['id']}", expected=(200, 204),
                json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": operations},
                headers={"Content-Type": "application/scim+json", "Accept": "application/scim+json"},
            )
        report.ok(f"Role {name} is configured")
        return role
    payload = {
        "schemas": [SCIM_ROLE],
        "displayName": name,
        "audience": {"value": app_id, "type": "application"},
        "permissions": [{"value": permission, "display": permission} for permission in permissions],
        "groups": [{"value": group["id"]} for group in (groups or [])],
        "users": [{"value": user["id"]} for user in (users or [])],
    }
    created = request(
        "POST", "/scim2/v2/Roles", expected=(201,), json=payload,
        headers={"Content-Type": "application/scim+json", "Accept": "application/scim+json"},
    ).json()
    report.ok(f"Created role {name}")
    return created

def ensure_agent(owner_user_id: str) -> dict[str, Any]:
    response = request("GET", "/scim2/Agents?count=100", headers={"Accept": "application/scim+json"})
    for agent in response.json().get("Resources", []):
        details = agent.get(AGENT_SCHEMA, {})
        if details.get("DisplayName") == "Inventory Reconciliation Agent":
            # The initial password is deliberately returned only at creation. Persisted
            # runtime configuration retains it across idempotent bootstrap executions.
            previous_secret = PREVIOUS_RUNTIME.get("agent", {}).get("secret")
            if previous_secret:
                agent["password"] = previous_secret
            report.ok("Managed agent identity already exists")
            return agent
    payload = {
        AGENT_SCHEMA: {
            "DisplayName": "Inventory Reconciliation Agent",
            "Description": "Autonomous agent that reconciles inventory using least-privilege API scopes.",
            "Owner": f"{owner_user_id}@carbon.super",
        }
    }
    created = request(
        "POST", "/scim2/Agents", expected=(201,), json=payload,
        headers={"Content-Type": "application/scim+json", "Accept": "application/scim+json"},
    ).json()
    report.ok("Created first-class managed agent identity")
    return created

def ensure_agent_app_setting(app_id: str) -> bool:
    """Enable the supported app-native authentication setting for agent login."""
    app = request("GET", f"/api/server/v1/applications/{app_id}").json()
    advanced = app.get("advancedConfigurations", {})
    if advanced.get("enableAPIBasedAuthentication") is True:
        report.ok("App-native authentication is enabled for the agent application")
        return True
    advanced["enableAPIBasedAuthentication"] = True
    response = session.patch(
        f"{WSO2}/api/server/v1/applications/{app_id}",
        json={"advancedConfigurations": advanced},
        timeout=45,
    )
    if response.status_code in (200, 204):
        report.ok("Enabled app-native authentication for the agent application")
        return True
    report.warn(f"The app-native application flag returned {response.status_code}; the dedicated client-credentials fallback remains available")
    return False


def ensure_oidc_department_claim() -> None:
    oidc_dialect_id = (
        "aHR0cDovL3dzbzIub3JnL29pZGMvY2xhaW0"
    )
    claims_path = (
        f"/api/server/v1/claim-dialects/"
        f"{oidc_dialect_id}/claims"
    )

    oidc_claims = request("GET", claims_path).json()

    department_mapping = next(
        (
            claim
            for claim in oidc_claims
            if claim.get("claimURI") == "department"
        ),
        None,
    )

    if department_mapping is None:
        request(
            "POST",
            claims_path,
            expected=(201, 409),
            json={
                "claimURI": "department",
                "mappedLocalClaimURI": (
                    "http://wso2.org/claims/department"
                ),
            },
        )
        report.ok(
            "Created OIDC department claim mapping"
        )
    else:
        mapped_local_claim = department_mapping.get(
            "mappedLocalClaimURI"
        )

        if (
            mapped_local_claim
            != "http://wso2.org/claims/department"
        ):
            claim_id = department_mapping["id"]

            request(
                "PUT",
                f"{claims_path}/{claim_id}",
                expected=(200,),
                json={
                    "claimURI": "department",
                    "mappedLocalClaimURI": (
                        "http://wso2.org/claims/department"
                    ),
                },
            )

        report.ok(
            "OIDC department claim mapping is configured"
        )

    scopes = request(
        "GET",
        "/api/server/v1/oidc/scopes",
    ).json()

    profile_scope = next(
        (
            scope
            for scope in scopes
            if scope.get("name") == "profile"
        ),
        None,
    )

    if profile_scope is None:
        raise RuntimeError(
            "The built-in OIDC profile scope was not found"
        )

    profile_claims = set(
        profile_scope.get("claims", [])
    )

    if "department" not in profile_claims:
        profile_claims.add("department")

        request(
            "PUT",
            "/api/server/v1/oidc/scopes/profile",
            expected=(200,),
            json={
                "displayName": profile_scope.get(
                    "displayName",
                    "Profile",
                ),
                "description": profile_scope.get(
                    "description",
                    "Retrieve profile information of the user.",
                ),
                "claims": sorted(profile_claims),
            },
        )

        report.ok(
            "Added department to the OIDC profile scope"
        )
    else:
        report.ok(
            "OIDC profile scope contains department"
        )


def configure_oidc_protocol(app_id: str, *, browser_origin: str | None = None, subject_token: bool = False) -> None:
    ensure_oidc_department_claim()
    path = f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc"
    oidc = request("GET", path).json()
    oidc.pop("state", None)
    oidc.pop("issuer", None)
    if browser_origin:
        oidc["allowedOrigins"] = sorted(set(oidc.get("allowedOrigins", []) + [browser_origin]))
    oidc.setdefault("accessToken", {})
    oidc["accessToken"]["type"] = "JWT"
    attributes = set(oidc["accessToken"].get("accessTokenAttributes", []))
    attributes.update({
        "username",
        "email",
        "given_name",
        "family_name",
        "department",
        "roles",
        "groups",
    })
    oidc["accessToken"]["accessTokenAttributes"] = sorted(attributes)
    validators = set(oidc.get("scopeValidators", []))
    validators.add("Role based scope validator")
    oidc["scopeValidators"] = sorted(validators)
    if subject_token:
        oidc.setdefault("subjectToken", {})
        oidc["subjectToken"].update({"enable": True, "applicationSubjectTokenExpiryInSeconds": 3600})
    request("PUT", path, expected=(200, 201), json=oidc)
    report.ok(f"Configured JWT claims and role-based scope validation for application {app_id}")


def set_application_role_audience(app_id: str) -> None:
    app = request("GET", f"/api/server/v1/applications/{app_id}").json()
    current = app.get("associatedRoles", {}).get("allowedAudience")
    if current == "APPLICATION":
        return
    request(
        "PATCH", f"/api/server/v1/applications/{app_id}", expected=(200, 204),
        json={"associatedRoles": {"allowedAudience": "APPLICATION"}},
    )
    report.ok(f"Set application role audience for {app_id}")


def oidc_authenticator_metadata() -> dict[str, Any] | None:
    catalog = request(
        "GET",
        (
            "/api/server/v1/identity-providers/"
            "meta/federated-authenticators"
        ),
    ).json()

    authenticators = (
        catalog
        if isinstance(catalog, list)
        else (
            catalog.get("federatedAuthenticators")
            or catalog.get("federatedAuthentators")
            or []
        )
    )

    summary = next(
        (
            item
            for item in authenticators
            if item.get("name")
            == "OpenIDConnectAuthenticator"
        ),
        None,
    )

    if summary is None:
        summary = next(
            (
                item
                for item in authenticators
                if "openid" in (
                    str(item.get("name", ""))
                    + str(item.get("displayName", ""))
                ).lower()
            ),
            None,
        )

    if summary is None:
        return None

    authenticator_id = (
        summary.get("authenticatorId")
        or summary.get("id")
    )

    if not authenticator_id:
        raise RuntimeError(
            "OIDC authenticator metadata did not contain "
            "authenticatorId"
        )

    details = request(
        "GET",
        (
            "/api/server/v1/identity-providers/"
            "meta/federated-authenticators/"
            f"{authenticator_id}"
        ),
    ).json()

    details.setdefault(
        "authenticatorId",
        authenticator_id,
    )

    return details


def authenticator_properties(
    metadata: dict[str, Any],
    values: dict[str, str],
) -> list[dict[str, str]]:
    properties: list[dict[str, str]] = []

    for prop in metadata.get("properties", []):
        key = prop.get("key") or prop.get("name")

        if not key:
            continue

        normalized = (
            key.lower()
            .replace(".", "")
            .replace("_", "")
            .replace("-", "")
        )

        value = prop.get("defaultValue", "")

        if "clientid" in normalized:
            value = values.get("clientid", value)

        elif "clientsecret" in normalized:
            value = values.get("clientsecret", value)

        elif (
            "oauth2authz" in normalized
            or "authorizationendpoint" in normalized
        ):
            value = values.get(
                "oauth2authzendpoint",
                value,
            )

        elif (
            "oauth2token" in normalized
            or "tokenendpoint" in normalized
        ):
            value = values.get(
                "oauth2tokenendpoint",
                value,
            )

        elif "userinfo" in normalized:
            value = values.get(
                "userinfoendpoint",
                value,
            )

        elif "jwks" in normalized:
            value = values.get("jwksuri", value)

        elif "issuer" in normalized:
            value = values.get("issuer", value)

        elif "scope" in normalized:
            value = values.get("scope", value)

        elif "callback" in normalized:
            value = values.get(
                "callbackurl",
                value,
            )

        mandatory = bool(
            prop.get("isMandatory", False)
        )

        if mandatory and (
            value is None
            or str(value).strip() == ""
        ):
            raise RuntimeError(
                "Missing mandatory OIDC authenticator "
                f"property: {key}"
            )

        if (
            value is None
            or str(value).strip() == ""
        ):
            continue

        properties.append({
            "key": key,
            "value": str(value),
        })

    return properties


def find_identity_provider(name: str) -> dict[str, Any] | None:
    response = session.get(
        f"{WSO2}/api/server/v1/identity-providers?filter={quote(f'name eq {name}')}&limit=100",
        timeout=45,
    )
    providers = response.json().get("identityProviders", []) if response.status_code == 200 else []
    if not providers:
        response = request("GET", "/api/server/v1/identity-providers?limit=100")
        providers = response.json().get("identityProviders", [])
    return next((provider for provider in providers if provider.get("name") == name), None)

def ensure_oidc_idp(name: str, description: str, values: dict[str, str]) -> dict[str, Any] | None:
    existing = find_identity_provider(name)
    if existing:
        report.ok(f"OIDC connection {name} already exists")
        return existing
    oidc = oidc_authenticator_metadata()
    if not oidc:
        report.warn(f"OIDC federated-authenticator metadata was not found; {name} creation was skipped")
        return None
    authenticator_id = (
        oidc.get("authenticatorId")
        or oidc.get("id")
    )

    if not authenticator_id:
        raise RuntimeError(
            "OpenID Connect authenticator ID "
            "was not returned by WSO2"
        )

    payload = {
        "name": name,
        "description": description,
        "isPrimary": False,
        "isFederationHub": False,
        "homeRealmIdentifier": "marketsphere.local",
        "federatedAuthenticators": {
            "defaultAuthenticatorId": authenticator_id,
            "authenticators": [{
                "authenticatorId": authenticator_id,
                "isEnabled": True,
                "isDefault": True,
                "properties": authenticator_properties(
                    oidc,
                    values,
                ),
            }],
        },
        "claims": {
            "userIdClaim": {"uri": "http://wso2.org/claims/username"},
            "roleClaim": {"uri": "http://wso2.org/claims/roles"},
            "mappings": [
                {"idpClaim": "preferred_username", "localClaim": {"uri": "http://wso2.org/claims/username"}},
                {"idpClaim": "email", "localClaim": {"uri": "http://wso2.org/claims/emailaddress"}},
                {"idpClaim": "given_name", "localClaim": {"uri": "http://wso2.org/claims/givenname"}},
                {"idpClaim": "family_name", "localClaim": {"uri": "http://wso2.org/claims/lastname"}},
                {"idpClaim": "department", "localClaim": {"uri": "http://wso2.org/claims/department"}},
                {"idpClaim": "groups", "localClaim": {"uri": "http://wso2.org/claims/roles"}},
            ],
        },
        "provisioning": {
            "jit": {
                "isEnabled": True,
                "scheme": "PROVISION_SILENTLY",
                "userstore": "PRIMARY",
                "associateLocalUser": False,
                "attributeSyncMethod": "OVERRIDE_ALL",
            }
        },
    }
    created = request("POST", "/api/server/v1/identity-providers", expected=(201,), json=payload).json()
    report.ok(f"Created OIDC connection {name} with normalized claims and JIT provisioning")
    return created


def ensure_external_oidc_idps() -> tuple[list[str], bool]:
    local = ensure_oidc_idp(
        "Corporate-OIDC-Keycloak",
        "Fully local enterprise OIDC provider used for deterministic federation and claims demonstrations.",
        {
            "clientid": "wso2-portal",
            "clientsecret": "wso2-portal-secret",
            "oauth2authzendpoint": f"{KEYCLOAK_PUBLIC}/realms/corporate/protocol/openid-connect/auth",
            "oauth2tokenendpoint": f"{KEYCLOAK}/realms/corporate/protocol/openid-connect/token",
            "userinfoendpoint": f"{KEYCLOAK}/realms/corporate/protocol/openid-connect/userinfo",
            "jwksuri": f"{KEYCLOAK}/realms/corporate/protocol/openid-connect/certs",
            "issuer": f"{KEYCLOAK_PUBLIC}/realms/corporate",
            "scope": "openid profile email groups",
            "callbackurl": f"{WSO2_PUBLIC}/commonauth",
        },
    )
    names = ["Corporate-OIDC-Keycloak"] if local else []
    entra_configured = all(os.getenv(key) for key in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"))
    if entra_configured:
        tenant = os.environ["ENTRA_TENANT_ID"]
        entra = ensure_oidc_idp(
            "Microsoft-Entra-ID",
            "Microsoft Entra ID corporate federation configured from environment variables.",
            {
                "clientid": os.environ["ENTRA_CLIENT_ID"],
                "clientsecret": os.environ["ENTRA_CLIENT_SECRET"],
                "oauth2authzendpoint": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
                "oauth2tokenendpoint": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                "userinfoendpoint": "https://graph.microsoft.com/oidc/userinfo",
                "jwksuri": f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
                "issuer": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "scope": "openid profile email",
                "callbackurl": f"{WSO2_PUBLIC}/commonauth",
            },
        )
        if entra:
            names.append("Microsoft-Entra-ID")
    return names, entra_configured


def configure_login_flow(
    app_id: str,
    idp_names: list[str],
) -> bool:
    options = [{
        "idp": "LOCAL",
        "authenticator": "BasicAuthenticator",
    }]

    options.extend(
        {
            "idp": name,
            "authenticator": "OpenIDConnectAuthenticator",
        }
        for name in idp_names
    )

    payload = {
        "authenticationSequence": {
            "type": "USER_DEFINED",
            "steps": [{
                "id": 1,
                "options": options,
            }],
            "subjectStepId": 1,
            "attributeStepId": 1,
        }
    }

    response = session.patch(
        f"{WSO2}/api/server/v1/applications/{app_id}",
        json=payload,
        timeout=45,
    )

    if response.status_code not in (200, 204):
        report.warn(
            "External connections were created, but the "
            "application authentication-sequence update "
            f"returned {response.status_code}: "
            f"{response.text[:400]}"
        )
        return False

    application = request(
        "GET",
        f"/api/server/v1/applications/{app_id}",
    ).json()

    sequence = application.get(
        "authenticationSequence",
        {},
    )

    steps = sequence.get("steps", [])
    configured_options = (
        steps[0].get("options", [])
        if steps
        else []
    )

    configured = {
        (
            option.get("idp"),
            option.get("authenticator"),
        )
        for option in configured_options
    }

    expected = {
        ("LOCAL", "BasicAuthenticator"),
        *{
            (
                name,
                "OpenIDConnectAuthenticator",
            )
            for name in idp_names
        },
    }

    missing = expected - configured

    if missing:
        report.warn(
            "Authentication sequence update returned success, "
            "but these options were not persisted: "
            f"{sorted(missing)}"
        )
        return False

    report.ok(
        "Enabled local and external OIDC sign-in options "
        "in the Portal login flow"
    )

    return True


def find_api_resource_by_identifier(
    identifier: str,
) -> dict[str, Any]:
    payload = request(
        "GET",
        "/api/server/v1/api-resources?limit=1000",
    ).json()

    resources = (
        payload.get("APIResources")
        or payload.get("apiResources")
        or payload.get("resources")
        or payload.get("items")
        or (
            payload
            if isinstance(payload, list)
            else []
        )
    )

    summary = next(
        (
            resource
            for resource in resources
            if resource.get("identifier") == identifier
        ),
        None,
    )

    if summary is None:
        raise RuntimeError(
            "Required WSO2 API resource was not found: "
            f"{identifier}"
        )

    resource_id = summary.get("id")

    if not resource_id:
        raise RuntimeError(
            "WSO2 API resource did not contain an ID: "
            f"{identifier}"
        )

    details = request(
        "GET",
        f"/api/server/v1/api-resources/{resource_id}",
    ).json()

    details.setdefault("id", resource_id)
    details.setdefault(
        "name",
        summary.get("name", identifier),
    )
    details.setdefault("identifier", identifier)

    return details


def bearer_request(
    method: str,
    path: str,
    token: str,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {token}"
    headers.setdefault("Accept", "application/json")

    response = session.request(
        method,
        f"{WSO2}{path}",
        headers=headers,
        timeout=45,
        **kwargs,
    )

    if response.status_code not in expected:
        body = response.text[:2000]

        raise RuntimeError(
            f"{method} {WSO2}{path} -> "
            f"{response.status_code}: {body}"
        )

    return response


def bootstrap_management_token() -> tuple[str, str]:
    application_name = (
        "MarketSphere Bootstrap Management Client"
    )

    client = ensure_client(
        "marketsphere-bootstrap-management",
        application_name,
        ["client_credentials"],
    )

    application = find_application(application_name)
    application_id = application["id"]

    client_id = client.get("client_id")
    client_secret_value = client.get("client_secret")

    if not client_id:
        raise RuntimeError(
            "The temporary bootstrap application did not "
            "return an OAuth client ID"
        )

    if not client_secret_value:
        raise RuntimeError(
            "The temporary bootstrap application already "
            "exists, but its OAuth client secret is no "
            "longer available. Delete the stale temporary "
            "application and rerun bootstrap."
        )

    idp_management_api = (
        find_api_resource_by_identifier(
            "/api/server/v1/identity-providers"
        )
    )

    authorize_api(
        application_id,
        idp_management_api,
        [
            "internal_idp_view",
            "internal_idp_create",
        ],
    )

    token_response = session.post(
        f"{WSO2}/oauth2/token",
        auth=(client_id, client_secret_value),
        data={
            "grant_type": "client_credentials",
            "scope": (
                "internal_idp_view "
                "internal_idp_create"
            ),
        },
        headers={
            "Accept": "application/json",
            "Content-Type": (
                "application/x-www-form-urlencoded"
            ),
        },
        timeout=45,
    )

    if token_response.status_code != 200:
        raise RuntimeError(
            "Could not obtain the scoped bootstrap "
            f"management token: {token_response.status_code}: "
            f"{token_response.text[:1200]}"
        )

    token_payload = token_response.json()
    access_token = token_payload.get("access_token")

    if not access_token:
        raise RuntimeError(
            "WSO2 token response did not contain "
            "access_token"
        )

    granted_scopes = set(
        str(token_payload.get("scope", "")).split()
    )

    required_scopes = {
        "internal_idp_view",
        "internal_idp_create",
    }

    missing_scopes = (
        required_scopes - granted_scopes
    )

    if missing_scopes:
        raise RuntimeError(
            "Bootstrap token was issued without the "
            "required management scopes: "
            f"{sorted(missing_scopes)}"
        )

    report.ok(
        "Obtained a least-privilege management token "
        "for trusted token issuer configuration"
    )

    return application_id, access_token


def remove_bootstrap_management_client(
    application_id: str,
) -> None:
    response = session.delete(
        (
            f"{WSO2}/api/server/v1/applications/"
            f"{application_id}"
        ),
        timeout=45,
    )

    if response.status_code in (200, 204, 404):
        report.ok(
            "Removed the temporary bootstrap "
            "management client"
        )
        return

    report.warn(
        "Trusted token issuer configuration completed, "
        "but the temporary bootstrap management client "
        f"could not be removed: {response.status_code}: "
        f"{response.text[:300]}"
    )


def ensure_trusted_token_issuer() -> dict[str, Any]:
    name = "Corporate-Keycloak-Token-Issuer"
    issuer = f"{KEYCLOAK_PUBLIC}/realms/corporate"
    alias = "wso2-token-exchange-source"
    application_id: str | None = None

    try:
        application_id, access_token = (
            bootstrap_management_token()
        )

        response = bearer_request(
            "GET",
            (
                "/api/server/v1/"
                "identity-providers?limit=100"
            ),
            access_token,
        )

        data = response.json()

        entries = (
            data
            if isinstance(data, list)
            else (
                data.get("identityProviders")
                or data.get("IdentityProviders")
                or []
            )
        )

        existing = next(
            (
                entry
                for entry in entries
                if entry.get("name") == name
            ),
            None,
        )

        if existing:
            resource_id = existing.get("id")

            if not resource_id:
                raise RuntimeError(
                    "Existing trusted issuer identity "
                    "provider did not contain an ID"
                )

            details = bearer_request(
                "GET",
                (
                    "/api/server/v1/"
                    f"identity-providers/{resource_id}"
                ),
                access_token,
            ).json()

            configured_issuer = (
                details.get("idpIssuerName")
                or details.get("issuer")
            )

            if configured_issuer != issuer:
                raise RuntimeError(
                    "An identity provider named "
                    f"{name} already exists, but its "
                    "trusted issuer does not match. "
                    f"Expected={issuer!r}, "
                    f"actual={configured_issuer!r}"
                )

            configured_alias = details.get("alias")

            if (
                configured_alias
                and configured_alias != alias
            ):
                raise RuntimeError(
                    "The existing trusted issuer alias "
                    "does not match the expected value. "
                    f"Expected={alias!r}, "
                    f"actual={configured_alias!r}"
                )

            report.ok(
                "Trusted token issuer for RFC 8693 "
                "is configured"
            )

            return details

        payload = {
            "name": name,
            "description": (
                "Deterministic third-party JWT issuer "
                "used by the RFC 8693 token-exchange "
                "scenario."
            ),
            "isPrimary": False,
            "isFederationHub": False,
            "idpIssuerName": issuer,
            "alias": alias,
            "certificate": {
                "jwksUri": (
                    f"{KEYCLOAK}/realms/corporate/"
                    "protocol/openid-connect/certs"
                )
            },
            "claims": {
                "userIdClaim": {
                    "uri": (
                        "http://wso2.org/claims/"
                        "username"
                    )
                },
                "roleClaim": {
                    "uri": (
                        "http://wso2.org/claims/roles"
                    )
                },
                "mappings": [
                    {
                        "idpClaim": (
                            "preferred_username"
                        ),
                        "localClaim": {
                            "uri": (
                                "http://wso2.org/"
                                "claims/username"
                            )
                        },
                    },
                    {
                        "idpClaim": "email",
                        "localClaim": {
                            "uri": (
                                "http://wso2.org/"
                                "claims/emailaddress"
                            )
                        },
                    },
                    {
                        "idpClaim": "department",
                        "localClaim": {
                            "uri": (
                                "http://wso2.org/"
                                "claims/department"
                            )
                        },
                    },
                    {
                        "idpClaim": "groups",
                        "localClaim": {
                            "uri": (
                                "http://wso2.org/"
                                "claims/roles"
                            )
                        },
                    },
                ],
            },
        }

        created = bearer_request(
            "POST",
            "/api/server/v1/identity-providers",
            access_token,
            expected=(201,),
            json=payload,
            headers={
                "Content-Type": "application/json",
            },
        ).json()

        resource_id = created.get("id")

        if not resource_id:
            raise RuntimeError(
                "WSO2 created the trusted issuer "
                "identity provider but did not return "
                "its resource ID"
            )

        details = bearer_request(
            "GET",
            (
                "/api/server/v1/"
                f"identity-providers/{resource_id}"
            ),
            access_token,
        ).json()

        configured_issuer = (
            details.get("idpIssuerName")
            or details.get("issuer")
        )

        if configured_issuer != issuer:
            raise RuntimeError(
                "WSO2 created the identity provider "
                "but did not persist the trusted issuer "
                f"value. Expected={issuer!r}, "
                f"actual={configured_issuer!r}"
            )

        report.ok(
            "Registered Corporate Keycloak as a "
            "trusted third-party JWT issuer through "
            "the Identity Provider Management API"
        )

        return details

    finally:
        if application_id:
            remove_bootstrap_management_client(
                application_id
            )


def client_secret(client: dict[str, Any], label: str) -> str:
    secret = client.get("client_secret")
    if secret:
        return secret
    # This only happens when a persistent runtime volume was removed independently
    # of the WSO2 database. Rotate the client by deleting/recreating in a reset.
    report.warn(f"{label} secret is unavailable from DCR; run ./demo.sh reset to rotate it")
    return "UNAVAILABLE-RUN-DEMO-RESET"


def configure_token_exchange_account_linking(
    issuer_id: str,
    application_id: str,
) -> None:
    request(
        "PUT",
        (
            "/api/server/v1/identity-providers/"
            f"{issuer_id}/implicit-association"
        ),
        expected=(200, 204),
        json={
            "isEnabled": True,
            "lookupAttribute": [
            "http://wso2.org/claims/username",
        ],
        },
    )

    application = request(
        "GET",
        (
            "/api/server/v1/applications/"
            f"{application_id}"
        ),
    ).json()

    claim_configuration = application.get(
        "claimConfiguration",
        {},
    )

    subject = claim_configuration.setdefault(
        "subject",
        {},
    )

    subject.setdefault(
        "claim",
        {
            "uri": (
                "http://wso2.org/claims/userid"
            )
        },
    )

    subject.setdefault(
        "includeUserDomain",
        False,
    )

    subject.setdefault(
        "includeTenantDomain",
        False,
    )

    subject["useMappedLocalSubject"] = True
    subject["mappedLocalSubjectMandatory"] = True

    role = claim_configuration.setdefault(
        "role",
        {},
    )

    role.setdefault(
        "includeUserDomain",
        True,
    )

    role["claim"] = {
        "uri": "http://wso2.org/claims/roles",
    }

    request(
        "PATCH",
        (
            "/api/server/v1/applications/"
            f"{application_id}"
        ),
        expected=(200, 204),
        json={
            "claimConfiguration":
                claim_configuration,
        },
    )

    implicit = request(
        "GET",
        (
            "/api/server/v1/identity-providers/"
            f"{issuer_id}/implicit-association"
        ),
    ).json()

    updated_application = request(
        "GET",
        (
            "/api/server/v1/applications/"
            f"{application_id}"
        ),
    ).json()

    updated_subject = (
        updated_application
        .get("claimConfiguration", {})
        .get("subject", {})
    )

    updated_role_claim = (
        updated_application
        .get("claimConfiguration", {})
        .get("role", {})
        .get("claim", {})
        .get("uri")
    )

    if not implicit.get("isEnabled"):
        raise RuntimeError(
            "Trusted issuer implicit association "
            "was not enabled"
        )

    if "http://wso2.org/claims/username" not in implicit.get(
        "lookupAttribute",
        [],
    ):
        raise RuntimeError(
            "Username was not persisted as the "
            "implicit-association lookup attribute"
        )

    if not updated_subject.get(
        "useMappedLocalSubject"
    ):
        raise RuntimeError(
            "Mapped local subject was not enabled"
        )

    if not updated_subject.get(
        "mappedLocalSubjectMandatory"
    ):
        raise RuntimeError(
            "Linked local account was not made "
            "mandatory"
        )

    if updated_role_claim != (
        "http://wso2.org/claims/roles"
    ):
        raise RuntimeError(
            "The valid WSO2 roles claim was not "
            "persisted"
        )

    report.ok(
        "Configured username-based local account "
        "linking for token exchange RBAC"
    )


def main() -> int:
    wait_for(f"{WSO2}/oauth2/jwks", "WSO2 Identity Server 7.3")
    wait_for(f"{KEYCLOAK}/realms/corporate/.well-known/openid-configuration", "Corporate OIDC provider")

    alice = ensure_user("alice", os.getenv("ALICE_PASSWORD", "Alice@123"), "Alice", "Silva", "alice@marketsphere.local", "Sales")
    bob = ensure_user("bob", os.getenv("BOB_PASSWORD", "Bob@1234"), "Bob", "Santos", "bob@marketsphere.local", "Engineering")
    carol = ensure_user("carol", os.getenv("CAROL_PASSWORD", "Carol@123"), "Carol", "Souza", "carol@marketsphere.local", "Security")

    portal_group = ensure_group("portal_users", [alice["id"], carol["id"]])
    admin_group = ensure_group("portal_admins", [carol["id"]])
    finance_group = ensure_group("finance_users", [alice["id"]])

    marketplace_api = ensure_api_resource("MarketSphere Protected API", "https://api.marketsphere.local", [
        {"name": "portal.read", "displayName": "Read corporate portal", "description": "Open the protected portal and profile"},
        {"name": "portal.admin", "displayName": "Administer portal", "description": "Run privileged demo operations"},
        {"name": "orders.read", "displayName": "Read orders", "description": "M2M access to orders"},
        {"name": "inventory.read", "displayName": "Read inventory", "description": "Agent inventory read access"},
        {"name": "inventory.write", "displayName": "Reconcile inventory", "description": "Agent inventory reconciliation"},
    ])
    downstream_api = ensure_api_resource("MarketSphere Downstream API", "https://downstream.marketsphere.local", [
        {"name": "downstream.read", "displayName": "Read downstream report", "description": "Delegated access through token exchange"}
    ])

    portal_client = ensure_client(
        "marketsphere-portal-spa", "Portal Corporativo", ["authorization_code", "refresh_token"],
        redirect_uris=["http://localhost:3000", "http://localhost:3000/callback"], public=True, pkce=True,
    )
    m2m_client = ensure_client("marketsphere-orders-m2m", "Orders M2M Client", ["client_credentials"])
    exchange_client = ensure_client("marketsphere-token-exchange", "Token Exchange Backend", ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"])
    agent_app_client = ensure_client(
        "marketsphere-agent-app", "Inventory Agent Application", ["authorization_code", "refresh_token"],
        redirect_uris=["http://inventory-agent:5001/callback"], public=True, pkce=True,
    )
    agent_workload_client = ensure_client("marketsphere-agent-workload", "Inventory Agent Workload Fallback", ["client_credentials"])
    finance_client = ensure_client(
        "marketsphere-finance-spa",
        "Finance Workspace",
        ["authorization_code", "refresh_token"],
        redirect_uris=["http://localhost:3000/callback"],
        public=True,
        pkce=True,
    )
    security_client = ensure_client(
        "marketsphere-security-spa",
        "Security Operations",
        ["authorization_code", "refresh_token"],
        redirect_uris=["http://localhost:3000/callback"],
        public=True,
        pkce=True,
    )
    # Dedicated Microsoft/Ping-style application launcher.
    # It is a real OIDC SPA, but it is intentionally NOT discoverable itself.
    myapps_client = ensure_client(
        "marketsphere-myapps-spa",
        "Application Portal",
        ["authorization_code", "refresh_token"],
        redirect_uris=[
            "http://localhost:3000/myapps/callback.html",
            "http://localhost:3000/myapps/",
        ],
        public=True,
        pkce=True,
    )

    portal_app = find_application("Portal Corporativo")
    finance_app = find_application("Finance Workspace")
    security_app = find_application("Security Operations")
    myapps_app = find_application("Application Portal")
    m2m_app = find_application("Orders M2M Client")
    exchange_app = find_application("Token Exchange Backend")
    agent_app = find_application("Inventory Agent Application")
    agent_workload_app = find_application("Inventory Agent Workload Fallback")

    for application in (portal_app, finance_app, security_app, m2m_app, exchange_app, agent_app, agent_workload_app):
        set_application_role_audience(application["id"])

    configure_oidc_protocol(portal_app["id"], browser_origin="http://localhost:3000")
    configure_oidc_protocol(finance_app["id"], browser_origin="http://localhost:3000")
    configure_oidc_protocol(security_app["id"], browser_origin="http://localhost:3000")
    configure_oidc_protocol(myapps_app["id"], browser_origin="http://localhost:3000")
    request(
        "PATCH",
        f"/api/server/v1/applications/{myapps_app['id']}",
        json={
            "advancedConfigurations": {
                "skipLoginConsent": True,
                "skipLogoutConsent": True,
            }
        },
    )
    report.ok("Configured Application Portal login experience")
    configure_oidc_protocol(m2m_app["id"])
    configure_oidc_protocol(exchange_app["id"], subject_token=True)
    configure_oidc_protocol(agent_app["id"])
    configure_oidc_protocol(agent_workload_app["id"])

    authorize_api(portal_app["id"], marketplace_api, ["portal.read", "portal.admin"])
    authorize_api(finance_app["id"], marketplace_api, ["portal.read"])
    authorize_api(security_app["id"], marketplace_api, ["portal.read", "portal.admin"])
    authorize_api(m2m_app["id"], marketplace_api, ["orders.read"])
    authorize_api(exchange_app["id"], downstream_api, ["downstream.read"])
    authorize_api(agent_app["id"], marketplace_api, ["inventory.read", "inventory.write"])
    authorize_api(agent_workload_app["id"], marketplace_api, ["inventory.read", "inventory.write"])

    external_portal_groups = []
    for candidate in ("CORP/portal_users", "portal_users"):
        matches = scim_filter("Groups", "displayName", candidate)
        matches = [group for group in matches if group.get("id") not in {portal_group["id"], admin_group["id"], finance_group["id"]}]
        if matches:
            external_portal_groups = matches
            report.ok("Resolved external LDAP portal_users group for role assignment")
            break
    if not external_portal_groups:
        report.warn("LDAP users are available, but the external portal_users group was not returned through SCIM during bootstrap")
    # Native WSO2 My Account catalog:
    #   Alice -> Portal Corporativo + Finance Workspace
    #   Carol -> Portal Corporativo + Security Operations
    #   Bob   -> no tiles from these entitlement groups
    ensure_discoverable_application(
        portal_app["id"],
        "http://localhost:3000/?launch=portal",
        [portal_group, *external_portal_groups],
    )
    ensure_discoverable_application(
        finance_app["id"],
        "http://localhost:3000/?launch=finance",
        [finance_group],
    )
    ensure_discoverable_application(
        security_app["id"],
        "http://localhost:3000/?launch=security",
        [admin_group],
    )


    ensure_role("portal-user", portal_app["id"], ["portal.read"], groups=[portal_group, *external_portal_groups])
    ensure_role("portal-admin", portal_app["id"], ["portal.read", "portal.admin"], groups=[admin_group])
    ensure_role("finance-user", portal_app["id"], ["portal.read"], groups=[finance_group])
    ensure_role(
        "finance-app-user",
        finance_app["id"],
        ["portal.read"],
        groups=[finance_group],
    )
    ensure_role(
        "security-app-admin",
        security_app["id"],
        ["portal.read", "portal.admin"],
        groups=[admin_group],
    )
    ensure_role("orders-service", m2m_app["id"], ["orders.read"])
    ensure_role("token-exchange-service", exchange_app["id"], ["downstream.read"], users=[alice])

    agent = ensure_agent(carol["id"])
    ensure_role("inventory-agent", agent_app["id"], ["inventory.read", "inventory.write"], users=[agent])
    ensure_role("inventory-agent-workload", agent_workload_app["id"], ["inventory.read", "inventory.write"])
    agent_native_enabled = ensure_agent_app_setting(agent_app["id"])

    idp_names, entra_configured = ensure_external_oidc_idps()
    federated_flow_enabled = bool(idp_names and configure_login_flow(portal_app["id"], idp_names))
    trusted_issuer = ensure_trusted_token_issuer()

    configure_token_exchange_account_linking(
        trusted_issuer["id"],
        exchange_app["id"],
    )

    runtime = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "product": {"name": "WSO2 Identity Server", "version": "7.3.0", "consoleUrl": f"{WSO2_PUBLIC}/console"},
        "issuer": f"{WSO2_PUBLIC}/oauth2/token",
        "internalIssuer": f"{WSO2}/oauth2/token",
        "authorizationEndpoint": f"{WSO2_PUBLIC}/oauth2/authorize",
        "tokenEndpoint": f"{WSO2_PUBLIC}/oauth2/token",
        "internalTokenEndpoint": f"{WSO2}/oauth2/token",
        "jwksUri": f"{WSO2_PUBLIC}/oauth2/jwks",
        "internalJwksUri": f"{WSO2}/oauth2/jwks",
        "userinfoEndpoint": f"{WSO2_PUBLIC}/oauth2/userinfo",
        "logoutEndpoint": f"{WSO2_PUBLIC}/oidc/logout",
        "apiBaseUrl": "http://localhost:4000",
        "apiInternalUrl": "http://marketplace-api:4000",
        "resources": {
            "marketplace": {"id": marketplace_api["id"], "identifier": marketplace_api["identifier"]},
            "downstream": {"id": downstream_api["id"], "identifier": downstream_api["identifier"]},
        },
        "clients": {
            "portal": {"clientId": portal_client["client_id"], "redirectUri": "http://localhost:3000/callback", "postLogoutRedirectUri": "http://localhost:3000", "scopes": "openid profile email portal.read portal.admin", "resourceIdentifier": marketplace_api["identifier"], "displayName": "Portal Corporativo"},
            "finance": {"clientId": finance_client["client_id"], "redirectUri": "http://localhost:3000/callback", "postLogoutRedirectUri": "http://localhost:3000", "scopes": "openid profile email portal.read", "resourceIdentifier": marketplace_api["identifier"], "displayName": "Finance Workspace"},
            "security": {"clientId": security_client["client_id"], "redirectUri": "http://localhost:3000/callback", "postLogoutRedirectUri": "http://localhost:3000", "scopes": "openid profile email portal.read portal.admin", "resourceIdentifier": marketplace_api["identifier"], "displayName": "Security Operations"},
            "appPortal": {"clientId": myapps_client["client_id"], "redirectUri": "http://localhost:3000/myapps/callback.html", "postLogoutRedirectUri": "http://localhost:3000/myapps/", "scopes": "openid profile email internal_login", "displayName": "Application Portal"},
            "m2m": {"clientId": m2m_client["client_id"], "clientSecret": client_secret(m2m_client, "M2M client"), "scope": "orders.read"},
            "tokenExchange": {"clientId": exchange_client["client_id"], "clientSecret": client_secret(exchange_client, "Token Exchange client"), "scope": "downstream.read"},
            "agentApp": {"clientId": agent_app_client["client_id"], "redirectUri": "http://inventory-agent:5001/callback", "scope": "openid inventory.read inventory.write"},
            "agentWorkload": {"clientId": agent_workload_client["client_id"], "clientSecret": client_secret(agent_workload_client, "Agent workload client"), "scope": "inventory.read inventory.write"},
        },
        "agent": {
            "id": agent.get("userName") or agent.get("id"),
            "resourceId": agent.get("id"),
            "secret": agent.get("password") or agent.get("secret"),
            "displayName": "Inventory Reconciliation Agent",
            "owner": "carol",
            "role": "inventory-agent",
            "authMode": "managed-agent" if agent_native_enabled and (agent.get("password") or agent.get("secret")) else "client-credentials-fallback",
            "managedAgentReady": bool(agent_native_enabled and (agent.get("password") or agent.get("secret"))),
        },
        "federation": {
            "localProvider": "Corporate-OIDC-Keycloak",
            "configuredProviders": idp_names,
            "publicUrl": f"{KEYCLOAK_PUBLIC}/realms/corporate/account",
            "loginFlowEnabled": federated_flow_enabled,
            "entraConfigured": entra_configured and "Microsoft-Entra-ID" in idp_names,
            "trustedTokenIssuer": {
                "id": trusted_issuer.get("id"),
                "name": trusted_issuer.get("name", "Corporate-Keycloak-Token-Issuer"),
                "issuer": f"{KEYCLOAK_PUBLIC}/realms/corporate",
                "alias": "wso2-token-exchange-source",
                "jwksUri": f"{KEYCLOAK_PUBLIC}/realms/corporate/protocol/openid-connect/certs",
            },
            "sourceToken": {
                "tokenEndpoint": f"{KEYCLOAK}/realms/corporate/protocol/openid-connect/token",
                "publicTokenEndpoint": f"{KEYCLOAK_PUBLIC}/realms/corporate/protocol/openid-connect/token",
                "clientId": "wso2-token-exchange-source",
                "clientSecret": "wso2-token-exchange-source-secret",
                "username": "alice",
                "password": "Alice@123",
                "scope": "openid profile email",
            },
        },
        "demoUsers": [
            {"username": "alice", "password": os.getenv("ALICE_PASSWORD", "Alice@123"), "groups": ["portal_users", "finance_users"], "expected": "Portal allowed"},
            {"username": "bob", "password": os.getenv("BOB_PASSWORD", "Bob@1234"), "groups": [], "expected": "Login valid, Portal denied"},
            {"username": "carol", "password": os.getenv("CAROL_PASSWORD", "Carol@123"), "groups": ["portal_users", "portal_admins"], "expected": "Portal and admin allowed"},
            {"username": "CORP/diana", "password": "Corporate@123", "groups": ["portal_users", "finance_users"], "expected": "External LDAP user"},
            {"username": "CORP/eduardo", "password": "Corporate@123", "groups": ["auditors"], "expected": "External LDAP user; Portal denied"},
            {"username": "federated.user", "password": "Federated@123", "groups": ["portal_users", "finance_users"], "expected": "Federated OIDC user"},
        ],
        "bootstrap": {"completed": report.completed, "warnings": report.warnings},
    }

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp = RUNTIME_DIR / f"runtime-config.{secrets.token_hex(4)}.tmp"
    tmp.write_text(json.dumps(runtime, indent=2), encoding="utf-8")
    tmp.replace(RUNTIME_DIR / "runtime-config.json")

    public_runtime = json.loads(json.dumps(runtime))
    for key in ("m2m", "tokenExchange", "agentWorkload"):
        public_runtime["clients"][key].pop("clientSecret", None)
    public_runtime["agent"].pop("secret", None)
    if "sourceToken" in public_runtime.get("federation", {}):
        public_runtime["federation"]["sourceToken"].pop("clientSecret", None)
        public_runtime["federation"]["sourceToken"].pop("password", None)
    (RUNTIME_DIR / "ui-config.json").write_text(json.dumps(public_runtime, indent=2), encoding="utf-8")
    (RUNTIME_DIR / "bootstrap-report.json").write_text(json.dumps({"completed": report.completed, "warnings": report.warnings}, indent=2), encoding="utf-8")
    report.ok("Published runtime configuration for API, agent, and UI")

    if STRICT and report.warnings:
        print("Bootstrap completed with warnings and BOOTSTRAP_STRICT=true", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - bootstrap must surface full fatal context
        print(f"[fatal] {exc}", file=sys.stderr)
        raise
