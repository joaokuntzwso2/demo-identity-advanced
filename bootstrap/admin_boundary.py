#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
RUNTIME = RUNTIME_DIR / "runtime-config.json"
UI_RUNTIME = RUNTIME_DIR / "ui-config.json"

ADMIN_USERNAME = os.getenv("WSO2_ADMIN_USER", "admin")
RESTRICTED_ROOT_USERS = ("alice", "bob", "carol")
MANAGEMENT_CLIENT_NAME = "marketsphere-b2b-bootstrap"
MANAGEMENT_APP = "MarketSphere B2B Bootstrap Client"
VERIFY_TLS = False

ROOT_SCOPES = [
    "internal_organization_create",
    "internal_organization_view",
    "internal_org_organization_create",
    "internal_org_organization_view",
    "internal_org_user_mgt_create",
    "internal_org_user_mgt_list",
    "internal_org_user_mgt_view",
    "internal_org_application_mgt_create",
    "internal_org_application_mgt_update",
    "internal_org_application_mgt_view",
    "internal_org_role_mgt_view",
    "internal_org_role_mgt_update",
]

ORG_SCOPES = [
    "internal_org_organization_create",
    "internal_org_organization_view",
    "internal_org_user_mgt_create",
    "internal_org_user_mgt_list",
    "internal_org_user_mgt_view",
    "internal_org_application_mgt_create",
    "internal_org_application_mgt_update",
    "internal_org_application_mgt_view",
    "internal_org_role_mgt_view",
    "internal_org_role_mgt_update",
]


def log(message: str) -> None:
    print(f"[admin-boundary] {message}", flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def json_items(payload: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def root_scim_user(username: str) -> dict[str, Any]:
    response = core.request(
        "GET",
        "/scim2/Users",
        expected=(200,),
        params={"filter": f'userName eq "{username}"', "count": 100},
        headers={"Accept": "application/scim+json"},
    )
    users = response.json().get("Resources") or []
    exact = [
        user for user in users
        if str(user.get("userName") or "").split("/", 1)[-1] == username
    ]
    if len(exact) != 1:
        fail(f"Expected exactly one root user {username!r}; found {len(exact)}")
    return exact[0]


def share_state(user_id: str) -> dict[str, Any]:
    response = core.request(
        "GET",
        f"/api/server/v2/users/{user_id}/share",
        expected=(200, 404),
        params={"limit": 100},
    )
    if response.status_code == 404 or not response.text.strip():
        return {}
    return response.json()


def has_shared_access(state: dict[str, Any]) -> bool:
    return bool(state.get("sharingMode") or state.get("organizations"))


def wait_until(predicate, description: str, timeout: int = 90) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = predicate()
        if last.get("ok"):
            return last
        time.sleep(2)
    fail(
        f"Timed out waiting for {description}: "
        f"{json.dumps(last, ensure_ascii=False)[:1800]}"
    )


def expected_orgs(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    orgs = ((runtime.get("b2b") or {}).get("organizations") or [])
    if len(orgs) != 6:
        fail(f"Expected 6 demo organizations; found {len(orgs)}")
    return orgs


def unshare_if_needed(user: dict[str, Any]) -> None:
    if not has_shared_access(share_state(user["id"])):
        return
    core.request(
        "POST",
        "/api/server/v2/users/unshare-with-all",
        expected=(202,),
        json={"userCriteria": {"userIds": [user["id"]]}},
    )

    def gone() -> dict[str, Any]:
        state = share_state(user["id"])
        return {"ok": not has_shared_access(state), "state": state}

    wait_until(gone, f"unsharing {user.get('userName')}")


def restrict_non_admins() -> list[str]:
    restricted = []
    for username in RESTRICTED_ROOT_USERS:
        user = root_scim_user(username)
        unshare_if_needed(user)
        if has_shared_access(share_state(user["id"])):
            fail(f"Restricted user {username} still has B2B shared access")
        log(f"Verified restricted root user {username} has no B2B shared access.")
        restricted.append(username)
    return restricted


def ensure_admin_shared(admin: dict[str, Any], orgs: list[dict[str, Any]]) -> None:
    expected_ids = {str(org["id"]) for org in orgs}
    state = share_state(admin["id"])
    current_ids = {
        str(item.get("orgId"))
        for item in state.get("organizations") or []
        if item.get("orgId")
    }

    if expected_ids.issubset(current_ids):
        log("Root admin is already shared with all six demo organizations.")
        return

    if has_shared_access(state):
        unshare_if_needed(admin)
        log("Removed incomplete previous sharing policy for root admin.")

    core.request(
        "POST",
        "/api/server/v2/users/share-with-all",
        expected=(202,),
        json={
            "userCriteria": {"userIds": [admin["id"]]},
            "policy": "ALL_EXISTING_AND_FUTURE_ORGS",
            "roleAssignment": {"mode": "NONE"},
        },
    )

    def shared() -> dict[str, Any]:
        latest = share_state(admin["id"])
        ids = {
            str(item.get("orgId"))
            for item in latest.get("organizations") or []
            if item.get("orgId")
        }
        return {"ok": expected_ids.issubset(ids), "state": latest}

    wait_until(shared, "root admin sharing")
    log("Shared root admin with all existing and future organizations.")


def discover_scope_owners(scope_names: list[str]) -> dict[str, tuple[str, str]]:
    response = core.request(
        "GET",
        "/api/server/v1/api-resources?limit=1000",
        expected=(200,),
    )
    resources = json_items(
        response.json(),
        ("APIResources", "apiResources", "resources", "items", "Resources"),
    )

    owners: dict[str, tuple[str, str]] = {}
    wanted = set(scope_names)

    for resource in resources:
        resource_id = resource.get("id")
        if not resource_id:
            continue
        scope_response = core.request(
            "GET",
            f"/api/server/v1/api-resources/{resource_id}/scopes",
            expected=(200, 404),
        )
        if scope_response.status_code == 404:
            continue
        scopes = json_items(
            scope_response.json(),
            ("scopes", "Scopes", "items", "Resources"),
        )
        for scope in scopes:
            name = scope.get("name")
            if name in wanted:
                owners[name] = (
                    resource_id,
                    resource.get("name")
                    or resource.get("displayName")
                    or resource_id,
                )

    return owners


def ensure_management_client() -> dict[str, str]:
    oauth = core.ensure_client(
        MANAGEMENT_CLIENT_NAME,
        MANAGEMENT_APP,
        ["client_credentials", "organization_switch"],
        redirect_uris=[],
        public=False,
        pkce=False,
    )
    app = core.find_application(MANAGEMENT_APP)

    client_id = oauth.get("client_id")
    client_secret = oauth.get("client_secret")
    app_id = app.get("id")

    if not client_id or not client_secret or not app_id:
        fail("Could not resolve B2B management client/application credentials")

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "application_id": app_id,
    }


def authorize_management_scopes(app_id: str) -> None:
    owners = discover_scope_owners(ROOT_SCOPES)
    missing = [scope for scope in ROOT_SCOPES if scope not in owners]
    if missing:
        fail(
            "Required management scopes are missing from IS API Resources: "
            + ", ".join(missing)
        )

    grouped: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}

    for scope in ROOT_SCOPES:
        resource_id, api_name = owners[scope]
        grouped[resource_id].append(scope)
        names[resource_id] = api_name

    for resource_id, scopes in grouped.items():
        core.authorize_api(
            app_id,
            {"id": resource_id, "name": names[resource_id]},
            sorted(set(scopes)),
        )
        log(
            f"Authorized {names[resource_id]}: "
            + ", ".join(sorted(set(scopes)))
        )


def root_token(client: dict[str, str]) -> str:
    response = requests.post(
        f"{core.WSO2}/oauth2/token",
        auth=(client["client_id"], client["client_secret"]),
        data={
            "grant_type": "client_credentials",
            "scope": " ".join(ROOT_SCOPES),
        },
        verify=VERIFY_TLS,
        timeout=45,
    )
    if response.status_code != 200:
        fail(
            f"Root Client Credentials failed: HTTP {response.status_code}: "
            f"{response.text[:1600]}"
        )
    token = response.json().get("access_token")
    if not token:
        fail("Root Client Credentials response contains no access_token")
    return token


def org_token(
    client: dict[str, str],
    root_access_token: str,
    org_id: str,
) -> str:
    last = ""
    for attempt in range(1, 16):
        response = requests.post(
            f"{core.WSO2}/oauth2/token",
            auth=(client["client_id"], client["client_secret"]),
            data={
                "grant_type": "organization_switch",
                "token": root_access_token,
                "switching_organization": org_id,
                "scope": " ".join(ORG_SCOPES),
            },
            verify=VERIFY_TLS,
            timeout=45,
        )
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                return token
        last = f"HTTP {response.status_code}: {response.text[:1200]}"
        time.sleep(min(attempt, 3))
    fail(f"Organization Switch failed for {org_id}: {last}")


def bearer(
    method: str,
    path: str,
    token: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **kwargs.pop("headers", {}),
    }
    response = requests.request(
        method,
        f"{core.WSO2}{path}",
        headers=headers,
        verify=VERIFY_TLS,
        timeout=45,
        **kwargs,
    )
    if response.status_code not in expected:
        fail(
            f"{method} {path} -> HTTP {response.status_code}: "
            f"{response.text[:1800]}"
        )
    return response


def org_user(token: str, username: str) -> dict[str, Any]:
    response = bearer(
        "GET",
        "/o/scim2/Users",
        token,
        params={"filter": f'userName eq "{username}"', "count": 100},
        headers={"Accept": "application/scim+json"},
    )
    users = response.json().get("Resources") or []
    exact = [
        user for user in users
        if str(user.get("userName") or "").split("/", 1)[-1] == username
    ]
    if len(exact) != 1:
        fail(
            f"Expected one shared/shadow user {username!r} "
            f"in organization; found {len(exact)}"
        )
    return exact[0]


def list_org_applications(token: str) -> list[dict[str, Any]]:
    response = bearer(
        "GET",
        "/o/api/server/v1/applications",
        token,
        params={"limit": 100},
    )
    return json_items(
        response.json(),
        ("applications", "Applications", "items"),
    )


def console_application_id(token: str) -> str | None:
    applications = list_org_applications(token)
    candidates = [
        app for app in applications
        if str(app.get("name") or "").strip().lower() == "console"
    ]
    if len(candidates) == 1:
        return candidates[0].get("id")
    return None


def list_admin_roles(token: str) -> list[dict[str, Any]]:
    response = bearer(
        "GET",
        "/o/scim2/v2/Roles",
        token,
        params={"filter": 'displayName eq "Administrator"', "count": 100},
        headers={"Accept": "application/scim+json"},
    )
    return response.json().get("Resources") or []


def resolve_console_admin_role(token: str) -> dict[str, Any]:
    roles = list_admin_roles(token)
    app_roles = [
        role for role in roles
        if (role.get("audience") or {}).get("type") == "application"
    ]

    by_display = [
        role for role in app_roles
        if "console" in str(
            (role.get("audience") or {}).get("display") or ""
        ).lower()
    ]
    if len(by_display) == 1:
        return by_display[0]

    console_id = console_application_id(token)
    if console_id:
        by_value = [
            role for role in app_roles
            if str((role.get("audience") or {}).get("value")) == str(console_id)
        ]
        if len(by_value) == 1:
            return by_value[0]

    if len(app_roles) == 1:
        return app_roles[0]

    fail(
        "Could not uniquely identify the Console Administrator role. "
        "Administrator roles returned: "
        + json.dumps(
            [
                {
                    "id": role.get("id"),
                    "displayName": role.get("displayName"),
                    "audience": role.get("audience"),
                }
                for role in roles
            ],
            ensure_ascii=False,
        )
    )


def get_role(token: str, role_id: str) -> dict[str, Any]:
    return bearer(
        "GET",
        f"/o/scim2/v2/Roles/{role_id}",
        token,
        headers={"Accept": "application/scim+json"},
    ).json()


def role_has_user(role: dict[str, Any], user_id: str) -> bool:
    return any(
        str(member.get("value")) == str(user_id)
        for member in role.get("users") or []
    )


def ensure_admin_in_org(
    client: dict[str, str],
    root_access_token: str,
    org: dict[str, Any],
    verify_only: bool,
) -> dict[str, Any]:
    token = org_token(client, root_access_token, org["id"])
    shadow = org_user(token, ADMIN_USERNAME)
    role = resolve_console_admin_role(token)
    role_id = role.get("id")
    if not role_id:
        fail(f"Console Administrator role has no id in {org['name']}")

    current = get_role(token, role_id)
    if role_has_user(current, shadow["id"]):
        log(f"admin has Console Administrator in {org['name']}.")
    else:
        if verify_only:
            fail(f"admin is NOT Console Administrator in {org['name']}")

        bearer(
            "PATCH",
            f"/o/scim2/v2/Roles/{role_id}",
            token,
            expected=(200, 204),
            headers={"Content-Type": "application/scim+json"},
            json={
                "schemas": [
                    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                ],
                "Operations": [
                    {
                        "op": "add",
                        "path": "users",
                        "value": [{"value": shadow["id"]}],
                    }
                ],
            },
        )

        def assigned() -> dict[str, Any]:
            fresh_token = org_token(
                client,
                root_access_token,
                org["id"],
            )
            fresh_role = get_role(fresh_token, role_id)
            return {
                "ok": role_has_user(fresh_role, shadow["id"]),
                "role": fresh_role,
            }

        wait_until(
            assigned,
            f"Console Administrator assignment in {org['name']}",
        )
        log(f"Assigned admin to Console / Administrator in {org['name']}.")

    return {
        "organization": org["name"],
        "organizationId": org["id"],
        "sharedUserId": shadow["id"],
        "roleId": role_id,
        "roleAudience": role.get("audience"),
    }


def publish(
    runtime: dict[str, Any],
    assignments: list[dict[str, Any]],
    restricted: list[str],
) -> None:
    metadata = {
        "ready": True,
        "rootAdministrator": ADMIN_USERNAME,
        "sharingPolicy": "ALL_EXISTING_AND_FUTURE_ORGS",
        "consoleRole": "Administrator",
        "organizationCount": len(assignments),
        "assignments": assignments,
        "restrictedRootUsers": restricted,
        "residentUsersConsoleAdministrator": False,
    }

    runtime.setdefault("b2b", {})["adminAccess"] = metadata
    RUNTIME.write_text(
        json.dumps(runtime, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if UI_RUNTIME.exists():
        ui = json.loads(UI_RUNTIME.read_text(encoding="utf-8"))
        ui.setdefault("b2b", {})["adminAccess"] = metadata
        UI_RUNTIME.write_text(
            json.dumps(ui, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    if not RUNTIME.exists():
        fail("runtime-config.json is missing; run RFP bootstrap first")

    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    orgs = expected_orgs(runtime)

    restricted = restrict_non_admins()
    admin = root_scim_user(ADMIN_USERNAME)

    if not args.verify_only:
        ensure_admin_shared(admin, orgs)

    state = share_state(admin["id"])
    expected_ids = {str(org["id"]) for org in orgs}
    shared_ids = {
        str(item.get("orgId"))
        for item in state.get("organizations") or []
        if item.get("orgId")
    }
    if not expected_ids.issubset(shared_ids):
        fail("Root admin is not shared to all six demo organizations")

    client = ensure_management_client()
    authorize_management_scopes(client["application_id"])
    root_access_token = root_token(client)

    assignments = [
        ensure_admin_in_org(
            client,
            root_access_token,
            org,
            args.verify_only,
        )
        for org in orgs
    ]

    publish(runtime, assignments, restricted)

    print("", flush=True)
    log("==================================================")
    log("ADMIN GLOBAL CONSOLE ACCESS READY")
    log("admin: Console Administrator in all 6 organizations")
    log("alice/bob/carol: no organization shared access")
    log("B2B resident users: no Console Administrator assignment from bootstrap")
    log("==================================================")
    print("", flush=True)


if __name__ == "__main__":
    main()
