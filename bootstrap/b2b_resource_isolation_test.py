#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

import rfp_extension as rfp

RUNTIME = Path(os.getenv("RUNTIME_DIR", "/runtime")) / "runtime-config.json"
API = os.getenv(
    "MARKETPLACE_API_INTERNAL", "http://marketplace-api:4000"
).rstrip("/")


def log(message: str) -> None:
    print(f"[b2b-isolation-test] {message}", flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def api_get(path: str, token: str) -> requests.Response:
    last_error = None
    for attempt in range(1, 11):
        try:
            return requests.get(
                f"{API}{path}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
        except requests.RequestException as exc:
            last_error = exc
            time.sleep(min(attempt, 3))
    fail(f"Could not call {API}{path}: {last_error}")


def main() -> None:
    if not RUNTIME.exists():
        fail("runtime-config.json is missing")

    cfg = json.loads(RUNTIME.read_text(encoding="utf-8"))
    b2b = cfg.get("b2b") or {}
    apps = b2b.get("organizationApplications") or []
    orgs = b2b.get("organizations") or []

    if len(apps) != 8:
        fail(f"Expected 8 B2B applications; found {len(apps)}")
    if len(orgs) != 6:
        fail(f"Expected 6 B2B organizations; found {len(orgs)}")

    for app in apps:
        if not app.get("resourceApiPath"):
            fail(f"{app.get('name')} has no resourceApiPath")

    org_by_key = {org["key"]: org for org in orgs}

    client = rfp.ensure_management_client(
        ["client_credentials", "organization_switch"]
    )
    rfp.authorize_management_scopes(client["application_id"])

    tokens = {}
    for org_key, org in org_by_key.items():
        root_token = rfp.token_client_credentials(client)
        tokens[org_key] = rfp.organization_switch(
            client,
            root_token,
            org["id"],
            scopes=rfp.ORG_APP_SCOPES,
        )
        log(f"token ready: {org['name']} ({org['id']})")

    allow_count = 0
    deny_count = 0

    for token_org_key, token in tokens.items():
        token_org = org_by_key[token_org_key]

        for app in apps:
            expected_allow = app["organizationKey"] == token_org_key
            response = api_get(app["resourceApiPath"], token)

            if expected_allow:
                if response.status_code != 200:
                    fail(
                        f"Expected 200: token={token_org['name']} "
                        f"resource={app['resourceApiPath']} -> "
                        f"{response.status_code} {response.text[:1000]}"
                    )
                payload = response.json()
                if payload.get("decision") != "allow":
                    fail(f"Expected allow decision: {payload}")
                if (
                    str((payload.get("organization") or {}).get("id"))
                    != str(token_org["id"])
                ):
                    fail(
                        "Allowed response organization does not match token "
                        f"organization: {payload}"
                    )
                allow_count += 1
                log(
                    f"ALLOW  {token_org['name']} -> "
                    f"{app['resourceApiPath']} [200]"
                )
            else:
                if response.status_code != 403:
                    fail(
                        f"Expected 403: token={token_org['name']} "
                        f"resource={app['resourceApiPath']} -> "
                        f"{response.status_code} {response.text[:1000]}"
                    )
                payload = response.json()
                if payload.get("code") != "cross_organization_access_denied":
                    fail(
                        "Expected cross_organization_access_denied, got: "
                        f"{payload}"
                    )
                deny_count += 1
                log(
                    f"DENY   {token_org['name']} -> "
                    f"{app['resourceApiPath']} [403]"
                )

    if allow_count != 8:
        fail(f"Expected 8 same-org allows; got {allow_count}")
    if deny_count != 40:
        fail(f"Expected 40 cross-org denials; got {deny_count}")

    seller = org_by_key["seller-alpha"]
    mexico = org_by_key["mexico"]

    seller_to_mexico = api_get(
        "/api/b2b/mexico/operations", tokens["seller-alpha"]
    )
    if seller_to_mexico.status_code != 403:
        fail("Seller Alpha token unexpectedly accessed Mexico Operations")

    mexico_to_seller = api_get(
        "/api/b2b/seller/storefront", tokens["mexico"]
    )
    if mexico_to_seller.status_code != 403:
        fail("Mexico token unexpectedly accessed Seller Storefront")

    print("")
    log("==================================================")
    log("CROSS-ORGANIZATION PROTECTED-RESOURCE TEST PASSED")
    log("8 same-organization decisions -> HTTP 200")
    log("40 cross-organization decisions -> HTTP 403")
    log(f"Seller Alpha ({seller['id']}) -> Mexico resource: DENIED 403")
    log(f"Mexico ({mexico['id']}) -> Seller resource: DENIED 403")
    log("==================================================")
    print("")


if __name__ == "__main__":
    main()
