#!/usr/bin/env python3
"""Configure the eight B2B demo applications as real organization-local OIDC SPAs."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
import urllib3

import bootstrap as core
import rfp_extension as rfp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
RUNTIME = RUNTIME_DIR / "runtime-config.json"
UI_RUNTIME = RUNTIME_DIR / "ui-config.json"

ROOT_ORG_HANDLE = os.getenv("WSO2_ROOT_ORG_HANDLE", "carbon.super")
WSO2_PUBLIC = os.getenv("WSO2_PUBLIC_BASE_URL", "https://localhost:9443").rstrip("/")
APP_SCOPES = [
    "internal_org_application_mgt_view",
    "internal_org_application_mgt_update",
]


def log(msg: str) -> None:
    print(f"[b2b-oidc] {msg}", flush=True)


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def management_client() -> dict[str, str]:
    client = rfp.ensure_management_client(["client_credentials", "organization_switch"])
    rfp.authorize_management_scopes(client["application_id"])
    for k in ("client_id", "client_secret", "application_id"):
        if not client.get(k):
            fail(f"B2B management client missing {k}")
    return client


def client_credentials(client: dict[str, str]) -> str:
    response = requests.post(
        f"{core.WSO2}/oauth2/token",
        auth=(client["client_id"], client["client_secret"]),
        data={
            "grant_type": "client_credentials",
            "scope": " ".join(APP_SCOPES),
        },
        verify=False,
        timeout=45,
    )
    if response.status_code != 200:
        fail(
            f"Client Credentials failed: HTTP {response.status_code}: "
            f"{response.text[:1200]}"
        )
    token = response.json().get("access_token")
    if not token:
        fail("Client Credentials response has no access_token")
    return token


def org_switch(client: dict[str, str], root_token: str, org_id: str) -> str:
    last = ""
    for attempt in range(1, 12):
        response = requests.post(
            f"{core.WSO2}/oauth2/token",
            auth=(client["client_id"], client["client_secret"]),
            data={
                "grant_type": "organization_switch",
                "token": root_token,
                "switching_organization": org_id,
                "scope": " ".join(APP_SCOPES),
            },
            verify=False,
            timeout=45,
        )
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                return token
        last = f"HTTP {response.status_code}: {response.text[:1000]}"
        time.sleep(min(attempt, 3))
    fail(f"Organization Switch failed for {org_id}: {last}")


def bearer(method: str, path: str, token: str, *, expected=(200,), **kwargs):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **kwargs.pop("headers", {}),
    }
    response = requests.request(
        method,
        f"{core.WSO2}{path}",
        headers=headers,
        verify=False,
        timeout=45,
        **kwargs,
    )
    if response.status_code not in expected:
        fail(
            f"{method} {path} -> HTTP {response.status_code}: "
            f"{response.text[:1600]}"
        )
    return response


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def configure_oidc(
    token: str,
    app_id: str,
    access_url: str,
) -> dict:
    redirect_uri = access_url.rstrip("/") + "/callback.html"
    oidc_path = (
        f"/o/api/server/v1/applications/{app_id}"
        "/inbound-protocols/oidc"
    )

    current_response = bearer(
        "GET",
        oidc_path,
        token,
        expected=(200, 404),
    )

    if current_response.status_code == 200:
        oidc = current_response.json()
        # Read-only fields returned by GET should not be echoed on PUT.
        for key in (
            "state",
            "issuer",
            "clientSecret",
            "clientSecretExpiresAt",
        ):
            oidc.pop(key, None)
    else:
        oidc = {}

    oidc["grantTypes"] = ["authorization_code"]
    oidc["callbackURLs"] = [redirect_uri]
    oidc["allowedOrigins"] = [origin(access_url)]
    oidc["publicClient"] = True
    oidc["pkce"] = {
        "mandatory": True,
        "supportPlainTransformAlgorithm": False,
    }

    # Keep JWT tokens explicit for useful claims during the demo.
    oidc["accessToken"] = {
        **oidc.get("accessToken", {}),
        "type": "JWT",
        "userAccessTokenExpiryInSeconds": 3600,
        "applicationAccessTokenExpiryInSeconds": 3600,
    }
    oidc["idToken"] = {
        **oidc.get("idToken", {}),
        "expiryInSeconds": 3600,
    }

    bearer(
        "PUT",
        oidc_path,
        token,
        expected=(200, 201),
        headers={"Content-Type": "application/json"},
        json=oidc,
    )

    configured = bearer("GET", oidc_path, token).json()
    client_id = configured.get("clientId")
    if not client_id:
        fail(f"OIDC client ID was not returned for application {app_id}")

    persisted_callbacks = configured.get("callbackURLs") or []
    if redirect_uri not in persisted_callbacks:
        fail(
            f"Callback URL not persisted for {app_id}: "
            f"{persisted_callbacks}"
        )
    if not configured.get("publicClient"):
        fail(f"Application {app_id} did not persist publicClient=true")

    pkce = configured.get("pkce") or {}
    if not pkce.get("mandatory"):
        fail(f"Application {app_id} did not persist mandatory PKCE")

    return {
        "clientId": client_id,
        "redirectUri": redirect_uri,
        "allowedOrigin": origin(access_url),
    }


def update_app_metadata(
    token: str,
    app_id: str,
    access_url: str,
) -> None:
    bearer(
        "PATCH",
        f"/o/api/server/v1/applications/{app_id}",
        token,
        expected=(200, 204),
        headers={"Content-Type": "application/json"},
        json={
            "accessUrl": access_url,
            "logoutReturnUrl": access_url,
        },
    )


def main() -> None:
    if not RUNTIME.exists():
        fail("runtime-config.json is missing")

    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    b2b = runtime.get("b2b") or {}
    apps = b2b.get("organizationApplications") or []

    if len(apps) != 8:
        fail(f"Expected 8 B2B applications; found {len(apps)}")

    client = management_client()
    root_token = client_credentials(client)

    seen_client_ids = set()
    for app in apps:
        org_id = app.get("organizationId")
        app_id = app.get("id")
        access_url = app.get("accessUrl")

        if not org_id or not app_id or not access_url:
            fail(f"Application is missing organizationId/id/accessUrl: {app}")

        # A fresh switched token per app avoids the stale-token problem we
        # already observed during bootstrap reconciliation.
        token = org_switch(client, root_token, org_id)

        update_app_metadata(token, app_id, access_url)
        oidc = configure_oidc(token, app_id, access_url)

        if oidc["clientId"] in seen_client_ids:
            fail(f"Duplicate OIDC clientId generated: {oidc['clientId']}")
        seen_client_ids.add(oidc["clientId"])

        app["clientId"] = oidc["clientId"]
        app["redirectUri"] = oidc["redirectUri"]
        app["authorizationEndpoint"] = (
            f"{WSO2_PUBLIC}/t/{ROOT_ORG_HANDLE}/o/{org_id}/oauth2/authorize"
        )
        app["tokenEndpoint"] = (
            f"{WSO2_PUBLIC}/t/{ROOT_ORG_HANDLE}/o/{org_id}/oauth2/token"
        )
        app["oidc"] = {
            "grantTypes": ["authorization_code"],
            "publicClient": True,
            "pkceRequired": True,
        }

        log(
            f"{app['organization']} / {app['name']} -> "
            f"{oidc['clientId']} -> {access_url}"
        )

    if len(seen_client_ids) != 8:
        fail("Expected eight unique B2B OIDC clients")

    b2b["organizationApplications"] = apps
    b2b["oidcReady"] = True
    runtime["b2b"] = b2b

    RUNTIME.write_text(
        json.dumps(runtime, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if UI_RUNTIME.exists():
        ui = json.loads(UI_RUNTIME.read_text(encoding="utf-8"))
        ui["b2b"] = b2b
        UI_RUNTIME.write_text(
            json.dumps(ui, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    print("", flush=True)
    log("==================================================")
    log("B2B ORGANIZATION OIDC APPLICATIONS READY")
    log("8 organization-local applications")
    log("8 unique OIDC public clients")
    log("Authorization Code + mandatory PKCE")
    log("8 distinct redirect URIs on ports 3201-3208")
    log("==================================================")
    print("", flush=True)


if __name__ == "__main__":
    main()
