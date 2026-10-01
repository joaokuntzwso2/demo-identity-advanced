#!/usr/bin/env python3
"""Give each browser/B2B demo application a realistic, distinct address.

This stage runs after the base bootstrap, B2B bootstrap, and admin-boundary
bootstrap. It is idempotent. Browser applications are real OIDC public clients
with independent redirect URIs; B2B organization applications get independent
access URLs. Service/agent clients intentionally remain non-browser workloads.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import bootstrap as core
import rfp_extension as rfp

RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
RUNTIME = RUNTIME_DIR / "runtime-config.json"
UI_RUNTIME = RUNTIME_DIR / "ui-config.json"

ROOT_APPS = {
    "appPortal": {
        "client_name": "marketsphere-myapps-spa",
        "display_name": "Application Portal",
        "url": "http://localhost:3100/",
        "redirect": "http://localhost:3100/callback",
        "scopes": "openid profile email internal_login",
    },
    "finance": {
        "client_name": "marketsphere-finance-spa",
        "display_name": "Finance Workspace",
        "url": "http://localhost:3101/",
        "redirect": "http://localhost:3101/callback",
        "scopes": "openid profile email portal.read",
    },
    "security": {
        "client_name": "marketsphere-security-spa",
        "display_name": "Security Operations",
        "url": "http://localhost:3102/",
        "redirect": "http://localhost:3102/callback",
        "scopes": "openid profile email portal.read portal.admin",
    },
}

B2B_URLS = {
    ("retail-br", "Retail Governance Console"): "http://localhost:3201/",
    ("seller-alpha", "Partner Storefront"): "http://localhost:3202/",
    ("seller-alpha", "Seller Backoffice"): "http://localhost:3203/",
    ("fintech-latam", "Settlement Service"): "http://localhost:3204/",
    ("seller-logistics", "Logistics Integration"): "http://localhost:3205/",
    ("international", "International Partner Console"): "http://localhost:3206/",
    ("mexico", "Partner Storefront"): "http://localhost:3207/",
    ("mexico", "Mexico Operations"): "http://localhost:3208/",
}


def log(message: str) -> None:
    print(f"[multi-apps] {message}", flush=True)


def exact_group(name: str) -> dict[str, Any]:
    groups = core.scim_filter("Groups", "displayName", name)
    exact = [
        group for group in groups
        if str(group.get("displayName") or "").split("/", 1)[-1] == name
    ]
    if len(exact) != 1:
        raise RuntimeError(
            f"Expected exactly one group named {name!r}; found {len(exact)}"
        )
    return exact[0]


def configure_root_apps(runtime: dict[str, Any]) -> None:
    finance_group = exact_group("finance_users")
    admin_group = exact_group("portal_admins")

    for key, spec in ROOT_APPS.items():
        client = core.ensure_client(
            spec["client_name"],
            spec["display_name"],
            ["authorization_code", "refresh_token"],
            redirect_uris=[spec["redirect"], spec["url"]],
            public=True,
            pkce=True,
        )
        app = core.find_application(spec["display_name"])
        core.configure_oidc_protocol(
            app["id"], browser_origin=spec["url"].rstrip("/")
        )

        if key == "finance":
            core.ensure_discoverable_application(
                app["id"], "http://localhost:3101/?sso=1", [finance_group]
            )
        elif key == "security":
            core.ensure_discoverable_application(
                app["id"], "http://localhost:3102/?sso=1", [admin_group]
            )
        else:
            core.request(
                "PATCH",
                f"/api/server/v1/applications/{app['id']}",
                expected=(200, 204),
                json={
                    "accessUrl": spec["url"],
                    "advancedConfigurations": {
                        "skipLoginConsent": True,
                        "skipLogoutConsent": True,
                    },
                },
            )

        entry = {
            "clientId": client["client_id"],
            "redirectUri": spec["redirect"],
            "postLogoutRedirectUri": spec["url"],
            "scopes": spec["scopes"],
            "displayName": spec["display_name"],
        }
        if key in {"finance", "security"}:
            entry["resourceIdentifier"] = runtime["resources"]["marketplace"]["identifier"]
        runtime.setdefault("clients", {})[key] = entry
        log(f"{spec['display_name']} -> {spec['url']}")


def configure_b2b_urls(runtime: dict[str, Any]) -> None:
    b2b = runtime.get("b2b") or {}
    apps = b2b.get("organizationApplications") or []
    if len(apps) != 8:
        raise RuntimeError(
            f"Expected 8 B2B organization applications; found {len(apps)}"
        )

    client = rfp.ensure_management_client(
        ["client_credentials", "organization_switch"]
    )
    rfp.authorize_management_scopes(client["application_id"])
    root_token = rfp.token_client_credentials(client)

    for app in apps:
        key = (app.get("organizationKey"), app.get("name"))
        url = B2B_URLS.get(key)
        if not url:
            raise RuntimeError(f"No distinct URL configured for {key}")
        org_id = app.get("organizationId")
        app_id = app.get("id")
        if not org_id or not app_id:
            raise RuntimeError(f"B2B application missing IDs: {app}")

        org_token = rfp.organization_switch(client, root_token, org_id, scopes=rfp.ORG_APP_SCOPES)
        rfp.bearer_request(
            "PATCH",
            f"/o/api/server/v1/applications/{app_id}",
            org_token,
            expected=(200, 204),
            headers={"Content-Type": "application/json"},
            json={"accessUrl": url},
        )
        verify = rfp.bearer_request(
            "GET",
            f"/o/api/server/v1/applications/{app_id}",
            org_token,
            expected=(200,),
        ).json()
        persisted = verify.get("accessUrl") or verify.get("accessURL")
        if persisted != url:
            raise RuntimeError(
                f"B2B accessUrl did not persist for {app['name']}: {persisted!r}"
            )
        app["accessUrl"] = url
        log(f"{app['organization']} / {app['name']} -> {url}")

    urls = [app.get("accessUrl") for app in apps]
    if len(set(urls)) != 8:
        raise RuntimeError("B2B application access URLs are not unique")


def publish(runtime: dict[str, Any]) -> None:
    topology = {
        "browserApplications": [
            {
                "name": "Portal Corporativo",
                "url": "http://localhost:3000/",
                "type": "OIDC SPA",
            },
            {
                "name": "Application Portal",
                "url": "http://localhost:3100/",
                "type": "OIDC application launcher",
            },
            {
                "name": "Finance Workspace",
                "url": "http://localhost:3101/",
                "type": "OIDC SPA",
            },
            {
                "name": "Security Operations",
                "url": "http://localhost:3102/",
                "type": "OIDC SPA",
            },
        ],
        "b2bApplications": [
            {
                "organization": app["organization"],
                "name": app["name"],
                "url": app["accessUrl"],
                "type": "organization-local browser application",
            }
            for app in runtime["b2b"]["organizationApplications"]
        ],
        "nonBrowserWorkloads": [
            "Orders M2M Client",
            "Token Exchange Backend",
            "Inventory Agent Application",
            "Inventory Agent Workload Fallback",
            "MarketSphere B2B Bootstrap Client",
        ],
    }
    runtime["applicationTopology"] = topology
    RUNTIME.write_text(
        json.dumps(runtime, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    ui = (
        json.loads(UI_RUNTIME.read_text(encoding="utf-8"))
        if UI_RUNTIME.exists()
        else {}
    )
    ui.setdefault("clients", {}).update(
        {
            "appPortal": runtime["clients"]["appPortal"],
            "finance": runtime["clients"]["finance"],
            "security": runtime["clients"]["security"],
        }
    )
    ui["b2b"] = runtime.get("b2b")
    ui["applicationTopology"] = topology
    UI_RUNTIME.write_text(
        json.dumps(ui, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    if not RUNTIME.exists():
        raise RuntimeError(
            "runtime-config.json is missing; base/RFP bootstrap must run first"
        )
    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    configure_root_apps(runtime)
    configure_b2b_urls(runtime)
    publish(runtime)

    print("", flush=True)
    log("==================================================")
    log("DISTINCT APPLICATION TOPOLOGY READY")
    log("Portal Corporativo     http://localhost:3000/")
    log("Application Portal     http://localhost:3100/")
    log("Finance Workspace      http://localhost:3101/")
    log("Security Operations    http://localhost:3102/")
    log("B2B applications       http://localhost:3201/ ... :3208/")
    log("==================================================")


if __name__ == "__main__":
    main()
