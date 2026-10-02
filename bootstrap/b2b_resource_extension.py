#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/runtime"))
RUNTIME = RUNTIME_DIR / "runtime-config.json"
UI_RUNTIME = RUNTIME_DIR / "ui-config.json"

RESOURCE_MAP = {
    ("retail-br", "Retail Governance Console"): "/api/b2b/retail/governance",
    ("seller-alpha", "Partner Storefront"): "/api/b2b/seller/storefront",
    ("seller-alpha", "Seller Backoffice"): "/api/b2b/seller/backoffice",
    ("fintech-latam", "Settlement Service"): "/api/b2b/fintech/settlements",
    ("seller-logistics", "Logistics Integration"): "/api/b2b/logistics/shipments",
    ("international", "International Partner Console"): "/api/b2b/international/partners",
    ("mexico", "Partner Storefront"): "/api/b2b/mexico/storefront",
    ("mexico", "Mexico Operations"): "/api/b2b/mexico/operations",
}

NEGATIVE_MAP = {
    ("retail-br", "Retail Governance Console"): "/api/b2b/mexico/operations",
    ("seller-alpha", "Partner Storefront"): "/api/b2b/mexico/storefront",
    ("seller-alpha", "Seller Backoffice"): "/api/b2b/mexico/operations",
    ("fintech-latam", "Settlement Service"): "/api/b2b/seller/storefront",
    ("seller-logistics", "Logistics Integration"): "/api/b2b/mexico/operations",
    ("international", "International Partner Console"): "/api/b2b/seller/storefront",
    ("mexico", "Partner Storefront"): "/api/b2b/seller/storefront",
    ("mexico", "Mexico Operations"): "/api/b2b/seller/backoffice",
}


def log(message: str) -> None:
    print(f"[b2b-resource] {message}", flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"Missing runtime configuration: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def enrich(config: dict[str, Any]) -> dict[str, Any]:
    b2b = config.get("b2b") or {}
    apps = b2b.get("organizationApplications") or []

    if len(apps) != 8:
        fail(f"Expected 8 B2B applications; found {len(apps)}")

    seen_paths: set[str] = set()

    for app in apps:
        key = (app.get("organizationKey"), app.get("name"))
        path = RESOURCE_MAP.get(key)
        negative = NEGATIVE_MAP.get(key)

        if not path or not negative:
            fail(f"No protected-resource mapping for {key!r}")

        if path in seen_paths:
            fail(f"Duplicate B2B protected-resource path: {path}")
        seen_paths.add(path)

        app["resourceApiPath"] = path
        app["negativeResourceApiPath"] = negative
        app["resourceIsolation"] = {
            "enforcedClaim": "org_id",
            "expectedOrganizationId": app.get("organizationId"),
            "mismatchStatus": 403,
            "mismatchCode": "cross_organization_access_denied",
        }

        log(
            f"{app.get('organization')} / {app.get('name')} -> {path} "
            f"(negative proof: {negative})"
        )

    if len(seen_paths) != 8:
        fail("Expected eight unique protected-resource paths")

    b2b["organizationApplications"] = apps
    b2b["protectedResourceIsolation"] = {
        "ready": True,
        "enforcedClaim": "org_id",
        "policy": (
            "Authenticated JWT org_id must equal the organization that owns "
            "the requested B2B resource."
        ),
        "mismatchStatus": 403,
        "mismatchCode": "cross_organization_access_denied",
        "resourceCount": 8,
    }
    config["b2b"] = b2b
    return config


def main() -> None:
    runtime = enrich(load(RUNTIME))
    RUNTIME.write_text(
        json.dumps(runtime, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if UI_RUNTIME.exists():
        ui = load(UI_RUNTIME)
        ui["b2b"] = runtime["b2b"]
        UI_RUNTIME.write_text(
            json.dumps(ui, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    print("")
    log("==================================================")
    log("CROSS-ORGANIZATION RESOURCE ISOLATION READY")
    log("8 B2B browser applications -> 8 protected API endpoints")
    log("enforcement: signed access-token org_id == resource organization")
    log("mismatch: HTTP 403 cross_organization_access_denied")
    log("==================================================")
    print("")


if __name__ == "__main__":
    main()
