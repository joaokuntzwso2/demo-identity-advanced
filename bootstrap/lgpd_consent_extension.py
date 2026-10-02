#!/usr/bin/env python3
from __future__ import annotations

import json
import os

import bootstrap as core

ENABLED = os.getenv("ENABLE_LGPD_CONSENT_DEMO", "false").lower() == "true"
UPDATE_LEVEL = int(os.getenv("WSO2_IS_UPDATE_LEVEL", "0") or "0")
TARGET_APPLICATION = os.getenv("LGPD_CONSENT_APP", "Portal Corporativo")


def log(message: str) -> None:
    print(f"[lgpd-consent] {message}", flush=True)


def main() -> None:
    if not ENABLED:
        log("Disabled for the baseline stack; use scripts/start-lgpd-consent.sh for the consent scenario.")
        return

    if UPDATE_LEVEL < 12:
        raise RuntimeError(
            "LGPD consent demo requires WSO2 IS 7.3.0 update level 12 or later. "
            f"WSO2_IS_UPDATE_LEVEL={UPDATE_LEVEL}"
        )

    app = core.find_application(TARGET_APPLICATION)
    if not app or not app.get("id"):
        raise RuntimeError(
            f"LGPD consent demo target application {TARGET_APPLICATION!r} was not found"
        )

    manifest = {
        "readyForAdminConfiguration": True,
        "product": {
            "baseVersion": "7.3.0",
            "minimumUpdateLevel": 12,
            "declaredUpdateLevel": UPDATE_LEVEL,
            "consentManagementV2": True,
        },
        "application": {
            "id": app.get("id"),
            "name": app.get("name"),
            "policyLoginConstraint": (
                "Use a local user for the policy-at-login demonstration; "
                "policy consent at login is not supported for federated "
                "or app-native authentication flows."
            ),
        },
        "policy": {
            "name": "Aviso de Privacidade LGPD — MarketSphere Brasil",
            "url": "http://localhost:8300/policy/lgpd",
            "mandatory": True,
            "meaning": "privacy notice acknowledgement / transparency",
        },
        "preferences": [
            {
                "name": "Marketing por e-mail",
                "optional": True,
                "attribute": "Email",
            },
            {
                "name": "Comunicações promocionais por telefone",
                "optional": True,
                "attribute": "Mobile",
            },
            {
                "name": "Personalização e analytics",
                "optional": True,
                "attribute": None,
            },
        ],
        "webhook": {
            "endpoint": "http://consent-audit:8300/webhooks/wso2",
            "signature": "HMAC-SHA256 / x-wso2-event-signature",
            "events": [
                "consentAdded",
                "consentRevoked",
                "purposeVersionAdded",
            ],
        },
    }

    print(json.dumps(manifest, indent=2), flush=True)
    log("============================================================")
    log("LGPD CONSENT PLATFORM READY")
    log(f"Target app: {TARGET_APPLICATION}")
    log(f"Declared WSO2 IS update level: 7.3.0.{UPDATE_LEVEL}")
    log("Consent Management v2 + consent webhook config: enabled by deployment override")
    log("Admin objects/Flow Builder configuration: follow docs/LGPD_CONSENT_DEMO.md")
    log("============================================================")


if __name__ == "__main__":
    main()
