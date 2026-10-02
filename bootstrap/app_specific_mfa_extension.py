#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

import bootstrap as core

FINANCE_APP = "Finance Workspace"
SECURITY_APP = "Security Operations"

# Standard OIDC ACR value used only by this demo.
# Normal Security Operations login => TOTP OR Passkey.
# If the client requests this ACR => Passkey only.
HIGH_RISK_ACR = "urn:marketsphere:security:high"

TOTP_AUTHENTICATOR = "totp"
PASSKEY_AUTHENTICATOR = "FIDOAuthenticator"

SECURITY_SCRIPT = r'''
var highRiskAcr = 'urn:marketsphere:security:high';

var onLoginRequest = function(context) {
    executeStep(1, {
        onSuccess: function(context) {
            var requestedAcr = context.requestedAcr || [];
            var highRisk = requestedAcr.indexOf(highRiskAcr) >= 0;

            if (highRisk) {
                context.selectedAcr = highRiskAcr;

                // High-assurance request: allow only Passkey in the MFA step.
                executeStep(2, {
                    authenticationOptions: [
                        {
                            authenticator: 'FIDOAuthenticator'
                        }
                    ]
                }, {});
            } else {
                // Normal Security Operations login still requires MFA.
                // Step 2 offers TOTP or Passkey.
                executeStep(2);
            }
        }
    });
};
'''.strip()


def log(message: str) -> None:
    print(f"[app-mfa] {message}", flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def _app(name: str) -> dict[str, Any]:
    app = core.find_application(name)
    if not app or not app.get("id"):
        fail(f"Application {name!r} was not found")
    return app


def _full_application(name: str) -> dict[str, Any]:
    app = _app(name)
    return core.request(
        "GET",
        f"/api/server/v1/applications/{app['id']}",
        expected=(200,),
    ).json()


def _step(sequence: dict[str, Any], step_id: int) -> dict[str, Any] | None:
    for item in sequence.get("steps") or []:
        if int(item.get("id") or 0) == step_id:
            return item
    return None


def _authenticators(step: dict[str, Any] | None) -> set[str]:
    if not step:
        return set()
    return {
        str(option.get("authenticator"))
        for option in (step.get("options") or [])
        if isinstance(option, dict) and option.get("authenticator")
    }


def _normalize_step1(current: dict[str, Any]) -> dict[str, Any]:
    existing = _step(current, 1)
    if existing and existing.get("options"):
        # Preserve the application's current primary-login options.
        return existing

    # REST API representation for the built-in username/password authenticator.
    return {
        "id": 1,
        "options": [
            {
                "idp": "LOCAL",
                "authenticator": "basic",
            }
        ],
    }


def configure_security_operations() -> dict[str, Any]:
    app = _app(SECURITY_APP)
    app_id = app["id"]

    before = _full_application(SECURITY_APP)
    current = before.get("authenticationSequence") or {}
    step1 = _normalize_step1(current)

    sequence = {
        "type": "USER_DEFINED",
        "steps": [
            step1,
            {
                "id": 2,
                "options": [
                    {
                        "idp": "LOCAL",
                        "authenticator": TOTP_AUTHENTICATOR,
                    },
                    {
                        "idp": "LOCAL",
                        "authenticator": PASSKEY_AUTHENTICATOR,
                    },
                ],
            },
        ],
        "requestPathAuthenticators": (
            current.get("requestPathAuthenticators") or []
        ),
        "subjectStepId": int(current.get("subjectStepId") or 1),
        "attributeStepId": int(current.get("attributeStepId") or 1),
    }

    # Configure the per-application two-step login flow.
    core.request(
        "PATCH",
        f"/api/server/v1/applications/{app_id}",
        json={"authenticationSequence": sequence},
        expected=(200,),
    )

    # WSO2 recommends the dedicated endpoint for script updates.
    core.request(
        "PUT",
        (
            f"/api/server/v1/applications/{app_id}"
            "/authenticationSequence/script"
        ),
        json={"script": SECURITY_SCRIPT},
        expected=(200,),
    )

    persisted = _full_application(SECURITY_APP)
    persisted_sequence = persisted.get("authenticationSequence") or {}

    step2_authenticators = _authenticators(_step(persisted_sequence, 2))
    required = {TOTP_AUTHENTICATOR, PASSKEY_AUTHENTICATOR}
    if not required.issubset(step2_authenticators):
        fail(
            "Security Operations did not persist the expected MFA options. "
            f"Expected {sorted(required)!r}; "
            f"got {sorted(step2_authenticators)!r}"
        )

    persisted_script = str(persisted_sequence.get("script") or "")
    for marker in (
        "context.requestedAcr",
        HIGH_RISK_ACR,
        "FIDOAuthenticator",
        "executeStep(2)",
    ):
        if marker not in persisted_script:
            fail(
                "Security Operations conditional authentication script "
                f"did not persist marker {marker!r}"
            )

    log(
        "Security Operations configured: "
        "step 1 = existing primary login; "
        "step 2 = TOTP | Passkey; "
        f"ACR {HIGH_RISK_ACR!r} = Passkey only"
    )
    return persisted


def verify_finance_is_distinct() -> dict[str, Any]:
    finance = _full_application(FINANCE_APP)
    sequence = finance.get("authenticationSequence") or {}
    script = str(sequence.get("script") or "")

    if HIGH_RISK_ACR in script:
        fail(
            "Finance Workspace unexpectedly contains the "
            "Security Operations adaptive-authentication script"
        )

    log(
        "Finance Workspace left unchanged; "
        "it retains its existing application-specific login flow"
    )
    return finance


def describe(app: dict[str, Any]) -> dict[str, Any]:
    sequence = app.get("authenticationSequence") or {}
    steps = []
    for item in sequence.get("steps") or []:
        steps.append(
            {
                "id": item.get("id"),
                "authenticators": sorted(_authenticators(item)),
            }
        )
    return {
        "name": app.get("name"),
        "id": app.get("id"),
        "authenticationSequenceType": sequence.get("type"),
        "steps": steps,
        "conditionalAuthentication": bool(sequence.get("script")),
    }


def main() -> None:
    finance = verify_finance_is_distinct()
    security = configure_security_operations()

    print()
    print(
        json.dumps(
            {
                "finance": describe(finance),
                "securityOperations": describe(security),
                "adaptiveCondition": {
                    "source": "OIDC acr_values",
                    "acr": HIGH_RISK_ACR,
                    "normal": "TOTP_OR_PASSKEY",
                    "highRisk": "PASSKEY_ONLY",
                },
            },
            indent=2,
        ),
        flush=True,
    )

    print()
    log("==================================================")
    log("APP-SPECIFIC MFA + ADAPTIVE AUTH READY")
    log("Finance Workspace: existing/normal login")
    log("Security Operations: mandatory MFA (TOTP | Passkey)")
    log(f"High-risk ACR: {HIGH_RISK_ACR} -> Passkey only")
    log("==================================================")


if __name__ == "__main__":
    main()
