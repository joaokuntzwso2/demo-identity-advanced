#!/usr/bin/env bash
set -euo pipefail

echo "== App-specific MFA / adaptive authentication =="

docker compose run --rm --no-deps bootstrap python - <<'PY'
import json
import bootstrap as core

FINANCE_APP = "Finance Workspace"
SECURITY_APP = "Security Operations"
HIGH_RISK_ACR = "urn:marketsphere:security:high"

EXPECTED_MFA = {"totp", "FIDOAuthenticator"}


def full(name):
    app = core.find_application(name)
    assert app and app.get("id"), f"Missing application: {name}"
    return core.request(
        "GET",
        f"/api/server/v1/applications/{app['id']}",
        expected=(200,),
    ).json()


def step(sequence, step_id):
    return next(
        (
            item
            for item in (sequence.get("steps") or [])
            if int(item.get("id") or 0) == step_id
        ),
        None,
    )


def authenticators(item):
    if not item:
        return set()
    return {
        x.get("authenticator")
        for x in (item.get("options") or [])
        if isinstance(x, dict) and x.get("authenticator")
    }


finance = full(FINANCE_APP)
security = full(SECURITY_APP)

finance_seq = finance.get("authenticationSequence") or {}
security_seq = security.get("authenticationSequence") or {}

security_step2 = authenticators(step(security_seq, 2))
assert EXPECTED_MFA.issubset(security_step2), (
    "Security Operations step 2 does not contain both TOTP and Passkey",
    security_step2,
)

security_script = str(security_seq.get("script") or "")
assert security_script, "Security Operations has no conditional-authentication script"
assert "context.requestedAcr" in security_script
assert HIGH_RISK_ACR in security_script
assert "FIDOAuthenticator" in security_script

finance_script = str(finance_seq.get("script") or "")
assert HIGH_RISK_ACR not in finance_script, (
    "Finance Workspace unexpectedly has the Security Operations high-risk policy"
)

result = {
    "financeWorkspace": {
        "id": finance.get("id"),
        "sequenceType": finance_seq.get("type"),
        "steps": [
            {
                "id": item.get("id"),
                "authenticators": sorted(authenticators(item)),
            }
            for item in (finance_seq.get("steps") or [])
        ],
        "securityHighRiskPolicy": False,
    },
    "securityOperations": {
        "id": security.get("id"),
        "sequenceType": security_seq.get("type"),
        "steps": [
            {
                "id": item.get("id"),
                "authenticators": sorted(authenticators(item)),
            }
            for item in (security_seq.get("steps") or [])
        ],
        "mandatoryMfa": True,
        "normalMfa": "TOTP_OR_PASSKEY",
        "conditionalSource": "OIDC acr_values",
        "highRiskAcr": HIGH_RISK_ACR,
        "highRiskMfa": "PASSKEY_ONLY",
    },
}

print(json.dumps(result, indent=2))
print()
print(
    "PASS: Finance and Security Operations have independent login policies; "
    "Security Operations has mandatory MFA plus ACR-based adaptive step-up."
)
PY
