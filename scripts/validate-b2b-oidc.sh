#!/usr/bin/env bash
set -euo pipefail

echo "== B2B OIDC application validation =="

for p in 3201 3202 3203 3204 3205 3206 3207 3208; do
  body="$(curl -fsS "http://localhost:${p}/")"
  grep -q "Sign in with WSO2" <<<"$body"
  grep -q "Organization-local OIDC application" <<<"$body"
  echo "PASS static OIDC SPA :${p}"
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsS http://localhost:4000/api/config > "$tmp"

python3 - "$tmp" <<'PY'
import json, sys

cfg = json.load(open(sys.argv[1]))
b2b = cfg.get("b2b") or {}

assert b2b.get("oidcReady") is True, "b2b.oidcReady != true"

apps = b2b.get("organizationApplications") or []
assert len(apps) == 8, f"expected 8 apps, got {len(apps)}"

client_ids = []
redirects = []

for app in apps:
    for field in (
        "id",
        "organizationId",
        "accessUrl",
        "clientId",
        "redirectUri",
        "authorizationEndpoint",
        "tokenEndpoint",
    ):
        assert app.get(field), f"{app.get('name')}: missing {field}"

    oidc = app.get("oidc") or {}
    assert oidc.get("publicClient") is True
    assert oidc.get("pkceRequired") is True
    assert oidc.get("grantTypes") == ["authorization_code"]

    assert (
        f"/o/{app['organizationId']}/oauth2/authorize"
        in app["authorizationEndpoint"]
    ), app["authorizationEndpoint"]

    assert (
        f"/o/{app['organizationId']}/oauth2/token"
        in app["tokenEndpoint"]
    ), app["tokenEndpoint"]

    expected_redirect = app["accessUrl"].rstrip("/") + "/callback.html"
    assert app["redirectUri"] == expected_redirect, (
        app["name"], app["redirectUri"], expected_redirect
    )

    client_ids.append(app["clientId"])
    redirects.append(app["redirectUri"])

assert len(set(client_ids)) == 8, "OIDC client IDs are not unique"
assert len(set(redirects)) == 8, "redirect URIs are not unique"

# Security check: inspect actual JSON field names instead of rejecting benign
# words such as "passwordless", "password authentication", etc.
sensitive_names = {
    "password",
    "clientsecret",
    "client_secret",
    "client-secret",
    "secret",
}

findings = []

def walk(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            if normalized in sensitive_names and child not in (None, "", False, [], {}):
                findings.append(f"{path}.{key}")
            walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            walk(child, f"{path}[{i}]")

walk(cfg)

assert not findings, (
    "public configuration contains populated sensitive fields: "
    + ", ".join(findings)
)

print("PASS 8 unique organization-local OIDC clients")
print("PASS Authorization Code + mandatory PKCE metadata")
print("PASS 8 organization-scoped authorization/token endpoints")
print("PASS public configuration contains no populated password/client-secret fields")
PY

echo "B2B OIDC VALIDATION PASSED"
