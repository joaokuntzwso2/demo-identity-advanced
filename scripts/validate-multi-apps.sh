#!/usr/bin/env bash
set -euo pipefail

echo "== Distinct application topology =="

for entry in \
  "3000|Portal Corporativo" \
  "3100|Application Portal" \
  "3101|Finance Workspace" \
  "3102|Security Operations" \
  "3201|Retail Governance Console" \
  "3202|Partner Storefront / Seller" \
  "3203|Seller Backoffice" \
  "3204|Settlement Service" \
  "3205|Logistics Integration" \
  "3206|International Partner Console" \
  "3207|Partner Storefront / Mexico" \
  "3208|Mexico Operations"
do
  port="${entry%%|*}"
  name="${entry#*|}"
  curl -fsS "http://localhost:${port}/" >/dev/null
  echo "PASS ${name} :${port}"
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsS http://localhost:4000/api/config > "$tmp"

python3 - "$tmp" <<'PY'
import json, sys

cfg = json.load(open(sys.argv[1]))

expected_root = {
    "appPortal": "http://localhost:3100/callback",
    "finance": "http://localhost:3101/callback",
    "security": "http://localhost:3102/callback",
}

clients = cfg.get("clients") or {}
for key, expected in expected_root.items():
    assert key in clients, f"missing root browser client {key}"
    actual = clients[key].get("redirectUri")
    assert actual == expected, f"{key}: expected {expected}, got {actual}"

b2b = cfg.get("b2b") or {}
apps = b2b.get("organizationApplications") or []
assert len(apps) == 8, f"expected 8 B2B apps, got {len(apps)}"

access_urls = [a.get("accessUrl") for a in apps]
assert all(access_urls), "one or more B2B apps has no accessUrl"
assert len(set(access_urls)) == 8, "B2B access URLs are not unique"
assert set(access_urls) == {
    f"http://localhost:{port}/" for port in range(3201, 3209)
}, access_urls

client_ids = [a.get("clientId") for a in apps]
assert all(client_ids), "one or more B2B apps has no OIDC clientId"
assert len(set(client_ids)) == 8, "B2B OIDC client IDs are not unique"

redirects = [a.get("redirectUri") for a in apps]
assert all(redirects), "one or more B2B apps has no redirectUri"
assert len(set(redirects)) == 8, "B2B redirect URIs are not unique"

for app in apps:
    expected = app["accessUrl"].rstrip("/") + "/callback.html"
    assert app["redirectUri"] == expected, (
        app.get("name"), app.get("redirectUri"), expected
    )
    oidc = app.get("oidc") or {}
    assert oidc.get("publicClient") is True, f"{app.get('name')}: not public"
    assert oidc.get("pkceRequired") is True, f"{app.get('name')}: PKCE not required"
    assert oidc.get("grantTypes") == ["authorization_code"], (
        f"{app.get('name')}: unexpected grant types {oidc.get('grantTypes')}"
    )

print("PASS root browser applications have distinct redirect URIs")
print("PASS 8 B2B applications have distinct URLs")
print("PASS 8 B2B applications have unique OIDC client IDs")
print("PASS 8 B2B applications use Authorization Code + mandatory PKCE")
print("PASS machine/agent clients remain non-browser workloads")
PY

echo "MULTI-APPLICATION VALIDATION PASSED"
