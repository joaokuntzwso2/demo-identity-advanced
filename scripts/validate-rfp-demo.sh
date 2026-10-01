#!/usr/bin/env bash
set -euo pipefail

HOST="${DEMO_HOST:-localhost}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "== Customer RFP/B2B validation =="

docker compose ps

curl -fsS "http://${HOST}:4000/api/config" -o "$TMP"

python3 - "$TMP" <<'PY'
import json, sys

cfg = json.load(open(sys.argv[1]))
b2b = cfg.get("b2b") or {}
rfp = cfg.get("rfp") or {}

assert b2b.get("ready") is True, "b2b.ready is not true"
assert len(b2b.get("organizations", [])) == 6, "expected 6 organizations"
assert max((x.get("depth", 0) for x in b2b["organizations"]), default=0) >= 3, "expected >=3 levels"
assert len(b2b.get("residentUsers", [])) == 8, "expected 8 resident users"
assert len(b2b.get("organizationApplications", [])) == 8, "expected 8 organization applications"
assert len(rfp.get("requirements", [])) == 21, "expected RF-01..RF-21"

users = [u for u in b2b["residentUsers"] if u.get("username") == "operator"]
assert len(users) == 2
assert len({u["organizationId"] for u in users}) == 2
assert len({u["id"] for u in users}) == 2

apps = [a for a in b2b["organizationApplications"] if a.get("name") == "Partner Storefront"]
assert len(apps) == 2
assert len({a["organizationId"] for a in apps}) == 2
assert len({a["id"] for a in apps}) == 2

forbidden = {"password", "client_secret", "clientSecret", "demoCredentials"}
def walk(v):
    if isinstance(v, dict):
        for k, x in v.items():
            assert k not in forbidden, f"public B2B payload contains forbidden key {k}"
            walk(x)
    elif isinstance(v, list):
        for x in v:
            walk(x)
walk(b2b)

print("PASS B2B runtime ready")
print("PASS 6 organizations / >=3 levels")
print("PASS 8 resident users")
print("PASS 8 organization-local applications")
print("PASS duplicate username isolation")
print("PASS duplicate application-name isolation")
print("PASS RF-01..RF-21 metadata")
print("PASS public B2B payload contains no passwords/client secrets")
PY

curl -fsS "http://${HOST}:3000/" >/dev/null
curl -fsS "http://${HOST}:3000/rfp-demo.html" >/dev/null
curl -kfsS "https://${HOST}:9443/console" >/dev/null
curl -kfsS "https://${HOST}:9443/myaccount" >/dev/null

echo "PASS main UI"
echo "PASS RFP Demo Center"
echo "PASS Console"
echo "PASS My Account"
