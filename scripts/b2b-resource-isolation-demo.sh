#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsS http://localhost:4000/api/config > "$tmp"

python3 - "$tmp" <<'PY'
import json, sys

cfg = json.load(open(sys.argv[1]))
apps = (cfg.get("b2b") or {}).get("organizationApplications") or []

print("")
print("B2B PROTECTED-RESOURCE ISOLATION DEMO")
print("=" * 74)

for app in apps:
    print(f"{app['organization']} / {app['name']}")
    print(f"  SPA        : {app['accessUrl']}")
    print(f"  ALLOW API  : {app.get('resourceApiPath')}")
    print(f"  DENY proof : {app.get('negativeResourceApiPath')}")
    print()

print("Recommended customer proof:")
print("  1. Open http://localhost:3202/ (Seller Alpha Partner Storefront).")
print("  2. Sign in with seller.admin / Seller@1234.")
print("  3. The Seller protected API automatically returns HTTP 200.")
print("  4. Click 'Try cross-organization access (expected 403)'.")
print("  5. The Mexico protected API returns HTTP 403")
print("     code=cross_organization_access_denied.")
print("")
print("Then run:")
print("  ./scripts/test-b2b-resource-isolation.sh")
print("=" * 74)
PY
