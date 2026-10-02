#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
============================================================
MARKETSPHERE BRASIL — LGPD CONSENT LIFECYCLE DEMO
============================================================

1. Open Portal Corporativo with a clean local-user browser session.
2. Register a NEW LOCAL user.
3. On registration:
   - acknowledge the mandatory LGPD Privacy Notice;
   - opt IN to Marketing por e-mail;
   - opt OUT of promotional phone communications;
   - choose the personalization preference independently.
4. Finish registration/login.
5. If application attributes are requested, approve only the attributes
   you intend to share.
6. Open My Account:
      https://localhost:9443/myaccount
   Navigate to Consents and show:
   - Application Consents
   - Policy Consents
   - Communication Preferences
7. Open downstream audit:
      http://localhost:8300
   Show consentAdded events.
8. In My Account, revoke "Marketing por e-mail".
9. Return to http://localhost:8300 and show consentRevoked plus the
   derived state changing to REVOKED.
10. In Console, create a new version of the LGPD Privacy Notice,
    enable "Prompt at next login", and keep Portal Corporativo assigned.
11. Log out and sign in again as the LOCAL user.
12. Show the updated policy prompt.
13. In the audit dashboard show:
    - purposeVersionAdded
    - the subsequent consentAdded after the user accepts the new version.

Important:
- Optional preferences must remain optional.
- The mandatory Privacy Notice is demonstrated as transparency /
  acknowledgement, not as blanket legal-basis consent for every processing
  operation.
- Policy-at-login is not supported for federated users or app-native flows,
  so use a local user for this path.
============================================================
EOF
