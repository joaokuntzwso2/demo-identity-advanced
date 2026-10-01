# Customer RFP Demo — WSO2 Identity Server 7.3

This is the presentation and validation runbook for the complete repository plus the customer RFP scenarios.

## 1. One-command non-interactive preflight

```bash
./scripts/test-e2e-rfp.sh
```

Expected final line:

```text
ALL NON-INTERACTIVE E2E CHECKS PASSED
```

Useful URLs:

```bash
./scripts/customer-demo.sh urls
```

## 2. Executive path — 12–15 minutes

### 2.1 RFP Demo Center

Open:

```text
http://localhost:3000/rfp-demo.html
```

Show:

- six organizations
- three hierarchy levels
- eight resident users
- eight organization-local applications
- the RF-01 → RF-21 coverage matrix
- the distinction between LIVE, CONFIGURED, PLATFORM, COMPLEMENTARY, ARCHITECTURE and CONTRACTUAL

### 2.2 B2B hierarchy

Open:

```text
https://localhost:9443/console
```

Navigate to Organizations and show:

```text
MarketSphere Retail Brazil
├── Seller Alpha Commerce
│   └── Seller Alpha Logistics
└── Partner Fintech LATAM

MarketSphere International
└── Marketplace Mexico
```

Explain the real API pattern used by bootstrap:

```text
Client Credentials
→ API Authorization
→ root Organization Management API
→ application sharing
→ Organization Switch
→ organization-scoped Management/SCIM APIs
```

### 2.3 Isolation

Show the resident user `operator` in:

- Seller Alpha Commerce
- Marketplace Mexico

Then show `Partner Storefront` in:

- Seller Alpha Commerce
- Marketplace Mexico

The WSO2 IDs are different in each organization context.

### 2.4 Core identity capabilities

Open:

```text
http://localhost:3000/
```

Demonstrate:

1. Alice — normal Portal authorization.
2. Bob — authentication succeeds, Portal authorization fails.
3. Carol — admin authorization.
4. External Corporate OIDC federation through Keycloak.
5. Client Credentials service identity.
6. RFC 8693 Token Exchange with privilege reduction.
7. Agent Identity / workload execution.

## 3. Full technical path — 30–45 minutes

### Flow 1 — Authorization Code + PKCE

Credentials:

```text
alice / Alice@123
```

Expected:

- Authorization Code with PKCE S256
- ID/access tokens from WSO2
- `portal.read`
- Portal access allowed
- admin operation denied

Covers RF-01, RF-06 and part of RF-12.

### Flow 2 — Authentication is not authorization

Credentials:

```text
bob / Bob@1234
```

Expected:

- login succeeds
- Portal access is denied because Bob lacks the required role/group authorization

This is the negative RBAC scenario.

### Flow 3 — Administrator authorization

Credentials:

```text
carol / Carol@123
```

Expected:

- `portal.read`
- `portal.admin`
- Portal operation allowed
- administrative operation allowed

### Flow 4 — Native My Account / discoverable applications

Open:

```text
https://localhost:9443/myaccount
```

Show the native self-service surface and discoverable applications.

Use this to discuss profile, sessions, consent, password and passkey-management capabilities without pretending every self-service path is pre-executed by bootstrap.

### Flow 5 — External OIDC federation

From the Portal choose the Corporate OIDC sign-in option.

Expected:

```text
Portal → WSO2 → Keycloak → WSO2 → Portal
```

Show normalized claims.

Covers RF-09.

### Flow 6 — Secondary LDAP

Use the existing CORP users from the repository.

Positive LDAP identity:

```text
CORP/diana / Corporate@123
```

Negative authorization identity:

```text
CORP/eduardo / Corporate@123
```

Expected:

- LDAP authentication works without migrating passwords into the primary WSO2 user store
- Eduardo is not treated as authorized merely because authentication succeeded

### Flow 7 — Client Credentials / service account

Use the existing Orders M2M scenario.

Expected:

```text
Orders M2M Client
→ client_credentials
→ JWT access token
→ orders.read
→ protected API ALLOW
```

Covers RF-02 and RF-17.

### Flow 8 — Token Exchange RFC 8693

Initiating user:

```text
carol / Carol@123
```

Expected chain:

```text
Carol
→ backend obtains external Keycloak token for Alice
→ WSO2 validates trusted external issuer
→ preferred_username maps to local username
→ local Alice association
→ local token-exchange-service authorization
→ exchanged token with downstream.read
→ downstream API ALLOW
```

The new token must not expand privileges.

Covers RF-04.

### Flow 9 — Token Exchange negative test

Initiating user:

```text
alice / Alice@123
```

Attempt the administrative exchange operation.

Expected:

```text
HTTP 403
required scope: portal.admin
```

### Flow 10 — Agent Identity

Initiating user:

```text
carol / Carol@123
```

Expected:

```text
Carol authorizes operation
→ Inventory Reconciliation Agent
→ dedicated workload identity
→ inventory.read + inventory.write
→ protected API ALLOW
```

Be precise in the presentation:

- the managed Agent identity is a first-class identity
- Agent owner/role metadata exists
- the tested execution path uses the dedicated Client Credentials workload fallback when the app-native flag is unavailable
- do not describe the fallback token as Carol's token or as native Agent authentication

### Flow 11 — B2B root organizations

Show:

- MarketSphere Retail Brazil
- MarketSphere International

These are created with the root Organization Management API.

### Flow 12 — Multi-level child organizations

Show:

- Seller Alpha Commerce beneath Retail Brazil
- Seller Alpha Logistics beneath Seller Alpha Commerce
- Partner Fintech LATAM beneath Retail Brazil
- Marketplace Mexico beneath International

This proves at least three hierarchy levels.

### Flow 13 — Resident users

Show:

```text
MarketSphere Retail Brazil
  retail.admin

Seller Alpha Commerce
  seller.admin
  operator

Seller Alpha Logistics
  logistics.operator

Partner Fintech LATAM
  fintech.admin

MarketSphere International
  intl.admin

Marketplace Mexico
  operator
  mexico.admin
```

### Flow 14 — Organization-local applications

Show:

```text
MarketSphere Retail Brazil
  Retail Governance Console

Seller Alpha Commerce
  Partner Storefront
  Seller Backoffice

Seller Alpha Logistics
  Logistics Integration

Partner Fintech LATAM
  Settlement Service

MarketSphere International
  International Partner Console

Marketplace Mexico
  Partner Storefront
  Mexico Operations
```

### Flow 15 — Isolation proof

Compare both `operator` identities and both `Partner Storefront` applications.

Expected:

- same display/user name
- different organization
- different WSO2 object ID

### Flow 16 — RFP capabilities shown as product evidence

Use the RFP Demo Center for capabilities that are technically real but should not be faked as local transactions:

- JWT Bearer / private_key_jwt
- OIDC Back-Channel Logout
- SAML 2.0
- Passkeys/WebAuthn
- TOTP, SMS OTP, Email OTP
- adaptive authentication and provider fallback
- consent history
- approval workflows
- organization/application branding
- notification templates and localization
- privacy / DSAR support
- MCP authorization
- CIBA/OBO patterns
- HA / non-persistent token architecture
- Enterprise support SLA

## 4. RFP product boundaries

### RF-16 — API Keys

Operational API-key lifecycle is a WSO2 API Manager capability. Do not present Identity Server as the API-key lifecycle product.

### RF-18 — scale and 99.99%

Explain the architecture:

```text
horizontally scalable IS nodes
+ load balancing
+ HA persistence/shared dependencies where required
+ self-contained/non-persistent JWT strategy
+ Kubernetes scaling / pre-scaling
```

A laptop demonstration does not prove a contractual SLA or Black-Friday throughput.

### RF-11 — MFA fallback

Real SMS/e-mail provider fallback needs actual providers and an explicit adaptive-authentication policy. Do not stage a fake provider outage.

### RF-19 — privacy

Native product controls and APIs are valid evidence. A full enterprise DSAR usually spans additional systems and workflow.

### Delegated human administration

The live bootstrap proves organization-scoped administration using a least-privilege M2M management client plus Organization Switch.

Human delegated Console administration is a native product capability but is not represented as a fake preconfigured human-admin role in this POC unless such role assignment is explicitly added and validated.

## 5. B2B demo-only credentials

These are local POC credentials and are not exposed by `/api/config`.

```text
MarketSphere Retail Brazil
  retail.admin / Retail@1234

Seller Alpha Commerce
  seller.admin / Seller@1234
  operator     / Seller@1234

Seller Alpha Logistics
  logistics.operator / Logistics@1234

Partner Fintech LATAM
  fintech.admin / Fintech@1234

MarketSphere International
  intl.admin / International@1234

Marketplace Mexico
  operator     / Mexico@1234
  mexico.admin / Mexico@1234
```

## 6. Final rehearsal

With existing volumes:

```bash
docker compose up --build -d
./scripts/test-e2e-rfp.sh
```

Then execute the interactive flows above.

Only after the persisted-state rehearsal passes, prove clean reproducibility:

```bash
docker compose down -v --remove-orphans
docker compose up --build -d
docker compose logs -f bootstrap
./scripts/test-e2e-rfp.sh
```

> **B2B application sharing:** the bootstrap uses WSO2 IS 7.3 `POST /api/server/v1/applications/share-with-all` with policy `ALL_EXISTING_AND_FUTURE_ORGS`. `Organization Switch` is enabled only after the management application is shared.

### Bootstrap idempotency validation

Before a customer presentation or before sharing the repository, validate that
the generated IAM state can be reconciled more than once:

```bash
./scripts/test-bootstrap-idempotency.sh
```

The test force-recreates the bootstrap container twice against the same WSO2
persistent state. Both runs must exit with code `0` and print
`CUSTOMER RFP DEMO READY`.

The B2B extension obtains a fresh Organization Switch token immediately before
organization-scoped SCIM and application-management operations. Organization
Switch tokens are treated as short-lived organization-context credentials
rather than cached across the whole bootstrap.

## Demo privileged-access boundary

The customer demo intentionally uses a strict privilege boundary:

- root `admin` is shared with **all existing and future organizations**;
- root `admin` receives the **Administrator** role of the WSO2 **Console** application in every organization;
- this grants root `admin` full Console access after switching organization context;
- `alice`, `bob`, and `carol` are explicitly kept out of organization shared access;
- B2B resident users remain resident in their own organization and are not assigned the Console Administrator role by the bootstrap.

The provisioning stage uses the supported **User Sharing API v2** and policy:

```text
ALL_EXISTING_AND_FUTURE_ORGS
```

with a selected role assignment:

```text
Console / Administrator
```

Emergency/idempotent repair:

```bash
./scripts/ensure-admin-access.sh
```

Read-only validation:

```bash
./scripts/verify-admin-boundary.sh
```

After provisioning or repairing access, **log out of WSO2 Console and log back in as `admin`** so the browser session receives the updated organization access.

Expected UI navigation:

```text
Root / Super
├── MarketSphere Retail Brazil          [Switch]
│   ├── Seller Alpha Commerce           [Switch]
│   │   └── Seller Alpha Logistics      [Switch]
│   └── Partner Fintech LATAM           [Switch]
└── MarketSphere International          [Switch]
    └── Marketplace Mexico              [Switch]
```

From each organization context, `admin` can inspect and manage users,
applications, roles, identity providers, login configuration, branding and
child organizations according to the Console Administrator permissions.

The other demo users are intentionally not global administrators. This is a
least-privilege demonstration, not six copies of the root super administrator.

### Demo-day preflight

Before the customer session run:

```bash
./scripts/demo-day-preflight.sh
```

The preflight checks Docker, known port conflicts, bootstrap completion, the
root-admin privilege boundary, repository smoke tests, RFP/B2B state and all
customer-facing HTTP surfaces. It finishes with `DEMO DAY READY` only when all
checks pass.

## Distinct application topology

The demo uses independent addresses for independent browser applications:

```text
Portal Corporativo       http://localhost:3000/
Application Portal       http://localhost:3100/
Finance Workspace        http://localhost:3101/
Security Operations      http://localhost:3102/
```

`Application Portal`, `Finance Workspace`, and `Security Operations` are
separate WSO2 applications with separate client IDs and redirect URIs. Finance
and Security run Authorization Code + PKCE from their own origins. The
Application Portal uses WSO2's native discoverable-application API and opens
the entitled application at its own URL; an existing WSO2 SSO session makes
the subsequent application login seamless while preserving the independent
OIDC client boundary.

The B2B organization applications also have unique addresses:

```text
3201  Retail Governance Console      MarketSphere Retail Brazil
3202  Partner Storefront             Seller Alpha Commerce
3203  Seller Backoffice              Seller Alpha Commerce
3204  Settlement Service             Partner Fintech LATAM
3205  Logistics Integration          Seller Alpha Logistics
3206  International Partner Console  MarketSphere International
3207  Partner Storefront             Marketplace Mexico
3208  Mexico Operations              Marketplace Mexico
```

The two `Partner Storefront` entries deliberately keep the same display name,
but have different WSO2 IDs, owning organizations and URLs. This is the B2B
namespace/isolation demonstration.

The following registered applications intentionally remain non-browser
workloads because they represent machine or agent identities:

```text
Orders M2M Client
Token Exchange Backend
Inventory Agent Application
Inventory Agent Workload Fallback
MarketSphere B2B Bootstrap Client
```

Giving those clients fake web sites would misrepresent their role.

Validate the topology with:

```bash
./scripts/validate-multi-apps.sh
```

### UI test flow for distinct applications

1. Open `http://localhost:3100/` and sign in to the Application Portal.
2. With Alice, the catalog should expose the applications allowed by her
   discoverability groups, including Finance Workspace.
3. Open Finance Workspace. It launches `http://localhost:3101/`, performs its
   own OIDC Authorization Code + PKCE flow, reuses the WSO2 SSO session, and
   calls the finance-specific protected API.
4. With Carol, use Application Portal to launch Security Operations at
   `http://localhost:3102/`; it requires the Security application entitlement
   plus `portal.read` and `portal.admin`.
5. In WSO2 Console as root `admin`, switch among the B2B organizations and
   inspect each application `Access URL`. The eight organization-local apps
   point to `3201` through `3208`, not to the main MarketSphere portal.

### Root admin Console traversal — explicit role assignment

The demo uses a strict access boundary:

```text
admin
  -> shared to ALL_EXISTING_AND_FUTURE_ORGS
  -> shared/shadow user in each organization
  -> Organization Switch
  -> SCIM2 Roles API
  -> Console / Administrator membership in each organization

alice / bob / carol
  -> no B2B shared access

B2B resident users
  -> organization-local
  -> no Console Administrator assignment from bootstrap
```

User sharing and Console authorization are treated as separate operations.
The bootstrap explicitly assigns the shared `admin` identity to the Console
`Administrator` application role inside each organization.

Validation:

```bash
./scripts/ensure-admin-access.sh
./scripts/verify-admin-boundary.sh
```

After changing organization access, fully sign out of the WSO2 Console and
sign in again as `admin` before testing the **Switch** control.

## B2B applications are real OIDC relying parties

The eight organization-local browser applications are not placeholder
Application Management records. Each has its own organization-scoped WSO2
OIDC client:

```text
Retail Governance Console       :3201
Partner Storefront / Seller     :3202
Seller Backoffice               :3203
Settlement Service              :3204
Logistics Integration           :3205
International Partner Console   :3206
Partner Storefront / Mexico     :3207
Mexico Operations               :3208
```

Each client is configured as:

```text
OAuth 2.0 / OpenID Connect
Authorization Code
Public client
PKCE mandatory (S256)
Unique callback URL
Unique JavaScript origin
Organization-specific authorize/token endpoint
```

The browser initiates authentication directly against:

```text
https://localhost:9443/t/carbon.super/o/<ORG_ID>/oauth2/authorize
```

and exchanges the code with:

```text
https://localhost:9443/t/carbon.super/o/<ORG_ID>/oauth2/token
```

Validation:

```bash
./scripts/validate-b2b-oidc.sh
```
