# MarketSphere Brasil — LGPD Consent Lifecycle Demo

## Goal

Demonstrate a realistic consent lifecycle with WSO2 Identity Server:

1. transparency / policy acknowledgement;
2. optional, purpose-specific consent preferences;
3. application attribute-sharing consent;
4. user self-service review and revocation in My Account;
5. signed downstream consent webhooks;
6. purpose versioning and re-prompt at the next login.

This is a technical demonstration of controls that can support an LGPD
program. It is **not** a claim that WSO2 configuration alone makes an
organization legally compliant.

## Product prerequisite

Consent Management v2, Policy Consent, Preference Management and the new
My Account consent experience require **WSO2 Identity Server 7.3.0 update
level 12 or later**.

The public `wso2/wso2is:7.3.0` image is the GA image without WSO2 Updates.
For this scenario, start the stack with an exact updated WSO2 subscription
image (preferably pinned by digest):

```bash
docker login <your-wso2-private-registry>

export WSO2_IS_IMAGE='<exact IS 7.3.0 updated image tag or digest>'
export WSO2_IS_UPDATE_LEVEL=12   # or the actual later level

./scripts/start-lgpd-consent.sh
./scripts/validate-lgpd-consent.sh
```

The consent-specific deployment configuration enables:

```toml
[consent_mgt]
enable_v2_api = true

[console.flows.scopes]
read = ["internal_flow_view", "internal_governance_view", "internal_consent_mgt_purpose_view"]

[identity_mgt.events.schemes]
ConsentEventHook.properties.enable = true
ConsentPurposeEventHook.properties.enable = true

[webhooks.event_profiles]
disabled_channels = []
```

## Why the LGPD UX is separated

Do **not** use a single blanket checkbox such as:

> "Aceito que meus dados sejam utilizados."

For the demo, distinguish:

- **Privacy Notice acknowledgement** — mandatory transparency / policy
  acknowledgement;
- **Marketing / personalization preferences** — optional, specific consent
  choices, each independently revocable;
- **Application attribute sharing** — the user's approval for WSO2 to release
  selected profile attributes to a specific application.

This makes the technical demo closer to the LGPD concepts of a free,
informed and unequivocal choice for a determined purpose.

## One-time Console configuration

### A. Create the LGPD privacy policy

Console:

**Login and Registration → Policy Management → New Policy**

Use:

**Name**

`Aviso de Privacidade LGPD — MarketSphere Brasil`

**Policy URL**

`http://localhost:8300/policy/lgpd`

**Description / checkbox label**

`Li o Aviso de Privacidade da MarketSphere Brasil e estou ciente de como meus dados pessoais são tratados, das finalidades informadas e de como exercer meus direitos previstos na LGPD.`

**Mandatory**

Enabled.

Create it and enable **Prompt at next login**.

Then open the policy:

**Applications → + Assign Application → Portal Corporativo**

The policy is now eligible to appear at login for users who have not
accepted the relevant version.

For the policy-at-login test, use a **local WSO2 user**. WSO2 does not
support policy consent at login for federated users or app-native
authentication flows.

### B. Create optional LGPD preferences

Console:

**Login and Registration → Preference Management**

Create these three independent preferences.

#### 1. Marketing por e-mail

Description:

`Autorizo o uso do meu endereço de e-mail para receber ofertas, novidades e comunicações de marketing da MarketSphere Brasil. Posso retirar este consentimento a qualquer momento em Minha Conta.`

Associate the **Email** user attribute.

#### 2. Comunicações promocionais por telefone

Description:

`Autorizo o uso do meu número de telefone para receber comunicações promocionais da MarketSphere Brasil por canais como SMS ou WhatsApp. Posso retirar este consentimento a qualquer momento em Minha Conta.`

Associate the **Mobile** / phone-number user attribute used by the tenant.

#### 3. Personalização e analytics

Description:

`Autorizo o uso de dados de navegação e interação para personalizar recomendações e medir o uso do Portal do Cliente.`

No user attribute is required for this preference in the demo.

All three preferences remain **optional**. A user must be able to decline
them and continue registration.

### C. Put consent into the Portal Corporativo registration flow

Console:

**Applications → Portal Corporativo → Login Flow → Registration**

Add:

1. **Policy Consent** widget
   - select `Aviso de Privacidade LGPD — MarketSphere Brasil`;
2. **Preference Management** widget
   - select the three LGPD preferences above.

Suggested heading:

`Privacidade e preferências`

Suggested description:

`Escolha como a MarketSphere Brasil pode usar seus dados para finalidades opcionais. Você pode alterar essas escolhas posteriormente em Minha Conta.`

Publish/update the registration flow.

### D. Demonstrate application attribute consent

Console:

**Applications → Portal Corporativo → User Attributes**

Select a small, justified set of attributes, for example:

- First Name
- Email
- Mobile

Do not request attributes that are unnecessary to the scenario.

Then:

**Applications → Portal Corporativo → Advanced**

Ensure **Skip login consent** is **unchecked**.

This gives the demo a third consent class: consent to release user attributes
to a particular relying application.

### E. Configure the signed consent webhook

The repo now includes a downstream consent consumer at:

`http://consent-audit:8300/webhooks/wso2`

Console:

**Webhooks → Add Webhook**

Use:

- **Name:** `MarketSphere LGPD Consent Audit`
- **Endpoint:** `http://consent-audit:8300/webhooks/wso2`
- **Secret:** the value from `.lgpd-consent.env`
- **Events:** subscribe to Consent and Consent Purpose events, including:
  - consent added;
  - consent revoked;
  - purpose version added.

Activate the webhook after creation.

The local receiver verifies the WSO2
`x-wso2-event-signature` HMAC-SHA256 signature against the raw body,
deduplicates by SET `jti`, and stores a minimal projection rather than the
full set of user claim values.

For production, use HTTPS and a secret manager; HTTP is used here only
because both services run on the local Docker network.

## End-to-end user demo

Run:

```bash
./scripts/lgpd-consent-demo.sh
```

Then perform the flow.

### 1. Registration

Open Portal Corporativo and register a **new local user**.

The user sees the privacy notice and the optional preferences.

Demo choice:

- Privacy Notice: **acknowledge**
- Marketing by email: **yes**
- Promotional phone communication: **no**
- Personalization / analytics: **yes**

The registration must still succeed with either optional preference refused.

### 2. Application attribute consent

When the Portal requests profile attributes, show that the user is informed
which attributes will be released to the application.

Approve the attributes needed for the demo.

### 3. My Account

Open:

`https://localhost:9443/myaccount`

Go to **Consents**.

Show the three WSO2 consent views:

- Application Consents
- Policy Consents
- Communication Preferences

### 4. Downstream consent event

Open:

`http://localhost:8300`

Show the `consentAdded` events and the current derived consent state.

### 5. Revoke marketing

In My Account:

**Consents → Communication Preferences → Marketing por e-mail → Revoke**

Return to:

`http://localhost:8300`

The downstream receiver should show a `consentRevoked` event and the
derived state for that purpose changes to `REVOKED`.

This is the important integration story: revocation is not merely a UI
setting in the identity system; downstream consumers can react to the change.

### 6. Revoke an application attribute

Under **Application Consents**, remove one previously shared attribute or
revoke the application consent.

The next login to that application should prompt the user for attribute
consent again when the application requests it.

### 7. Demonstrate policy versioning

As administrator:

**Login and Registration → Policy Management → Aviso de Privacidade LGPD**

Create a new policy version. Change visible text or point the URL to an
updated document.

Enable **Prompt at next login** for the new version.

Keep **Portal Corporativo** assigned to the policy.

The consent audit receiver can receive the `purposeVersionAdded` event.

Log the local user out and sign in to Portal Corporativo again.

The user is asked to review the new policy version before login completes.
After acceptance, the audit receiver receives the corresponding consent
addition event.

## What this demo proves

The scenario demonstrates:

- explicit policy acknowledgement and version history;
- optional purpose-specific preferences;
- granular application attribute-sharing consent;
- user review and revocation;
- re-consent after a policy update;
- downstream near-real-time reaction to grant/revocation events;
- HMAC-protected webhook delivery;
- idempotent event processing;
- data minimization in the downstream audit projection.

## Production hardening beyond this local demo

For an actual production deployment:

- use an updated WSO2 subscription image pinned by immutable digest;
- use an external supported RDBMS rather than embedded evaluation storage;
- serve policy documents and webhook endpoints over trusted HTTPS;
- keep webhook secrets in a secrets manager and rotate them;
- define controller/DPO/contact/retention/sharing details from the real
  processing inventory;
- map each processing activity to its correct LGPD legal basis — consent is
  only one possible legal basis;
- connect consent revocation events to the systems that actually perform the
  affected processing;
- establish deletion/retention workflows where required;
- monitor webhook failures/retries and maintain operational evidence.
