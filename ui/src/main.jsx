import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity, Bot, Braces, Building2, CheckCircle2, ChevronRight, CircleUserRound,
  Database, ExternalLink, FileKey2, Fingerprint, KeyRound, LayoutDashboard,
  LockKeyhole, LogIn, LogOut, Network, Play, RefreshCw, ServerCog, ShieldCheck,
  UsersRound, Workflow, XCircle,
} from "lucide-react";
import "./styles.css";

const API = "http://localhost:4000";
const TOKEN_KEY = "marketsphere.oidc.tokens";
const PKCE_KEY = "marketsphere.oidc.pkce";

const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (size = 32) => base64url(crypto.getRandomValues(new Uint8Array(size)));
async function sha256(value) { return crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)); }
function decodeJwt(token) {
  try {
    const segment = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = segment.padEnd(Math.ceil(segment.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch { return {}; }
}
function validateIdToken(idToken, config, expectedNonce) {
  if (!idToken) throw new Error("The OpenID Connect response did not include an ID token");
  const claims = decodeJwt(idToken);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== config.issuer) throw new Error("OIDC issuer validation failed");
  if (!audiences.includes(config.clients.portal.clientId)) throw new Error("OIDC audience validation failed");
  if (claims.nonce !== expectedNonce) throw new Error("OIDC nonce validation failed");
  if (!claims.exp || claims.exp <= Math.floor(Date.now() / 1000)) throw new Error("OIDC ID token is expired");
  return claims;
}
function loadTokens() { try { return JSON.parse(sessionStorage.getItem(TOKEN_KEY)) || null; } catch { return null; } }

async function api(path, { method = "GET", token, body } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(data.message || `HTTP ${response.status}`), { status: response.status, data });
  return data;
}

async function beginLogin(config) {
  const verifier = random(48);
  const challenge = base64url(await sha256(verifier));
  const state = random(20);
  const nonce = random(20);
  sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state, nonce }));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clients.portal.clientId,
    redirect_uri: config.clients.portal.redirectUri,
    scope: config.clients.portal.scopes,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: config.resources.marketplace.identifier,
  });
  location.assign(`${config.authorizationEndpoint}?${params}`);
}

async function finishLogin(config) {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  if (!code) return null;
  const saved = JSON.parse(sessionStorage.getItem(PKCE_KEY) || "{}");
  if (!saved.verifier || saved.state !== params.get("state")) throw new Error("OIDC state/PKCE validation failed");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clients.portal.clientId,
    redirect_uri: config.clients.portal.redirectUri,
    code,
    code_verifier: saved.verifier,
  });
  const response = await fetch(config.tokenEndpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const tokens = await response.json();
  if (!response.ok) throw new Error(tokens.error_description || tokens.error || "Authorization code exchange failed");
  validateIdToken(tokens.id_token, config, saved.nonce);
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
  sessionStorage.removeItem(PKCE_KEY);
  history.replaceState({}, "", "/");
  return tokens;
}

const navigation = [
  ["overview", "Overview", LayoutDashboard],
  ["oidc", "Authorization Code", KeyRound],
  ["rbac", "RBAC and groups", ShieldCheck],
  ["m2m", "Client Credentials", ServerCog],
  ["federation", "Federation and claims", Network],
  ["userstore", "External user store", Database],
  ["exchange", "Token Exchange", Workflow],
  ["agent", "Agent Identity", Bot],
];

function StatusBadge({ value }) {
  const okay = ["UP", "CONFIGURED", "CONNECTION_READY", "COMPLETED", "ALLOW"].includes(value);
  return <span className={`status ${okay ? "ok" : "warn"}`}>{okay ? <CheckCircle2 size={14}/> : <XCircle size={14}/>} {value}</span>;
}
function CodeBlock({ value }) { return <pre className="code-block">{JSON.stringify(value, null, 2)}</pre>; }
function SectionTitle({ eyebrow, title, description }) {
  return <div className="section-title"><span>{eyebrow}</span><h2>{title}</h2><p>{description}</p></div>;
}
function ActionButton({ onClick, children, secondary = false, disabled = false }) {
  return <button className={secondary ? "button secondary" : "button"} onClick={onClick} disabled={disabled}>{children}</button>;
}
function ResultPanel({ result, error }) {
  if (!result && !error) return <div className="empty-result"><Braces size={22}/><span>Run the scenario to view the decision, claims, and API response.</span></div>;
  return <CodeBlock value={error ? { error: error.message, status: error.status, details: error.data } : result}/>;
}

function App() {
  const [config, setConfig] = useState(null);
  const [status, setStatus] = useState(null);
  const [tokens, setTokens] = useState(loadTokens);
  const [active, setActive] = useState("overview");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [bootError, setBootError] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const loaded = await api("/api/config");
        setConfig(loaded);
        const completed = await finishLogin(loaded);
        if (completed) setTokens(completed);
        setStatus(await api("/api/status"));
      } catch (e) { setBootError(e); }
    })();
  }, []);

  const accessToken = tokens?.access_token;
  const claims = useMemo(() => accessToken ? decodeJwt(accessToken) : null, [accessToken]);
  const idClaims = useMemo(() => tokens?.id_token ? decodeJwt(tokens.id_token) : null, [tokens]);
  const userName = claims?.username || claims?.preferred_username || idClaims?.preferred_username || claims?.sub;

  async function run(fn) {
    setBusy(true); setError(null); setResult(null);
    try { setResult(await fn()); } catch (e) { setError(e); }
    finally { setBusy(false); }
  }
  function logout() {
    sessionStorage.removeItem(TOKEN_KEY); setTokens(null);
    if (tokens?.id_token) {
      const params = new URLSearchParams({ id_token_hint: tokens.id_token, post_logout_redirect_uri: config.clients.portal.postLogoutRedirectUri });
      location.assign(`${config.logoutEndpoint}?${params}`);
    }
  }

  if (bootError) return <div className="fatal"><LockKeyhole/><h1>The environment is not ready yet</h1><p>{bootError.message}</p><p>Run <code>./demo.sh up</code> and first open <a href="https://localhost:9443/console" target="_blank">the WSO2 Console</a> to accept the local certificate.</p></div>;
  if (!config) return <div className="loader"><div className="spinner"/><p>Loading the identity POC…</p></div>;

  const scenarios = {
    overview: <Overview config={config} status={status} tokens={tokens} onLogin={() => beginLogin(config)} />,
    oidc: <Oidc config={config} tokens={tokens} claims={claims} idClaims={idClaims} onLogin={() => beginLogin(config)} onRun={() => run(() => api("/api/me", { token: accessToken }))} busy={busy} result={result} error={error}/>,
    rbac: <Rbac config={config} tokens={tokens} onPortal={() => run(() => api("/api/portal", { token: accessToken }))} onAdmin={() => run(() => api("/api/admin", { token: accessToken }))} busy={busy} result={result} error={error}/>,
    m2m: <M2M config={config} onRun={() => run(() => api("/api/demo/m2m", { method: "POST" }))} busy={busy} result={result} error={error}/>,
    federation: <Federation config={config}/>,
    userstore: <UserStore config={config}/>,
    exchange: <TokenExchange tokens={tokens} onRun={() => run(() => api("/api/demo/token-exchange", { method: "POST", token: accessToken }))} busy={busy} result={result} error={error}/>,
    agent: <Agent config={config} tokens={tokens} onRun={() => run(() => api("/api/admin/agent-run", { method: "POST", token: accessToken }))} busy={busy} result={result} error={error}/>,
  };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Fingerprint/></div><div><strong>MarketSphere</strong><span>Identity Control Center</span></div></div>
      <div className="environment"><span className="pulse"/><div><strong>Customer POC</strong><small>WSO2 IS 7.3.0</small></div></div>
      <nav>{navigation.map(([id, label, Icon]) => <button key={id} className={active === id ? "active" : ""} onClick={() => { setActive(id); setResult(null); setError(null); }}><Icon size={18}/><span>{label}</span><ChevronRight size={15}/></button>)}</nav>
      <div className="sidebar-footer"><a href={config.product.consoleUrl} target="_blank"><ExternalLink size={15}/> Open WSO2 Console</a><span>Demo architecture v2.0</span></div>
    </aside>
    <main>
      <header className="topbar"><div><span className="breadcrumb">POC / {navigation.find(([id]) => id === active)?.[1]}</span></div><div className="identity">{tokens ? <><div className="avatar">{(userName || "U")[0].toUpperCase()}</div><div><strong>{userName}</strong><small>Active OIDC session</small></div><button title="Sign out" onClick={logout}><LogOut size={18}/></button></> : <><CircleUserRound size={21}/><span>Not authenticated</span><button className="mini-login" onClick={() => beginLogin(config)}><LogIn size={16}/> Sign in</button></>}</div></header>
      <div className="content">{scenarios[active]}</div>
    </main>
  </div>;
}

function Overview({ config, status, tokens, onLogin }) {
  return <>
    <div className="hero">
      <div><span className="hero-tag"><ShieldCheck size={15}/> CORPORATE POC</span><h1>Centralized identity.<br/><em>Demonstrable decisions.</em></h1><p>A complete environment for validating authentication, authorization, claims, federation, external user stores, token exchange, and agent identities.</p><div className="hero-actions"><ActionButton onClick={onLogin}>{tokens ? <><RefreshCw size={17}/> Switch user</> : <><LogIn size={17}/> Start OIDC login</>}</ActionButton><a className="button secondary" href={config.product.consoleUrl} target="_blank"><ExternalLink size={17}/> Administration Console</a></div></div>
      <div className="architecture-mini"><div className="node users"><UsersRound/><span>Users & Agents</span></div><div className="line"/><div className="node identity-node"><Fingerprint/><strong>WSO2 IS</strong><span>7.3.0</span></div><div className="split"><i/><i/><i/></div><div className="destinations"><span><Building2/> Portal</span><span><ServerCog/> APIs</span><span><Bot/> Agent</span></div></div>
    </div>
    <div className="metrics">
      <Metric icon={Activity} value={status?.status || "…"} label="Environment health"/>
      <Metric icon={FileKey2} value="5" label="Preloaded OAuth applications"/>
      <Metric icon={ShieldCheck} value="6" label="Business scopes"/>
      <Metric icon={UsersRound} value={config.demoUsers.length} label="Demo personas"/>
    </div>
    <SectionTitle eyebrow="TOPOLOGY" title="Components and operational status" description="All components are started and configured with a single command."/>
    <div className="component-grid">{Object.entries(status?.components || {}).map(([name, value]) => <div className="component" key={name}><div><ComponentIcon name={name}/><span>{name}</span></div><StatusBadge value={value}/></div>)}</div>
    {status?.warnings?.length > 0 && <div className="warning-box"><strong>Bootstrap notes</strong>{status.warnings.map((warning) => <p key={warning}>{warning}</p>)}</div>}
  </>;
}
function Metric({ icon: Icon, value, label }) { return <div className="metric"><Icon/><div><strong>{value}</strong><span>{label}</span></div></div>; }
function ComponentIcon({ name }) { const Icon = name.includes("identity") ? Fingerprint : name.includes("agent") ? Bot : name.includes("ldap") ? Database : name.includes("federation") ? Network : ServerCog; return <Icon size={19}/>; }

function Oidc({ config, tokens, claims, idClaims, onLogin, onRun, busy, result, error }) {
  return <><SectionTitle eyebrow="INTERACTIVE FLOW" title="Authorization Code + OIDC + PKCE" description="Redirect-based login, S256 code challenge, JWT access token, ID token, and normalized claims."/>
    <div className="two-col"><div className="panel"><h3><KeyRound/> Public client configuration</h3><Definition rows={[["Client ID", config.clients.portal.clientId],["Grant", "authorization_code + refresh_token"],["PKCE", "Required / S256"],["Redirect URI", config.clients.portal.redirectUri],["Scopes", config.clients.portal.scopes]]}/><ActionButton onClick={tokens ? onRun : onLogin} disabled={busy}>{busy ? "Validating…" : tokens ? <><Play size={17}/> Validate token with the API</> : <><LogIn size={17}/> Authenticate user</>}</ActionButton></div>
    <div className="panel"><h3><Fingerprint/> Issued claims</h3>{claims ? <CodeBlock value={{ access_token: claims, id_token: idClaims }}/> : <div className="empty-result"><CircleUserRound/><span>Sign in to inspect the claims.</span></div>}</div></div>
    <div className="result-card"><h3>Cryptographic and principal validation result</h3><ResultPanel result={result} error={error}/></div></>;
}

function Rbac({ config, tokens, onPortal, onAdmin, busy, result, error }) {
  return <><SectionTitle eyebrow="AUTHORIZATION" title="RBAC with roles, groups, and scopes" description="Authentication does not imply authorization: the API combines scopes with group or role membership and returns an explicit decision."/>
    <div className="policy-flow"><div><KeyRound/><strong>Valid JWT</strong><span>signature, issuer, exp</span></div><ChevronRight/><div><FileKey2/><strong>Scope</strong><span>portal.read / portal.admin</span></div><ChevronRight/><div><UsersRound/><strong>Group or role</strong><span>portal_users / portal-admin</span></div><ChevronRight/><div className="decision"><ShieldCheck/><strong>ALLOW / DENY</strong><span>at the protected API</span></div></div>
    <div className="persona-grid">{config.demoUsers.slice(0,3).map((user) => <div className="persona" key={user.username}><div className="avatar large">{user.username[0].toUpperCase()}</div><div><strong>{user.username}</strong><span>{user.groups.length ? user.groups.join(", ") : "no authorized group"}</span><small>{user.expected}</small></div></div>)}</div>
    <div className="action-row"><ActionButton onClick={onPortal} disabled={!tokens || busy}><Play size={17}/> Test Corporate Portal</ActionButton><ActionButton secondary onClick={onAdmin} disabled={!tokens || busy}><LockKeyhole size={17}/> Test admin operation</ActionButton></div>
    <div className="result-card"><h3>Authorization decision</h3><ResultPanel result={result} error={error}/></div></>;
}

function M2M({ config, onRun, busy, result, error }) {
  return <><SectionTitle eyebrow="MACHINE TO MACHINE" title="OAuth2 Client Credentials" description="The backend uses a confidential client, requests orders.read, and presents the JWT to the API. The secret never reaches the browser."/>
    <div className="sequence"><div><ServerCog/><strong>Orders Service</strong><small>client_id + secret</small></div><span>1. token request</span><div className="highlight"><Fingerprint/><strong>WSO2 IS 7.3</strong><small>issues a scoped JWT</small></div><span>2. Bearer token</span><div><LockKeyhole/><strong>Orders API</strong><small>validates JWKS + scope</small></div></div>
    <div className="panel compact"><Definition rows={[["Client ID", config.clients.m2m.clientId],["Grant", "client_credentials"],["Scope", config.clients.m2m.scope],["Secret handling", "Backend only"]]}/><ActionButton onClick={onRun} disabled={busy}><Play size={17}/> {busy ? "Running…" : "Run complete flow"}</ActionButton></div>
    <div className="result-card"><h3>Issued token and API response</h3><ResultPanel result={result} error={error}/></div></>;
}

function Federation({ config }) {
  return <><SectionTitle eyebrow="CORPORATE IDENTITY" title="OIDC federation and claim normalization" description="A local OIDC IdP makes the POC reproducible; the same connection can be configured for Microsoft Entra ID using the provided variables."/>
    <div className="federation-map"><div className="provider"><Building2/><strong>Microsoft Entra ID</strong><span>optional through .env</span></div><div className="provider active"><Network/><strong>Corporate OIDC</strong><span>Keycloak local preloaded</span></div><div className="mapping"><span>email → emailaddress</span><span>given_name → givenname</span><span>family_name → lastname</span><span>department → department</span><span>groups → roles/groups</span></div><div className="identity-core"><Fingerprint/><strong>WSO2 IS</strong><span>JIT provisioning + canonical claims</span></div></div>
    <div className="two-col"><div className="panel"><h3>Federated user</h3><Definition rows={[["Username", "federated.user"],["Password", "Federated@123"],["Groups", "portal_users, finance_users"],["Department", "Finance"]]}/><a className="button secondary" href={config.federation.publicUrl} target="_blank"><ExternalLink size={17}/> Open corporate provider</a></div><div className="panel"><h3>Connection status</h3><Definition rows={[["Connection", config.federation.localProvider],["Login flow", config.federation.loginFlowEnabled ? "Enabled automatically" : "Connection ready; see the runbook"],["Microsoft Entra ID", config.federation.entraConfigured ? "Configured automatically" : "Optional; variables not provided"]]}/></div></div></>;
}

function UserStore({ config }) {
  const users = config.demoUsers.filter((user) => user.username.startsWith("CORP/"));
  return <><SectionTitle eyebrow="EXTERNAL DIRECTORY" title="Corporate LDAP as a secondary user store" description="WSO2 queries identities and groups in the external directory without duplicating passwords in the local store."/>
    <div className="userstore-architecture"><div><Database/><strong>OpenLDAP</strong><span>dc=marketsphere,dc=local</span></div><div className="connector"><span>ldap://ldap:389</span><i/></div><div><Fingerprint/><strong>WSO2 IS</strong><span>Domain: CORP</span></div><div className="connector"><span>OIDC / OAuth2</span><i/></div><div><Building2/><strong>Portal & APIs</strong><span>normalized claims</span></div></div>
    <div className="persona-grid">{users.map((user) => <div className="persona" key={user.username}><div className="avatar large corp">{user.username.split("/")[1][0].toUpperCase()}</div><div><strong>{user.username}</strong><span>{user.groups.join(", ")}</span><small>{user.expected}</small></div></div>)}</div>
    <div className="info-box"><Database/><div><strong>Ready for Active Directory</strong><p>The CORP.xml file uses the read-only UniqueID LDAP manager. For Active Directory, switch to UniqueIDActiveDirectoryUserStoreManager and adjust the search bases and filters.</p></div></div></>;
}

function TokenExchange({ tokens, onRun, busy, result, error }) {
  return <><SectionTitle eyebrow="DELEGATION" title="OAuth 2.0 Token Exchange" description="A confidential backend obtains a JWT from a corporate issuer registered as a trusted token issuer and exchanges it for a WSO2 token tailored to the downstream API."/>
    <div className="exchange-flow"><div><Building2/><strong>Third-party JWT</strong><span>Corporate Keycloak / Entra-compatible</span></div><ChevronRight/><div><ServerCog/><strong>Confidential backend</strong><span>credentials stay server-side</span></div><ChevronRight/><div className="highlight"><Workflow/><strong>WSO2 Token Exchange</strong><span>trusted issuer + JWKS</span></div><ChevronRight/><div><LockKeyhole/><strong>Downstream API</strong><span>downstream.read</span></div></div>
    <ActionButton onClick={onRun} disabled={!tokens || busy}><Play size={17}/> {busy ? "Exchanging token…" : "Run token exchange"}</ActionButton>
    {!tokens && <p className="hint">Sign in as carol to authorize the administrative scenario.</p>}
    <div className="info-box"><ShieldCheck/><div><strong>Separation of duties</strong><p>The carol user authorizes the demonstration; the subject token comes from the external IdP, and the confidential client authenticates the backend exchange.</p></div></div>
    <div className="result-card"><h3>External JWT, WSO2 token, and downstream response</h3><ResultPanel result={result} error={error}/></div></>;
}

function AgentExecutionResult({ result, error }) {
  if (error || !result) {
    return <ResultPanel result={result} error={error}/>;
  }

  const agent = result.agent || {};
  const authentication = result.authentication || {};
  const protectedResult = result.protectedApiResult || {};
  const reconciliation = protectedResult.reconciliation || {};
  const principal = protectedResult.principal || {};

  if (!reconciliation.runId) {
    return <ResultPanel result={result} error={error}/>;
  }

  const completed =
    protectedResult.decision === "allow"
    && reconciliation.status === "COMPLETED";

  const identityLabel =
    protectedResult.identityType === "WSO2_MANAGED_AGENT"
      ? "WSO2 managed agent identity"
      : "Dedicated workload identity";

  const scopes = Array.isArray(principal.scopes)
    ? principal.scopes.join(", ")
    : principal.scopes || "Not available";

  const authenticatedPrincipal =
    principal.username
    || principal.clientId
    || principal.subject
    || "Not available";

  return <div className="agent-execution-result">
    <div className={`agent-result-banner ${completed ? "success" : "warning"}`}>
      <div className="agent-result-icon">
        {completed
          ? <CheckCircle2/>
          : <XCircle/>}
      </div>

      <div className="agent-result-heading">
        <span>AGENT EXECUTION RESULT</span>
        <h4>
          {completed
            ? "Inventory reconciliation completed successfully"
            : "Inventory reconciliation returned an unexpected result"}
        </h4>
        <p>
          {completed
            ? `${agent.displayName || "The agent"} authenticated independently, called the protected inventory API, and completed the reconciliation operation.`
            : "Review the authorization decision and technical details below."}
        </p>
      </div>

      <StatusBadge
        value={
          completed
            ? "COMPLETED"
            : reconciliation.status || "UNKNOWN"
        }
      />
    </div>

    <div className="agent-result-metrics">
      <div className="agent-result-metric">
        <span>Items compared</span>
        <strong>{reconciliation.compared ?? "—"}</strong>
      </div>

      <div className="agent-result-metric">
        <span>Records adjusted</span>
        <strong>{reconciliation.adjusted ?? "—"}</strong>
      </div>

      <div className="agent-result-metric">
        <span>Exceptions found</span>
        <strong>{reconciliation.exceptions ?? "—"}</strong>
      </div>

      <div className="agent-result-metric">
        <span>API decision</span>
        <strong className={
          protectedResult.decision === "allow"
            ? "decision-allow"
            : "decision-deny"
        }>
          {(protectedResult.decision || "unknown").toUpperCase()}
        </strong>
      </div>
    </div>

    <div className="agent-result-details">
      <div>
        <span>Agent</span>
        <strong>{agent.displayName || agent.id}</strong>
        <small>{agent.id}</small>
      </div>

      <div>
        <span>Run ID</span>
        <strong>{reconciliation.runId}</strong>
      </div>

      <div>
        <span>Authentication mode</span>
        <strong>{identityLabel}</strong>
        <small>{authentication.mode}</small>
      </div>

      <div>
        <span>Authorized principal</span>
        <strong>{authenticatedPrincipal}</strong>
      </div>

      <div>
        <span>Granted scopes</span>
        <strong>{scopes}</strong>
      </div>

      <div>
        <span>Agent owner</span>
        <strong>{agent.owner || "Not available"}</strong>
      </div>
    </div>

    {authentication.mode === "client-credentials-fallback" && (
      <div className="agent-fallback-note">
        <ShieldCheck/>
        <div>
          <strong>Dedicated workload compatibility mode</strong>
          <p>
            The agent authenticated with its own confidential OAuth client,
            independently from the signed-in user. WSO2 issued
            inventory.read and inventory.write, and the protected API
            authorized the reconciliation operation.
          </p>
        </div>
      </div>
    )}

    <details className="agent-technical-details">
      <summary>
        View technical token, identity, and API response
      </summary>
      <CodeBlock value={result}/>
    </details>
  </div>;
}


function Agent({ config, tokens, onRun, busy, result, error }) {
  return <><SectionTitle eyebrow="NON-HUMAN IDENTITY" title="Agent identity with roles and least privilege" description="The agent is registered as a first-class principal, has its own owner and role, and uses only inventory.read/inventory.write."/>
    <div className="agent-card"><div className="agent-avatar"><Bot/></div><div className="agent-main"><span className="agent-type">WSO2 MANAGED AGENT</span><h3>{config.agent.displayName}</h3><p>Autonomous inventory reconciliation with verifiable authorization on every call.</p><div className="agent-meta"><span><Fingerprint/> {config.agent.id}</span><span><CircleUserRound/> Owner: {config.agent.owner}</span><span><ShieldCheck/> Role: {config.agent.role}</span></div></div><StatusBadge value={config.agent.managedAgentReady ? "CONFIGURED" : "CONNECTION_READY"}/></div>
    <div className="two-col"><div className="panel"><h3>Security model</h3><Definition rows={[["Principal", "Unique agent ID"],["Credential", "Agent secret displayed once"],["Application", config.clients.agentApp.clientId],["Scopes", config.clients.agentApp.scope],["Fallback", "Dedicated workload client (explicit)"]]}/></div><div className="panel"><h3>Implemented controls</h3><ul className="check-list"><li><CheckCircle2/> Identity distinguishable from a human user</li><li><CheckCircle2/> Auditable owner and role</li><li><CheckCircle2/> JWT validation through JWKS</li><li><CheckCircle2/> Minimum API scopes</li><li><CheckCircle2/> Transparent fallback in the result</li></ul></div></div>
    <ActionButton onClick={onRun} disabled={!tokens || busy}><Play size={17}/> {busy ? "Running agent…" : "Run reconciliation"}</ActionButton><p className="hint">Execution requires the carol persona / portal_admins.</p>
    <div className="result-card"><h3>Agent execution result</h3><AgentExecutionResult result={result} error={error}/></div></>;
}

function Definition({ rows }) { return <dl className="definition">{rows.map(([term, value]) => <React.Fragment key={term}><dt>{term}</dt><dd>{value}</dd></React.Fragment>)}</dl>; }

createRoot(document.getElementById("root")).render(<App/>);
