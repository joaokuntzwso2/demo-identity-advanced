const API = "http://localhost:4000";
const appPort = location.port;
const tokenKey = `marketsphere.b2b.${appPort}.tokens`;
const pkceKey = `marketsphere.b2b.${appPort}.pkce`;

const $ = id => document.getElementById(id);

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function random(size = 32) {
  return base64url(crypto.getRandomValues(new Uint8Array(size)));
}
async function sha256(value) {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
}
function decodeJwt(token) {
  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, "=");
    return JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(padded), c => c.charCodeAt(0))
      )
    );
  } catch {
    return {};
  }
}
async function publicConfig() {
  const r = await fetch(`${API}/api/config`);
  if (!r.ok) throw new Error(`Runtime configuration unavailable: HTTP ${r.status}`);
  return r.json();
}
function findApp(cfg) {
  const apps = cfg?.b2b?.organizationApplications || [];
  const app = apps.find(item => {
    try { return new URL(item.accessUrl).port === appPort; }
    catch { return false; }
  });
  if (!app) throw new Error(`No B2B application configuration for port ${appPort}`);
  if (!app.clientId || !app.authorizationEndpoint || !app.tokenEndpoint) {
    throw new Error("This B2B app has not been OIDC-provisioned yet.");
  }
  if (!app.resourceApiPath || !app.negativeResourceApiPath) {
    throw new Error("This B2B app has not been mapped to its protected resource yet.");
  }
  return app;
}
async function beginLogin(app) {
  const verifier = random(48);
  const challenge = base64url(await sha256(verifier));
  const state = random(24);
  const nonce = random(24);
  sessionStorage.setItem(pkceKey, JSON.stringify({ verifier, state, nonce }));

  const q = new URLSearchParams({
    response_type: "code",
    client_id: app.clientId,
    redirect_uri: app.redirectUri,
    scope: "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  location.assign(`${app.authorizationEndpoint}?${q}`);
}
async function finishLogin(app) {
  const q = new URLSearchParams(location.search);
  if (!q.get("code")) return null;

  const saved = JSON.parse(sessionStorage.getItem(pkceKey) || "{}");
  if (!saved.verifier || saved.state !== q.get("state")) {
    throw new Error("OIDC state/PKCE validation failed");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: app.clientId,
    redirect_uri: app.redirectUri,
    code: q.get("code"),
    code_verifier: saved.verifier,
  });

  const r = await fetch(app.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const tokens = await r.json();
  if (!r.ok) {
    throw new Error(
      tokens.error_description || tokens.error || `Token exchange HTTP ${r.status}`
    );
  }

  sessionStorage.setItem(tokenKey, JSON.stringify(tokens));
  sessionStorage.removeItem(pkceKey);
  history.replaceState({}, "", "/");
  return tokens;
}
function renderIdentity(app, tokens) {
  const claims = decodeJwt(tokens.id_token || tokens.access_token);
  $("status").textContent = "Authenticated";
  $("status").className = "pill authenticated";
  $("who").textContent =
    claims.username || claims.preferred_username || claims.sub || "organization user";
  $("claims").textContent = JSON.stringify({
    sub: claims.sub,
    username: claims.username || claims.preferred_username,
    org_id: claims.org_id,
    org_name: claims.org_name,
    email: claims.email,
    aud: claims.aud,
    client_id: app.clientId,
  }, null, 2);
  $("session").hidden = false;
  $("login").hidden = true;
  $("logout").hidden = false;
}
function ensureResourcePanel(app) {
  if (document.getElementById("protectedResourcePanel")) return;

  const host = document.querySelector(".wrap") || document.body;
  const section = document.createElement("section");
  section.id = "protectedResourcePanel";
  section.className = "hero";
  section.style.marginTop = "22px";
  section.innerHTML = `
    <span class="eyebrow">RF-15 • Protected-resource isolation</span>
    <h2>Organization-bound protected API</h2>
    <p>
      WSO2 validates the access token. The API then enforces that the signed
      <code>org_id</code> claim matches the organization that owns the resource.
    </p>
    <div class="grid">
      <div class="card">
        <strong>Own organization API</strong>
        <div class="mono">${app.resourceApiPath}</div>
        <div id="ownResourceStatus" style="margin-top:10px">Sign in to test.</div>
      </div>
      <div class="card">
        <strong>Cross-organization negative proof</strong>
        <div class="mono">${app.negativeResourceApiPath}</div>
        <div id="crossResourceStatus" style="margin-top:10px">Not tested.</div>
      </div>
    </div>
    <div class="actions">
      <button class="btn secondary" id="crossOrgTest" disabled>
        Try cross-organization access (expected 403)
      </button>
    </div>
    <pre id="resourcePayload" class="claims">{}</pre>
  `;
  host.appendChild(section);
}
async function invokeResource(path, token) {
  const response = await fetch(`${API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const text = await response.text();
  let payload = {};
  try { payload = text ? JSON.parse(text) : {}; }
  catch { payload = { raw: text }; }
  return { response, payload };
}
async function loadOwnResource(app, tokens) {
  const { response, payload } = await invokeResource(
    app.resourceApiPath, tokens.access_token
  );
  const status = document.getElementById("ownResourceStatus");
  const output = document.getElementById("resourcePayload");

  if (response.ok) {
    status.textContent = `Allowed • HTTP ${response.status}`;
    status.style.color = "#196c43";
  } else {
    status.textContent = `Unexpected denial • HTTP ${response.status}`;
    status.style.color = "#9b1c1c";
  }
  output.textContent = JSON.stringify(payload, null, 2);
}
async function runCrossOrgTest(app, tokens) {
  const button = document.getElementById("crossOrgTest");
  const status = document.getElementById("crossResourceStatus");
  const output = document.getElementById("resourcePayload");

  button.disabled = true;
  status.textContent = "Testing…";

  try {
    const { response, payload } = await invokeResource(
      app.negativeResourceApiPath, tokens.access_token
    );

    if (
      response.status === 403 &&
      payload.code === "cross_organization_access_denied"
    ) {
      status.textContent = "Correctly denied • HTTP 403";
      status.style.color = "#196c43";
    } else {
      status.textContent = `UNEXPECTED • HTTP ${response.status}`;
      status.style.color = "#9b1c1c";
    }
    output.textContent = JSON.stringify(payload, null, 2);
  } finally {
    button.disabled = false;
  }
}
function logout() {
  sessionStorage.removeItem(tokenKey);
  location.assign("/");
}

(async () => {
  try {
    const cfg = await publicConfig();
    const app = findApp(cfg);
    ensureResourcePanel(app);

    $("clientId").textContent = app.clientId;
    $("orgId").textContent = app.organizationId;
    $("redirectUri").textContent = app.redirectUri;
    $("login").onclick = () => beginLogin(app);
    $("logout").onclick = logout;

    let tokens = JSON.parse(sessionStorage.getItem(tokenKey) || "null");
    tokens = await finishLogin(app) || tokens;

    if (tokens) {
      renderIdentity(app, tokens);
      const button = document.getElementById("crossOrgTest");
      button.disabled = false;
      button.onclick = () => runCrossOrgTest(app, tokens);
      await loadOwnResource(app, tokens);
    }
  } catch (e) {
    $("status").textContent = "Configuration error";
    $("error").textContent = e.stack || e.message;
    $("error").hidden = false;
  }
})();
