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
function logout() {
  sessionStorage.removeItem(tokenKey);
  location.assign("/");
}

(async () => {
  try {
    const cfg = await publicConfig();
    const app = findApp(cfg);

    $("clientId").textContent = app.clientId;
    $("orgId").textContent = app.organizationId;
    $("redirectUri").textContent = app.redirectUri;
    $("login").onclick = () => beginLogin(app);
    $("logout").onclick = logout;

    let tokens = JSON.parse(sessionStorage.getItem(tokenKey) || "null");
    tokens = await finishLogin(app) || tokens;

    if (tokens) renderIdentity(app, tokens);
  } catch (e) {
    $("status").textContent = "Configuration error";
    $("error").textContent = e.stack || e.message;
    $("error").hidden = false;
  }
})();