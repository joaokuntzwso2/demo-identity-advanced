import fs from "node:fs";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";

const PORT = Number(process.env.PORT || 4000);
const CONFIG_PATH = process.env.RUNTIME_CONFIG_PATH || "/runtime/runtime-config.json";
const AGENT_URL = process.env.AGENT_URL || "http://inventory-agent:5001";

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function listClaim(value) {
  if (Array.isArray(value)) return value.flatMap(listClaim);
  if (typeof value !== "string") return [];
  return value.split(/[ ,]+/).map((entry) => entry.trim()).filter(Boolean);
}

function principalFrom(payload) {
  const roles = new Set([
    ...listClaim(payload.roles),
    ...listClaim(payload.role),
    ...listClaim(payload["http://wso2.org/claims/role"]),
    ...listClaim(payload["http://wso2.org/claims/roles"]),
  ]);
  const groups = new Set([
    ...listClaim(payload.groups),
    ...listClaim(payload.group),
    ...listClaim(payload["http://wso2.org/claims/groups"]),
  ]);
  const scopes = new Set(listClaim(payload.scope));
  return {
    subject: payload.sub,
    username: payload.username || payload.preferred_username || payload.sub,
    email: payload.email || payload["http://wso2.org/claims/emailaddress"],
    givenName: payload.given_name || payload["http://wso2.org/claims/givenname"],
    familyName: payload.family_name || payload["http://wso2.org/claims/lastname"],
    department: payload.department || payload["http://wso2.org/claims/department"],
    clientId: payload.azp || payload.client_id,
    roles: [...roles],
    groups: [...groups],
    scopes: [...scopes],
    tokenClaims: payload,
  };
}

let jwksCache;
let jwksUriCache;
function jwks(config) {
  if (!jwksCache || jwksUriCache !== config.internalJwksUri) {
    jwksUriCache = config.internalJwksUri;
    jwksCache = createRemoteJWKSet(new URL(config.internalJwksUri));
  }
  return jwksCache;
}

async function authenticate(req, res, next) {
  try {
    const raw = req.headers.authorization || "";
    const [scheme, token] = raw.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ code: "missing_access_token", message: "Provide a Bearer access token." });
    }
    const config = loadConfig();
    const { payload, protectedHeader } = await jwtVerify(token, jwks(config), {
      issuer: config.issuer,
      algorithms: ["RS256"],
      clockTolerance: 10,
    });
    const acceptedAudiences = new Set([
      config.resources.marketplace.identifier,
      config.resources.downstream.identifier,
      ...Object.values(config.clients).map((client) => client.clientId).filter(Boolean),
    ]);
    const audiences = listClaim(payload.aud);
    if (!audiences.length || !audiences.some((aud) => acceptedAudiences.has(aud))) {
      return res.status(401).json({ code: "invalid_audience", message: "The token was not issued for this demonstration.", audiences });
    }
    req.accessToken = token;
    req.jwtHeader = protectedHeader;
    req.principal = principalFrom(payload);
    next();
  } catch (error) {
    res.status(401).json({ code: "invalid_access_token", message: "The token is invalid or expired.", detail: error.message });
  }
}

function requireScope(...required) {
  return (req, res, next) => {
    const granted = new Set(req.principal.scopes);
    const missing = required.filter((scope) => !granted.has(scope));
    if (missing.length) {
      return res.status(403).json({ code: "missing_scope", message: "The token does not contain the required scopes.", required, granted: [...granted] });
    }
    next();
  };
}

function requireEntitlement({ groups = [], roles = [] }) {
  return (req, res, next) => {
    const currentGroups = new Set(req.principal.groups.map((item) => item.replace(/^.*\//, "")));
    const currentRoles = new Set(req.principal.roles.map((item) => item.replace(/^.*\//, "")));
    const allowed = groups.some((group) => currentGroups.has(group)) || roles.some((role) => currentRoles.has(role));
    if (!allowed) {
      return res.status(403).json({
        code: "rbac_access_denied",
        message: "The credentials are valid, but the user does not belong to the required group or role.",
        required: { groups, roles },
        actual: { groups: [...currentGroups], roles: [...currentRoles] },
      });
    }
    next();
  };
}

async function clientCredentials(client, config) {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: client.scope,
    resource: config.resources.marketplace.identifier,
  });
  const response = await axios.post(config.internalTokenEndpoint, body, {
    auth: { username: client.clientId, password: client.clientSecret },
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  });
  return response.data;
}

async function callWithToken(url, token, method = "get", data) {
  const response = await axios({
    method,
    url,
    data,
    headers: { Authorization: `Bearer ${token}` },
    timeout: 30000,
  });
  return response.data;
}

function publicConfig(config) {
  return {
    product: config.product,
    issuer: config.issuer,
    authorizationEndpoint: config.authorizationEndpoint,
    tokenEndpoint: config.tokenEndpoint,
    logoutEndpoint: config.logoutEndpoint,
    resources: config.resources,
    clients: {
      portal: config.clients.portal,
      m2m: { clientId: config.clients.m2m.clientId, scope: config.clients.m2m.scope },
      tokenExchange: { clientId: config.clients.tokenExchange.clientId, scope: config.clients.tokenExchange.scope },
      agentApp: config.clients.agentApp,
    },
    agent: { ...config.agent, secret: undefined },
    federation: {
      ...config.federation,
      sourceToken: config.federation?.sourceToken
        ? {
            publicTokenEndpoint: config.federation.sourceToken.publicTokenEndpoint,
            clientId: config.federation.sourceToken.clientId,
            username: config.federation.sourceToken.username,
            scope: config.federation.sourceToken.scope,
          }
        : undefined,
    },
    demoUsers: config.demoUsers,
    bootstrap: config.bootstrap,
  };
}

const app = express();
app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: ["http://localhost:3000"], credentials: false }));
app.use(express.json({ limit: "200kb" }));
app.use(morgan("combined"));

app.get("/health", (_req, res) => res.json({ status: "UP", service: "marketsphere-api" }));
app.get("/api/config", (_req, res) => res.json(publicConfig(loadConfig())));
app.get("/api/status", async (_req, res) => {
  const config = loadConfig();
  const checks = await Promise.allSettled([
    axios.get(config.internalJwksUri, { timeout: 5000 }),
    axios.get(`${AGENT_URL}/health`, { timeout: 5000 }),
    axios.get(`${config.federation.sourceToken.tokenEndpoint.replace(/\/protocol\/openid-connect\/token$/, "")}/.well-known/openid-configuration`, { timeout: 5000 }),
  ]);
  res.json({
    status: checks.every((item) => item.status === "fulfilled") ? "UP" : "DEGRADED",
    product: config.product,
    components: {
      identityServer: checks[0].status === "fulfilled" ? "UP" : "DOWN",
      protectedApi: "UP",
      inventoryAgent: checks[1].status === "fulfilled" ? "UP" : "DOWN",
      ldap: "CONFIGURED",
      federation: checks[2].status === "fulfilled" && config.federation.loginFlowEnabled ? "CONFIGURED" : "DEGRADED",
      trustedTokenIssuer: config.federation.trustedTokenIssuer?.name ? "CONFIGURED" : "MISSING",
    },
    warnings: config.bootstrap.warnings,
  });
});

app.get("/api/me", authenticate, (req, res) => {
  res.json({ principal: req.principal, jwtHeader: req.jwtHeader, decision: "authenticated" });
});

app.get(
  "/api/portal",
  authenticate,
  requireScope("portal.read"),
  requireEntitlement({ groups: ["portal_users", "portal_admins"], roles: ["portal-user", "portal-admin"] }),
  (req, res) => res.json({
    decision: "allow",
    policy: "scope portal.read AND membership portal_users/portal_admins",
    principal: req.principal,
    applications: [
      { name: "Corporate Marketplace", owner: "Digital Commerce", sensitivity: "Internal" },
      { name: "Finance Insights", owner: "Finance", sensitivity: "Restricted" },
      { name: "Inventory Operations", owner: "Supply Chain", sensitivity: "Confidential" },
    ],
  }),
);

app.get(
  "/api/admin",
  authenticate,
  requireScope("portal.admin"),
  requireEntitlement({ groups: ["portal_admins"], roles: ["portal-admin"] }),
  (req, res) => res.json({ decision: "allow", message: "Administrative operation authorized.", principal: req.principal }),
);

app.get("/api/m2m/orders", authenticate, requireScope("orders.read"), (req, res) => {
  res.json({
    decision: "allow",
    grantType: "client_credentials",
    caller: req.principal.clientId || req.principal.subject,
    orders: [
      { id: "ORD-1042", customer: "ACME Brazil", status: "READY", total: 18450.75 },
      { id: "ORD-1043", customer: "Northwind LATAM", status: "PROCESSING", total: 7230.00 },
    ],
  });
});

app.post("/api/demo/m2m", async (_req, res) => {
  try {
    const config = loadConfig();
    const token = await clientCredentials(config.clients.m2m, config);
    const result = await callWithToken(`${config.apiInternalUrl}/api/m2m/orders`, token.access_token);
    res.json({
      token: { ...token, access_token: "[redacted]", decoded: decodeJwt(token.access_token) },
      protectedApiResult: result,
      security: "The client secret stayed in the backend; only the decoded demonstration claims are returned.",
    });
  } catch (error) {
    res.status(error.response?.status || 502).json({ code: "m2m_demo_failed", message: error.message, upstream: error.response?.data });
  }
});

app.get("/api/downstream/report", authenticate, requireScope("downstream.read"), (req, res) => {
  res.json({
    decision: "allow",
    delegatedSubject: req.principal.subject,
    actorClient: req.principal.clientId,
    report: { quarter: "Q3 2026", risk: "LOW", pendingApprovals: 3 },
  });
});

app.post(
  "/api/demo/token-exchange",
  authenticate,
  requireScope("portal.admin"),
  requireEntitlement({ groups: ["portal_admins"], roles: ["portal-admin"] }),
  async (req, res) => {
    try {
      const config = loadConfig();
      const source = config.federation.sourceToken;
      const sourceBody = new URLSearchParams({
        grant_type: "password",
        client_id: source.clientId,
        client_secret: source.clientSecret,
        username: source.username,
        password: source.password,
        scope: source.scope,
      });
      const sourceResponse = await axios.post(source.tokenEndpoint, sourceBody, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 30000,
      });
      const sourceToken = sourceResponse.data.access_token;
      if (!sourceToken || sourceToken.split(".").length !== 3) {
        throw new Error("The configured third-party identity provider did not return a JWT access token.");
      }

      const client = config.clients.tokenExchange;
      const exchangeBody = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: sourceToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        scope: client.scope,
        resource: config.resources.downstream.identifier,
      });
      const exchanged = await axios.post(config.internalTokenEndpoint, exchangeBody, {
        auth: { username: client.clientId, password: client.clientSecret },
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 30000,
      });
      const downstream = await callWithToken(`${config.apiInternalUrl}/api/downstream/report`, exchanged.data.access_token);
      res.json({
        initiatedBy: {
          username: req.principal.username,
          subject: req.principal.subject,
          roles: req.principal.roles,
          scopes: req.principal.scopes,
        },
        sourceToken: {
          provider: config.federation.localProvider,
          issuer: config.federation.trustedTokenIssuer.issuer,
          access_token: "[redacted]",
          decoded: decodeJwt(sourceToken),
        },
        exchangedToken: {
          ...exchanged.data,
          access_token: "[redacted]",
          decoded: decodeJwt(exchanged.data.access_token),
        },
        downstream,
        security: "The third-party credential and confidential client secret remained server-side. WSO2 validated the external JWT using the registered issuer and JWKS before issuing the downstream token.",
      });
    } catch (error) {
      res.status(error.response?.status || 502).json({
        code: "token_exchange_failed",
        message: error.message,
        upstream: error.response?.data,
      });
    }
  },
);

app.post(
  "/api/admin/agent-run",
  authenticate,
  requireScope("portal.admin"),
  requireEntitlement({ groups: ["portal_admins"], roles: ["portal-admin"] }),
  async (req, res) => {
    try {
      const response = await axios.post(`${AGENT_URL}/run`, { requestedBy: req.principal.username }, { timeout: 45000 });
      res.json(response.data);
    } catch (error) {
      res.status(error.response?.status || 502).json({ code: "agent_run_failed", message: error.message, upstream: error.response?.data });
    }
  },
);

app.post("/api/agent/inventory/reconcile", authenticate, requireScope("inventory.read", "inventory.write"), (req, res) => {
  const config = loadConfig();
  const roles = new Set(req.principal.roles.map((value) => value.replace(/^.*\//, "")));
  const isManagedAgent = String(req.principal.username || req.principal.subject).startsWith("AGENT/");
  const isFallbackWorkload = req.principal.clientId === config.clients.agentWorkload.clientId;
  if (!isManagedAgent && !isFallbackWorkload && !roles.has("inventory-agent")) {
    return res.status(403).json({ code: "agent_identity_required", message: "A token with managed-agent identity or the dedicated fallback workload is required." });
  }
  res.json({
    decision: "allow",
    identityType: isManagedAgent ? "WSO2_MANAGED_AGENT" : "DEDICATED_WORKLOAD_FALLBACK",
    principal: req.principal,
    reconciliation: {
      runId: `REC-${Date.now()}`,
      compared: 1248,
      adjusted: 7,
      exceptions: 2,
      status: "COMPLETED",
    },
  });
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ code: "internal_error", message: "Unexpected API error." });
});

app.listen(PORT, "0.0.0.0", () => console.log(`MarketSphere API listening on ${PORT}`));
