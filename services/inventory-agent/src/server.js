import crypto from "node:crypto";
import fs from "node:fs";
import express from "express";
import axios from "axios";
import { decodeJwt } from "jose";

const PORT = Number(process.env.PORT || 5001);
const CONFIG_PATH = process.env.RUNTIME_CONFIG_PATH || "/runtime/runtime-config.json";
const MARKETPLACE_API_URL = process.env.MARKETPLACE_API_URL || "http://marketplace-api:4000";

const base64url = (input) => Buffer.from(input).toString("base64url");
function loadConfig() { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); }
function findDeep(node, names) {
  if (!node || typeof node !== "object") return undefined;
  for (const [key, value] of Object.entries(node)) {
    if (names.includes(key) && typeof value === "string") return value;
    const nested = findDeep(value, names);
    if (nested) return nested;
  }
  return undefined;
}

async function managedAgentToken(config) {
  if (!config.agent.managedAgentReady || !config.agent.secret) {
    throw new Error("Managed agent credentials or app-native flag are not available in runtime configuration");
  }
  const verifier = base64url(crypto.randomBytes(48));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  const state = base64url(crypto.randomBytes(18));
  const client = config.clients.agentApp;
  const authorize = new URL(config.authorizationEndpoint.replace("localhost", "wso2is"));
  authorize.search = new URLSearchParams({
    response_type: "code",
    response_mode: "direct",
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    scope: client.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: config.resources.marketplace.identifier,
  }).toString();

  const initiated = await axios.get(authorize.toString(), {
    headers: { Accept: "application/json" },
    maxRedirects: 0,
    validateStatus: (status) => status >= 200 && status < 400,
    timeout: 30000,
  });
  const flow = initiated.data;
  const flowId = findDeep(flow, ["flowId"]);
  const authenticatorId = flow?.nextStep?.authenticators?.[0]?.authenticatorId || findDeep(flow, ["authenticatorId"]);
  if (!flowId || !authenticatorId) throw new Error(`App-native initiation did not return flowId/authenticatorId: ${JSON.stringify(flow)}`);

  const authenticated = await axios.post(
    config.internalTokenEndpoint.replace(/\/token$/, "/authn"),
    {
      flowId,
      selectedAuthenticator: {
        authenticatorId,
        params: { username: config.agent.id, password: config.agent.secret },
      },
    },
    { headers: { "Content-Type": "application/json", Accept: "application/json" }, timeout: 30000 },
  );
  const code = findDeep(authenticated.data, ["code", "authorizationCode"]);
  if (!code) throw new Error(`Agent authentication did not return an authorization code: ${JSON.stringify(authenticated.data)}`);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    code,
    code_verifier: verifier,
  });
  const token = await axios.post(config.internalTokenEndpoint, body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 30000,
  });
  return { ...token.data, mode: "managed-agent" };
}

async function workloadToken(config) {
  const client = config.clients.agentWorkload;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: client.scope,
    resource: config.resources.marketplace.identifier,
  });
  const token = await axios.post(config.internalTokenEndpoint, body, {
    auth: { username: client.clientId, password: client.clientSecret },
    headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 30000,
  });
  return { ...token.data, mode: "client-credentials-fallback" };
}

async function obtainToken(config) {
  if (config.agent.authMode === "managed-agent") {
    try { return await managedAgentToken(config); }
    catch (error) {
      console.warn(`Managed agent authentication failed; applying explicit fallback: ${error.message}`);
      const fallback = await workloadToken(config);
      fallback.fallbackReason = error.message;
      return fallback;
    }
  }
  return workloadToken(config);
}

const app = express();
app.use(express.json({ limit: "100kb" }));
app.get("/health", (_req, res) => res.json({ status: "UP", service: "inventory-agent" }));
app.get("/identity", (_req, res) => {
  const config = loadConfig();
  res.json({
    id: config.agent.id,
    displayName: config.agent.displayName,
    owner: config.agent.owner,
    role: config.agent.role,
    configuredMode: config.agent.authMode,
    managedAgentReady: config.agent.managedAgentReady,
  });
});
app.post("/run", async (req, res) => {
  try {
    const config = loadConfig();
    const token = await obtainToken(config);
    const response = await axios.post(
      `${MARKETPLACE_API_URL}/api/agent/inventory/reconcile`,
      { requestedBy: req.body?.requestedBy || "portal-admin" },
      { headers: { Authorization: `Bearer ${token.access_token}` }, timeout: 30000 },
    );
    res.json({
      agent: { id: config.agent.id, displayName: config.agent.displayName, owner: config.agent.owner, role: config.agent.role },
      authentication: {
        mode: token.mode,
        fallbackReason: token.fallbackReason,
        token: { ...token, access_token: "[redacted]", decoded: decodeJwt(token.access_token) },
      },
      protectedApiResult: response.data,
    });
  } catch (error) {
    res.status(error.response?.status || 502).json({ code: "agent_execution_failed", message: error.message, upstream: error.response?.data });
  }
});
app.listen(PORT, "0.0.0.0", () => console.log(`Inventory agent listening on ${PORT}`));
