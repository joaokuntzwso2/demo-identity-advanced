import crypto from "node:crypto";
import fs from "node:fs";
import express from "express";
import axios from "axios";
import { decodeJwt } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const PORT = Number(process.env.PORT || 5002);
const CONFIG_PATH =
  process.env.RUNTIME_CONFIG_PATH || "/runtime/runtime-config.json";
const PRIVATE_PATH =
  process.env.AGENT_MCP_PRIVATE_PATH || "/runtime/agent-mcp-private.json";
const MCP_URL =
  process.env.INVENTORY_MCP_URL || "http://inventory-mcp:8200/mcp";

const pending = new Map();

const base64url = (input) => Buffer.from(input).toString("base64url");

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function loadPrivate() {
  return JSON.parse(fs.readFileSync(PRIVATE_PATH, "utf8"));
}

function findDeep(node, names) {
  if (!node || typeof node !== "object") return undefined;
  for (const [key, value] of Object.entries(node)) {
    if (names.includes(key) && typeof value === "string") return value;
    const nested = findDeep(value, names);
    if (nested) return nested;
  }
  return undefined;
}

function tokenScopes(payload) {
  return Array.isArray(payload.scope)
    ? payload.scope.map(String)
    : String(payload.scope || "").split(/\s+/).filter(Boolean);
}

function publicClaims(token) {
  const p = decodeJwt(token);
  return {
    sub: p.sub,
    act: p.act,
    aut: p.aut,
    scope: tokenScopes(p),
    aud: p.aud,
    azp: p.azp || p.client_id,
    roles: p.roles || p.application_roles,
    jti: p.jti,
    iss: p.iss,
    exp: p.exp,
  };
}

async function obtainAgentActorToken(config, secret) {
  const verifier = base64url(crypto.randomBytes(48));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
  const state = base64url(crypto.randomBytes(18));

  const authorizeBody = new URLSearchParams({
    response_type: "code",
    response_mode: "direct",
    client_id: secret.clientId,
    redirect_uri: config.agentMcp.client.redirectUri,
    scope: "openid inventory.mcp.read",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: config.agentMcp.resource.identifier,
  });

  let initiated;

  try {
    initiated = await axios.post(
      secret.authorizationEndpointInternal,
      authorizeBody,
      {
        auth: {
          username: secret.clientId,
          password: secret.clientSecret,
        },
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
        timeout: 30000,
      }
    );
  } catch (error) {
    throw new Error(
      `APP_NATIVE_AUTHORIZE_FAILED: ${
        error.response?.status || "no-status"
      } ${JSON.stringify(error.response?.data || error.message)}`
    );
  }

  const flow = initiated.data;
  const flowId = findDeep(flow, ["flowId"]);
  const authenticatorId =
    flow?.nextStep?.authenticators?.[0]?.authenticatorId ||
    findDeep(flow, ["authenticatorId"]);

  if (!flowId || !authenticatorId) {
    throw new Error(
      `App-Native Agent initiation did not return flowId/authenticatorId: ${JSON.stringify(flow)}`
    );
  }

  let authenticated;

  try {
    authenticated = await axios.post(
      secret.authnEndpointInternal,
      {
        flowId,
        selectedAuthenticator: {
          authenticatorId,
          params: {
            username: secret.agentId,
            password: secret.agentSecret,
          },
        },
      },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        timeout: 30000,
      }
    );
  } catch (error) {
    throw new Error(
      `APP_NATIVE_AUTHN_FAILED: ${
        error.response?.status || "no-status"
      } ${JSON.stringify(error.response?.data || error.message)}`
    );
  }

  const code = findDeep(authenticated.data, [
    "code",
    "authorizationCode",
  ]);
  if (!code) {
    throw new Error(
      `Agent authentication did not return authorization code: ${JSON.stringify(authenticated.data)}`
    );
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: secret.clientId,
    client_secret: secret.clientSecret,
    redirect_uri: config.agentMcp.client.redirectUri,
    code,
    code_verifier: verifier,
  });

  let tokenResponse;

  try {
    tokenResponse = await axios.post(
      secret.tokenEndpointInternal,
      body,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 30000,
      }
    );
  } catch (error) {
    throw new Error(
      `AGENT_TOKEN_EXCHANGE_FAILED: ${
        error.response?.status || "no-status"
      } ${JSON.stringify(error.response?.data || error.message)}`
    );
  }

  const accessToken = tokenResponse.data.access_token;
  if (!accessToken) throw new Error("Agent token response has no access_token");

  const claims = publicClaims(accessToken);
  if (claims.aut !== "AGENT") {
    throw new Error(
      `Expected native Agent token aut=AGENT; received ${JSON.stringify(claims)}`
    );
  }
  if (!claims.scope.includes("inventory.mcp.read")) {
    throw new Error("Agent token is missing inventory.mcp.read");
  }
  if (claims.scope.includes("inventory.mcp.adjust")) {
    throw new Error(
      "Least-privilege violation: autonomous Agent received inventory.mcp.adjust"
    );
  }

  return { accessToken, claims };
}

async function mcpTool(token, name, args) {
  const transport = new StreamableHTTPClientTransport(
    new URL(MCP_URL),
    {
      requestInit: {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    }
  );

  const client = new Client(
    {
      name: "marketsphere-inventory-agent",
      version: "1.0.0",
    },
    { capabilities: {} }
  );

  try {
    await client.connect(transport);
    const result = await client.callTool({
      name,
      arguments: args,
    });
    return result;
  } finally {
    await client.close().catch(() => {});
  }
}

function toolPayload(result) {
  if (result?.structuredContent) return result.structuredContent;
  const text = result?.content?.find((x) => x.type === "text")?.text;
  if (!text) return result;
  try { return JSON.parse(text); } catch { return { text }; }
}

async function autonomousEvidence(config, secret, mutation) {
  const actor = await obtainAgentActorToken(config, secret);

  const read = await mcpTool(
    actor.accessToken,
    "inventory_get_snapshot",
    {}
  );
  if (read.isError) {
    throw new Error(
      `Agent read unexpectedly denied: ${JSON.stringify(toolPayload(read))}`
    );
  }

  const denied = await mcpTool(
    actor.accessToken,
    "inventory_adjust_stock",
    mutation
  );
  if (!denied.isError) {
    throw new Error(
      "Security failure: Agent-only token unexpectedly executed sensitive mutation"
    );
  }

  const deniedPayload = toolPayload(denied);
  if (
    !["insufficient_scope", "human_approval_required"].includes(
      deniedPayload.code
    )
  ) {
    throw new Error(
      `Unexpected mutation denial: ${JSON.stringify(deniedPayload)}`
    );
  }

  return {
    actor,
    read: toolPayload(read),
    deniedMutation: deniedPayload,
  };
}

function externalize(url, config) {
  if (!url) return url;
  return String(url)
    .replace("https://wso2is:9443", "https://localhost:9443")
    .replace("http://wso2is:9443", "https://localhost:9443");
}

async function initiateCiba(config, secret, actorToken, mutation) {
  const bindingMessage =
    `Inventory Agent requests approval: ${mutation.sku} ` +
    `${mutation.delta >= 0 ? "+" : ""}${mutation.delta} units. ` +
    `Reason: ${mutation.reason}`;

  const body = new URLSearchParams({
    scope: config.agentMcp.ciba.requestedScopes.join(" "),
    login_hint: config.agentMcp.ciba.loginHint,
    binding_message: bindingMessage,
    actor_token: actorToken,
    notification_channel: "external",
  });

  const response = await axios.post(
    secret.cibaEndpointInternal,
    body,
    {
      auth: {
        username: secret.clientId,
        password: secret.clientSecret,
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 30000,
    }
  );

  if (!response.data.auth_req_id) {
    throw new Error(
      `CIBA response contains no auth_req_id: ${JSON.stringify(response.data)}`
    );
  }
  if (!response.data.auth_url) {
    throw new Error(
      "CIBA External channel did not return auth_url. Verify the application's CIBA notification channel."
    );
  }

  return {
    authReqId: response.data.auth_req_id,
    authUrl: externalize(response.data.auth_url, config),
    expiresIn: Number(response.data.expires_in || 300),
    interval: Number(response.data.interval || 2),
    bindingMessage,
  };
}

async function pollCiba(secret, request, timeoutSeconds = 120) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let interval = Math.max(2, Number(request.interval || 2));

  while (Date.now() < deadline) {
    const body = new URLSearchParams({
      grant_type: "urn:openid:params:grant-type:ciba",
      auth_req_id: request.authReqId,
    });

    try {
      const response = await axios.post(
        secret.cibaTokenEndpointInternal,
        body,
        {
          auth: {
            username: secret.clientId,
            password: secret.clientSecret,
          },
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          timeout: 30000,
        }
      );
      if (response.data.access_token) return response.data;
      throw new Error(`CIBA token response has no access_token`);
    } catch (error) {
      const code = error.response?.data?.error;
      if (code === "authorization_pending") {
        await new Promise((resolve) => setTimeout(resolve, interval * 1000));
        continue;
      }
      if (code === "slow_down") {
        interval += 2;
        await new Promise((resolve) => setTimeout(resolve, interval * 1000));
        continue;
      }
      if (code === "access_denied") {
        throw new Error("Human approver denied the CIBA request");
      }
      if (code === "expired_token") {
        throw new Error("CIBA request expired before approval");
      }
      throw error;
    }
  }

  throw new Error("Timed out polling for CIBA approval");
}

function assertObo(oboToken, actorSub) {
  const claims = publicClaims(oboToken);
  const act =
    typeof claims.act === "string"
      ? JSON.parse(claims.act)
      : claims.act;

  if (!claims.sub) throw new Error("OBO token has no human sub");
  if (!act?.sub) throw new Error("OBO token has no act.sub");
  if (String(act.sub) !== String(actorSub)) {
    throw new Error(
      `OBO act.sub mismatch: expected ${actorSub}, got ${act.sub}`
    );
  }
  if (String(claims.sub) === String(act.sub)) {
    throw new Error("OBO token does not contain distinct user and agent identities");
  }
  if (!claims.scope.includes("inventory.mcp.adjust")) {
    throw new Error("Approved OBO token is missing inventory.mcp.adjust");
  }

  return claims;
}

const app = express();
app.use(express.json({ limit: "128kb" }));

app.get("/health", (_req, res) => {
  res.json({
    status: "UP",
    service: "inventory-agent-mcp",
    scenario: "Agent Identity + MCP + CIBA OBO",
  });
});

app.get("/config", (_req, res) => {
  const config = loadConfig().agentMcp;
  res.json(config);
});

app.post("/demo/preflight", async (_req, res) => {
  try {
    const config = loadConfig();
    const secret = loadPrivate();
    const mutation = {
      sku: "SKU-LAPTOP-001",
      delta: -7,
      reason: "Cycle count correction requested by autonomous agent",
    };
    const evidence = await autonomousEvidence(config, secret, mutation);

    res.json({
      ok: true,
      phase: "AUTONOMOUS_AGENT_LEAST_PRIVILEGE",
      agentToken: evidence.actor.claims,
      readResult: evidence.read,
      sensitiveMutation: {
        attempted: mutation,
        result: evidence.deniedMutation,
        expected: "DENIED_PENDING_HUMAN_CIBA_APPROVAL",
      },
    });
  } catch (error) {
    res.status(error.response?.status || 502).json({
      ok: false,
      code: "agent_mcp_preflight_failed",
      message: error.message,
      upstream: error.response?.data,
    });
  }
});

app.post("/demo/start", async (req, res) => {
  try {
    const config = loadConfig();
    const secret = loadPrivate();
    const mutation = {
      sku: req.body?.sku || "SKU-LAPTOP-001",
      delta: Number(req.body?.delta ?? -7),
      reason:
        req.body?.reason ||
        "Cycle count correction requires human approval",
    };

    const evidence = await autonomousEvidence(config, secret, mutation);
    const ciba = await initiateCiba(
      config,
      secret,
      evidence.actor.accessToken,
      mutation
    );

    const requestId = crypto.randomUUID();
    pending.set(requestId, {
      createdAt: Date.now(),
      actorSub: evidence.actor.claims.sub,
      mutation,
      ciba,
    });

    res.json({
      ok: true,
      requestId,
      phase: "WAITING_FOR_HUMAN_CIBA_APPROVAL",
      agentToken: evidence.actor.claims,
      readResult: evidence.read,
      sensitiveMutation: {
        attempted: mutation,
        result: evidence.deniedMutation,
      },
      ciba: {
        authUrl: ciba.authUrl,
        expiresIn: ciba.expiresIn,
        interval: ciba.interval,
        bindingMessage: ciba.bindingMessage,
        notificationChannel: "external",
      },
    });
  } catch (error) {
    res.status(error.response?.status || 502).json({
      ok: false,
      code: "ciba_start_failed",
      message: error.message,
      upstream: error.response?.data,
    });
  }
});

app.post("/demo/complete", async (req, res) => {
  try {
    const requestId = req.body?.requestId;
    const record = pending.get(requestId);
    if (!record) {
      return res.status(404).json({
        ok: false,
        code: "unknown_request",
        message: "No pending CIBA request exists for this requestId",
      });
    }

    const config = loadConfig();
    const secret = loadPrivate();
    const tokenResponse = await pollCiba(
      secret,
      record.ciba,
      Number(req.body?.timeoutSeconds || 120)
    );

    const oboToken = tokenResponse.access_token;
    const oboClaims = assertObo(oboToken, record.actorSub);

    const mutationResult = await mcpTool(
      oboToken,
      "inventory_adjust_stock",
      record.mutation
    );
    if (mutationResult.isError) {
      throw new Error(
        `Human-approved mutation was denied: ${JSON.stringify(toolPayload(mutationResult))}`
      );
    }

    const auditResult = await mcpTool(
      oboToken,
      "inventory_get_audit",
      { limit: 5 }
    );
    if (auditResult.isError) {
      throw new Error(
        `Audit read failed: ${JSON.stringify(toolPayload(auditResult))}`
      );
    }

    pending.delete(requestId);

    res.json({
      ok: true,
      phase: "HUMAN_APPROVED_OBO_EXECUTED",
      oboToken: oboClaims,
      dualIdentity: {
        humanSub: oboClaims.sub,
        agentSub:
          typeof oboClaims.act === "object"
            ? oboClaims.act?.sub
            : JSON.parse(oboClaims.act || "{}")?.sub,
      },
      mutationResult: toolPayload(mutationResult),
      audit: toolPayload(auditResult),
    });
  } catch (error) {
    res.status(error.response?.status || 502).json({
      ok: false,
      code: "ciba_complete_failed",
      message: error.message,
      upstream: error.response?.data,
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("============================================================");
  console.log("MarketSphere Inventory Agent - MCP/CIBA Expert Flow");
  console.log(`Agent API: http://0.0.0.0:${PORT}`);
  console.log(`MCP      : ${MCP_URL}`);
  console.log("============================================================");
});
