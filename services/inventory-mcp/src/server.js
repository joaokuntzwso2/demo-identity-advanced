import fs from "node:fs";
import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod/v3";

const PORT = Number(process.env.PORT || 8200);
const CONFIG_PATH =
  process.env.RUNTIME_CONFIG_PATH || "/runtime/runtime-config.json";

const inventory = new Map([
  ["SKU-LAPTOP-001", { sku: "SKU-LAPTOP-001", name: "Enterprise Laptop", quantity: 125, reorderPoint: 40 }],
  ["SKU-ROUTER-042", { sku: "SKU-ROUTER-042", name: "Branch Router", quantity: 48, reorderPoint: 25 }],
  ["SKU-SENSOR-900", { sku: "SKU-SENSOR-900", name: "Warehouse Sensor", quantity: 310, reorderPoint: 80 }],
]);

const audit = [];

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function scopes(payload) {
  const value = payload.scope;
  if (Array.isArray(value)) return new Set(value.map(String));
  return new Set(String(value || "").split(/\s+/).filter(Boolean));
}

function parseAct(payload) {
  const act = payload.act;
  if (!act) return null;
  if (typeof act === "object") return act;
  if (typeof act === "string") {
    try { return JSON.parse(act); } catch { return null; }
  }
  return null;
}

function normalizeSubject(value) {
  const s = String(value || "");
  return s.includes("@") ? s.split("@", 1)[0] : s;
}

function expectedAgent(payload, config) {
  const expected = config.agentMcp?.agent?.expectedSubjects || [];
  const actual = normalizeSubject(payload);
  return expected.some((candidate) => {
    const c = normalizeSubject(candidate);
    return actual === c || String(payload || "") === String(candidate || "");
  });
}

function toolOk(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    structuredContent: data,
  };
}

function toolDenied(code, message, details = {}) {
  const data = { ok: false, status: 403, code, message, ...details };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    structuredContent: data,
  };
}

function requireScopes(auth, required) {
  const missing = required.filter((scope) => !auth.scopes.has(scope));
  return missing;
}

function requireOBO(auth, config) {
  const act = parseAct(auth.payload);
  if (!act?.sub) {
    return {
      ok: false,
      code: "human_approval_required",
      message: "Sensitive MCP tool requires an OBO token containing act.sub.",
    };
  }
  if (!expectedAgent(act.sub, config)) {
    return {
      ok: false,
      code: "unexpected_actor",
      message: `OBO token actor ${act.sub} is not the Inventory Reconciliation Agent.`,
    };
  }
  if (!auth.payload.sub || normalizeSubject(auth.payload.sub) === normalizeSubject(act.sub)) {
    return {
      ok: false,
      code: "invalid_dual_identity",
      message: "OBO token must identify a human in sub and the agent in act.sub.",
    };
  }
  return { ok: true, act };
}

let jwksCache = null;
let jwksUrlCache = null;

async function verifyBearer(req) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ")) {
    const error = new Error("Bearer access token is required");
    error.status = 401;
    throw error;
  }

  const config = loadConfig();
  const token = header.slice("Bearer ".length);
  const jwksUrl = config.internalJwksUri;

  if (!jwksCache || jwksUrlCache !== jwksUrl) {
    jwksCache = createRemoteJWKSet(new URL(jwksUrl));
    jwksUrlCache = jwksUrl;
  }

  const { payload } = await jwtVerify(token, jwksCache, {
    issuer: config.issuer,
  });

  const expectedClientId = config.agentMcp?.client?.clientId;
  const audiences = Array.isArray(payload.aud)
    ? payload.aud.map(String)
    : [String(payload.aud || "")].filter(Boolean);

  const clientMatches =
    String(payload.azp || "") === expectedClientId ||
    String(payload.client_id || "") === expectedClientId ||
    String(payload.clientId || "") === expectedClientId ||
    audiences.includes(expectedClientId);

  if (!clientMatches) {
    const error = new Error(
      `Token was not issued to Inventory MCP Agent Client. azp=${payload.azp || ""} aud=${JSON.stringify(payload.aud)}`
    );
    error.status = 401;
    throw error;
  }

  return { token, payload, scopes: scopes(payload), config };
}

function createServer(auth) {
  const config = auth.config;
  const server = new McpServer({
    name: "marketsphere-inventory-mcp",
    version: "1.0.0",
  });

  server.registerTool(
    "inventory_get_snapshot",
    {
      title: "Read Inventory Snapshot",
      description:
        "Read current inventory. This is the autonomous, low-risk Agent operation.",
      inputSchema: {
        sku: z.string().optional().describe("Optional SKU to filter"),
      },
    },
    async ({ sku }) => {
      const missing = requireScopes(auth, ["inventory.mcp.read"]);
      if (missing.length) {
        return toolDenied(
          "insufficient_scope",
          "Inventory read scope is required.",
          { requiredScopes: ["inventory.mcp.read"], missingScopes: missing }
        );
      }

      const rows = sku
        ? [inventory.get(sku)].filter(Boolean)
        : [...inventory.values()];

      return toolOk({
        ok: true,
        operation: "read",
        principal: {
          sub: auth.payload.sub,
          aut: auth.payload.aut,
          act: parseAct(auth.payload),
        },
        inventory: rows,
      });
    }
  );

  server.registerTool(
    "inventory_adjust_stock",
    {
      title: "Adjust Inventory Stock",
      description:
        "Sensitive mutation. Requires human-approved CIBA OBO token with user sub + agent act.sub.",
      inputSchema: {
        sku: z.string(),
        delta: z.number().int().min(-100).max(100),
        reason: z.string().min(8),
      },
    },
    async ({ sku, delta, reason }) => {
      const required = ["inventory.mcp.read", "inventory.mcp.adjust"];
      const missing = requireScopes(auth, required);
      if (missing.length) {
        return toolDenied(
          "insufficient_scope",
          "Agent-only token cannot mutate inventory. Human CIBA approval is required.",
          { requiredScopes: required, missingScopes: missing }
        );
      }

      const obo = requireOBO(auth, config);
      if (!obo.ok) {
        return toolDenied(obo.code, obo.message, {
          requiredScopes: required,
        });
      }

      const row = inventory.get(sku);
      if (!row) {
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({
            ok: false,
            status: 404,
            code: "sku_not_found",
            sku,
          }) }],
        };
      }

      const before = row.quantity;
      const after = before + delta;
      if (after < 0) {
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({
            ok: false,
            status: 409,
            code: "negative_inventory",
            before,
            delta,
          }) }],
        };
      }

      row.quantity = after;
      const event = {
        id: `audit-${String(audit.length + 1).padStart(4, "0")}`,
        at: new Date().toISOString(),
        tool: "inventory_adjust_stock",
        sku,
        delta,
        before,
        after,
        reason,
        authorization: {
          humanSub: auth.payload.sub,
          agentSub: obo.act.sub,
          aut: auth.payload.aut,
          azp: auth.payload.azp || auth.payload.client_id,
          jti: auth.payload.jti,
          scopes: [...auth.scopes].sort(),
        },
      };
      audit.push(event);

      return toolOk({
        ok: true,
        operation: "mutation",
        inventory: { ...row },
        approval: {
          type: "CIBA_OBO",
          humanSub: auth.payload.sub,
          agentSub: obo.act.sub,
        },
        auditId: event.id,
      });
    }
  );

  server.registerTool(
    "inventory_get_audit",
    {
      title: "Read Inventory Agent Audit Trail",
      description:
        "Read the dual-identity audit trail produced by human-approved Agent mutations.",
      inputSchema: {
        limit: z.number().int().min(1).max(20).optional(),
      },
    },
    async ({ limit = 10 }) => {
      const missing = requireScopes(auth, ["inventory.mcp.audit"]);
      if (missing.length) {
        return toolDenied(
          "insufficient_scope",
          "Audit scope is required.",
          { requiredScopes: ["inventory.mcp.audit"], missingScopes: missing }
        );
      }

      const obo = requireOBO(auth, config);
      if (!obo.ok) {
        return toolDenied(obo.code, obo.message);
      }

      return toolOk({
        ok: true,
        count: Math.min(limit, audit.length),
        events: audit.slice(-limit).reverse(),
      });
    }
  );

  return server;
}

const app = express();
app.use(express.json({ limit: "256kb" }));

app.get("/health", (_req, res) => {
  res.json({
    status: "UP",
    service: "marketsphere-inventory-mcp",
    transport: "streamable-http",
  });
});

app.get("/policy", (_req, res) => {
  const cfg = loadConfig().agentMcp;
  res.json({
    resource: cfg.resource,
    client: {
      displayName: cfg.client.displayName,
      clientId: cfg.client.clientId,
      appNativeAuthentication: cfg.client.appNativeAuthentication,
      grantTypes: cfg.client.grantTypes,
    },
    roles: cfg.roles,
    tools: cfg.mcpServer.tools,
    enforcement: [
      "JWT signature / issuer validation against WSO2 JWKS",
      "OAuth client/audience validation",
      "scope enforcement per MCP tool",
      "sensitive mutation requires OBO act.sub",
      "act.sub must identify Inventory Reconciliation Agent",
      "human sub and agent act.sub are written to audit",
    ],
  });
});

app.post("/mcp", async (req, res) => {
  let auth;
  try {
    auth = await verifyBearer(req);
  } catch (error) {
    return res.status(error.status || 401).json({
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "Unauthorized MCP request",
        data: { reason: error.message },
      },
      id: req.body?.id ?? null,
    });
  }

  const server = createServer(auth);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  res.on("close", () => {
    transport.close().catch?.(() => {});
    server.close().catch?.(() => {});
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("[mcp] request failed", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: error.message },
        id: req.body?.id ?? null,
      });
    }
  }
});

app.get("/mcp", (_req, res) => {
  res.status(405).json({
    error: "This demo uses stateless Streamable HTTP POST requests.",
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("============================================================");
  console.log("MarketSphere Inventory MCP Server");
  console.log(`MCP URL : http://0.0.0.0:${PORT}/mcp`);
  console.log("Tools   : inventory_get_snapshot");
  console.log("          inventory_adjust_stock [CIBA OBO required]");
  console.log("          inventory_get_audit [CIBA OBO required]");
  console.log("============================================================");
});
