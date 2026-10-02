import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.PORT || "8300");
const SECRET = process.env.CONSENT_WEBHOOK_SECRET || "";
const REQUIRE_SIGNATURE =
  String(process.env.REQUIRE_WEBHOOK_SIGNATURE || "true").toLowerCase() !== "false";
const DATA_FILE = process.env.CONSENT_EVENT_FILE || "/data/events.ndjson";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const POLICY_FILE = path.join(__dirname, "..", "policy", "lgpd-privacy-notice-pt-BR.html");

const CONSENT_ADDED =
  "https://schemas.identity.wso2.org/events/consent/event-type/consentAdded";
const CONSENT_REVOKED =
  "https://schemas.identity.wso2.org/events/consent/event-type/consentRevoked";
const PURPOSE_VERSION_ADDED =
  "https://schemas.identity.wso2.org/events/consent-purpose/event-type/purposeVersionAdded";

if (REQUIRE_SIGNATURE && !SECRET) {
  console.error(
    "CONSENT_WEBHOOK_SECRET is required when REQUIRE_WEBHOOK_SIGNATURE=true"
  );
  process.exit(1);
}

fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });

const seen = new Set();
const events = [];

function loadExisting() {
  if (!fs.existsSync(DATA_FILE)) return;

  for (const line of fs.readFileSync(DATA_FILE, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line);
      if (event.jti) seen.add(event.jti);
      events.push(event);
    } catch {
      // Preserve availability if a local demo file contains a damaged line.
    }
  }
}
loadExisting();

function secureEqual(a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function verifySignature(rawBody, header) {
  if (!REQUIRE_SIGNATURE) return true;
  if (!header) return false;

  const expected =
    "sha256=" +
    crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");

  return secureEqual(expected, String(header).trim());
}

function eventName(uri) {
  if (uri === CONSENT_ADDED) return "consentAdded";
  if (uri === CONSENT_REVOKED) return "consentRevoked";
  if (uri === PURPOSE_VERSION_ADDED) return "purposeVersionAdded";
  return null;
}

function projectEvent(payload) {
  const eventEntries = Object.entries(payload.events || {});
  const recognized = eventEntries.find(([uri]) => eventName(uri));

  if (!recognized) {
    return null;
  }

  const [uri, detail] = recognized;
  const consent = detail?.consent || {};
  const purpose = consent?.purpose || detail?.purpose || {};
  const version =
    typeof purpose?.version === "object"
      ? purpose.version?.version
      : purpose?.version;

  const elements =
    consent?.purpose?.elements ||
    purpose?.version?.elements ||
    purpose?.elements ||
    [];

  // Intentionally retain only identifiers and consent metadata required for
  // audit / downstream reaction. Arbitrary user claims are not persisted.
  return {
    jti: payload.jti || null,
    rci: payload.rci || null,
    issuer: payload.iss || null,
    issuedAt: payload.iat || null,
    receivedAt: new Date().toISOString(),
    eventUri: uri,
    eventType: eventName(uri),
    initiatorType: detail?.initiatorType || null,
    action: detail?.action || null,
    organizationId:
      detail?.organization?.id ||
      detail?.tenant?.id ||
      null,
    userId: detail?.user?.id || null,
    consent: {
      id: consent?.id || null,
      subjectId: consent?.subjectId || null,
      state: consent?.state || null,
      serviceId: consent?.serviceId || null,
      purposeId: purpose?.id || null,
      purposeName: purpose?.name || null,
      purposeVersion: version || null,
      elements: Array.isArray(elements)
        ? elements.map((item) => ({
            name: item?.name || null,
            mandatory:
              typeof item?.mandatory === "boolean" ? item.mandatory : null
          }))
        : []
    }
  };
}

function appendEvent(event) {
  if (event.jti && seen.has(event.jti)) {
    return false;
  }

  if (event.jti) seen.add(event.jti);
  events.push(event);
  fs.appendFileSync(DATA_FILE, JSON.stringify(event) + "\n", "utf8");
  return true;
}

function latestState() {
  const state = new Map();

  for (const event of events) {
    if (!["consentAdded", "consentRevoked"].includes(event.eventType)) continue;
    const subject =
      event.consent?.subjectId ||
      event.userId ||
      "unknown-subject";
    const purpose =
      event.consent?.purposeName ||
      event.consent?.purposeId ||
      "unknown-purpose";
    const key = `${subject}::${purpose}`;

    state.set(key, {
      subject,
      purpose,
      status:
        event.eventType === "consentAdded" ? "APPROVED" : "REVOKED",
      at: event.receivedAt,
      eventJti: event.jti
    });
  }

  return [...state.values()].sort((a, b) =>
    String(b.at).localeCompare(String(a.at))
  );
}

function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body, null, 2));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(data.length),
    "cache-control": "no-store"
  });
  res.end(data);
}

function html(res, status, body) {
  const data = Buffer.from(body);
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": String(data.length),
    "cache-control": "no-store"
  });
  res.end(data);
}

function dashboard() {
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MarketSphere · LGPD Consent Audit</title>
  <style>
    :root { font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #151515; }
    body { margin: 0; background: #f6f7f8; }
    header { background: #111; color: #fff; padding: 22px 30px; }
    header strong { color: #f14e23; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    .card { background: #fff; border: 1px solid #ddd; border-radius: 10px; padding: 20px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; vertical-align: top; }
    .ok { color: #18794e; font-weight: 700; }
    .revoked { color: #b42318; font-weight: 700; }
    code { background: #f1f1f1; border-radius: 5px; padding: 2px 5px; }
    a { color: #c53d1b; }
    @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<header>
  <div><strong>MarketSphere Brasil</strong> · LGPD Consent Audit</div>
  <small>Eventos assinados do WSO2 Identity Server — projeção mínima para auditoria</small>
</header>
<main>
  <div class="grid">
    <section class="card">
      <h2>Estado atual dos consentimentos</h2>
      <div id="state">Carregando…</div>
    </section>
    <section class="card">
      <h2>Cenário</h2>
      <p>
        Demonstra consentimento de política, preferências opcionais,
        revogação pelo titular e propagação por webhook.
      </p>
      <p><a href="/policy/lgpd" target="_blank">Abrir Aviso de Privacidade LGPD</a></p>
      <p><a href="https://localhost:9443/myaccount" target="_blank">Abrir My Account</a></p>
    </section>
  </div>
  <section class="card" style="margin-top:18px">
    <h2>Trilha de eventos</h2>
    <div id="events">Carregando…</div>
  </section>
</main>
<script>
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

async function refresh() {
  const [eventsRes, stateRes] = await Promise.all([
    fetch("/api/events"),
    fetch("/api/state")
  ]);
  const events = await eventsRes.json();
  const state = await stateRes.json();

  document.getElementById("state").innerHTML =
    state.items.length === 0
      ? "<p>Nenhum consentimento recebido ainda.</p>"
      : "<table><thead><tr><th>Titular</th><th>Finalidade</th><th>Estado</th><th>Atualizado</th></tr></thead><tbody>" +
        state.items.map((x) =>
          "<tr><td><code>" + esc(x.subject) + "</code></td><td>" +
          esc(x.purpose) + "</td><td class='" +
          (x.status === "APPROVED" ? "ok" : "revoked") + "'>" +
          esc(x.status) + "</td><td>" + esc(x.at) + "</td></tr>"
        ).join("") +
        "</tbody></table>";

  document.getElementById("events").innerHTML =
    events.items.length === 0
      ? "<p>Nenhum evento recebido ainda.</p>"
      : "<table><thead><tr><th>Quando</th><th>Evento</th><th>Ação</th><th>Finalidade</th><th>Versão</th><th>JTI</th></tr></thead><tbody>" +
        events.items.slice().reverse().map((x) =>
          "<tr><td>" + esc(x.receivedAt) + "</td><td>" +
          esc(x.eventType) + "</td><td>" + esc(x.action) + "</td><td>" +
          esc(x.consent?.purposeName) + "</td><td>" +
          esc(x.consent?.purposeVersion) + "</td><td><code>" +
          esc(x.jti) + "</code></td></tr>"
        ).join("") +
        "</tbody></table>";
}

refresh();
setInterval(refresh, 2500);
</script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, {
      ok: true,
      service: "marketsphere-consent-audit",
      signatureVerification: REQUIRE_SIGNATURE,
      persistedEvents: events.length
    });
  }

  if (req.method === "GET" && url.pathname === "/") {
    return html(res, 200, dashboard());
  }

  if (req.method === "GET" && url.pathname === "/policy/lgpd") {
    return html(res, 200, fs.readFileSync(POLICY_FILE, "utf8"));
  }

  if (req.method === "GET" && url.pathname === "/api/events") {
    return json(res, 200, {
      count: events.length,
      items: events.slice(-200)
    });
  }

  if (req.method === "GET" && url.pathname === "/api/state") {
    return json(res, 200, {
      items: latestState()
    });
  }

  if (req.method === "POST" && url.pathname === "/webhooks/wso2") {
    const chunks = [];
    let length = 0;
    const maxBody = 1024 * 1024;

    req.on("data", (chunk) => {
      length += chunk.length;
      if (length > maxBody) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (length > maxBody) {
        return json(res, 413, { ok: false, code: "payload_too_large" });
      }

      const rawBody = Buffer.concat(chunks);
      const signature = req.headers["x-wso2-event-signature"];

      if (!verifySignature(rawBody, signature)) {
        return json(res, 401, {
          ok: false,
          code: "invalid_webhook_signature"
        });
      }

      let payload;
      try {
        payload = JSON.parse(rawBody.toString("utf8"));
      } catch {
        return json(res, 400, {
          ok: false,
          code: "invalid_json"
        });
      }

      const projected = projectEvent(payload);
      if (!projected) {
        // Forward compatible behavior: acknowledge event families this
        // consumer does not use instead of failing the webhook delivery.
        return json(res, 202, {
          ok: true,
          ignored: true
        });
      }

      const inserted = appendEvent(projected);
      return json(res, inserted ? 202 : 200, {
        ok: true,
        duplicate: !inserted,
        jti: projected.jti,
        eventType: projected.eventType
      });
    });

    return;
  }

  return json(res, 404, {
    ok: false,
    code: "not_found"
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("============================================================");
  console.log("MarketSphere LGPD Consent Audit");
  console.log(`Dashboard : http://localhost:${PORT}`);
  console.log(`Webhook   : http://consent-audit:${PORT}/webhooks/wso2`);
  console.log(`Policy    : http://localhost:${PORT}/policy/lgpd`);
  console.log(`HMAC      : ${REQUIRE_SIGNATURE ? "required" : "disabled"}`);
  console.log("============================================================");
});
