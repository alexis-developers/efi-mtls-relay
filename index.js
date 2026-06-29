const express = require("express");
const https = require("https");
const fetch = require("node-fetch");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

const HMAC_SECRET       = process.env.HMAC_SECRET;
const EFI_CLIENT_ID     = process.env.EFI_CLIENT_ID;
const EFI_CLIENT_SECRET = process.env.EFI_CLIENT_SECRET;
const EFI_CERT_PEM      = process.env.EFI_CERT_PEM;
const EFI_KEY_PEM       = process.env.EFI_KEY_PEM;
const EFI_BASE_URL      = process.env.EFI_BASE_URL || "https://pix.api.efipay.com.br";
const PORT              = process.env.PORT || 3000;

let _agent = null;
function getMtlsAgent() {
  if (!_agent) {
    if (!EFI_CERT_PEM || !EFI_KEY_PEM) throw new Error("EFI_CERT_PEM / EFI_KEY_PEM not set");
    _agent = new https.Agent({
      cert: Buffer.from(EFI_CERT_PEM, "base64"),
      key:  Buffer.from(EFI_KEY_PEM,  "base64"),
      rejectUnauthorized: true,
    });
  }
  return _agent;
}

const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

app.get("/health", (req, res) => res.json({ ok: true }));

function requireHmac(req, res, next) {
  const token = req.headers["x-relay-token"];
  if (!token || token !== HMAC_SECRET) return res.status(401).json({ error: "Unauthorized" });
  next();
}

app.post("/oauth/token", requireHmac, async (req, res) => {
  try {
    const creds = Buffer.from(`${EFI_CLIENT_ID}:${EFI_CLIENT_SECRET}`).toString("base64");
    const r = await fetch(`${EFI_BASE_URL}/oauth/token`, {
      method: "POST",
      headers: { "Authorization": `Basic ${creds}`, "Content-Type": "application/json" },
      body: JSON.stringify({ grant_type: "client_credentials" }),
      agent: getMtlsAgent(),
    });
    res.status(r.status).json(await r.json());
  } catch (err) {
    console.error("[oauth/token]", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.all("/v2/*", requireHmac, async (req, res) => {
  try {
    const r = await fetch(`${EFI_BASE_URL}${req.originalUrl}`, {
      method: req.method,
      headers: { "Authorization": req.headers["authorization"], "Content-Type": "application/json" },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body),
      agent: getMtlsAgent(),
    });
    res.status(r.status).json(await r.json());
  } catch (err) {
    console.error("[v2 proxy]", err.message);
    res.status(500).json({ error: err.message });
  }
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.listen(PORT, () => console.log(`Relay listening on port ${PORT}`));
