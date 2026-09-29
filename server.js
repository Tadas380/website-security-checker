// Website Security Checker – HTTP server. No npm dependencies (Node.js 18+).
// Start with:  node server.js

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const netlib = require("./lib/net");
const { runScan } = require("./lib/checks");
const { buildReportPdf } = require("./lib/report-pdf");

const PORT = process.env.PORT || 3000;
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_TARGETS === "1";   // local development only
const PUBLIC_DIR = path.join(__dirname, "public");
const SCAN_TIMEOUT_MS = 25_000;
const MAX_CONCURRENT_SCANS = 4;

// ---------- scanner wiring ----------
const lookup = netlib.makeSafeLookup({ allowPrivate: ALLOW_PRIVATE });

let wpCache = { at: 0, version: null };
async function latestWordPress() {
  if (Date.now() - wpCache.at < 6 * 3600_000) return wpCache.version;
  try {
    const r = await fetch("https://api.wordpress.org/core/version-check/1.7/", { signal: AbortSignal.timeout(5000) });
    const data = await r.json();
    wpCache = { at: Date.now(), version: data.offers && data.offers[0] && data.offers[0].current || null };
  } catch { wpCache = { at: Date.now(), version: null }; }
  return wpCache.version;
}

const scannerDeps = {
  tlsInfo: host => netlib.tlsInfo(host, { lookup }),
  request: (url, opts) => netlib.request(url, { ...opts, lookup }),
  resolveTxt: netlib.resolveTxt,
  resolveMx: netlib.resolveMx,
  latestWordPress,
};

// ---------- results kept for 1 hour so the PDF can be downloaded ----------
const results = new Map();
function remember(scan) {
  const id = crypto.randomBytes(9).toString("base64url");
  results.set(id, { scan, at: Date.now() });
  if (results.size > 500) results.delete(results.keys().next().value);
  return id;
}
setInterval(() => {
  for (const [id, r] of results) if (Date.now() - r.at > 3600_000) results.delete(id);
}, 600_000).unref();

// ---------- abuse protection ----------
const hits = new Map();
function rateLimited(ip, limit = 6, windowMs = 60_000) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < windowMs);
  list.push(now);
  hits.set(ip, list);
  return list.length > limit;
}
let running = 0;

// ---------- helpers ----------
// The checker practises what it checks: every response carries the security headers.
const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function send(res, status, body, type = "application/json; charset=utf-8", extra = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": type, ...extra });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}
function readJson(req, limit = 4_000) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > limit) { reject(new Error("too large")); req.destroy(); } });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}
const MIME = { ".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8" };

function serveStatic(res, pathname) {
  const file = path.normalize(path.join(PUBLIC_DIR, pathname === "/" ? "index.html" : decodeURIComponent(pathname)));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, "Forbidden", "text/plain");
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, "Not found", "text/plain");
    send(res, 200, buf, MIME[path.extname(file)] || "application/octet-stream");
  });
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, "http://localhost"); } catch { return send(res, 400, "Bad request", "text/plain"); }

  if (req.method === "POST" && url.pathname === "/api/scan") {
    if (rateLimited(clientIp(req))) return send(res, 429, { error: "Too many checks. Please wait a minute." });
    let body;
    try { body = await readJson(req); } catch { return send(res, 400, { error: "Bad request." }); }
    if (body.consent !== true) return send(res, 400, { error: "Please confirm you own the website or have permission to check it." });
    let host;
    try { host = netlib.normalizeTarget(body.url); } catch (e) { return send(res, 400, { error: e.message }); }
    if (running >= MAX_CONCURRENT_SCANS) return send(res, 503, { error: "The checker is busy. Please try again in a few seconds." });

    running++;
    try {
      const scan = await Promise.race([
        runScan(host, scannerDeps),
        new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("The website took too long to respond."), { userFacing: true })), SCAN_TIMEOUT_MS)),
      ]);
      const id = remember(scan);
      console.log(`scan ${host} -> ${scan.grade} (${scan.score}) in ${scan.durationMs} ms`);
      return send(res, 200, { id, ...scan });
    } catch (e) {
      console.error(`scan ${host} failed:`, e.message);
      return send(res, e.userFacing ? 422 : 500, { error: e.userFacing ? e.message : "Something went wrong while checking. Please try again." });
    } finally { running--; }
  }

  const pdfMatch = url.pathname.match(/^\/api\/report\/([A-Za-z0-9_-]{8,20})\.pdf$/);
  if (req.method === "GET" && pdfMatch) {
    const r = results.get(pdfMatch[1]);
    if (!r) return send(res, 404, { error: "This report has expired. Run the check again." });
    const name = `security-report-${r.scan.host}-${r.scan.scannedAt.slice(0, 10)}.pdf`.replace(/[^a-z0-9.-]/gi, "-");
    return send(res, 200, buildReportPdf(r.scan), "application/pdf", { "Content-Disposition": `attachment; filename="${name}"` });
  }

  if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { ok: true });
  if (req.method === "GET" || req.method === "HEAD") return serveStatic(res, url.pathname);
  send(res, 405, "Method not allowed", "text/plain");
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Website Security Checker running: http://localhost:${PORT}`);
    if (ALLOW_PRIVATE) console.log("WARNING: private/local targets are allowed (ALLOW_PRIVATE_TARGETS=1). Never use this in production.");
  });
}

module.exports = { server, rateLimited, results };
