// Networking helpers with SSRF protection.
// Every connection resolves DNS through `safeLookup`, which refuses private,
// loopback, link-local and cloud-metadata addresses. The check happens at
// connect time, so DNS rebinding tricks can't slip past it.

const dns = require("dns");
const net = require("net");
const http = require("http");
const https = require("https");
const tls = require("tls");

const USER_AGENT = "WebsiteSecurityChecker/1.0 (+https://github.com/Tadas380/website-security-checker)";

// ---------- private address detection ----------
function ipv4ToInt(ip) {
  return ip.split(".").reduce((n, part) => (n << 8) + Number(part), 0) >>> 0;
}
const V4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([base, bits]) => [ipv4ToInt(base), bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0]);

function isPrivateIp(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKED.some(([base, mask]) => ((n & mask) >>> 0) === base);
  }
  if (kind === 6) {
    const a = ip.toLowerCase();
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    if (a === "::" || a === "::1") return true;
    if (/^f[cd][0-9a-f]{2}:/.test(a)) return true;        // fc00::/7 unique local
    if (/^fe[89ab][0-9a-f]:/.test(a)) return true;        // fe80::/10 link local
    if (/^ff[0-9a-f]{2}:/.test(a)) return true;           // multicast
    if (/^2001:db8:/.test(a)) return true;                // documentation
    return false;
  }
  return true; // not an IP at all: refuse
}

function makeSafeLookup({ allowPrivate = false } = {}) {
  return function safeLookup(hostname, options, callback) {
    if (typeof options === "function") { callback = options; options = {}; }
    dns.lookup(hostname, { all: true, family: options.family || 0 }, (err, addresses) => {
      if (err) return callback(err);
      if (!allowPrivate) {
        const bad = addresses.find(a => isPrivateIp(a.address));
        if (bad) {
          const e = new Error(`Refusing to connect to a private address (${bad.address})`);
          e.code = "EPRIVATEADDR";
          return callback(e);
        }
      }
      if (options.all) return callback(null, addresses);
      callback(null, addresses[0].address, addresses[0].family);
    });
  };
}

// ---------- target validation ----------
// Accepts "example.lt", "https://example.lt/page" etc. and returns the bare hostname.
function normalizeTarget(input) {
  const raw = String(input || "").trim();
  if (!raw || raw.length > 300) throw new Error("Enter a website address, e.g. example.lt");
  let url;
  try { url = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`); }
  catch { throw new Error("That doesn't look like a website address."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only http and https websites can be checked.");
  if (url.username || url.password) throw new Error("Addresses with login details aren't allowed.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Only standard ports (80 and 443) can be checked.");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (net.isIP(host.replace(/^\[|\]$/g, ""))) throw new Error("Enter a domain name, not an IP address.");
  if (!/^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/.test(host)) throw new Error("That doesn't look like a valid domain name.");
  return host;
}

// ---------- HTTP(S) request without following redirects ----------
function request(url, { method = "GET", maxBytes = 200_000, timeout = 8000, lookup, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, {
      method,
      lookup,
      timeout,
      rejectUnauthorized: false, // certificate problems are reported by the TLS check instead
      headers: { "User-Agent": USER_AGENT, Accept: "text/html,*/*;q=0.8", ...headers },
    }, res => {
      const chunks = []; let size = 0;
      res.on("data", c => {
        size += c.length;
        if (size <= maxBytes) chunks.push(c);
        if (size >= maxBytes) res.destroy();
      });
      const done = () => resolve({
        url, status: res.statusCode, headers: res.headers,
        setCookies: res.headers["set-cookie"] || [],
        body: Buffer.concat(chunks).subarray(0, maxBytes),
      });
      res.on("end", done);
      res.on("close", done);
      res.on("error", done);
    });
    req.on("timeout", () => req.destroy(Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" })));
    req.on("error", reject);
    req.end();
  });
}

// ---------- TLS handshake details ----------
function tlsInfo(host, { timeout = 8000, lookup } = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, lookup, rejectUnauthorized: false, timeout }, () => {
      const cert = socket.getPeerCertificate();
      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        protocol: socket.getProtocol(),
        validFrom: cert && cert.valid_from,
        validTo: cert && cert.valid_to,
        issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || "") : "",
        subject: cert && cert.subject ? cert.subject.CN || "" : "",
      });
      socket.end();
    });
    socket.on("timeout", () => socket.destroy(Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" })));
    socket.on("error", reject);
  });
}

// ---------- DNS ----------
async function resolveTxt(name) {
  try { return (await dns.promises.resolveTxt(name)).map(parts => parts.join("")); }
  catch (e) { if (["ENODATA", "ENOTFOUND", "ESERVFAIL", "ETIMEOUT", "EREFUSED"].includes(e.code)) return []; throw e; }
}
async function resolveMx(name) {
  try { return await dns.promises.resolveMx(name); }
  catch (e) { if (["ENODATA", "ENOTFOUND", "ESERVFAIL", "ETIMEOUT", "EREFUSED"].includes(e.code)) return []; throw e; }
}

module.exports = { isPrivateIp, makeSafeLookup, normalizeTarget, request, tlsInfo, resolveTxt, resolveMx, USER_AGENT };
