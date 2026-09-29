// The security checks. Everything here is passive and read-only: normal page
// requests, a TLS handshake and public DNS lookups. The analyse* functions are
// pure (data in, findings out) so they are easy to unit-test.

// Short "what's wrong" titles used when a check fails or warns (e.g. in "Fix these first").
const PROBLEMS = {
  https: "No working HTTPS", "cert-valid": "Certificate is not trusted", "cert-expiry": "Certificate expires soon",
  "tls-version": "Outdated TLS version", "http-redirect": "HTTP doesn't redirect to HTTPS", hsts: "HSTS is missing",
  csp: "No Content Security Policy", clickjacking: "No clickjacking protection", nosniff: "MIME sniffing not blocked",
  referrer: "No referrer policy", permissions: "No permissions policy", "server-version": "Server version is visible",
  "powered-by": "Technology is advertised", wordpress: "WordPress is outdated or advertised", "security-txt": "No security.txt contact",
  cookies: "Cookies lack protection flags", "exposed-git": "Git repository is public", "exposed-env": "Environment file (.env) is public",
  "exposed-phpinfo": "phpinfo page is public", "exposed-ds-store": ".DS_Store file is public", spf: "SPF is missing or too weak",
  dmarc: "DMARC is missing or not enforced",
};

function finding(id, title, status, severity, detail, fix = "") {
  const f = { id, title, status, severity, detail, fix };
  if (status === "fail" || status === "warn") f.problem = PROBLEMS[id] || title;
  return f;
}
const pass = (id, title, detail) => finding(id, title, "pass", "low", detail);
const info = (id, title, detail) => finding(id, title, "info", "low", detail);

// ---------- 1. HTTPS & certificate ----------
function analyseTransport({ tls, tlsError, httpProbe, httpsHeaders, now = new Date() }) {
  const out = [];
  if (!tls) {
    out.push(finding("https", "HTTPS is available", "fail", "high",
      `Could not open a secure (HTTPS) connection${tlsError ? `: ${tlsError}` : ""}.`,
      "Install a free TLS certificate (e.g. Let's Encrypt, usually one click in your hosting panel) so the site loads over https://."));
    return out;
  }
  out.push(pass("https", "HTTPS is available", `Secure connection works (${tls.protocol}).`));

  if (tls.authorized) {
    out.push(pass("cert-valid", "Certificate is trusted", `Issued by ${tls.issuer || "a trusted authority"}.`));
  } else {
    out.push(finding("cert-valid", "Certificate is trusted", "fail", "high",
      `Browsers will show a security warning: ${tls.authorizationError || "certificate not trusted"}.`,
      "Replace the certificate with one from a trusted authority that covers this exact domain (including www)."));
  }

  if (tls.validTo) {
    const days = Math.floor((new Date(tls.validTo) - now) / 86_400_000);
    const when = new Date(tls.validTo).toISOString().slice(0, 10);
    if (days < 0) out.push(finding("cert-expiry", "Certificate is not expiring soon", "fail", "high", `Expired on ${when}.`, "Renew the certificate now and turn on automatic renewal."));
    else if (days < 14) out.push(finding("cert-expiry", "Certificate is not expiring soon", "fail", "medium", `Expires in ${days} days (${when}).`, "Renew the certificate and make sure automatic renewal is on."));
    else if (days < 30) out.push(finding("cert-expiry", "Certificate is not expiring soon", "warn", "low", `Expires in ${days} days (${when}).`, "Check that automatic renewal is set up."));
    else out.push(pass("cert-expiry", "Certificate is not expiring soon", `Valid for ${days} more days (until ${when}).`));
  }

  if (/^TLSv1(\.1)?$/.test(tls.protocol || "")) {
    out.push(finding("tls-version", "Modern TLS version", "fail", "medium", `Negotiated an outdated protocol (${tls.protocol}).`, "Enable TLS 1.2 and 1.3 and disable TLS 1.0/1.1 in the server settings."));
  } else {
    out.push(pass("tls-version", "Modern TLS version", `${tls.protocol} is used.`));
  }

  if (httpProbe) {
    const loc = String(httpProbe.headers && httpProbe.headers.location || "");
    if ([301, 302, 303, 307, 308].includes(httpProbe.status) && /^https:\/\//i.test(loc)) {
      out.push(pass("http-redirect", "HTTP redirects to HTTPS", `http:// sends visitors to ${loc.slice(0, 80)}.`));
    } else if (httpProbe.status >= 200 && httpProbe.status < 400) {
      out.push(finding("http-redirect", "HTTP redirects to HTTPS", "fail", "medium",
        "The site also loads over insecure http:// without redirecting.",
        "Add a permanent (301) redirect from http:// to https:// in the hosting panel or web server config."));
    }
  }

  const hsts = httpsHeaders && httpsHeaders["strict-transport-security"];
  if (!hsts) {
    out.push(finding("hsts", "HSTS is enabled", "fail", "medium",
      "No Strict-Transport-Security header, so browsers may still try insecure http:// first.",
      "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"));
  } else {
    const age = Number((String(hsts).match(/max-age=(\d+)/i) || [])[1] || 0);
    if (age >= 15_552_000) out.push(pass("hsts", "HSTS is enabled", `max-age is ${Math.round(age / 86400)} days.`));
    else out.push(finding("hsts", "HSTS is enabled", "warn", "low", `max-age is only ${Math.round(age / 86400)} days.`, "Raise max-age to at least 6 months (15552000), ideally 1 year."));
  }
  return out;
}

// ---------- 2. Security headers ----------
function analyseHeaders(h = {}) {
  const out = [];
  const csp = h["content-security-policy"];
  out.push(csp
    ? pass("csp", "Content Security Policy", "A Content-Security-Policy header is set.")
    : finding("csp", "Content Security Policy", "fail", "medium",
      "No Content-Security-Policy header. It is the main browser-side defence against injected scripts (XSS).",
      "Start with a report-only policy (Content-Security-Policy-Report-Only), fix what it reports, then enforce it."));

  const xfo = String(h["x-frame-options"] || "").toUpperCase();
  const frameAncestors = /frame-ancestors/i.test(csp || "");
  out.push(xfo === "DENY" || xfo === "SAMEORIGIN" || frameAncestors
    ? pass("clickjacking", "Clickjacking protection", frameAncestors ? "CSP frame-ancestors is set." : `X-Frame-Options: ${xfo}.`)
    : finding("clickjacking", "Clickjacking protection", "fail", "medium",
      "Other sites can load this site in an invisible frame and trick visitors into clicking.",
      "Add the header: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self')."));

  out.push(String(h["x-content-type-options"] || "").toLowerCase() === "nosniff"
    ? pass("nosniff", "MIME sniffing blocked", "X-Content-Type-Options: nosniff is set.")
    : finding("nosniff", "MIME sniffing blocked", "fail", "low",
      "Browsers may guess file types, which can turn uploads into scripts.",
      "Add the header: X-Content-Type-Options: nosniff"));

  out.push(h["referrer-policy"]
    ? pass("referrer", "Referrer policy", `Referrer-Policy: ${h["referrer-policy"]}.`)
    : finding("referrer", "Referrer policy", "fail", "low",
      "Full page addresses (which can contain private details) may be sent to other websites.",
      "Add the header: Referrer-Policy: strict-origin-when-cross-origin"));

  out.push(h["permissions-policy"]
    ? pass("permissions", "Permissions policy", "Permissions-Policy header is set.")
    : finding("permissions", "Permissions policy", "warn", "low",
      "Embedded content could ask for camera, microphone or location.",
      "Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()"));
  return out;
}

// ---------- 3. Information leakage ----------
function analyseLeaks(h = {}, html = "", latestWordPress = null) {
  const out = [];
  const server = String(h["server"] || "");
  if (/\d/.test(server)) out.push(finding("server-version", "Server version hidden", "fail", "low", `The Server header reveals software and version: "${server.slice(0, 60)}".`, "Hide version numbers (e.g. server_tokens off in nginx, ServerTokens Prod in Apache)."));
  else out.push(pass("server-version", "Server version hidden", server ? `Server header: "${server.slice(0, 60)}" (no version).` : "No Server header."));

  const powered = h["x-powered-by"];
  if (powered) out.push(finding("powered-by", "Technology not advertised", "fail", "low", `X-Powered-By reveals: "${String(powered).slice(0, 60)}".`, "Remove the X-Powered-By header in the server or framework settings."));
  else out.push(pass("powered-by", "Technology not advertised", "No X-Powered-By header."));

  const gen = (html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i) || [])[1];
  const wp = gen && gen.match(/WordPress\s*([\d.]+)/i);
  if (wp) {
    const v = wp[1];
    if (latestWordPress && compareVersions(v, latestWordPress) < 0) {
      out.push(finding("wordpress", "WordPress is up to date", "fail", "high", `WordPress ${v} is running; the latest is ${latestWordPress}. Old versions have known, publicly listed vulnerabilities.`, "Update WordPress, themes and plugins, and turn on automatic updates. Also hide the version number."));
    } else {
      out.push(finding("wordpress", "WordPress version hidden", "warn", "low", `The page advertises WordPress ${v}${latestWordPress ? " (up to date)" : ""}. Attackers use this to pick exploits.`, "Remove the generator meta tag (a security plugin can do it) and keep auto-updates on."));
    }
  } else if (/wp-content\//i.test(html)) {
    out.push(info("wordpress", "WordPress detected", "The site runs WordPress; the version is not advertised."));
  }
  return out;
}

function compareVersions(a, b) {
  const pa = String(a).split(".").map(Number), pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

// ---------- 4. Cookies ----------
function analyseCookies(setCookies = []) {
  if (!setCookies.length) return [pass("cookies", "Cookies are protected", "The homepage sets no cookies.")];
  const problems = [];
  for (const c of setCookies) {
    const name = c.split("=")[0].trim().slice(0, 40);
    const missing = [];
    if (!/;\s*secure/i.test(c)) missing.push("Secure");
    if (!/;\s*httponly/i.test(c)) missing.push("HttpOnly");
    if (!/;\s*samesite=/i.test(c)) missing.push("SameSite");
    if (missing.length) problems.push(`${name} (missing ${missing.join(", ")})`);
  }
  if (!problems.length) return [pass("cookies", "Cookies are protected", `${setCookies.length} cookie(s), all with Secure, HttpOnly and SameSite.`)];
  return [finding("cookies", "Cookies are protected", "warn", "low",
    `Cookies without full protection: ${problems.slice(0, 4).join("; ")}${problems.length > 4 ? "…" : ""}.`,
    "Set cookies with Secure; HttpOnly; SameSite=Lax (HttpOnly may be skipped only for cookies JavaScript must read).")];
}

// ---------- 5. Exposed files ----------
// Only the status and a signature are checked. File contents are never stored or shown.
const EXPOSED_FILES = [
  { id: "git", path: "/.git/HEAD", title: "Git repository not exposed", severity: "high",
    test: r => r.status === 200 && /^(ref: refs\/|[0-9a-f]{40}\s*$)/.test(r.text.trim()),
    detail: "The /.git folder is public. Anyone can download the full source code, often including passwords.",
    fix: "Block access to /.git in the web server config and move deployments to a proper build/upload process." },
  { id: "env", path: "/.env", title: "Environment file not exposed", severity: "high",
    test: r => r.status === 200 && !/<html/i.test(r.text) && /^[A-Z][A-Z0-9_]*=/m.test(r.text),
    detail: "The .env file is public. It usually holds database passwords and API keys.",
    fix: "Delete it from the public folder or block it in the server config. Then change every password and key it contained." },
  { id: "phpinfo", path: "/phpinfo.php", title: "No phpinfo page", severity: "medium",
    test: r => r.status === 200 && /phpinfo\(\)|PHP Version/i.test(r.text) && /<title>[^<]*phpinfo/i.test(r.text),
    detail: "A phpinfo() page is public and shows detailed server configuration.",
    fix: "Delete phpinfo.php from the server." },
  { id: "ds-store", path: "/.DS_Store", title: "No macOS folder index exposed", severity: "low",
    test: r => r.status === 200 && r.raw && r.raw.length > 8 && r.raw.subarray(4, 8).toString("latin1") === "Bud1",
    detail: "A .DS_Store file lists the names of files and folders on the server.",
    fix: "Delete .DS_Store files from the server and block them in the web server config." },
];

function analyseExposed(results) {
  return EXPOSED_FILES.map(f => {
    const r = results[f.id];
    if (r && f.test(r)) return finding(`exposed-${f.id}`, f.title, "fail", f.severity, f.detail, f.fix);
    return pass(`exposed-${f.id}`, f.title, `${f.path} is not publicly readable.`);
  });
}

// ---------- 6. Email spoofing protection ----------
// Sites on a hosting platform's shared address (e.g. myapp.onrender.com) can't set
// their own DNS records, so SPF/DMARC are the platform's job, not the owner's.
const SHARED_PLATFORMS = {
  "onrender.com": "Render", "vercel.app": "Vercel", "netlify.app": "Netlify", "github.io": "GitHub Pages",
  "herokuapp.com": "Heroku", "pages.dev": "Cloudflare Pages", "workers.dev": "Cloudflare Workers",
  "web.app": "Firebase", "firebaseapp.com": "Firebase", "fly.dev": "Fly.io", "up.railway.app": "Railway",
  "azurewebsites.net": "Azure", "appspot.com": "Google App Engine", "glitch.me": "Glitch", "replit.app": "Replit",
  "wixsite.com": "Wix", "squarespace.com": "Squarespace", "wordpress.com": "WordPress.com", "blogspot.com": "Blogger",
  "webflow.io": "Webflow", "framer.website": "Framer", "myshopify.com": "Shopify", "surge.sh": "Surge",
};
function sharedPlatform(host) {
  const suffix = Object.keys(SHARED_PLATFORMS).find(d => host.endsWith(`.${d}`));
  return suffix ? { domain: suffix, name: SHARED_PLATFORMS[suffix] } : null;
}

function analyseEmail({ spf = [], dmarc = [], mx = [], platform = null }) {
  if (platform) {
    const why = `This site uses ${platform.name}'s shared address (${platform.domain}), so its email records are managed by ${platform.name}, not the site owner.`;
    const later = "Not scored. It will matter once the site moves to its own domain.";
    return [info("spf", "SPF record", `${why} ${later}`), info("dmarc", "DMARC policy", `${why} ${later}`)];
  }
  const out = [];
  const hasMail = mx.length > 0;
  const spfRec = spf.find(t => /^v=spf1\b/i.test(t));
  if (!spfRec) {
    out.push(finding("spf", "SPF record", "fail", "medium",
      "No SPF record. Anyone can send emails that pretend to come from this domain.",
      hasMail ? "Add a TXT record listing your mail senders, e.g. v=spf1 include:_spf.google.com ~all (your email provider gives the exact value)."
              : "The domain has no email, so publish v=spf1 -all to say it never sends mail."));
  } else if (/(^|\s)\+?all\b/i.test(spfRec)) {   // "+all" or a bare "all" lets anyone send
    out.push(finding("spf", "SPF record", "fail", "high", `SPF allows every server to send mail: "${spfRec.slice(0, 90)}".`, "Change the ending to ~all or -all."));
  } else if (/\?all\b/i.test(spfRec)) {
    out.push(finding("spf", "SPF record", "warn", "low", `SPF is neutral (?all), so it gives little protection.`, "Change the ending to ~all or -all."));
  } else {
    out.push(pass("spf", "SPF record", `"${spfRec.slice(0, 90)}"`));
  }

  const dm = dmarc.find(t => /^v=DMARC1\b/i.test(t));
  const policy = dm && (dm.match(/;\s*p=(\w+)/i) || [])[1];
  if (!dm) {
    out.push(finding("dmarc", "DMARC policy", "fail", "medium",
      "No DMARC record, so receiving mail servers aren't told to reject fake emails from this domain.",
      "Add a TXT record at _dmarc with v=DMARC1; p=quarantine; rua=mailto:you@yourdomain (start with p=none to monitor)."));
  } else if (!policy || policy.toLowerCase() === "none") {
    out.push(finding("dmarc", "DMARC policy", "warn", "low", "DMARC exists but only monitors (p=none), so fake emails are still delivered.", "Once reports look clean, change p=none to p=quarantine, then p=reject."));
  } else {
    out.push(pass("dmarc", "DMARC policy", `Policy is p=${policy}.`));
  }
  return out;
}

// ---------- 7. Extras ----------
function analyseSecurityTxt(r) {
  if (r && r.status === 200 && /^\s*(Contact|Expires):/im.test(r.text)) return [pass("security-txt", "security.txt contact", "Researchers know how to report problems.")];
  return [finding("security-txt", "security.txt contact", "warn", "low", "No /.well-known/security.txt, so people who find a problem don't know whom to tell.", "Publish /.well-known/security.txt with a Contact: email and an Expires: date (see securitytxt.org).")];
}

// ---------- scoring ----------
// Each check has a weight (how much it matters). A pass earns the full weight,
// a warning half, a failure nothing. The score is the share of points earned.
// Critical failures also cap the grade, so an exposed .env file can never get a "B".
const WEIGHTS = {
  https: 3, "cert-valid": 3, "cert-expiry": 2, "tls-version": 2, "http-redirect": 2, hsts: 2,
  csp: 2, clickjacking: 2, nosniff: 1, referrer: 1, permissions: 1,
  "server-version": 1, "powered-by": 1, wordpress: 3, "security-txt": 1, cookies: 1,
  "exposed-git": 3, "exposed-env": 3, "exposed-phpinfo": 2, "exposed-ds-store": 1,
  spf: 2, dmarc: 2,
};
const GRADES = ["A", "B", "C", "D", "F"];

function score(categories) {
  let earned = 0, possible = 0, highFails = 0;
  for (const c of categories) for (const f of c.checks) {
    if (f.status === "info") continue;
    const w = WEIGHTS[f.id] || 1;
    possible += w;
    if (f.status === "pass") earned += w;
    if (f.status === "warn") earned += w / 2;
    if (f.status === "fail" && f.severity === "high") highFails++;
  }
  const points = possible ? Math.round((earned / possible) * 100) : 0;
  let grade = points >= 90 ? "A" : points >= 80 ? "B" : points >= 65 ? "C" : points >= 50 ? "D" : "F";
  const cap = highFails >= 2 ? "F" : highFails === 1 ? "D" : "A";
  if (GRADES.indexOf(cap) > GRADES.indexOf(grade)) grade = cap;
  return { score: points, grade };
}

// ---------- full scan ----------
async function runScan(host, deps) {
  const started = Date.now();
  const text = r => r ? { ...r, text: r.body.toString("utf8"), raw: r.body } : null;
  const safe = p => p.then(v => v, e => ({ __error: e }));

  const [tlsR, httpsR, httpR, spf, dmarc, mx, wpLatest] = await Promise.all([
    safe(deps.tlsInfo(host)),
    safe(deps.request(`https://${host}/`, { maxBytes: 400_000 })),
    safe(deps.request(`http://${host}/`, { maxBytes: 2_000 })),
    safe(deps.resolveTxt(apexOf(host))),
    safe(deps.resolveTxt(`_dmarc.${apexOf(host)}`)),
    safe(deps.resolveMx(apexOf(host))),
    safe(deps.latestWordPress ? deps.latestWordPress() : Promise.resolve(null)),
  ]);

  const ok = v => v && !v.__error ? v : null;
  const tls = ok(tlsR), home = ok(httpsR) || ok(httpR);
  if (!tls && !ok(httpR)) {
    const e = (tlsR.__error || httpR.__error);
    const err = new Error(e && e.code === "EPRIVATEADDR" ? "That address points to a private network and can't be checked."
      : e && e.code === "ENOTFOUND" ? "That domain doesn't exist or has no website."
      : "The website didn't respond. Check the address and try again.");
    err.userFacing = true;
    throw err;
  }

  const base = tls ? `https://${host}` : `http://${host}`;
  const probes = await Promise.all([
    ...EXPOSED_FILES.map(f => safe(deps.request(base + f.path, { maxBytes: 4_000 }))),
    safe(deps.request(`${base}/.well-known/security.txt`, { maxBytes: 4_000 })),
  ]);
  const exposed = {};
  EXPOSED_FILES.forEach((f, i) => { exposed[f.id] = text(ok(probes[i])); });

  const headers = home ? home.headers : {};
  const html = home ? home.body.toString("utf8") : "";
  const categories = [
    { id: "transport", title: "HTTPS & certificate", checks: analyseTransport({ tls, tlsError: tlsR.__error && tlsR.__error.message, httpProbe: ok(httpR), httpsHeaders: ok(httpsR) && httpsR.headers }) },
    { id: "headers", title: "Security headers", checks: analyseHeaders(headers) },
    { id: "exposed", title: "Exposed files", checks: analyseExposed(exposed) },
    { id: "email", title: "Email spoofing protection", checks: analyseEmail({ spf: ok(spf) || [], dmarc: ok(dmarc) || [], mx: ok(mx) || [], platform: sharedPlatform(host) }) },
    { id: "leaks", title: "Information leakage", checks: [...analyseLeaks(headers, html, ok(wpLatest)), ...analyseSecurityTxt(text(ok(probes[EXPOSED_FILES.length])))] },
    { id: "cookies", title: "Cookies", checks: analyseCookies(home ? home.setCookies : []) },
  ];
  const { score: points, grade } = score(categories);
  const all = categories.flatMap(c => c.checks);
  return {
    host, scannedAt: new Date().toISOString(), durationMs: Date.now() - started,
    score: points, grade,
    summary: { pass: all.filter(f => f.status === "pass").length, warn: all.filter(f => f.status === "warn").length, fail: all.filter(f => f.status === "fail").length },
    categories,
  };
}

// "www.shop.example.lt" -> "example.lt" is not always right for every TLD,
// but for SPF/DMARC we only strip a leading "www.".
function apexOf(host) { return host.replace(/^www\./, ""); }

module.exports = { WEIGHTS, sharedPlatform, runScan, analyseTransport, analyseHeaders, analyseLeaks, analyseCookies, analyseExposed, analyseEmail, analyseSecurityTxt, score, compareVersions, EXPOSED_FILES };
