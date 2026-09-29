const test = require("node:test");
const assert = require("node:assert/strict");
const c = require("../lib/checks");

const byId = (list, id) => list.find(f => f.id === id);

test("transport: no HTTPS at all is a high-risk failure", () => {
  const out = c.analyseTransport({ tls: null, tlsError: "ECONNREFUSED" });
  assert.equal(out[0].status, "fail");
  assert.equal(out[0].severity, "high");
});

test("transport: healthy HTTPS setup passes every check", () => {
  const now = new Date("2026-01-01");
  const out = c.analyseTransport({
    now,
    tls: { authorized: true, protocol: "TLSv1.3", issuer: "Let's Encrypt", validTo: "Jun 1 00:00:00 2026 GMT" },
    httpProbe: { status: 301, headers: { location: "https://example.lt/" } },
    httpsHeaders: { "strict-transport-security": "max-age=31536000" },
  });
  assert.deepEqual(out.map(f => f.status), ["pass", "pass", "pass", "pass", "pass", "pass"]);
});

test("transport: expired certificate, no redirect and short HSTS are flagged", () => {
  const out = c.analyseTransport({
    now: new Date("2026-06-10"),
    tls: { authorized: false, authorizationError: "CERT_HAS_EXPIRED", protocol: "TLSv1.2", validTo: "Jun 1 00:00:00 2026 GMT" },
    httpProbe: { status: 200, headers: {} },
    httpsHeaders: { "strict-transport-security": "max-age=600" },
  });
  assert.equal(byId(out, "cert-valid").status, "fail");
  assert.equal(byId(out, "cert-expiry").severity, "high");
  assert.equal(byId(out, "http-redirect").status, "fail");
  assert.equal(byId(out, "hsts").status, "warn");
});

test("headers: all recommended headers present means all pass", () => {
  const out = c.analyseHeaders({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
  });
  assert.ok(out.every(f => f.status === "pass"), JSON.stringify(out.map(f => [f.id, f.status])));
});

test("headers: nothing set gives fails with fixes", () => {
  const out = c.analyseHeaders({});
  assert.equal(out.filter(f => f.status === "fail").length, 4);
  assert.ok(out.every(f => f.status === "pass" || f.fix.length > 10));
});

test("exposed files: real .git and .env are detected", () => {
  const r = (status, text) => ({ status, text, raw: Buffer.from(text) });
  const out = c.analyseExposed({ git: r(200, "ref: refs/heads/main\n"), env: r(200, "DB_PASSWORD=x\n") });
  assert.equal(byId(out, "exposed-git").status, "fail");
  assert.equal(byId(out, "exposed-env").status, "fail");
});

test("exposed files: 'soft 404' pages that return HTML for every URL are not false alarms", () => {
  const html = "<html><body>Page not found</body></html>";
  const r = { status: 200, text: html, raw: Buffer.from(html) };
  const out = c.analyseExposed({ git: r, env: r, phpinfo: r, "ds-store": r });
  assert.ok(out.every(f => f.status === "pass"));
});

test("email: SPF and DMARC variants", () => {
  const spf = rec => byId(c.analyseEmail({ spf: [rec], dmarc: [], mx: [1] }), "spf");
  assert.equal(spf("v=spf1 include:_spf.google.com ~all").status, "pass");
  assert.equal(spf("v=spf1 -all").status, "pass");
  assert.equal(spf("v=spf1 ?all").status, "warn");
  assert.equal(spf("v=spf1 +all").severity, "high");
  assert.equal(spf("v=spf1 a mx all").status, "fail");
  const dmarc = rec => byId(c.analyseEmail({ spf: [], dmarc: rec ? [rec] : [], mx: [] }), "dmarc");
  assert.equal(dmarc(null).status, "fail");
  assert.equal(dmarc("v=DMARC1; p=none").status, "warn");
  assert.equal(dmarc("v=DMARC1; p=reject; rua=mailto:x@y.lt").status, "pass");
});

test("cookies: missing flags are reported, fully protected cookies pass", () => {
  assert.equal(c.analyseCookies([])[0].status, "pass");
  assert.equal(c.analyseCookies(["a=1; Secure; HttpOnly; SameSite=Lax"])[0].status, "pass");
  const bad = c.analyseCookies(["sid=abc; Path=/"])[0];
  assert.equal(bad.status, "warn");
  assert.match(bad.detail, /Secure, HttpOnly, SameSite/);
});

test("leaks: version numbers and outdated WordPress", () => {
  const html = '<meta name="generator" content="WordPress 6.1.1">';
  const out = c.analyseLeaks({ server: "Apache/2.4.41", "x-powered-by": "PHP/7.4" }, html, "6.8.3");
  assert.equal(byId(out, "server-version").status, "fail");
  assert.equal(byId(out, "powered-by").status, "fail");
  assert.equal(byId(out, "wordpress").severity, "high");
  assert.equal(c.compareVersions("6.8", "6.8.0"), 0);
  assert.equal(c.compareVersions("6.10", "6.9"), 1);
});

test("score: critical failures cap the grade even when most checks pass", () => {
  const checks = Object.keys(c.WEIGHTS).map(id => ({ id, status: "pass", severity: "low" }));
  assert.deepEqual(c.score([{ checks }]), { score: 100, grade: "A" });
  checks.find(f => f.id === "exposed-env").status = "fail";
  checks.find(f => f.id === "exposed-env").severity = "high";
  assert.equal(c.score([{ checks }]).grade, "D");
  checks.find(f => f.id === "exposed-git").status = "fail";
  checks.find(f => f.id === "exposed-git").severity = "high";
  assert.equal(c.score([{ checks }]).grade, "F");
});

test("runScan: full scan with fake network gives a complete, graded result", async () => {
  const res = (status, headers = {}, body = "") => ({ status, headers, body: Buffer.from(body), setCookies: [] });
  const scan = await c.runScan("example.lt", {
    tlsInfo: async () => ({ authorized: true, protocol: "TLSv1.3", issuer: "R3", validTo: new Date(Date.now() + 90 * 864e5).toUTCString() }),
    request: async url => url.startsWith("http://") ? res(301, { location: "https://example.lt/" })
      : url.endsWith("/") ? res(200, { "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY" }, "<html>hi</html>")
      : res(404),
    resolveTxt: async name => name.startsWith("_dmarc") ? ["v=DMARC1; p=reject"] : ["v=spf1 -all"],
    resolveMx: async () => [],
  });
  assert.equal(scan.host, "example.lt");
  assert.equal(scan.categories.length, 6);
  assert.ok(["A", "B", "C"].includes(scan.grade), scan.grade);
  assert.equal(scan.summary.pass + scan.summary.warn + scan.summary.fail + scan.categories.flatMap(x => x.checks).filter(f => f.status === "info").length,
    scan.categories.flatMap(x => x.checks).length);
});

test("runScan: unreachable site gives a friendly error", async () => {
  const fail = async () => { throw Object.assign(new Error("nope"), { code: "ENOTFOUND" }); };
  await assert.rejects(c.runScan("nothing-here.lt", { tlsInfo: fail, request: fail, resolveTxt: async () => [], resolveMx: async () => [] }),
    e => e.userFacing && /doesn't exist/.test(e.message));
});

test("email: shared hosting addresses aren't blamed for the platform's DNS", () => {
  assert.deepEqual(c.sharedPlatform("myapp.onrender.com"), { domain: "onrender.com", name: "Render" });
  assert.equal(c.sharedPlatform("onrender.com"), null);            // the platform itself is still checked
  assert.equal(c.sharedPlatform("shop.example.lt"), null);
  const out = c.analyseEmail({ spf: [], dmarc: [], mx: [], platform: c.sharedPlatform("myapp.vercel.app") });
  assert.deepEqual(out.map(f => f.status), ["info", "info"]);
  assert.match(out[0].detail, /Vercel/);
  const checks = Object.keys(c.WEIGHTS).map(id => ({ id, status: "pass", severity: "low" }));
  checks.find(f => f.id === "spf").status = "info";
  assert.equal(c.score([{ checks }]).score, 100, "info results don't lower the score");
});
