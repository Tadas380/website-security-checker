const test = require("node:test");
const assert = require("node:assert/strict");
const zlib = require("node:zlib");
const net = require("../lib/net");
const { PDFDocument, toWinAnsi } = require("../lib/pdf");
const { buildReportPdf } = require("../lib/report-pdf");

// ---------- SSRF protection ----------
test("isPrivateIp blocks internal, loopback and cloud-metadata addresses", () => {
  for (const ip of ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd12::1", "fe80::1", "::ffff:10.0.0.1"])
    assert.equal(net.isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2a00:1450:4001::1"])
    assert.equal(net.isPrivateIp(ip), false, ip);
});

test("safeLookup refuses hostnames that resolve to private addresses", async () => {
  const lookup = net.makeSafeLookup();
  const err = await new Promise(resolve => lookup("localhost", {}, e => resolve(e)));
  assert.equal(err && err.code, "EPRIVATEADDR");
});

test("normalizeTarget accepts domains and rejects everything else", () => {
  assert.equal(net.normalizeTarget("Example.LT"), "example.lt");
  assert.equal(net.normalizeTarget("https://shop.example.lt/path?q=1"), "shop.example.lt");
  for (const bad of ["", "localhost", "127.0.0.1", "http://[::1]/", "ftp://x.lt", "x.lt:8080", "user:pw@x.lt", "not a url"])
    assert.throws(() => net.normalizeTarget(bad), undefined, bad);
});

// ---------- PDF writer ----------
test("WinAnsi encoding keeps € and – and falls back for Lithuanian letters", () => {
  assert.deepEqual(toWinAnsi("€–"), [0x80, 0x96]);
  assert.deepEqual(toWinAnsi("ąč"), [97, 99]);
});

test("wrap never produces a line wider than the box", () => {
  const doc = new PDFDocument();
  const lines = doc.wrap("A fairly long sentence that must wrap across several lines, including averyveryveryverylongwordwithoutspaces.", 120, 10);
  assert.ok(lines.length > 2);
  for (const l of lines) assert.ok(doc.widthOf(l, 10) <= 120, l);
});

test("generated PDF has a valid structure and correct cross-reference offsets", () => {
  const doc = new PDFDocument({ title: "Test – ą" });
  doc.text("Hello (world) \\ test", 50, 50);
  doc.addPage().rect(10, 10, 100, 50, { fill: "#ff0000", radius: 8 });
  const buf = doc.toBuffer();
  const s = buf.toString("latin1");
  assert.ok(s.startsWith("%PDF-1.4"));
  assert.ok(s.trimEnd().endsWith("%%EOF"));
  const startxref = Number(s.match(/startxref\n(\d+)/)[1]);
  assert.ok(s.slice(startxref).startsWith("xref"));
  const offsets = [...s.slice(startxref).matchAll(/^(\d{10}) 00000 n $/gm)].map(m => Number(m[1]));
  offsets.forEach((o, i) => assert.ok(s.slice(o).startsWith(`${i + 1} 0 obj`), `object ${i + 1}`));
  assert.match(s, /\/Count 2/);
  const stream = buf.subarray(s.indexOf("stream\n") + 7, s.indexOf("\nendstream"));
  assert.match(zlib.inflateSync(stream).toString("latin1"), /\(Hello \\\(world\\\) \\\\ test\) Tj/);
});

test("report PDF renders a full scan", () => {
  const scan = {
    host: "example.lt", scannedAt: "2026-09-29T10:00:00Z", score: 72, grade: "C", summary: { pass: 1, warn: 1, fail: 1 },
    categories: [{ id: "headers", title: "Security headers", checks: [
      { id: "csp", title: "Content Security Policy", status: "fail", severity: "medium", detail: "Missing.", fix: "Add it.", problem: "No Content Security Policy" },
      { id: "nosniff", title: "MIME sniffing blocked", status: "pass", severity: "low", detail: "OK." },
      { id: "permissions", title: "Permissions policy", status: "warn", severity: "low", detail: "Missing.", fix: "Add it.", problem: "No permissions policy" },
    ] }],
  };
  const buf = buildReportPdf(scan);
  assert.ok(buf.length > 1500);
  assert.ok(buf.toString("latin1").startsWith("%PDF-"));
});

// ---------- HTTP server ----------
test("server: security headers, consent, validation and report expiry", async () => {
  const { server } = require("../server");
  await new Promise(r => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const home = await fetch(base + "/");
    assert.equal(home.status, 200);
    for (const h of ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"])
      assert.ok(home.headers.get(h), h);

    const post = body => fetch(base + "/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    assert.equal((await post({ url: "example.lt" })).status, 400);                        // no consent
    const bad = await post({ url: "127.0.0.1", consent: true });
    assert.equal(bad.status, 400);
    assert.match((await bad.json()).error, /domain name/);

    assert.equal((await fetch(base + "/api/report/unknownid123.pdf")).status, 404);
    assert.notEqual((await fetch(base + "/..%2fserver.js")).status, 200);
    assert.equal((await fetch(base + "/.well-known/security.txt")).status, 200);
  } finally { server.close(); }
});
