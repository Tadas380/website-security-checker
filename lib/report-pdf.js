// Lays out a scan result as a clean, owner-friendly PDF report.
const { PDFDocument } = require("./pdf");

const C = {
  ink: "#101828", sub: "#475467", faint: "#98A2B3", line: "#E4E7EC", panel: "#F5F7FA", white: "#FFFFFF",
  accent: "#3D5AFE",
  pass: "#12B76A", warn: "#F79009", fail: "#F04438", info: "#667085",
};
const GRADE_COLOR = { A: "#12B76A", B: "#6CC24A", C: "#F79009", D: "#F2692E", F: "#F04438" };
const SEV_RANK = { high: 0, medium: 1, low: 2 };
const M = 48;                    // page margin
const FOOTER = 40;               // space reserved at the bottom

function buildReportPdf(scan) {
  const doc = new PDFDocument({ title: `Security report – ${scan.host}`, author: "Website Security Checker" });
  const W = doc.width, H = doc.height, CW = W - 2 * M;
  let y = 0;

  const ensure = needed => { if (y + needed > H - FOOTER - 8) { doc.addPage(); y = M; } };

  // ---------- header band ----------
  doc.rect(0, 0, W, 132, { fill: C.ink });
  doc.rect(0, 132, W, 4, { fill: C.accent });
  doc.text("WEBSITE SECURITY REPORT", M, 34, { size: 9, font: "bold", color: "#8EA2FF" });
  const hostSize = doc.widthOf(scan.host, 24, "bold") > CW - 120 ? 17 : 24;
  doc.text(scan.host, M, 52, { size: hostSize, font: "bold", color: C.white });
  const when = new Date(scan.scannedAt);
  doc.text(`Checked ${when.toISOString().slice(0, 10)} at ${when.toISOString().slice(11, 16)} UTC  ·  passive, read-only checks`, M, 92, { size: 9, color: "#B8C2D6" });

  // grade badge
  const gx = W - M - 84;
  doc.rect(gx, 26, 84, 84, { fill: GRADE_COLOR[scan.grade] || C.info, radius: 12 });
  doc.text(scan.grade, gx, 34, { size: 46, font: "bold", color: C.white, align: "center", width: 84 });
  doc.text(`${scan.score} / 100`, gx, 88, { size: 10, font: "bold", color: C.white, align: "center", width: 84 });

  // ---------- summary tiles ----------
  y = 160;
  const tiles = [["Passed", scan.summary.pass, C.pass], ["Warnings", scan.summary.warn, C.warn], ["Failed", scan.summary.fail, C.fail]];
  const tw = (CW - 24) / 3;
  tiles.forEach(([label, n, color], i) => {
    const x = M + i * (tw + 12);
    doc.rect(x, y, tw, 58, { fill: C.panel, radius: 8 });
    doc.rect(x, y + 12, 3, 34, { fill: color });
    doc.text(String(n), x + 16, y + 10, { size: 22, font: "bold", color: C.ink });
    doc.text(label, x + 16, y + 38, { size: 9.5, color: C.sub });
  });
  y += 84;

  // ---------- what the grade means ----------
  const verdict = {
    A: "Strong setup. Only minor improvements are possible.",
    B: "Good overall, with a few gaps worth closing.",
    C: "Several common protections are missing. Fixing the priorities below will make a clear difference.",
    D: "Important protections are missing. Visitors and the business's email reputation are at risk.",
    F: "Serious problems were found. Fix the priorities below as soon as possible.",
  }[scan.grade];
  y += doc.paragraph(verdict, M, y, CW, { size: 11, color: C.ink }) + 14;

  // ---------- top priorities ----------
  const all = scan.categories.flatMap(c => c.checks);
  const priorities = all.filter(f => f.status === "fail" || f.status === "warn")
    .sort((a, b) => (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1) || SEV_RANK[a.severity] - SEV_RANK[b.severity])
    .slice(0, 5);

  sectionTitle(priorities.length ? "Fix these first" : "No problems found");
  if (!priorities.length) {
    y += doc.paragraph("Every check passed. Re-check after big website changes.", M, y, CW, { size: 10, color: C.sub }) + 10;
  }
  priorities.forEach((f, i) => {
    const fixLines = doc.wrap(f.fix, CW - 60, 9.5);
    const h = 22 + fixLines.length * 13 + 12;
    ensure(h + 6);
    doc.rect(M, y, CW, h, { fill: C.panel, radius: 8 });
    doc.rect(M + 12, y + 12, 22, 22, { fill: C.ink, radius: 11 });
    doc.text(String(i + 1), M + 12, y + 17, { size: 10, font: "bold", color: C.white, align: "center", width: 22 });
    doc.text(f.problem || f.title, M + 46, y + 12, { size: 11, font: "bold", color: C.ink });
    pill(sevLabel(f), M + 46 + doc.widthOf(f.problem || f.title, 11, "bold") + 8, y + 12, pillColor(f));
    fixLines.forEach((l, j) => doc.text(l, M + 46, y + 30 + j * 13, { size: 9.5, color: C.sub }));
    y += h + 8;
  });
  y += 10;

  // ---------- all checks by category ----------
  for (const cat of scan.categories) {
    ensure(70);
    sectionTitle(cat.title);
    for (const f of cat.checks) {
      const detailLines = doc.wrap(f.detail, CW - 78, 9.5);
      const fixLines = f.status === "pass" || f.status === "info" || !f.fix ? [] : doc.wrap(`How to fix: ${f.fix}`, CW - 78, 9);
      const h = 18 + detailLines.length * 13 + (fixLines.length ? fixLines.length * 12 + 4 : 0) + 8;
      ensure(h);
      pill(f.status.toUpperCase(), M, y + 1, C[f.status], 52);
      doc.text(f.title, M + 66, y, { size: 10.5, font: "bold", color: C.ink });
      let ty = y + 17;
      detailLines.forEach(l => { doc.text(l, M + 66, ty, { size: 9.5, color: C.sub }); ty += 13; });
      if (fixLines.length) { ty += 2; fixLines.forEach(l => { doc.text(l, M + 66, ty, { size: 9, color: C.ink }); ty += 12; }); }
      y += h;
      doc.line(M + 66, y - 4, W - M, y - 4, { color: C.line, lineWidth: 0.6 });
      y += 4;
    }
    y += 12;
  }

  // ---------- disclaimer ----------
  ensure(60);
  y += doc.paragraph("About this report: all checks are passive. They use normal page requests, a TLS handshake and public DNS records, the same information any visitor's browser can see. No attacks, logins or vulnerability exploits were attempted. A good grade does not guarantee a site is secure; it shows common protections are in place.", M, y, CW, { size: 8.5, color: C.faint });

  // ---------- footers ----------
  const total = doc.pages.length;
  doc.pages.forEach((_, i) => {
    doc.page = doc.pages[i];
    doc.line(M, H - 32, W - M, H - 32, { color: C.line, lineWidth: 0.6 });
    doc.text("Website Security Checker  ·  github.com/Tadas380/website-security-checker", M, H - 26, { size: 8, color: C.faint });
    doc.text(`Page ${i + 1} of ${total}`, M, H - 26, { size: 8, color: C.faint, align: "right", width: CW });
  });

  return doc.toBuffer();

  // helpers (hoisted)
  function sectionTitle(t) {
    doc.text(t.toUpperCase(), M, y, { size: 9.5, font: "bold", color: C.accent });
    y += 16;
    doc.line(M, y, W - M, y, { color: C.line, lineWidth: 0.8 });
    y += 12;
  }
  function pill(label, x, top, color, fixedWidth) {
    const w = fixedWidth || doc.widthOf(label, 7.5, "bold") + 12;
    doc.rect(x, top, w, 14, { fill: color, radius: 7 });
    doc.text(label, x, top + 3.5, { size: 7.5, font: "bold", color: C.white, align: "center", width: w });
  }
  function sevLabel(f) { return f.status === "warn" ? "WARNING" : `${f.severity.toUpperCase()} RISK`; }
  function pillColor(f) { return f.status === "warn" ? C.warn : f.severity === "high" ? C.fail : f.severity === "medium" ? "#F2692E" : C.warn; }
}

module.exports = { buildReportPdf };
