// A tiny PDF writer with no dependencies.
// Supports A4 pages, Helvetica / Helvetica-Bold text with exact word wrapping,
// filled/stroked (rounded) rectangles and lines. Coordinates are top-left based
// (like the web); they are flipped to PDF's bottom-left system internally.
// Page contents are compressed with zlib (FlateDecode).

const zlib = require("zlib");
const WIDTHS = require("./font-widths");

const FONTS = { regular: { key: "F1", name: "Helvetica" }, bold: { key: "F2", name: "Helvetica-Bold" } };

// Windows-1252 code points for characters outside Latin-1.
const CP1252 = { "€": 0x80, "‚": 0x82, "„": 0x84, "…": 0x85, "‘": 0x91, "’": 0x92, "“": 0x93, "”": 0x94, "•": 0x95, "–": 0x96, "—": 0x97, "™": 0x99, "š": 0x9a, "Š": 0x8a, "ž": 0x9e, "Ž": 0x8e };

// Converts text to single-byte WinAnsi codes. Characters the standard fonts
// can't show (e.g. ą, č, ę) fall back to their base letter (a, c, e).
function toWinAnsi(str) {
  const out = [];
  for (const ch of String(str)) {
    const code = ch.codePointAt(0);
    if (code >= 32 && code <= 126) out.push(code);
    else if (CP1252[ch]) out.push(CP1252[ch]);
    else if (code >= 160 && code <= 255) out.push(code);
    else if (ch === "\t" || ch === "\n") out.push(32);
    else {
      const base = ch.normalize("NFD").replace(/[̀-ͯ]/g, "");
      out.push(base && base.codePointAt(0) < 127 ? base.codePointAt(0) : 63); // "?"
    }
  }
  return out;
}

function hexToRgb(hex) {
  const h = hex.replace("#", "");
  return [0, 2, 4].map(i => (parseInt(h.slice(i, i + 2), 16) / 255).toFixed(3)).join(" ");
}
const num = n => (Math.round(n * 100) / 100).toString();

class PDFDocument {
  constructor({ width = 595.28, height = 841.89, title = "", author = "" } = {}) {
    this.width = width; this.height = height;
    this.title = title; this.author = author;
    this.pages = [];
    this.addPage();
  }

  addPage() { this.page = []; this.pages.push(this.page); return this; }

  widthOf(text, size, font = "regular") {
    const table = WIDTHS[FONTS[font].name];
    return toWinAnsi(text).reduce((w, c) => w + (table[c - 32] || 500), 0) * size / 1000;
  }

  // Splits text into lines that fit `maxWidth`. Long words are broken if needed.
  wrap(text, maxWidth, size, font = "regular") {
    const lines = [];
    for (const para of String(text).split("\n")) {
      let line = "";
      for (const word of para.split(/\s+/).filter(Boolean)) {
        const candidate = line ? `${line} ${word}` : word;
        if (this.widthOf(candidate, size, font) <= maxWidth) { line = candidate; continue; }
        if (line) lines.push(line);
        if (this.widthOf(word, size, font) <= maxWidth) { line = word; continue; }
        let chunk = "";                              // word longer than a whole line
        for (const ch of word) {
          if (this.widthOf(chunk + ch, size, font) > maxWidth) { lines.push(chunk); chunk = ""; }
          chunk += ch;
        }
        line = chunk;
      }
      lines.push(line);
    }
    return lines;
  }

  text(str, x, y, { size = 10, font = "regular", color = "#000000", align = "left", width } = {}) {
    let tx = x;
    if (align !== "left" && width) {
      const w = this.widthOf(str, size, font);
      tx = align === "right" ? x + width - w : x + (width - w) / 2;
    }
    const bytes = toWinAnsi(str);
    let s = "";
    for (const b of bytes) {
      const c = String.fromCharCode(b);
      s += c === "(" || c === ")" || c === "\\" ? "\\" + c : c;
    }
    // y is the top of the text box; the PDF baseline sits ~0.8em below it.
    const baseline = this.height - y - size * 0.8;
    this.page.push(`BT /${FONTS[font].key} ${num(size)} Tf ${hexToRgb(color)} rg ${num(tx)} ${num(baseline)} Td (${s}) Tj ET`);
    return this;
  }

  // Writes wrapped text and returns the height it used.
  paragraph(str, x, y, width, { size = 10, font = "regular", color = "#000000", lineHeight = 1.35 } = {}) {
    const lines = this.wrap(str, width, size, font);
    lines.forEach((line, i) => this.text(line, x, y + i * size * lineHeight, { size, font, color }));
    return lines.length * size * lineHeight;
  }

  rect(x, y, w, h, { fill, stroke, lineWidth = 1, radius = 0 } = {}) {
    const ops = [];
    if (fill) ops.push(`${hexToRgb(fill)} rg`);
    if (stroke) ops.push(`${hexToRgb(stroke)} RG ${num(lineWidth)} w`);
    const X = x, Y = this.height - y - h;
    if (radius > 0) {
      const r = Math.min(radius, w / 2, h / 2), k = r * 0.5523;
      ops.push(`${num(X + r)} ${num(Y)} m ${num(X + w - r)} ${num(Y)} l`,
        `${num(X + w - r + k)} ${num(Y)} ${num(X + w)} ${num(Y + r - k)} ${num(X + w)} ${num(Y + r)} c`,
        `${num(X + w)} ${num(Y + h - r)} l ${num(X + w)} ${num(Y + h - r + k)} ${num(X + w - r + k)} ${num(Y + h)} ${num(X + w - r)} ${num(Y + h)} c`,
        `${num(X + r)} ${num(Y + h)} l ${num(X + r - k)} ${num(Y + h)} ${num(X)} ${num(Y + h - r + k)} ${num(X)} ${num(Y + h - r)} c`,
        `${num(X)} ${num(Y + r)} l ${num(X)} ${num(Y + r - k)} ${num(X + r - k)} ${num(Y)} ${num(X + r)} ${num(Y)} c h`);
    } else {
      ops.push(`${num(X)} ${num(Y)} ${num(w)} ${num(h)} re`);
    }
    ops.push(fill && stroke ? "B" : fill ? "f" : "S");
    this.page.push(ops.join(" "));
    return this;
  }

  line(x1, y1, x2, y2, { color = "#000000", lineWidth = 1 } = {}) {
    this.page.push(`${hexToRgb(color)} RG ${num(lineWidth)} w ${num(x1)} ${num(this.height - y1)} m ${num(x2)} ${num(this.height - y2)} l S`);
    return this;
  }

  // Builds the final file: header, objects, cross-reference table, trailer.
  toBuffer() {
    const objects = [];                                   // index + 1 = object number
    const add = body => { objects.push(body); return objects.length; };
    const catalog = add(null), pagesObj = add(null);
    const f1 = add(Buffer.from(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`));
    const f2 = add(Buffer.from(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`));
    const pageIds = this.pages.map(ops => {
      const data = zlib.deflateSync(Buffer.from(ops.join("\n"), "latin1"));
      const content = add(Buffer.concat([Buffer.from(`<< /Length ${data.length} /Filter /FlateDecode >>\nstream\n`), data, Buffer.from("\nendstream")]));
      return add(Buffer.from(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${num(this.width)} ${num(this.height)}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${content} 0 R >>`));
    });
    objects[catalog - 1] = Buffer.from(`<< /Type /Catalog /Pages ${pagesObj} 0 R >>`);
    objects[pagesObj - 1] = Buffer.from(`<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`);
    const d = new Date(), pad = n => String(n).padStart(2, "0");
    const date = `D:${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
    // Document info strings use UTF-16BE so any character (– ą č …) shows correctly.
    const pdfStr = s => "<FEFF" + [...String(s)].map(ch => {
      const cp = ch.codePointAt(0);
      if (cp < 0x10000) return cp.toString(16).padStart(4, "0");
      const v = cp - 0x10000;
      return ((v >> 10) + 0xd800).toString(16) + ((v & 0x3ff) + 0xdc00).toString(16);
    }).join("").toUpperCase() + ">";
    const infoId = add(Buffer.from(`<< /Title ${pdfStr(this.title)} /Author ${pdfStr(this.author)} /Producer (website-security-checker) /CreationDate (${date}) >>`, "latin1"));

    const parts = [Buffer.from("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n", "latin1")];
    let offset = parts[0].length;
    const offsets = [];
    objects.forEach((body, i) => {
      offsets.push(offset);
      const chunk = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`), body, Buffer.from("\nendobj\n")]);
      parts.push(chunk); offset += chunk.length;
    });
    const xref = [`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`, ...offsets.map(o => `${String(o).padStart(10, "0")} 00000 n \n`)].join("");
    parts.push(Buffer.from(`${xref}trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${infoId} 0 R >>\nstartxref\n${offset}\n%%EOF\n`));
    return Buffer.concat(parts);
  }
}

module.exports = { PDFDocument, toWinAnsi };
