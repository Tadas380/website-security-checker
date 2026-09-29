// Front-end for the checker. All text from the server is inserted with
// textContent (never innerHTML), so a malicious website can't inject markup
// into the results.

const $ = sel => document.querySelector(sel);
const form = $("#form"), input = $("#url"), consent = $("#consent"), go = $("#go");
const errorBox = $("#error"), progress = $("#progress"), resultsEl = $("#results"), about = $("#about");
const GRADE_COLOR = { A: "#12B76A", B: "#6CC24A", C: "#F79009", D: "#F2692E", F: "#F04438" };
const VERDICT = {
  A: "Strong setup. Only minor improvements are possible.",
  B: "Good overall, with a few gaps worth closing.",
  C: "Several common protections are missing. The fixes below will make a clear difference.",
  D: "Important protections are missing. Visitors and your email reputation are at risk.",
  F: "Serious problems were found. Fix the items below as soon as possible.",
};

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k in node) node[k] = v;
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null && c !== false) node.append(c.nodeType ? c : String(c));
  return node;
}

function showError(msg) { errorBox.textContent = msg; errorBox.hidden = !msg; }

// ---------- progress animation (the real scan runs in parallel on the server) ----------
let stepTimer;
function startProgress(host) {
  $("#progress-title").textContent = `Checking ${host}…`;
  const items = [...document.querySelectorAll("#steps li")];
  items.forEach(li => { li.className = ""; li.querySelector(".dot").textContent = ""; });
  let i = 0;
  const advance = () => {
    if (i > 0) { items[i - 1].className = "done"; items[i - 1].querySelector(".dot").textContent = "✓"; }
    if (i < items.length - 1) { items[i].className = "active"; i++; stepTimer = setTimeout(advance, 1400 + Math.random() * 900); }
    else items[i].className = "active";
  };
  progress.hidden = false;
  advance();
}
function stopProgress() { clearTimeout(stepTimer); progress.hidden = true; }

// ---------- scan ----------
async function scan(target) {
  showError("");
  if (!target.trim()) return showError("Enter a website address, e.g. yourwebsite.lt");
  if (!consent.checked) return showError("Please confirm you own the website or have permission to check it.");
  go.disabled = true; go.textContent = "Checking…";
  resultsEl.hidden = true;
  startProgress(target.replace(/^https?:\/\//, "").split("/")[0]);
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: target, consent: true }),
    });
    const data = await r.json().catch(() => ({ error: "Unexpected response from the server." }));
    if (!r.ok) throw new Error(data.error || "The check failed. Please try again.");
    render(data);
    history.replaceState(null, "", `?url=${encodeURIComponent(data.host)}`);
  } catch (e) {
    showError(e.message === "Failed to fetch" ? "Couldn't reach the checker. Check your connection and try again." : e.message);
  } finally {
    stopProgress();
    go.disabled = false; go.textContent = "Check website";
  }
}

// ---------- results ----------
function render(scan) {
  about.hidden = true;
  const when = new Date(scan.scannedAt);
  const all = scan.categories.flatMap(c => c.checks);
  const rank = { high: 0, medium: 1, low: 2 };
  const priorities = all.filter(f => f.status === "fail" || f.status === "warn")
    .sort((a, b) => (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1) || rank[a.severity] - rank[b.severity])
    .slice(0, 5);

  const riskPill = f => el("span", { class: "pill", style: `background:${f.status === "warn" ? "#F79009" : f.severity === "high" ? "#F04438" : f.severity === "medium" ? "#F2692E" : "#F79009"}` },
    f.status === "warn" ? "WARNING" : `${f.severity.toUpperCase()} RISK`);

  const parts = [
    el("div", { class: "scorecard" },
      el("div", { class: "grade", style: `background:${GRADE_COLOR[scan.grade]}`, "aria-label": `Grade ${scan.grade}` }, scan.grade),
      el("div", {},
        el("div", { class: "host" }, scan.host),
        el("div", { class: "meta" }, `Score ${scan.score}/100 · checked ${when.toLocaleString()}`),
        el("div", { class: "chips" },
          el("span", { class: "chip" }, el("b", { style: "color:#6CE9A6" }, scan.summary.pass), "passed"),
          el("span", { class: "chip" }, el("b", { style: "color:#FEC84B" }, scan.summary.warn), "warnings"),
          el("span", { class: "chip" }, el("b", { style: "color:#FDA29B" }, scan.summary.fail), "failed"))),
      el("a", { class: "dl", href: `/api/report/${scan.id}.pdf`, download: "" }, "⬇ Download PDF report")),

    el("p", { class: "verdict" }, VERDICT[scan.grade]),

    priorities.length ? el("div", { class: "card" },
      el("h2", {}, "Fix these first"),
      el("ol", { class: "prio" }, priorities.map(f => el("li", {},
        el("div", {}, el("b", {}, f.problem || f.title, riskPill(f)), el("p", {}, f.fix)))))) : null,

    scan.categories.map(cat => {
      const n = s => cat.checks.filter(f => f.status === s).length;
      const bad = n("fail") + n("warn");
      return el("details", { class: "cat", open: bad > 0 },
        el("summary", {}, cat.title, el("span", { class: "counts" }, bad ? [n("fail") && `${n("fail")} failed`, n("warn") && `${n("warn")} warning${n("warn") > 1 ? "s" : ""}`].filter(Boolean).join(" · ") : "all passed")),
        cat.checks.map(f => el("div", { class: "check" },
          el("span", { class: `status ${f.status}` }, f.status.toUpperCase()),
          el("div", {},
            el("b", {}, f.title),
            el("div", { class: "d" }, f.detail),
            (f.status === "fail" || f.status === "warn") && f.fix ? el("div", { class: "fix" }, el("b", {}, "How to fix: "), f.fix) : null))));
    }),

    el("div", { class: "again" }, el("button", { type: "button", onclick: () => { window.scrollTo({ top: 0, behavior: "smooth" }); input.focus(); input.select(); } }, "Check another website")),
  ];
  resultsEl.replaceChildren(...parts.flat().filter(Boolean));
  resultsEl.hidden = false;
  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", e => { e.preventDefault(); scan(input.value); });
document.querySelectorAll("[data-example]").forEach(b => b.addEventListener("click", () => { input.value = b.dataset.example; consent.checked = true; scan(input.value); }));

const pre = new URLSearchParams(location.search).get("url");
if (pre) input.value = pre;
