/* ═══════════════════════════════════════════════════════════════
   Advanced Phishing Mail Detector — app.js
   ═══════════════════════════════════════════════════════════════ */

/* ── Element refs ── */
const tabBtns           = document.querySelectorAll("[data-tab]");
const tabPanels         = document.querySelectorAll(".tab-panel");
const openAnalysisBtns  = document.querySelectorAll("[data-open-analysis]");
const form              = document.getElementById("analysis-form");
const fileInput         = document.getElementById("email-file");
const dropZone          = document.getElementById("drop-zone");
const selectedFileEl    = document.getElementById("selected-file");
const resultState       = document.getElementById("result-state");
const resultTemplate    = document.getElementById("result-template");
const resetBtn          = document.getElementById("reset-button");
const analysisModal     = document.getElementById("analysis-modal");
const closeModalBtn     = document.getElementById("close-modal");
const modalStatus       = document.getElementById("modal-status");
const analysisControls  = document.getElementById("analysis-controls");
const topUploadBtn      = document.getElementById("top-upload-btn");
const fileSwitcherBtn   = document.getElementById("file-switcher-btn");
const fileSwitcherLabel = document.getElementById("file-switcher-label");
const fileSwitcherMenu  = document.getElementById("file-switcher-menu");
const fileDeleteBtn     = document.getElementById("file-delete-btn");
const openLatestBtns    = document.querySelectorAll("[data-open-latest]");

let latestReport = null;
let currentHistoryId = null;
let switcherOpen = false;

const HISTORY_KEY = "apd-history-v1";
const HISTORY_LIMIT = 12;

/* ══════════════════════════════════════════
   TAB ROUTING
   ══════════════════════════════════════════ */
function switchTab(name) {
  tabBtns.forEach(b   => b.classList.toggle("is-active",    b.dataset.tab === name));
  tabPanels.forEach(p => p.classList.toggle("is-active",    p.id === `tab-${name}`));
  updateAnalysisControls(name);
}
tabBtns.forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab)));
openAnalysisBtns.forEach(b => b.addEventListener("click", () => {
  switchTab("analysis");
  openModal();
}));
openLatestBtns.forEach(b => b.addEventListener("click", () => {
  openLatestReport();
}));

if (topUploadBtn) {
  topUploadBtn.addEventListener("click", () => {
    switchTab("analysis");
    openModal();
  });
}

function openModal() {
  if (!analysisModal) return;
  analysisModal.classList.add("is-open");
  analysisModal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
  setModalBusy(false, "");
}

function closeModal() {
  if (!analysisModal) return;
  analysisModal.classList.remove("is-open");
  analysisModal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

function setModalBusy(isBusy, message) {
  if (modalStatus) {
    modalStatus.textContent = isBusy ? (message || "Analyzing... please wait.") : "";
    modalStatus.classList.toggle("is-active", isBusy);
  }
  if (form) {
    form.querySelectorAll("input, button").forEach(el => {
      el.disabled = isBusy;
    });
    const submitBtn = form.querySelector("button[type='submit']");
    if (submitBtn) {
      if (isBusy) {
        submitBtn.dataset.label = submitBtn.textContent;
        submitBtn.textContent = "Analyzing...";
      } else if (submitBtn.dataset.label) {
        submitBtn.textContent = submitBtn.dataset.label;
      }
    }
  }
}


if (analysisModal) {
  analysisModal.addEventListener("click", event => {
    if (event.target === analysisModal) {
      closeModal();
    }
  });
}

if (closeModalBtn) {
  closeModalBtn.addEventListener("click", closeModal);
}

if (fileSwitcherBtn) {
  fileSwitcherBtn.addEventListener("click", event => {
    event.stopPropagation();
    toggleSwitcher();
  });
}

if (fileDeleteBtn) {
  fileDeleteBtn.addEventListener("click", event => {
    event.stopPropagation();
    if (currentHistoryId) {
      deleteHistoryItem(currentHistoryId, { renderNext: true });
    }
  });
}

document.addEventListener("click", event => {
  if (!fileSwitcherMenu || !switcherOpen) return;
  if (fileSwitcherMenu.contains(event.target) || fileSwitcherBtn?.contains(event.target)) return;
  closeSwitcher();
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape" && analysisModal?.classList.contains("is-open")) {
    closeModal();
  }
  if (event.key === "Escape" && switcherOpen) {
    closeSwitcher();
  }
});

function updateAnalysisControls(activeTab) {
  if (!analysisControls) return;
  const visible = activeTab === "analysis";
  analysisControls.classList.toggle("is-visible", visible);
}

function toggleSwitcher() {
  if (!fileSwitcherMenu) return;
  const items = loadHistory();
  if (!items.length) return;
  if (switcherOpen) {
    closeSwitcher();
  } else {
    renderFileSwitcher();
    fileSwitcherMenu.classList.add("is-open");
    fileSwitcherBtn?.classList.add("is-open");
    switcherOpen = true;
  }
}

function closeSwitcher() {
  if (!fileSwitcherMenu) return;
  fileSwitcherMenu.classList.remove("is-open");
  fileSwitcherBtn?.classList.remove("is-open");
  switcherOpen = false;
}

/* ══════════════════════════════════════════
   FILE DROP / SELECT
   ══════════════════════════════════════════ */
function updateSelectedFile() {
  const f = fileInput.files[0];
  selectedFileEl.textContent = f ? `${f.name}  —  ${fmtBytes(f.size)}` : "No file selected";
}
fileInput.addEventListener("change", updateSelectedFile);

["dragenter", "dragover"].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add("is-dragover"); }));
["dragleave", "drop"].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove("is-dragover"); }));
dropZone.addEventListener("drop", e => {
  const files = e.dataTransfer.files;
  if (!files.length) return;
  fileInput.files = files;
  updateSelectedFile();
});

/* ══════════════════════════════════════════
   FORM SUBMIT
   ══════════════════════════════════════════ */
if (form) {
  form.addEventListener("submit", async e => {
  e.preventDefault();
  if (!fileInput.files.length) { renderError("Select an .eml file before running analysis."); return; }

  const fd = new FormData();
  fd.append("email_file",         fileInput.files[0]);
  fd.append("external_enrichment", document.getElementById("external-enrichment").checked ? "true" : "false");
  fd.append("resolve_redirects",   document.getElementById("resolve-redirects").checked   ? "true" : "false");

  setModalBusy(true);
  renderLoading();
  try {
    const res     = await fetch("/api/analyze", { method: "POST", body: fd, headers: { "X-Requested-With": "XMLHttpRequest" } });
    const payload = await res.json();
    if (!res.ok) throw new Error(payload.error || "Analysis failed.");
    renderResults(payload, { fromHistory: false });
    switchTab("analysis");
    closeModal();
  } catch (err) {
    latestReport = null;
    renderError(err.message);
  } finally {
    setModalBusy(false);
  }
  });
}

if (resetBtn) {
  resetBtn.addEventListener("click", () => {
    form.reset();
    latestReport = null;
    updateSelectedFile();
    renderEmpty();
    setModalBusy(false, "");
  });
}

/* ══════════════════════════════════════════
   STATE RENDERS
   ══════════════════════════════════════════ */
function renderEmpty() {
  resultState.innerHTML = "";
  const el = document.createElement("div");
  el.className = "empty-state";
  el.innerHTML = "<strong>No analysis yet</strong><span>Select a case from the top bar or run a new scan.</span>";
  resultState.appendChild(el);
}

function renderLoading() {
  resultState.innerHTML = "";
  const el = document.createElement("div");
  el.className = "loading";
  el.textContent = "Analyzing email evidence…";
  resultState.appendChild(el);
}

function renderError(msg) {
  resultState.innerHTML = "";
  const el = document.createElement("div");
  el.className = "error-box";
  el.textContent = msg;
  resultState.appendChild(el);
}

/* ══════════════════════════════════════════
   MAIN RENDER
   ══════════════════════════════════════════ */
function renderResults(payload, opts = {}) {
  const fromHistory = Boolean(opts.fromHistory);
  const historyId = opts.historyId || null;
  resultState.innerHTML = "";
  const frag = resultTemplate.content.cloneNode(true);
  resultState.appendChild(frag);

  const score    = Number(payload.score || 0);
  const severity = payload.severity || "low";
  const details  = payload.details  || {};
  const header   = details.header_findings || {};
  const options  = payload.options  || {};

  // Store full payload for export (includes everything)
  latestReport = payload.report || payload || null;

  /* ── Verdict banner ── */
  const bannerClass = { low: "banner-safe", medium: "banner-cautious", high: "banner-unsafe" }[severity] || "banner-safe";
  const bannerIcon  = { SAFE: "OK", CAUTIOUS: "!", UNSAFE: "!" }[payload.verdict] || "AP";
  document.getElementById("verdict-banner").classList.add(bannerClass);
  document.getElementById("banner-icon").textContent       = bannerIcon;
  document.getElementById("banner-verdict-text").textContent = payload.verdict;
  const bannerFile = document.getElementById("banner-file");
  bannerFile.textContent = `${payload.file?.name || "Unknown file"}  -  ${fmtBytes(payload.file?.size_bytes)}`;
  bannerFile.title = bannerFile.textContent;
  document.getElementById("score-big").textContent = score;

  const pillsEl = document.getElementById("signal-pills");
  const sc = payload.signal_counts || {};
  if (sc.critical) pillsEl.appendChild(pill(`${sc.critical} critical`, "crit"));
  if (sc.warning)  pillsEl.appendChild(pill(`${sc.warning} warnings`,  "warn"));
  if (sc.positive) pillsEl.appendChild(pill(`${sc.positive} passed`,   "ok"));

  /* ── Risk meter ── */
  const fillClass = { low: "fill-low", medium: "fill-medium", high: "fill-high" }[severity] || "fill-low";
  document.getElementById("risk-score-label").textContent = `Score: ${score} / 10`;
  const bar = document.getElementById("risk-bar");
  bar.classList.add(fillClass);
  setTimeout(() => { bar.style.width = `${Math.min(Math.max(score, 0), 10) * 10}%`; }, 80);

  /* ── Export button ── */
  document.getElementById("download-report").addEventListener("click", downloadReport);

  /* ── Sections ── */
  renderFindings(payload.feedback || []);
  renderAuth(header, details);
  renderSenderKV(header, details, options);
  renderReceivedPath(header["Received Path"] || []);
  renderSpoofFindings(details.spoof_findings || {});
  renderContentFindings(details.content_findings || {});
  renderUrlTable(details.url_results || []);
  renderAttachmentTable(details.attachment_results || []);
  renderIOCs(details.observables || []);
  renderVTSummary(details.virustotal || null, options);
  renderUrlscanDetails(details);
  renderUrlscanSearch(details);

  if (!fromHistory) {
    const item = addHistoryItem(payload);
    if (item) currentHistoryId = item.id;
  } else if (historyId) {
    currentHistoryId = historyId;
  }
  renderFileSwitcher();
}

/* ══════════════════════════════════════════
   HISTORY
   ══════════════════════════════════════════ */
function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    return [];
  }
}

function saveHistory(items) {
  try {
    const json = JSON.stringify(items);
    // Guard against localStorage quota exceeded (5-10MB typical)
    if (json.length > 4 * 1024 * 1024) {
      // If payload too large, drop oldest items until it fits
      while (items.length > 1 && JSON.stringify(items).length > 4 * 1024 * 1024) {
        items.pop();
      }
    }
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
  } catch (err) {
    // Ignore storage errors (private mode or quota exceeded).
    console.warn("Could not save history:", err.message);
  }
}

function addHistoryItem(payload) {
  const report = payload.report || {};
  const timestamp = report.analysis_time_utc ? Date.parse(report.analysis_time_utc) : Date.now();
  const item = {
    id: `h-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    fileName: payload.file?.name || report.file || "Unknown file",
    verdict: payload.verdict || "UNKNOWN",
    score: Number(payload.score || 0),
    severity: payload.severity || "low",
    time: Number.isFinite(timestamp) ? timestamp : Date.now(),
    payload,
  };

  const items = loadHistory();
  items.unshift(item);
  saveHistory(items.slice(0, HISTORY_LIMIT));
  renderFileSwitcher();
  return item;
}

function renderFileSwitcher() {
  if (!fileSwitcherBtn || !fileSwitcherMenu || !fileDeleteBtn || !fileSwitcherLabel) return;
  const items = loadHistory();
  fileSwitcherMenu.innerHTML = "";

  if (!items.length) {
    fileSwitcherLabel.textContent = "No reports yet";
    fileSwitcherBtn.classList.add("is-empty");
    fileDeleteBtn.disabled = true;
    return;
  }

  const current = items.find(item => item.id === currentHistoryId) || items[0];
  currentHistoryId = current.id;
  fileSwitcherLabel.textContent = current.fileName;
  fileSwitcherBtn.classList.remove("is-empty");
  fileDeleteBtn.disabled = false;

  items.forEach(item => {
    const row = document.createElement("div");
    row.className = "switcher-item";

    const main = document.createElement("div");
    main.className = "switcher-main";
    const name = document.createElement("div");
    name.className = "switcher-name";
    name.textContent = item.fileName;
    const meta = document.createElement("div");
    meta.className = "switcher-meta";
    meta.textContent = `${item.verdict} · score ${item.score} · ${formatTime(item.time)}`;
    main.append(name, meta);

    const actions = document.createElement("div");
    actions.className = "switcher-actions";
    const selectBtn = document.createElement("button");
    selectBtn.className = "switcher-btn select";
    selectBtn.type = "button";
    selectBtn.textContent = "View";
    selectBtn.addEventListener("click", () => {
      renderResults(item.payload, { fromHistory: true, historyId: item.id });
      switchTab("analysis");
      closeSwitcher();
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "switcher-btn delete";
    deleteBtn.type = "button";
    deleteBtn.setAttribute("aria-label", `Delete ${item.fileName}`);
    deleteBtn.innerHTML = `
      <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
        <path d="M4 7h16" />
        <path d="M10 11v6" />
        <path d="M14 11v6" />
        <path d="M6 7l1 14h10l1-14" />
        <path d="M9 7V4h6v3" />
      </svg>
    `;
    deleteBtn.addEventListener("click", event => {
      event.stopPropagation();
      deleteHistoryItem(item.id, { renderNext: true });
    });

    actions.append(selectBtn, deleteBtn);
    row.append(main, actions);
    fileSwitcherMenu.appendChild(row);
  });
}

function deleteHistoryItem(id, opts = {}) {
  const items = loadHistory().filter(item => item.id !== id);
  saveHistory(items);

  if (currentHistoryId === id) {
    currentHistoryId = items.length ? items[0].id : null;
  }

  renderFileSwitcher();

  if (opts.renderNext) {
    if (items.length) {
      renderResults(items[0].payload, { fromHistory: true, historyId: items[0].id });
      switchTab("analysis");
    } else {
      renderEmpty();
    }
  }
}

function openLatestReport() {
  const items = loadHistory();
  if (!items.length) {
    switchTab("analysis");
    openModal();
    return;
  }
  renderResults(items[0].payload, { fromHistory: true, historyId: items[0].id });
  switchTab("analysis");
}

/* ══════════════════════════════════════════
   FINDINGS — structured dict format
   ══════════════════════════════════════════ */
function renderFindings(items) {
  const list = document.getElementById("feedback-list");
  list.innerHTML = "";
  if (!items.length) { list.appendChild(emptyMsg("No findings returned.")); return; }
  const seen = new Set();
  items.forEach(item => {
    const level = item.level || "warning";
    const title = item.title || "Unknown";
    const msg   = item.message || "";
    const key = `${level}|${title}|${(item.detail || "").slice(0, 80)}`;
    if (seen.has(key)) return;
    seen.add(key);

    const row = document.createElement("div");
    row.className = `finding-row ${level === "critical" ? "crit" : level === "positive" ? "pos" : "warn"}`;

    const titleEl = document.createElement("div");
    titleEl.className = "finding-title";
    const badge = document.createElement("span");
    badge.className = "finding-badge";
    badge.textContent = level === "critical" ? "!!" : level === "positive" ? "OK" : "i";
    const name = document.createElement("span");
    name.textContent = title;
    titleEl.append(badge, name);

    const evidence = document.createElement("div");
    evidence.className = "finding-evidence";
    evidence.textContent = msg;

    const extra = document.createElement("div");
    extra.className = "finding-extra";
    extra.textContent = item.detail || "—";

    row.append(titleEl, evidence, extra);
    list.appendChild(row);
  });
}

/* ══════════════════════════════════════════
   AUTHENTICATION GRID
   ══════════════════════════════════════════ */
function renderAuth(header, details) {
  const grid = document.getElementById("auth-grid");
  grid.innerHTML = "";

  const authItems = [
    {
      proto:  "SPF",
      result: header["SPF Result"] || "Not checked",
      align:  header["SPF Aligned"] !== undefined
        ? `Aligned: ${header["SPF Aligned"] ? "Yes" : "No"}`
        : (header["SPF MailFrom Domains"] ? `Domains: ${(header["SPF MailFrom Domains"] || []).join(", ")}` : ""),
    },
    {
      proto:  "DKIM",
      result: header["DKIM Result"] || "Not checked",
      align:  header["DKIM Aligned"] !== undefined
        ? `Aligned: ${header["DKIM Aligned"] ? "Yes" : "No"}`
        : (header["DKIM Domains"] ? `Domains: ${(header["DKIM Domains"] || []).join(", ")}` : ""),
    },
    {
      proto:  "DMARC",
      result: header["DMARC Result"] || "Not checked",
      align:  "",
    },
  ];

  authItems.forEach(({ proto, result, align }) => {
    const resultLower = result.toLowerCase();
    const state = resultLower.includes("pass") ? "auth-pass"
                : resultLower.includes("fail") ? "auth-fail"
                : "auth-none";
    const cell = document.createElement("div");
    cell.className = `auth-cell ${state}`;
    cell.innerHTML = `
      <div class="auth-proto">${proto}</div>
      <div class="auth-result">${escapeHtml(result)}</div>
      ${align ? `<div class="auth-align">${escapeHtml(align)}</div>` : ""}
    `;
    grid.appendChild(cell);
  });
}

/* ══════════════════════════════════════════
   SENDER KV TABLE
   ══════════════════════════════════════════ */
function renderSenderKV(header, details, options) {
  const table = document.getElementById("sender-table");
  table.innerHTML = "";

  const fromAddress = header["From Address"];
  const fromBox = header["From"] || {};
  const domainAge = details.domain_age_days;
  const senderDomain = fromAddress && fromAddress.includes("@") ? fromAddress.split("@").pop() : "";
  const ageDisplay = domainAge != null
    ? `${Number(domainAge).toLocaleString()} days${senderDomain ? ` (${senderDomain})` : ""}`
    : (options.external_enrichment === false
      ? "Not checked (external enrichment off)"
      : (options.whois_available === false
        ? "Not available (whois not installed)"
        : "Not available"));

  const senderIps = Array.isArray(header["Sender IPs"]) && header["Sender IPs"].length
    ? header["Sender IPs"].join(", ")
    : "None";

  const rows = [];
  pushRow(rows, "From", fromAddress);
  pushRow(rows, "Display Name", fromBox.display_name);
  pushRow(rows, "Reply-To", header["Reply-To Address"]);
  pushRow(rows, "Return-Path", header["Return-Path Address"]);
  pushRow(rows, "Subject", header["Subject"]);
  pushRow(rows, "Sender IPs", senderIps);
  pushRow(rows, "Sender Domain Age", ageDisplay, true);
  pushRow(rows, "SPF MailFrom Domain", (header["SPF MailFrom Domains"] || []).join(", "));
  pushRow(rows, "DKIM Signing Domain", (header["DKIM Domains"] || []).join(", "));

  if (!rows.length) {
    table.appendChild(emptyMsg("No sender identity fields available."));
    return;
  }

  rows.forEach(({ key, val }) => {
    const row = document.createElement("div");
    row.className = "kv-row";
    const keyEl = document.createElement("span");
    keyEl.className = "kv-key";
    keyEl.textContent = key;
    const valEl = document.createElement("span");
    valEl.className = "kv-val";
    if (key === "Reply-To" && header["From Address"] && val && val !== header["From Address"]) {
      valEl.classList.add("kv-warn");
    }
    valEl.textContent = val;
    row.append(keyEl, valEl);
    table.appendChild(row);
  });
}

/* ══════════════════════════════════════════
   RECEIVED PATH TIMELINE
   ══════════════════════════════════════════ */
function renderReceivedPath(hops) {
  const container = document.getElementById("received-path");
  container.innerHTML = "";
  if (!hops.length) { container.appendChild(emptyMsg("No received path data.")); return; }

  hops.forEach(hop => {
    const ips = (hop.public_ips?.length ? hop.public_ips : hop.ips || []);
    const item = document.createElement("div");
    item.className = "timeline-item";
    const hopNum = document.createElement("div");
    hopNum.className = "hop-num";
    hopNum.textContent = hop.hop || "?";

    const content = document.createElement("div");
    const fromEl = document.createElement("div");
    fromEl.className = "hop-from";
    fromEl.textContent = `from ${hop.from || "unknown"}`;

    const meta = document.createElement("div");
    meta.className = "hop-meta";
    const byEl = document.createElement("span");
    byEl.textContent = `by ${hop.by || "unknown"}`;
    meta.appendChild(byEl);

    if (ips.length) {
      const sep = document.createElement("span");
      sep.textContent = "·";
      const ipWrap = document.createElement("span");
      ipWrap.className = "hop-meta-ips";
      const label = document.createElement("span");
      label.textContent = "IPs:";
      ipWrap.appendChild(label);
      ips.forEach(ip => {
        const chip = document.createElement("span");
        chip.className = "hop-ip";
        chip.textContent = ip;
        ipWrap.appendChild(chip);
      });
      meta.append(sep, ipWrap);
    }

    content.append(fromEl, meta);
    item.append(hopNum, content);
    container.appendChild(item);
  });
}

/* ══════════════════════════════════════════
   SPOOFING FINDINGS
   ══════════════════════════════════════════ */
function renderSpoofFindings(findings) {
  const list = document.getElementById("spoof-list");
  list.innerHTML = "";
  if (!findings || typeof findings !== "object") {
    list.appendChild(emptyMsg("No spoofing signals detected."));
    return;
  }

  const rows = [];
  if (findings.registered_domain) {
    rows.push({ label: "Registered domain", value: findings.registered_domain });
  }
  if (findings.unicode_normalized) {
    rows.push({ label: "Unicode normalized", value: findings.unicode_normalized });
  }
  if (findings.punycode_version) {
    rows.push({ label: "Punycode form", value: findings.punycode_version, state: "warn" });
  }
  if (typeof findings.is_homograph_attack === "boolean") {
    rows.push({
      label: "Homograph detected",
      value: findings.is_homograph_attack ? "Yes" : "No",
      state: findings.is_homograph_attack ? "bad" : "good",
    });
  }

  if (!rows.length) {
    list.appendChild(emptyMsg("No spoofing signals detected."));
    return;
  }

  rows.forEach(row => list.appendChild(infoRow(row)));
}

/* ══════════════════════════════════════════
   CONTENT FINDINGS
   ══════════════════════════════════════════ */
function renderContentFindings(findings) {
  const container = document.getElementById("content-findings");
  container.innerHTML = "";
  if (!findings || typeof findings !== "object") {
    container.appendChild(emptyMsg("No content indicators found."));
    return;
  }

  const scriptCount = Number(findings.script_count || 0);
  const formCount = Number(findings.form_count || 0);
  const passwordInputs = Number(findings.password_inputs || 0);
  const iframeSources = Array.isArray(findings.iframe_sources) ? findings.iframe_sources : [];
  const metaRefresh = Array.isArray(findings.meta_refresh_urls) ? findings.meta_refresh_urls : [];
  const hiddenCount = Number(findings.hidden_element_count || 0);
  const hiddenSamples = Array.isArray(findings.hidden_element_samples)
    ? findings.hidden_element_samples
    : [];
  const jsPresent = Boolean(findings.javascript_present);

  const rows = [
    {
      label: "JavaScript present",
      value: jsPresent ? "Yes" : "No",
      state: jsPresent ? "warn" : "good",
    },
    {
      label: "Scripts",
      value: String(scriptCount),
      state: scriptCount > 0 ? "warn" : "good",
    },
    {
      label: "Forms",
      value: String(formCount),
      detail: `Password inputs: ${passwordInputs}`,
      state: formCount > 0 && passwordInputs > 0 ? "warn" : "good",
    },
    {
      label: "Iframes",
      value: String(iframeSources.length),
      detail: iframeSources.length ? summarizeList(iframeSources, 2) : "None detected",
      state: iframeSources.length ? "warn" : "good",
    },
    {
      label: "Meta refresh URLs",
      value: String(metaRefresh.length),
      detail: metaRefresh.length ? summarizeList(metaRefresh, 2) : "None detected",
      state: metaRefresh.length ? "warn" : "good",
    },
    {
      label: "Hidden elements",
      value: String(hiddenCount),
      detail: hiddenCount > 0
        ? (hiddenSamples.length
          ? `Samples: ${summarizePlainList(hiddenSamples, 2)}`
          : "Hidden elements detected (details unavailable)")
        : "None detected",
      state: hiddenCount > 0 ? "warn" : "good",
    },
  ];

  rows.forEach(row => container.appendChild(infoRow(row)));
}

/* ══════════════════════════════════════════
   URL TABLE
   ══════════════════════════════════════════ */
function renderUrlTable(urls) {
  const container = document.getElementById("url-table");
  container.innerHTML = "";
  const displayUrls = mergeUrlRecordsForDisplay(urls);
  if (!displayUrls.length) { container.appendChild(emptyMsg("No URLs detected.")); return; }

  const table = mkTable(["Defanged URL", "Host", "Source", "Features / Indicators", "VirusTotal", "urlscan.io"]);
  table.classList.add("url-table");
  const tbody = table.querySelector("tbody");

  displayUrls.forEach(u => {
    const vt = extractVT(u);
    const us = extractUrlscan(u);
    const row = document.createElement("tr");
    row.append(
      tdMono(u.defanged || defangText(u.normalized_url) || "—"),
      tdMono(u.host || "—"),
      td(formatSourceList(u.source)),
      tdTags(u.features || []),
      tdVT(vt),
      tdUrlscan(us),
    );
    tbody.appendChild(row);
  });
  container.appendChild(table);
}

/* ══════════════════════════════════════════
   ATTACHMENT TABLE
   ══════════════════════════════════════════ */
function renderAttachmentTable(attachments) {
  const container = document.getElementById("attachment-table");
  container.innerHTML = "";
  if (!attachments.length) { container.appendChild(emptyMsg("No attachments found.")); return; }

  const table = mkTable(["Filename", "Detected Type", "Size", "SHA-256", "Indicators", "VirusTotal"]);
  table.classList.add("attachment-table");
  const tbody = table.querySelector("tbody");

  attachments.forEach(a => {
    const vt = extractVT(a);
    const row = document.createElement("tr");

    const indicatorCell = document.createElement("td");
    const indicators = Array.isArray(a.indicators) ? a.indicators : [];
    if (indicators.length) {
      const list = document.createElement("div");
      list.className = "tag-list";
      indicators.forEach(indicator => {
        list.appendChild(tagEl(indicator));
      });
      indicatorCell.appendChild(list);
    } else {
      indicatorCell.textContent = "None detected";
    }

    const embeddedUrls = dedupeUrlValues(Array.isArray(a.embedded_urls) ? a.embedded_urls : []);
    if (embeddedUrls.length) {
      const note = document.createElement("div");
      note.className = "cell-note";
      note.textContent = `Embedded URLs: ${summarizeList(embeddedUrls, 2)}`;
      indicatorCell.appendChild(note);
    }

    row.append(
      tdFileName(a.filename || "—"),
      td(a.detected_type || a.content_type || "—"),
      td(fmtBytes(a.size_bytes || 0)),
      tdHash(a.hashes?.sha256 || a.hashes?.md5 || a.sha256 || a.md5 || "—"),
      indicatorCell,
      tdVT(vt),
    );
    tbody.appendChild(row);
  });
  container.appendChild(table);
}

/* ══════════════════════════════════════════
   IOC GROUPS
   ══════════════════════════════════════════ */
const IOC_TYPE_CLASS = {
  email:  "t-email",
  domain: "t-domain",
  ip:     "t-ip",
  url:    "t-url",
  sha256: "t-sha256",
};

function renderIOCs(observables) {
  const container = document.getElementById("ioc-list");
  container.innerHTML = "";
  const displayObservables = mergeObservablesForDisplay(observables);
  if (!displayObservables.length) { container.appendChild(emptyMsg("No observables extracted.")); return; }

  const grouped = {};
  displayObservables.forEach(obs => {
    const key = (obs.type || "other").toLowerCase();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(obs);
  });

  const ORDER = ["email", "domain", "ip", "url", "sha256"];
  const keys  = [...ORDER.filter(k => grouped[k]), ...Object.keys(grouped).filter(k => !ORDER.includes(k))];

  keys.forEach(type => {
    const items = grouped[type];
    const block = document.createElement("div");
    block.className = "ioc-type-block";

    const header = document.createElement("div");
    header.className = "ioc-type-header";
    const label = document.createElement("span");
    label.className = `ioc-type-label ${IOC_TYPE_CLASS[type] || "t-other"}`;
    label.textContent = type.toUpperCase();
    const count = document.createElement("span");
    count.className = "ioc-count";
    count.textContent = `${items.length} ${items.length === 1 ? "entry" : "entries"}`;
    header.append(label, count);

    const entries = document.createElement("div");
    entries.className = "ioc-entries";

    items.slice(0, 50).forEach(obs => {
      const vt = extractVT(obs);
      const entry = document.createElement("div");
      entry.className = "ioc-entry";

      const left = document.createElement("div");
      const valEl = document.createElement("div");
      valEl.className = "ioc-value";
      valEl.textContent = obs.defanged || obs.value || "—";

      const srcEl = document.createElement("div");
      srcEl.className = "ioc-source";
      const sources = obs.source || (Array.isArray(obs.sources) ? obs.sources.join(", ") : "");
      srcEl.textContent = sources ? `Source: ${formatSourceList(sources)}` : "";

      left.append(valEl, srcEl);

      const meta = document.createElement("div");
      meta.className = "ioc-meta";
      if (vt.available) meta.appendChild(vtBadge(vt));

      entry.append(left, meta);
      entries.appendChild(entry);
    });

    if (items.length > 50) {
      const more = document.createElement("div");
      more.style.cssText = "font-size:11px;color:var(--muted);padding:4px 0;";
      more.textContent = `… and ${items.length - 50} more`;
      entries.appendChild(more);
    }

    block.append(header, entries);
    container.appendChild(block);
  });
}

/* ══════════════════════════════════════════
   VIRUSTOTAL SUMMARY
   ══════════════════════════════════════════ */
function renderVTSummary(vt, options) {
  const titleEl = document.getElementById("vt-title");
  const container = document.getElementById("vt-summary");
  if (!container) return;
  container.innerHTML = "";

  if (!options.external_enrichment) {
    if (titleEl) titleEl.textContent = "VirusTotal Summary (disabled)";
    const note = document.createElement("div");
    note.className = "vt-note";
    note.textContent = "Enable external enrichment to scan domains, IPs, URLs, and file hashes.";
    container.appendChild(note);
    return;
  }

  if (!options.virustotal_available) {
    if (titleEl) titleEl.textContent = "VirusTotal Summary (key missing)";
    const note = document.createElement("div");
    note.className = "vt-note";
    note.textContent = "Add a VirusTotal API key to enable enrichment results.";
    container.appendChild(note);
    return;
  }

  if (!vt) {
    if (titleEl) titleEl.textContent = "VirusTotal Summary";
    const note = document.createElement("div");
    note.className = "vt-note";
    note.textContent = "No VirusTotal summary returned for this analysis.";
    container.appendChild(note);
    return;
  }

  const stats = typeof vt === "object" ? vt : {};

  if (typeof stats.scanned === "number") {
    const scanned = document.createElement("div");
    scanned.className = "vt-stat";
    scanned.innerHTML = `<div class="vt-num">${stats.scanned}</div><div class="vt-lbl">Items scanned</div>`;
    container.appendChild(scanned);

    if (stats.skipped_reason) {
      const note = document.createElement("div");
      note.className = "vt-note";
      note.textContent = `Skipped reason: ${formatVtReason("skipped", stats.skipped_reason)}`;
      container.appendChild(note);
    }
    return;
  }

  // Show per-object-type breakdowns when available
  if (stats.domain_count !== undefined || stats.ip_count !== undefined || stats.url_count !== undefined || stats.file_count !== undefined) {
    const statItems = [
      { num: stats.domain_count ?? "—", lbl: "Domains scanned" },
      { num: stats.ip_count ?? "—", lbl: "IPs scanned" },
      { num: stats.url_count ?? "—", lbl: "URLs scanned" },
      { num: stats.file_count ?? "—", lbl: "Files scanned" },
    ];
    statItems.forEach(({ num, lbl }) => {
      const cell = document.createElement("div");
      cell.className = "vt-stat";
      const numEl = document.createElement("div");
      numEl.className = "vt-num";
      numEl.textContent = String(num);
      const lblEl = document.createElement("div");
      lblEl.className = "vt-lbl";
      lblEl.textContent = lbl;
      cell.append(numEl, lblEl);
      container.appendChild(cell);
    });
  }
}

/* ══════════════════════════════════════════
   HELPERS
   ══════════════════════════════════════════ */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function cleanDisplayText(value) {
  return String(value || "").replace(/(?:hxxps?|https?):\/\/[^\s,]+/gi, match => cleanDisplayUrl(match));
}

function cleanDisplayUrl(value) {
  let url = String(value || "").trim();
  const pairs = { ")": "(", "]": "[", "}": "{" };
  while (url) {
    const last = url.slice(-1);
    if (".,;:".includes(last)) {
      url = url.slice(0, -1);
      continue;
    }
    if (pairs[last] && countChar(url, last) > countChar(url, pairs[last])) {
      url = url.slice(0, -1);
      continue;
    }
    break;
  }
  return url;
}

function countChar(value, char) {
  return [...String(value || "")].filter(item => item === char).length;
}

function canonicalUrlKey(value) {
  return cleanDisplayUrl(value)
    .replace(/^hxxps?:\/\//i, "https://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[:\.\]/g, ":")
    .replace(/^meow:\/\//i, "https://")
    .toLowerCase();
}

function hostFromDisplayUrl(value) {
  try {
    const canonical = canonicalUrlKey(value);
    return canonical ? new URL(canonical).hostname : "";
  } catch (err) {
    return "";
  }
}

function dedupeUrlValues(values) {
  const seen = new Set();
  const output = [];
  (values || []).forEach(value => {
    const cleaned = cleanDisplayUrl(value);
    const key = canonicalUrlKey(cleaned);
    if (!cleaned || seen.has(key)) return;
    seen.add(key);
    output.push(cleaned);
  });
  return output;
}

function mergeUrlRecordsForDisplay(urls) {
  const merged = new Map();
  (urls || []).forEach(record => {
    const displayUrl = cleanDisplayUrl(record.defanged || defangText(record.normalized_url || record.url));
    const normalizedUrl = cleanDisplayUrl(record.normalized_url || record.url || displayUrl);
    const key = canonicalUrlKey(normalizedUrl || displayUrl);
    if (!key) return;

    const next = {
      ...record,
      defanged: displayUrl || defangText(normalizedUrl),
      normalized_url: normalizedUrl,
      host: record.host || hostFromDisplayUrl(normalizedUrl || displayUrl),
      features: Array.isArray(record.features) ? record.features : [],
    };

    if (!merged.has(key)) {
      merged.set(key, next);
      return;
    }

    const current = merged.get(key);
    current.source = mergeSourceStrings(current.source, next.source);
    current.features = mergeTextArrays(current.features, next.features);
    if (vtRank(next) > vtRank(current)) current.vt = next.vt;
    if (!current.host && next.host) current.host = next.host;
  });
  return [...merged.values()];
}

function mergeObservablesForDisplay(observables) {
  const merged = new Map();
  (observables || []).forEach(observable => {
    const type = (observable.type || "other").toLowerCase();
    const next = { ...observable };
    const rawSources = Array.isArray(next.sources)
      ? next.sources
      : String(next.source || "").split(",").map(source => source.trim()).filter(Boolean);
    next.sources = rawSources;
    next.source = rawSources.join(",");

    let keyValue = String(next.value || next.defanged || "");
    if (type === "url") {
      const displayUrl = cleanDisplayUrl(next.defanged || defangText(next.value));
      const normalizedUrl = cleanDisplayUrl(next.value || displayUrl);
      next.defanged = displayUrl || defangText(normalizedUrl);
      next.value = normalizedUrl || displayUrl;
      keyValue = canonicalUrlKey(next.value || next.defanged);
    }

    const key = `${type}:${keyValue.toLowerCase()}`;
    if (!keyValue) return;
    if (!merged.has(key)) {
      merged.set(key, next);
      return;
    }

    const current = merged.get(key);
    current.sources = mergeTextArrays(current.sources, next.sources);
    current.source = mergeSourceStrings(current.source, next.source);
    if (vtRank(next) > vtRank(current)) current.vt = next.vt;
  });
  return [...merged.values()];
}

function mergeTextArrays(left, right) {
  const seen = new Set();
  const output = [];
  [...(left || []), ...(right || [])].forEach(value => {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) return;
    seen.add(text);
    output.push(text);
  });
  return output;
}

function mergeSourceStrings(left, right) {
  return mergeTextArrays(
    String(left || "").split(",").map(source => source.trim()).filter(Boolean),
    String(right || "").split(",").map(source => source.trim()).filter(Boolean),
  ).join(",");
}

function vtRank(item) {
  const vt = extractVT(item);
  if (!vt.available) return -1;
  if (Number(vt.flagged || 0) > 0) return 1000 + Number(vt.flagged || 0);
  if (vt.flagged === 0) return 10;
  return vt.label ? 1 : 0;
}

function infoRow({ label, value, detail, state }) {
  const row = document.createElement("div");
  row.className = "info-row";

  const labelEl = document.createElement("div");
  labelEl.className = "info-label";
  labelEl.textContent = label;

  const valueWrap = document.createElement("div");
  const valueEl = document.createElement("div");
  valueEl.className = `info-value ${state || ""}`.trim();
  valueEl.textContent = value !== undefined && value !== null && String(value).trim()
    ? String(value)
    : "Not available";
  valueWrap.appendChild(valueEl);

  if (detail) {
    const detailEl = document.createElement("div");
    detailEl.className = "info-detail";
    detailEl.textContent = detail;
    valueWrap.appendChild(detailEl);
  }

  row.append(labelEl, valueWrap);
  return row;
}

function defangText(value) {
  if (!value) return "";
  const cleaned = cleanDisplayUrl(value);
  // Defang scheme and domain dots only, preserve path dots
  const schemeMatch = cleaned.match(/^(https?):\/\/([^\/]+)(.*)/i);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase() === "https" ? "hxxps" : "hxxp";
    const domain = schemeMatch[2].replace(/\./g, "[.]");
    const rest = schemeMatch[3] || "";
    return `${scheme}://${domain}${rest}`;
  }
  return cleaned.replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:").replace(/\./g, "[.]");
}

function summarizeList(values, limit) {
  const items = (values || []).filter(Boolean);
  if (!items.length) return "None";
  const uniqueItems = dedupeUrlValues(items);
  const shown = uniqueItems.slice(0, limit).map(defangText);
  const extra = uniqueItems.length > limit ? ` +${uniqueItems.length - limit} more` : "";
  return `${shown.join(", ")}${extra}`;
}

function summarizePlainList(values, limit) {
  const items = (values || []).filter(Boolean);
  if (!items.length) return "None";
  const shown = items.slice(0, limit);
  const extra = items.length > limit ? ` +${items.length - limit} more` : "";
  return `${shown.join(", ")}${extra}`;
}

function tagClassForText(text) {
  const value = String(text || "").toLowerCase();
  if (!value) return "";
  if (value.includes("malicious") || value.includes("flagged") || value.includes("macro")) {
    return "tag-bad";
  }
  if (
    value.includes("suspicious") ||
    value.includes("subdomain") ||
    value.includes("punycode") ||
    value.includes("redirect") ||
    value.includes("embedded") ||
    value.includes("external")
  ) {
    return "tag-warn";
  }
  return "tag-info";
}

function formatSourceLabel(source) {
  if (!source) return "Unknown";
  const label = source.trim();
  const redirectSuffix = label.endsWith(".redirect_final") ? " (redirect target)" : "";
  const baseLabel = label.replace(/\.redirect_final$/i, "");

  const exactLabels = {
    "body.text": "Text body",
    "body.html.text": "HTML text",
    "body.html.href": "HTML link",
    "body.html.img.src": "Image source",
    "body.html.iframe.src": "Iframe source",
    "body.html.script.src": "Script source",
    "body.html.form.action": "Form action",
    "body.html.meta": "Meta refresh",
    "auth.smtp.mailfrom": "SPF MailFrom domain",
    "auth.header.from": "Header From domain",
    "auth.header.d": "DKIM signing domain",
    "auth_or_received.sender_ip": "Sender IP",
  };
  if (exactLabels[baseLabel]) return `${exactLabels[baseLabel]}${redirectSuffix}`;

  const headerMatch = baseLabel.match(/^header\.([^.]+)(?:\.display_name)?$/i);
  if (headerMatch) {
    const headerName = headerMatch[1].replace(/-/g, " ");
    return baseLabel.toLowerCase().endsWith(".display_name")
      ? `Display name in ${headerName}`
      : `Header: ${headerName}`;
  }

  const receivedMatch = baseLabel.match(/^received\.hop_(\d+)$/i);
  if (receivedMatch) return `Received hop ${receivedMatch[1]}`;

  const attachmentUrlMatch = baseLabel.match(/^attachment\.(.+?)\.embedded_url$/i);
  if (attachmentUrlMatch) return `Attachment URL: ${attachmentUrlMatch[1]}${redirectSuffix}`;

  const attachmentMatch = baseLabel.match(/^attachment\.(.+)$/i);
  if (attachmentMatch) return `Attachment file: ${attachmentMatch[1]}${redirectSuffix}`;

  const imageMatch = baseLabel.match(/^image\.(.+?)\.qr_or_ocr$/i);
  if (imageMatch) return `Image QR/OCR: ${imageMatch[1]}${redirectSuffix}`;

  return label;
}

function formatSourceList(source) {
  const parts = String(source || "")
    .split(",")
    .map(part => part.trim())
    .filter(Boolean);
  const seen = new Set();
  const labels = [];
  parts.forEach(part => {
    const label = formatSourceLabel(part);
    if (!seen.has(label)) {
      seen.add(label);
      labels.push(label);
    }
  });
  return labels.join(", ") || "Unknown";
}

function pushRow(rows, key, val, force = false) {
  const hasValue = val !== undefined && val !== null && String(val).trim() !== "";
  if (!force && !hasValue) return;
  rows.push({ key, val: String(val).trim() || "Not available" });
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch (err) {
    return "Unknown time";
  }
}

function formatVtReason(status, reason) {
  const text = reason ? String(reason) : "";
  if (status === "skipped") {
    if (text.includes("VT_API_KEY")) return "Not scanned (VT key missing)";
    if (text.includes("disabled")) return "Not scanned (external enrichment off)";
    if (text.includes("max VT item limit")) return "Skipped (limit reached)";
    return text ? `Not scanned (${text})` : "Not scanned";
  }
  if (status === "not_found") return "Not found in VirusTotal";
  if (status === "rate_limited") return "Rate limited";
  if (status === "error") return text ? `Error: ${text}` : "Error";
  return text ? `${status}: ${text}` : status;
}

function computeVtCounts(raw) {
  if (!raw || typeof raw !== "object") return { flagged: null, total: null };

  if (raw.detections !== undefined || raw.total_engines !== undefined) {
    return {
      flagged: Number(raw.detections || 0),
      total: raw.total_engines ?? null,
    };
  }

  if (raw.positives !== undefined || raw.total !== undefined) {
    return {
      flagged: Number(raw.positives || 0),
      total: raw.total ?? null,
    };
  }

  const stats = raw.last_analysis_stats || raw.stats;
  if (stats && typeof stats === "object") {
    const values = Object.values(stats).filter(v => typeof v === "number");
    const total = values.reduce((sum, val) => sum + val, 0);
    return {
      flagged: Number(stats.malicious || 0) + Number(stats.suspicious || 0),
      total: total || null,
    };
  }

  if (raw.flagged !== undefined || raw.engines !== undefined) {
    return {
      flagged: Number(raw.flagged || 0),
      total: raw.engines ?? null,
    };
  }

  return { flagged: null, total: null };
}

function extractVT(obj) {
  const raw = obj?.vt_result ?? obj?.virustotal ?? obj?.vt ?? null;
  if (!raw) return { available: false };
  if (typeof raw === "string") {
    const m = raw.match(/(\d+)\s+of\s+(\d+)/i);
    if (m) return { available: true, flagged: parseInt(m[1]), total: parseInt(m[2]) };
    return { available: true, label: raw };
  }
  if (typeof raw === "object") {
    if (raw.status) {
      if (raw.status === "ok") {
        const counts = computeVtCounts(raw);
        if (counts.total == null && counts.flagged != null) {
          return { available: true, label: `${counts.flagged} flagged (total unknown)` };
        }
        return { available: true, flagged: counts.flagged ?? 0, total: counts.total ?? "?" };
      }
      return { available: true, label: formatVtReason(raw.status, raw.reason), status: raw.status };
    }

    const counts = computeVtCounts(raw);
    if (counts.flagged != null && counts.total == null) {
      return { available: true, label: `${counts.flagged} flagged (total unknown)` };
    }
    if (counts.flagged != null || counts.total != null) {
      return { available: true, flagged: counts.flagged ?? 0, total: counts.total ?? "?" };
    }
    return { available: true, label: "Not scanned" };
  }
  return { available: false };
}

function vtBadge(vt) {
  if (!vt.available) return null;
  const el = document.createElement("span");
  if (vt.label) {
    el.className = "vt-badge vt-unknown";
    el.textContent = vt.label;

    return el;
  }
  const flagged = vt.flagged ?? 0;
  const total   = vt.total   ?? "?";
  el.className = `vt-badge ${flagged > 0 ? "vt-flagged" : "vt-clean"}`;
  el.textContent = `${flagged} / ${total}`;
  return el;
}

function tdVT(vt) {
  const cell = document.createElement("td");
  if (!vt.available) {
    const badge = document.createElement("span");
    badge.className = "vt-badge vt-unknown";
    badge.textContent = "Not scanned";
    cell.appendChild(badge);
  } else {
    cell.appendChild(vtBadge(vt));
  }
  return cell;
}

/* ── urlscan.io helpers ── */
function extractUrlscan(obj) {
  const raw = obj?.urlscan ?? null;
  if (!raw) return { available: false };
  if (typeof raw === "object") {
    if (raw.status === "ok") {
      const malicious = raw.malicious || false;
      const score = raw.score || 0;
      const brands = raw.brands || [];
      const categories = raw.categories || [];
      return {
        available: true,
        malicious: malicious,
        score: score,
        brands: brands,
        categories: categories,
        report_url: raw.report_url || null,
        label: malicious
          ? `Malicious (${score})${brands.length ? " — " + brands.join(", ") : ""}`
          : score > 0
            ? `Suspicious (${score})`
            : "Clean",
      };
    }
    if (raw.status === "skipped") return { available: true, label: "Not configured", status: "skipped" };
    if (raw.status === "rate_limited") return { available: true, label: "Rate limited", status: "rate_limited" };
    if (raw.status === "error") return { available: true, label: "Error", status: "error" };
    if (raw.status === "timeout") return { available: true, label: "Timed out", status: "timeout" };
    return { available: true, label: raw.status || "Unknown" };
  }
  return { available: false };
}

function urlscanBadge(us) {
  if (!us.available) return null;
  const el = document.createElement("span");
  if (us.label && !us.malicious && !us.score) {
    el.className = "vt-badge vt-unknown";
    el.textContent = us.label;
    return el;
  }
  if (us.malicious) {
    el.className = "vt-badge vt-flagged";
    el.textContent = us.label || "Malicious";
  } else if (us.score > 0) {
    el.className = "vt-badge vt-flagged";
    el.textContent = us.label || `Suspicious (${us.score})`;
  } else {
    el.className = "vt-badge vt-clean";
    el.textContent = us.label || "Clean";
  }
  return el;
}

function tdUrlscan(us) {
  const cell = document.createElement("td");
  if (!us.available) {
    const badge = document.createElement("span");
    badge.className = "vt-badge vt-unknown";
    badge.textContent = "Not scanned";
    cell.appendChild(badge);
  } else {
    const badge = urlscanBadge(us);
    if (badge) cell.appendChild(badge);
    if (us.report_url) {
      const link = document.createElement("a");
      link.href = us.report_url;
      link.target = "_blank";
      link.className = "urlscan-link";
      link.textContent = "Report";
      link.style.cssText = "display:block;font-size:10px;color:var(--sky);margin-top:2px;";
      cell.appendChild(link);
    }
  }
  return cell;
}

/* ── urlscan.io enhanced rendering ── */
function renderUrlscanDetails(details) {
  const container = document.getElementById("urlscan-details");
  const summaryRow = document.getElementById("urlscan-row");
  if (!container) return;
  container.innerHTML = "";
  container.style.display = "none";
  if (summaryRow) summaryRow.style.display = "none";

  const urlscan = details.urlscan || {};
  const doms = details.urlscan_doms || {};
  const hars = details.urlscan_hars || {};

  // Find the first "ok" result
  let primaryResult = null;
  let primaryUrl = "";
  for (const [url, result] of Object.entries(urlscan)) {
    if (url.startsWith("_search_")) continue;
    if (result && result.status === "ok") {
      primaryResult = result;
      primaryUrl = url;
      break;
    }
  }
  if (!primaryResult) return;

  // Show the urlscan summary row
  if (summaryRow) {
    summaryRow.style.display = "flex";
    const summaryContainer = document.getElementById("urlscan-summary");
    if (summaryContainer) {
      summaryContainer.innerHTML = "";
      const us = extractUrlscan({urlscan: primaryResult});
      const badge = urlscanBadge(us);
      if (badge) summaryContainer.appendChild(badge);
      if (primaryResult.reused_scan) {
        const cached = document.createElement("span");
        cached.className = "urlscan-note";
        cached.style.marginLeft = "8px";
        cached.textContent = "(cached scan)";
        summaryContainer.appendChild(cached);
      }
    }
  }

  container.style.display = "block";

  // ── Screenshot ──
  if (primaryResult.screenshot_url) {
    const section = document.createElement("div");
    section.className = "urlscan-section";
    section.innerHTML = `
      <div class="urlscan-section-title">📸 Screenshot</div>
      <div class="urlscan-screenshot-wrap">
        <img src="${escapeHtml(primaryResult.screenshot_url)}" 
             alt="Screenshot of ${escapeHtml(primaryResult.domain || primaryUrl)}"
             class="urlscan-screenshot"
             loading="lazy"
             onerror="this.parentElement.innerHTML='<span class=\'urlscan-note\'>Screenshot not available</span>'" />
      </div>
      <div class="urlscan-screenshot-url">
        <a href="${escapeHtml(primaryResult.report_url || '#')}" target="_blank" rel="noopener">
          View full report on urlscan.io →
        </a>
      </div>
    `;
    container.appendChild(section);
  }

  // ── Page Info ──
  const pageInfo = document.createElement("div");
  pageInfo.className = "urlscan-section";
  let pageRows = "";
  const fields = [
    ["Domain", primaryResult.domain],
    ["IP", primaryResult.ip],
    ["ASN", primaryResult.asn ? `${primaryResult.asn} (${primaryResult.asnname || ""})` : null],
    ["Country", primaryResult.country],
    ["Server", primaryResult.server],
    ["Status", primaryResult.status_code],
    ["Title", primaryResult.title],
    ["TLS Issuer", primaryResult.tls_issuer],
    ["Requests", primaryResult.requests_count],
    ["Unique Countries", primaryResult.unique_countries],
  ];
  for (const [label, val] of fields) {
    if (val !== null && val !== undefined && val !== "") {
      pageRows += `<div class="urlscan-info-row"><span class="urlscan-info-label">${escapeHtml(label)}</span><span class="urlscan-info-value">${escapeHtml(String(val))}</span></div>`;
    }
  }
  pageInfo.innerHTML = `
    <div class="urlscan-section-title">🌐 Page Info</div>
    ${pageRows}
  `;
  container.appendChild(pageInfo);

  // ── Community Votes ──
  if (primaryResult.community_votes > 0) {
    const votes = document.createElement("div");
    votes.className = "urlscan-section";
    votes.innerHTML = `
      <div class="urlscan-section-title">👥 Community Votes</div>
      <div class="urlscan-info-row">
        <span class="urlscan-info-label">Total Votes</span>
        <span class="urlscan-info-value">${primaryResult.community_votes}</span>
      </div>
      <div class="urlscan-info-row">
        <span class="urlscan-info-label">Malicious</span>
        <span class="urlscan-info-value ${primaryResult.community_malicious > 0 ? 'text-bad' : ''}">${primaryResult.community_malicious}</span>
      </div>
      <div class="urlscan-info-row">
        <span class="urlscan-info-label">Harmless</span>
        <span class="urlscan-info-value text-ok">${primaryResult.community_harmless}</span>
      </div>
    `;
    container.appendChild(votes);
  }

  // ── Domains Contacted (from HAR) ──
  const harData = hars[primaryUrl];
  if (harData && harData.domains_contacted && harData.domains_contacted.length > 0) {
    const domains = document.createElement("div");
    domains.className = "urlscan-section";
    const domainTags = harData.domains_contacted.slice(0, 20).map(d => 
      `<span class="tag tag-info">${escapeHtml(d)}</span>`
    ).join("");
    const extra = harData.domains_contacted.length > 20 ? `<span class="urlscan-note">+${harData.domains_contacted.length - 20} more</span>` : "";
    domains.innerHTML = `
      <div class="urlscan-section-title">🔗 Domains Contacted (${harData.domains_contacted.length})</div>
      <div class="tag-list">${domainTags}</div>
      ${extra}
    `;
    container.appendChild(domains);
  }

  // ── Network Requests (from HAR) ──
  if (harData && harData.requests && harData.requests.length > 0) {
    const reqs = document.createElement("div");
    reqs.className = "urlscan-section";
    const reqRows = harData.requests.slice(0, 15).map(r => {
      const statusClass = r.status >= 400 ? "text-bad" : r.status >= 300 ? "text-warn" : "";
      return `<tr>
        <td class="mono-cell" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(r.url)}">${escapeHtml(r.domain || "")}</td>
        <td>${escapeHtml(r.method || "GET")}</td>
        <td class="${statusClass}">${r.status || "—"}</td>
        <td>${escapeHtml(r.content_type || "")}</td>
        <td>${fmtBytes(r.size || 0)}</td>
      </tr>`;
    }).join("");
    reqs.innerHTML = `
      <div class="urlscan-section-title">📡 Network Requests (${harData.total_entries} total)</div>
      <table class="data-table urlscan-req-table">
        <thead><tr><th>Domain</th><th>Method</th><th>Status</th><th>Type</th><th>Size</th></tr></thead>
        <tbody>${reqRows}</tbody>
      </table>
      ${harData.total_entries > 15 ? `<div class="urlscan-note">Showing 15 of ${harData.total_entries} requests</div>` : ""}
    `;
    container.appendChild(reqs);
  }

  // ── Links Found ──
  if (primaryResult.links && primaryResult.links.length > 0) {
    const links = document.createElement("div");
    links.className = "urlscan-section";
    const linkItems = primaryResult.links.slice(0, 10).map(l => {
      const href = typeof l === "string" ? l : (l.href || l.url || "");
      const text = typeof l === "string" ? l : (l.text || l.href || "");
      return `<div class="urlscan-link-item"><a href="${escapeHtml(href)}" target="_blank" rel="noopener" class="mono-cell" style="font-size:11px">${escapeHtml(text.slice(0, 100))}</a></div>`;
    }).join("");
    links.innerHTML = `
      <div class="urlscan-section-title">🔗 Links Found (${primaryResult.links.length})</div>
      ${linkItems}
    `;
    container.appendChild(links);
  }

  // ── Certificates ──
  if (primaryResult.certificates && primaryResult.certificates.length > 0) {
    const certs = document.createElement("div");
    certs.className = "urlscan-section";
    const certRows = primaryResult.certificates.map(c => {
      return `<div class="urlscan-info-row">
        <span class="urlscan-info-label">${escapeHtml(c.issuer || "Unknown")}</span>
        <span class="urlscan-info-value">${escapeHtml(c.subject || "")} (valid: ${escapeHtml(c.validFrom || "")} → ${escapeHtml(c.validTo || "")})</span>
      </div>`;
    }).join("");
    certs.innerHTML = `
      <div class="urlscan-section-title">🔒 TLS Certificates (${primaryResult.certificates.length})</div>
      ${certRows}
    `;
    container.appendChild(certs);
  }
}

function renderUrlscanSearch(details) {
  const container = document.getElementById("urlscan-search-results");
  if (!container) return;
  container.innerHTML = "";
  container.style.display = "none";

  const urlscan = details.urlscan || {};
  // Find search results (keys starting with _search_)
  const searchEntries = Object.entries(urlscan).filter(([k]) => k.startsWith("_search_"));
  if (!searchEntries.length) return;

  for (const [key, searchResult] of searchEntries) {
    if (!searchResult || searchResult.status !== "ok" || !searchResult.results || !searchResult.results.length) continue;
    container.style.display = "block";

    const section = document.createElement("div");
    section.className = "urlscan-section";
    const domain = key.replace("_search_domain:", "");
    const rows = searchResult.results.slice(0, 5).map(r => {
      const statusClass = r.malicious ? "text-bad" : r.score > 0 ? "text-warn" : "text-ok";
      const label = r.malicious ? "Malicious" : r.score > 0 ? "Suspicious" : "Clean";
      return `<tr>
        <td class="mono-cell" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(r.url || "")}">${escapeHtml(r.domain || "")}</td>
        <td>${escapeHtml(r.title || "—")}</td>
        <td class="${statusClass}">${label}${r.score ? ` (${r.score})` : ""}</td>
        <td>${r.brands && r.brands.length ? escapeHtml(r.brands.join(", ")) : "—"}</td>
        <td>${r.report_url ? `<a href="${escapeHtml(r.report_url)}" target="_blank" rel="noopener" style="font-size:11px">View</a>` : "—"}</td>
      </tr>`;
    }).join("");

    section.innerHTML = `
      <div class="urlscan-section-title">🔍 Previous urlscan.io Scans of ${escapeHtml(domain)} (${searchResult.total} total)</div>
      <table class="data-table">
        <thead><tr><th>Domain</th><th>Title</th><th>Verdict</th><th>Brands</th><th>Report</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${searchResult.has_more ? `<div class="urlscan-note">Showing ${searchResult.results.length} of ${searchResult.total} results</div>` : ""}
    `;
    container.appendChild(section);
  }
}



function mkTable(headers) {
  const table = document.createElement("table");
  table.className = "data-table";
  const thead = document.createElement("thead");
  const tr    = document.createElement("tr");
  headers.forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    tr.appendChild(th);
  });
  thead.appendChild(tr);
  table.appendChild(thead);
  table.appendChild(document.createElement("tbody"));
  return table;
}

function td(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}
function tdFileName(text) {
  const cell = document.createElement("td");
  cell.className = "filename-cell";
  cell.textContent = text;
  cell.title = text;
  return cell;
}
function tdMono(text) {
  const cell = document.createElement("td");
  cell.className = "mono-cell";
  cell.textContent = text;
  return cell;
}
function tdHash(text) {
  const cell = document.createElement("td");
  cell.className = "hash-cell";
  cell.textContent = text;
  return cell;
}
function tdTags(values) {
  const cell = document.createElement("td");
  if (!values.length) { cell.textContent = "None detected"; return cell; }
  const list = document.createElement("div");
  list.className = "tag-list";
  values.forEach(v => {
    list.appendChild(tagEl(v));
  });
  cell.appendChild(list);
  return cell;
}

function tagEl(text) {
  const tag = document.createElement("span");
  tag.className = `tag ${tagClassForText(text)}`.trim();
  tag.textContent = text;
  return tag;
}

function pill(text, cls) {
  const el = document.createElement("span");
  el.className = `sig-pill ${cls}`;
  el.textContent = text;
  return el;
}

function emptyMsg(text) {
  const el = document.createElement("div");
  el.style.cssText = "color:var(--muted);font-size:13px;padding:10px 0;";
  el.textContent = text;
  return el;
}

function fmtBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024)        return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/* ══════════════════════════════════════════
   EXPORT
   ══════════════════════════════════════════ */
function downloadReport() {
  if (!latestReport) {
    // Fallback: try to get from current history
    const items = loadHistory();
    if (items.length && items[0].payload) {
      latestReport = items[0].payload.report || items[0].payload;
    }
  }
  if (!latestReport) {
    alert("No report available. Run an analysis first.");
    return;
  }
  try {
    const json = JSON.stringify(latestReport, null, 2);
    if (!json || json === "null" || json === "{}") {
      alert("Report data is empty.");
      return;
    }
    const blob = new Blob([json], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    const filename = (latestReport.file || "report").toString().replace(/[^a-z0-9_-]/gi, "_");
    a.download = `phishing-report-${filename}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  } catch (err) {
    console.error("Export failed:", err);
    alert("Export failed: " + err.message);
  }
}

renderFileSwitcher();
updateAnalysisControls(document.querySelector(".tab-btn.is-active")?.dataset.tab || "overview");
