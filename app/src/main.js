// Phase 4.4 — Live Run UI.
// Consumes the parsed contract events the Rust shell emits (run:event
// = { schemaMajor, event }) and renders phases / progress / log live.
// No contract knowledge is re-implemented here — the Rust `contract`
// module already typed everything; this just paints it.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let els = {};
let supportedMajor = 1;
const phaseRows = new Map(); // phase name -> <li>
const PROCESS_TAIL_LIMIT = 80;
let runHadResult = false;
let processTail = [];
let lastRunModules = [];
let authVerificationUri = "";
let authRawBuffer = "";
let shownDeviceCode = "";

// Access Review (UAR) — plan §4.3. The campaign folder is durable audit
// evidence spanning days, so it is never the run's TEMP output dir; the
// webview owns the remembered value (no Rust settings store needed).
const AR_DIR_KEY = "entrachecks.accessReview.dir";
const AR_DIR_UNSET = "not set — choose a campaign folder";
const AR_MAX_ROWS = 50;
let arCampaigns = [];
let arSelectedId = "";

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c]
  );
}

function logLine(text, cls) {
  const span = document.createElement("span");
  span.className = "logln" + (cls ? " " + cls : "");
  span.textContent = text + "\n";
  els.log.appendChild(span);
  els.log.scrollTop = els.log.scrollHeight;
}

function rememberProcessLine(text) {
  processTail.push(String(text == null ? "" : text));
  if (processTail.length > PROCESS_TAIL_LIMIT) processTail.shift();
}

function logProcessLine(text, cls) {
  rememberProcessLine(text);
  logLine(text, cls);
}

function resetView() {
  phaseRows.clear();
  els.phases.innerHTML = "";
  els.log.textContent = "";
  els.runStatus.textContent = "";
  els.runStatus.className = "run-status";
  els.resultCard.classList.add("hidden");
  els.resultSummary.innerHTML = "";
  els.resultSoc2.innerHTML = "";
  els.resultArtifacts.innerHTML = "";
  els.resultErrors.innerHTML = "";
  setArStatus("");
}

function metric(label, value, cls) {
  return `<div class="metric ${cls || ""}">
    <span class="m-val">${value}</span>
    <span class="m-lbl">${label}</span></div>`;
}

function renderResult(ev) {
  els.resultBadge.textContent = ev.status;
  els.resultBadge.className = "badge st-" + ev.status;

  const modCount = ev.modulesRun && ev.modulesRun.length
    ? ev.modulesRun.length
    : "—";
  els.resultSummary.innerHTML =
    metric("Findings", ev.findings) +
    metric("Critical", ev.critical, ev.critical > 0 ? "sev-crit" : "") +
    metric("High", ev.high, ev.high > 0 ? "sev-high" : "") +
    metric("Medium", ev.medium) +
    metric("Low", ev.low) +
    metric("Modules", modCount);

  // SOC 2 verdict is an analyst-attention flag — shown verbatim,
  // never re-interpreted as a formal audit determination.
  if (ev.soc2 && ev.soc2.ran) {
    els.resultSoc2.innerHTML = `<strong>SOC 2:</strong> ${escapeHtml(
      ev.soc2.verdict || "(no verdict reported)"
    )}`;
  } else {
    els.resultSoc2.innerHTML = "";
  }

  els.resultArtifacts.innerHTML = "";
  (ev.artifacts || []).forEach((a) => {
    const btn = document.createElement("button");
    btn.className = "secondary";
    btn.textContent = `Open ${a.kind}`;
    btn.addEventListener("click", () =>
      invoke("open_report", { path: a.path }).catch((e) =>
        logLine(`[report] could not open: ${e}`, "warn")
      )
    );
    const row = document.createElement("div");
    row.className = "artifact-row";
    row.appendChild(btn);
    const p = document.createElement("span");
    p.className = "art-path";
    p.textContent = a.path;
    row.appendChild(p);
    els.resultArtifacts.appendChild(row);
  });
  if (!(ev.artifacts || []).length)
    els.resultArtifacts.innerHTML =
      `<p class="muted">No report artifacts were produced.</p>`;

  els.resultErrors.innerHTML = "";
  (ev.errors || []).forEach((e) => {
    const d = document.createElement("div");
    d.className = "result-err";
    d.innerHTML =
      `<span class="logln error">${escapeHtml(e.code)}: ${escapeHtml(
        e.message
      )}</span>` +
      (e.remediation
        ? `<span class="muted"> → ${escapeHtml(e.remediation)}</span>`
        : "");
    els.resultErrors.appendChild(d);
  });

  els.resultCard.classList.remove("hidden");
}

function selectedModules() {
  return els.moduleChecks
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.module);
}

function setModuleSelection(mode) {
  els.moduleChecks.forEach((cb) => {
    cb.checked = mode === "all" || cb.dataset.module === "Core";
  });
}

function selectedDeepDives() {
  if (!els.deepDiveChecks) return [];
  return els.deepDiveChecks
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.deepdive);
}

function setDeepDiveSelection(mode) {
  if (!els.deepDiveChecks) return;
  els.deepDiveChecks.forEach((cb) => {
    cb.checked = mode === "all";
  });
}

// --- Access Review (UAR) ---------------------------------------------
//
// Campaign lifecycle only: Open mints the folder + worksheet, a human
// fills the CSV in Excel outside the app, Close verifies it and renders
// the report. Every action rides the same run:event stream an assessment
// does, so phases / log / artifacts / cancel need no special casing.

function joinWinPath(base, leaf) {
  return String(base == null ? "" : base).replace(/[\\/]+$/, "") + "\\" + leaf;
}

function loadCampaignDir() {
  try {
    return localStorage.getItem(AR_DIR_KEY) || "";
  } catch (_) {
    return "";
  }
}

function saveCampaignDir(dir) {
  try {
    localStorage.setItem(AR_DIR_KEY, dir);
  } catch (_) {
    /* storage unavailable — the field still works for this session */
  }
}

async function defaultCampaignDir() {
  // Resolved in Rust (std::env), never composed here: a `%USERPROFILE%`
  // literal would reach PowerShell verbatim and create a folder of that
  // name. "" means "no home dir" — the panel then just asks for one.
  try {
    return (await invoke("default_campaign_dir")) || "";
  } catch (_) {
    return "";
  }
}

function campaignDir() {
  return els.arDir ? els.arDir.value.trim() : "";
}

function updateCampaignDirHint() {
  if (!els.arDirHint) return;
  els.arDirHint.textContent = campaignDir() || AR_DIR_UNSET;
}

function setArStatus(text, cls) {
  if (!els.arStatus) return;
  els.arStatus.textContent = text;
  els.arStatus.className = "run-status" + (cls ? " " + cls : "");
}

function selectedCampaign() {
  return arCampaigns.find((c) => c.id === arSelectedId) || null;
}

function syncAccessReviewButtons() {
  if (!els.arOpen) return;
  // Same run-in-flight signal the Run button uses: Cancel is visible
  // exactly while an engine process is alive. Kept in one helper so
  // setRunning() and renderReadiness() can't disagree about it.
  // A dependency install is also a busy pwsh — starting a campaign
  // underneath one would fight it for the module state it is writing.
  const busy = !els.cancel.classList.contains("hidden") || installing;
  const sel = selectedCampaign();
  els.arRefresh.disabled = busy;
  els.arFolder.disabled = busy;
  els.arOpen.disabled = busy || !appReady;
  els.arWorksheet.disabled = busy || !sel;
  els.arClose.disabled = busy || !appReady || !sel || sel.status !== "Open";
  els.arReport.disabled = busy || !appReady || !sel;
  // Closed only: the generator reads the *decisions* of a finished
  // campaign. An open one has none yet, so offering the button there
  // would promise a script the engine cannot write.
  els.arRemediate.disabled = busy || !appReady || !sel || sel.status !== "Closed";
}

function fmtCampaignOpened(utc) {
  // `new Date(null)` is epoch 0 — a campaign.json with no timestamp
  // would otherwise render as 1969 in what is audit evidence.
  if (!utc) return "";
  const d = new Date(utc);
  if (isNaN(d.getTime())) return String(utc);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function renderCampaigns() {
  const list = els.arList;
  if (!list) return;
  list.innerHTML = "";
  if (!arCampaigns.length) {
    const empty = document.createElement("li");
    empty.className = "ar-empty muted";
    empty.textContent =
      "No campaigns in this folder yet. Open new campaign creates one " +
      "(roster, worksheet, manifest) without running an assessment.";
    list.appendChild(empty);
    els.arCount.textContent = "";
    syncAccessReviewButtons();
    return;
  }

  const head = document.createElement("li");
  head.className = "ar-row ar-head";
  head.innerHTML =
    `<span></span><span>Campaign</span><span>Period</span>` +
    `<span>Status</span><span>Opened</span>`;
  list.appendChild(head);

  // Cap the rendered rows: a folder kept for years is a long list, and
  // only the newest few are ever acted on (plan §7).
  const shown = arCampaigns.slice(0, AR_MAX_ROWS);
  shown.forEach((c) => {
    const row = document.createElement("li");
    row.className = "ar-row";
    row.dataset.state = c.status === "Open" ? "open" : "closed";
    row.innerHTML =
      `<span class="ar-pick"><input type="radio" name="ar-pick" ` +
      `value="${escapeHtml(c.id)}"` +
      (c.id === arSelectedId ? " checked" : "") +
      ` aria-label="Select campaign ${escapeHtml(c.id)}" /></span>` +
      `<span class="ar-id" title="${escapeHtml(c.path)}">${escapeHtml(
        c.id
      )}</span>` +
      `<span>${escapeHtml(c.period)}</span>` +
      `<span>${escapeHtml(c.status)}</span>` +
      `<span class="ar-opened">${escapeHtml(
        fmtCampaignOpened(c.generatedUtc)
      )}</span>`;
    row.querySelector("input").addEventListener("change", () => {
      arSelectedId = c.id;
      syncAccessReviewButtons();
    });
    list.appendChild(row);
  });

  els.arCount.textContent =
    arCampaigns.length > shown.length
      ? `Showing ${shown.length} of ${arCampaigns.length} campaigns, newest first.`
      : `${arCampaigns.length} campaign${
          arCampaigns.length === 1 ? "" : "s"
        }, newest first.`;
  syncAccessReviewButtons();
}

async function refreshCampaigns() {
  if (!els.arList) return;
  const dir = campaignDir();
  if (!dir) {
    arCampaigns = [];
    arSelectedId = "";
    renderCampaigns();
    setArStatus("Set a campaign folder to list campaigns.", "st-Failed");
    return;
  }
  try {
    arCampaigns = (await invoke("list_campaigns", { campaignDir: dir })) || [];
    setArStatus("");
  } catch (e) {
    arCampaigns = [];
    setArStatus(`Could not list campaigns: ${e}`, "st-Failed");
  }
  // A refreshed list may no longer contain the selected row.
  if (!arCampaigns.some((c) => c.id === arSelectedId)) arSelectedId = "";
  renderCampaigns();
}

async function runAccessReview(action) {
  const dir = campaignDir();
  const tenant = els.tenant.value.trim();
  const sel = selectedCampaign();
  if (!tenant) {
    setArStatus(
      "Enter a tenant name above before running a campaign action.",
      "st-Failed"
    );
    return;
  }
  if (!dir) {
    setArStatus(
      "Set a campaign folder before running a campaign action.",
      "st-Failed"
    );
    return;
  }
  if (action !== "Open" && !sel) {
    setArStatus("Select a campaign row first.", "st-Failed");
    return;
  }
  resetView();
  hideAuth();
  resetAuthCapture();
  runHadResult = false;
  processTail = [];
  lastRunModules = [];
  setRunning(true);
  setArStatus(`${action} — starting…`);
  els.runStatus.textContent = "Starting…";
  startOp(`Access review — ${action}`, {
    sub: "Waiting for the first phase…",
  });
  try {
    await invoke("run_access_review", {
      tenant,
      authMethod: els.authMode.value,
      action,
      campaignDir: dir,
      campaignId: action === "Open" ? "" : sel.id,
    });
  } catch (e) {
    setArStatus(`Could not start: ${e}`, "st-Failed");
    els.runStatus.textContent = `Could not start: ${e}`;
    els.runStatus.classList.add("st-Failed");
    setRunning(false);
    endOp();
  }
}

function openWorksheet() {
  const sel = selectedCampaign();
  if (!sel) return;
  // Phase B of a campaign happens in Excel, outside this app.
  invoke("open_report", {
    path: joinWinPath(sel.path, "review-worksheet.csv"),
  }).catch((e) =>
    setArStatus(`Could not open the worksheet: ${e}`, "st-Failed")
  );
}

function openCampaignFolder() {
  const dir = campaignDir();
  if (!dir) {
    setArStatus("Set a campaign folder first.", "st-Failed");
    return;
  }
  invoke("open_external", { target: dir }).catch((e) =>
    setArStatus(`Could not open the folder: ${e}`, "st-Failed")
  );
}

function synthesizeFailedResult(code, message, remediation) {
  if (runHadResult) return;
  runHadResult = true;
  const tail = processTail.slice(-10).join("\n");
  const detail = tail ? `${message}\n\nRecent process output:\n${tail}` : message;
  els.runStatus.textContent = "Failed — see Result";
  els.runStatus.className = "run-status st-Failed";
  renderResult({
    status: "Failed",
    findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    modulesRun: lastRunModules,
    soc2: null,
    artifacts: [],
    errors: [
      {
        code,
        message: detail,
        fatal: true,
        remediation,
      },
    ],
  });
}

function phaseRow(name) {
  let li = phaseRows.get(name);
  if (!li) {
    li = document.createElement("li");
    li.className = "phase";
    li.innerHTML = `<span class="ph-name"></span><span class="ph-info"></span>`;
    li.querySelector(".ph-name").textContent = name;
    els.phases.appendChild(li);
    phaseRows.set(name, li);
  }
  return li;
}

function setPhase(name, state, info) {
  const li = phaseRow(name);
  li.dataset.state = state;
  if (info !== undefined) li.querySelector(".ph-info").textContent = info;
}

function showAuth(html) {
  els.authBody.innerHTML = html;
  els.authPanel.classList.remove("hidden");
  // The panel sits above the Access Review card, so an action triggered
  // from down there reveals the sign-in code off-screen — which reads as
  // "it never prompted". Fixed here rather than at the call sites so
  // every auth path (browser, device code, failure) is covered.
  els.authPanel.scrollIntoView({ behavior: "smooth", block: "center" });
}
function hideAuth() {
  els.authPanel.classList.add("hidden");
  els.authBody.innerHTML = "";
}

function resetAuthCapture() {
  authVerificationUri = "";
  authRawBuffer = "";
  shownDeviceCode = "";
}

function renderDeviceCodePanel(verificationUri, userCode) {
  const uri = verificationUri || "https://microsoft.com/devicelogin";
  const codeBlock = userCode
    ? `<div class="dc-code">${escapeHtml(userCode)}</div>`
    : `<p class="muted">Requesting a sign-in code from Microsoft… <br />
         If this doesn't update within ~30 seconds, check the Log
         below — the request may be blocked by a firewall or proxy.</p>`;
  showAuth(
    `<p>To sign in, open the verification page and enter the code:</p>
     ${codeBlock}
     <p><button id="dc-open" class="link">Open ${escapeHtml(uri)}</button></p>`
  );
  const b = document.querySelector("#dc-open");
  if (b)
    b.addEventListener("click", () =>
      invoke("open_external", { target: uri }).catch((e) =>
        logLine(`[auth] could not open browser: ${e}`, "warn")
      )
    );
}

const DEVICE_CODE_STOPWORDS = new Set([
  "AUTHENTICATE",
  "AUTHENTICATING",
  "AUTHENTICATION",
  "BELOW",
  "CONNECTING",
  "DEVICE",
  "DEVICEAUTH",
  "DEVICECODE",
  "DEVICELOGIN",
  "DEVICLOGIN",
  "ENTRACHECKS",
  "GRAPH",
  "HTTPS",
  "INFO",
  "MICROSOFT",
  "POWERSHELL",
  "PROCESS",
  "SHOWN",
  "STARTING",
  "WARNING",
]);

function normalizeDeviceCodeToken(token, allowPlainWord = false) {
  const cleaned = String(token || "")
    .trim()
    .replace(/^[^A-Z0-9]+|[^A-Z0-9]+$/gi, "")
    .toUpperCase();
  const compact = cleaned.replace(/-/g, "");
  if (!/^[A-Z0-9-]{6,21}$/.test(cleaned)) return "";
  if (compact.length < 6 || compact.length > 20) return "";
  if (DEVICE_CODE_STOPWORDS.has(cleaned) || DEVICE_CODE_STOPWORDS.has(compact))
    return "";
  if (!allowPlainWord && !/[-0-9]/.test(cleaned)) return "";
  return cleaned;
}

function findDeviceCode(text) {
  const raw = String(text || "");
  const directPatterns = [
    /\b(?:enter|copy|use)\s+(?:the\s+)?code(?:\s+is|:)?[ \t]*([A-Z0-9][A-Z0-9-]{5,20})\b/gi,
    /\bcode(?:\s+is|:)[ \t]*([A-Z0-9][A-Z0-9-]{5,20})\b/gi,
  ];
  for (const pattern of directPatterns) {
    let match;
    while ((match = pattern.exec(raw)) !== null) {
      const code = normalizeDeviceCodeToken(match[1], true);
      if (code) return code;
    }
  }
  const belowPattern =
    /\b(?:code\s+shown\s+below|enter\s+the\s+code\s+below)[^\S\r\n]*(?:\r?\n)+\s*([A-Z0-9][A-Z0-9-]{5,20})\b/gi;
  let belowMatch;
  while ((belowMatch = belowPattern.exec(raw)) !== null) {
    const code = normalizeDeviceCodeToken(belowMatch[1]);
    if (code) return code;
  }

  if (
    !/microsoft\.com\/devicelogin|device\s+code|enter\s+the\s+code|copy\s+the\s+code/i.test(
      raw
    )
  )
    return "";
  const tokens = raw.toUpperCase().match(/\b[A-Z0-9][A-Z0-9-]{5,20}\b/g) || [];
  for (const token of tokens) {
    const code = normalizeDeviceCodeToken(token);
    if (code) return code;
  }
  return "";
}

function maybeCaptureDeviceCode(text) {
  if (!authVerificationUri) return;
  authRawBuffer = `${authRawBuffer}\n${String(text || "")}`.slice(-6000);
  const code = findDeviceCode(authRawBuffer);
  if (code && code !== shownDeviceCode) {
    shownDeviceCode = code;
    renderDeviceCodePanel(authVerificationUri, code);
    logLine(`[auth] device code captured: ${code}`, "ok");
  }
}

let appReady = false;

function setRunning(on) {
  // Run is disabled either because we're already running OR because
  // Readiness says the engine can't run (pwsh / Microsoft.Graph
  // missing). The latter wins until the user fixes it (5.3).
  els.run.disabled = on || !appReady;
  els.cancel.classList.toggle("hidden", !on);
  els.cancel.disabled = false;
  syncAccessReviewButtons();
}

let installing = false;

// Always flip the flag through here: an install is a busy pwsh, and the
// Access Review buttons have to disable the moment it starts, not at the
// next readiness render.
function setInstalling(on) {
  installing = on;
  syncAccessReviewButtons();
}
let wingetOk = false;

// --- op-banner: determinate progress for long-running operations -----
//
// A spinner-only "busy" indicator looks frozen after ~10s of no
// movement; a real progress bar shows the user the run isn't stuck.
// Use determinate where total is known (install, with [plan] total=N
// from the bundled script); indeterminate elsewhere — but ALWAYS
// pair with a live elapsed-time tick so even an indeterminate state
// proves it's alive.
let opTimer = null;
let opStart = 0;

function fmtElapsed(ms) {
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

function startOp(label, { determinate = false, total = null, sub = "" } = {}) {
  const banner = document.querySelector("#op-banner");
  const pb = document.querySelector("#op-progress");
  document.querySelector("#op-label").textContent = label;
  document.querySelector("#op-sub").textContent = sub;
  document.querySelector("#op-elapsed").textContent = "0s";
  if (determinate && total) {
    pb.max = total;
    pb.value = 0;
  } else {
    // Indeterminate: clear `value` so the browser animates the bar.
    pb.removeAttribute("value");
  }
  banner.classList.remove("hidden");
  opStart = Date.now();
  if (opTimer) clearInterval(opTimer);
  opTimer = setInterval(() => {
    document.querySelector("#op-elapsed").textContent = fmtElapsed(
      Date.now() - opStart
    );
  }, 1000);
}

function setOpProgress(value, sub) {
  const pb = document.querySelector("#op-progress");
  if (value != null) pb.value = value;
  if (sub != null) document.querySelector("#op-sub").textContent = sub;
}

function setOpTotal(total) {
  const pb = document.querySelector("#op-progress");
  pb.max = total;
  if (!pb.hasAttribute("value")) pb.value = 0;
}

function setOpSub(sub) {
  document.querySelector("#op-sub").textContent = sub;
}

function endOp() {
  if (opTimer) {
    clearInterval(opTimer);
    opTimer = null;
  }
  document.querySelector("#op-banner").classList.add("hidden");
}

// Install-stream parser state — reset on every install start.
let installTotal = null;
let installDone = 0;
let installCurrent = null;

async function refreshWingetAvailability() {
  try {
    wingetOk = !!(await invoke("winget_available"));
  } catch (_) {
    wingetOk = false;
  }
}

async function installPwshClick() {
  if (installing) return;
  if (
    !confirm(
      "Install PowerShell 7 via winget?\n\nwinget will display its own " +
        "UAC prompt; this app does not self-elevate. Output streams to " +
        "the Log below."
    )
  )
    return;
  setInstalling(true);
  logLine("[install] starting pwsh 7 via winget…");
  try {
    await invoke("install_pwsh_via_winget");
  } catch (e) {
    logLine(`[install] could not start: ${e}`, "error");
    setInstalling(false);
  }
}

async function installPrereqsClick(includeAzure) {
  if (installing) return;
  // Module counts mirror Install-Prerequisites.ps1 / the [plan] line.
  // ImportExcel ships in both modes (small, no creds, no scope quirks)
  // so the GUI can produce Excel reports without a manual install
  // step. Graph-only: Microsoft.Graph + ImportExcel. Full: + Az.*.
  const totalModules = includeAzure ? 9 : 2;
  const set = includeAzure
    ? "Microsoft.Graph + the Az.* set + ImportExcel (9 modules)"
    : "Microsoft.Graph + ImportExcel (2 modules)";
  if (
    !confirm(
      `Install ${set}?\n\n` +
        "Scope: CurrentUser (no elevation needed). " +
        "Typically takes 3–10 minutes depending on network speed; " +
        "single-module downloads can stretch 30–90 seconds with no " +
        "new log output (it's not frozen — the progress bar above " +
        "ticks elapsed time and advances per module).\n\n" +
        "Output streams to the Log pane below as each step runs."
    )
  )
    return;
  setInstalling(true);
  installTotal = null;
  installDone = 0;
  installCurrent = null;
  startOp("Installing dependencies", {
    determinate: true,
    total: totalModules,
    sub: `0 of ${totalModules} modules complete · preparing…`,
  });
  logLine(
    `[install] starting Install-Prerequisites.ps1 (${
      includeAzure ? "Graph + Az" : "Graph only"
    })…`
  );
  try {
    await invoke("install_prereqs", { includeAzure });
  } catch (e) {
    logLine(`[install] could not start: ${e}`, "error");
    setInstalling(false);
    endOp();
  }
}

async function relaunchAsAdminClick() {
  if (
    !confirm(
      "Restart EntraChecks under administrator rights?\n\n" +
        "Windows will show a UAC prompt. The current window will close " +
        "and an elevated instance will open. Some local-machine checks " +
        "(AD/hybrid, BitLocker, event logs) need this."
    )
  )
    return;
  try {
    await invoke("relaunch_as_admin");
  } catch (e) {
    logLine(`[elevation] relaunch failed: ${e}`, "error");
  }
}

function renderReadiness(r) {
  const list = els.readinessList;
  list.innerHTML = "";

  // Elevation row — Windows only; non-Windows dev hosts skip it
  // entirely because the concept doesn't translate there.
  if (r.windows) {
    const elevRow = document.createElement("li");
    elevRow.className = "ready-row";
    if (r.elevated) {
      elevRow.dataset.state = "ok";
      elevRow.innerHTML =
        `<span class="rd-name">Administrator</span>` +
        `<span class="rd-req">when needed</span>` +
        `<span class="rd-ver">running elevated</span>` +
        `<span class="rd-path">Local-machine checks have full access.</span>`;
    } else {
      elevRow.dataset.state = "optional";
      elevRow.innerHTML =
        `<span class="rd-name">Administrator</span>` +
        `<span class="rd-req">when needed</span>` +
        `<span class="rd-ver">not elevated</span>` +
        `<span class="rd-path rd-actions">` +
        `<button class="link" data-act="relaunch-admin">Restart as administrator</button>` +
        `</span>`;
    }
    list.appendChild(elevRow);
    const btn = elevRow.querySelector('button[data-act="relaunch-admin"]');
    if (btn) btn.addEventListener("click", relaunchAsAdminClick);
  }

  // pwsh row — its own "module" with a different label format.
  const pwshRow = document.createElement("li");
  pwshRow.className = "ready-row";
  if (r.pwsh) {
    pwshRow.dataset.state = "ok";
    pwshRow.innerHTML =
      `<span class="rd-name">PowerShell 7</span>` +
      `<span class="rd-req">required</span>` +
      `<span class="rd-ver">${escapeHtml(r.pwsh.version)}</span>` +
      `<span class="rd-path" title="${escapeHtml(r.pwsh.path)}">${escapeHtml(
        r.pwsh.path
      )}</span>`;
  } else {
    pwshRow.dataset.state = "missing";
    pwshRow.innerHTML =
      `<span class="rd-name">PowerShell 7</span>` +
      `<span class="rd-req">required</span>` +
      `<span class="rd-ver">not installed</span>` +
      `<span class="rd-path rd-actions">` +
      (wingetOk
        ? `<button class="link" data-act="winget">Install via winget</button>`
        : "") +
      `<button class="link" data-act="open">Download PowerShell 7</button>` +
      `</span>`;
  }
  list.appendChild(pwshRow);

  let missingRequired = !r.pwsh;
  let anyModuleMissing = false;
  let anyAzMissing = false;
  (r.modules || []).forEach((m) => {
    const row = document.createElement("li");
    row.className = "ready-row";
    row.dataset.state = m.present ? "ok" : m.required ? "missing" : "optional";
    if (m.required && !m.present) {
      missingRequired = true;
    }
    if (!m.present) anyModuleMissing = true;
    if (m.name.startsWith("Az.") && !m.present) anyAzMissing = true;
    row.innerHTML =
      `<span class="rd-name">${escapeHtml(m.name)}</span>` +
      `<span class="rd-req">${m.required ? "required" : "optional"}</span>` +
      `<span class="rd-ver">${
        m.present ? escapeHtml(m.version || "installed") : "not installed"
      }</span>` +
      `<span class="rd-path"></span>`;
    list.appendChild(row);
  });

  // Per-row actions for the pwsh row (event delegation kept tiny).
  if (!r.pwsh) {
    pwshRow.querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.dataset.act === "winget") {
          installPwshClick();
        } else {
          invoke("open_external", { target: "https://aka.ms/powershell" });
        }
      });
    });
  }

  // Bottom action: a single "Install dependencies" button shown
  // whenever *any* module row is missing — required OR optional. The
  // bundled `Install-Prerequisites.ps1` is idempotent (each
  // Install-RequiredModule skips when already present), so re-running
  // with everything checked simply tops up the remaining gaps. This
  // covers the case where a user already installed Graph + Az.* but
  // ImportExcel is still showing as "not installed" — previously
  // there was no path from the GUI to fix that without dropping to
  // a pwsh prompt.
  const actionBar = document.createElement("div");
  actionBar.className = "ready-actions";
  if (anyModuleMissing && r.pwsh) {
    const includeAzDefault = anyAzMissing;
    actionBar.innerHTML =
      `<button id="btn-install-prereqs">Install missing modules</button>` +
      `<label class="check"><input type="checkbox" id="chk-az"` +
      (includeAzDefault ? " checked" : "") +
      `/> Include Az.* (Defender / Policy / Recovery)</label>`;
    list.appendChild(actionBar);
    actionBar
      .querySelector("#btn-install-prereqs")
      .addEventListener("click", () =>
        installPrereqsClick(
          actionBar.querySelector("#chk-az").checked
        )
      );
  }

  appReady = !missingRequired;
  els.readinessHint.textContent = installing
    ? "Installing… Run will re-enable when Readiness re-checks."
    : appReady
    ? "All required dependencies present — Run is enabled."
    : "Run is disabled until the required items above are installed.";
  els.run.disabled =
    !appReady || installing || !els.cancel.classList.contains("hidden");
  syncAccessReviewButtons();
}

async function loadReadiness() {
  // Up-top, animated, with elapsed time — so users don't think the
  // app launched empty while pwsh is being probed (typically 2–5s).
  startOp("Checking PowerShell 7 and required modules", {
    sub: "Probing the local install…",
  });
  els.readinessHint.textContent = "Checking…";
  try {
    const r = await invoke("readiness");
    renderReadiness(r);
  } catch (e) {
    els.readinessHint.textContent = `Readiness check failed: ${e}`;
    appReady = false;
    els.run.disabled = true;
    syncAccessReviewButtons();
  } finally {
    endOp();
  }
}

async function cancelRun() {
  els.cancel.disabled = true;
  try {
    await invoke("cancel_run");
    els.runStatus.textContent = "Cancelling… (finishing the current step)";
    els.runStatus.className = "run-status st-Cancelled";
  } catch (e) {
    logLine(`[cancel] could not request cancel: ${e}`, "warn");
    els.cancel.disabled = false;
  }
}

function onEvent(payload) {
  const { schemaMajor, event } = payload;
  if (schemaMajor > supportedMajor) els.banner.classList.remove("hidden");

  switch (event.type) {
    case "runStarted":
      hideAuth();
      els.runStatus.textContent = "Running…";
      setRunning(true);
      break;
    case "phaseStarted":
      setPhase(event.phase, "running", "…");
      setOpSub(`Phase: ${event.phase}`);
      break;
    case "phaseProgress": {
      const counter =
        event.total > 0 ? `[${event.current}/${event.total}] ` : "";
      setPhase(event.phase, "running", counter + (event.message || ""));
      break;
    }
    case "phaseCompleted":
      setPhase(event.phase, event.status); // ok | skipped | failed
      break;
    case "log":
      logLine(
        `[${event.level}] ${event.message}` +
          (event.code ? `  (${event.code})` : ""),
        event.level
      );
      if (event.remediation) logLine("   → " + event.remediation, "hint");
      break;
    case "warning":
      logLine(`[warn] ${event.message}  (${event.code})`, "warn");
      break;
    case "authInfo":
      logLine(`[auth] ${event.message || ""}`);
      break;
    case "authBrowser":
      showAuth(
        `<p>${escapeHtml(
          event.message || "Opening the system browser to sign in…"
        )}</p>`
      );
      logLine(`[auth] ${event.message || "browser sign-in"}`);
      break;
    case "authDeviceCode": {
      authVerificationUri =
        event.verificationUri || "https://microsoft.com/devicelogin";
      authRawBuffer = "";
      shownDeviceCode = event.userCode || "";
      renderDeviceCodePanel(authVerificationUri, shownDeviceCode);
      logLine(`[auth] device-code sign-in → ${authVerificationUri}`, "warn");
      break;
    }
    case "authSucceeded":
      hideAuth();
      resetAuthCapture();
      logLine(
        `[auth] signed in${event.account ? " as " + event.account : ""}`,
        "ok"
      );
      break;
    case "authFailed":
      resetAuthCapture();
      showAuth(
        `<p class="logln error">Sign-in failed: ${escapeHtml(
          event.message
        )}</p>` +
          (event.remediation
            ? `<p class="muted">→ ${escapeHtml(event.remediation)}</p>`
            : "")
      );
      logLine(`[auth] sign-in failed: ${event.message}`, "error");
      break;
    case "runCancelled":
      logLine(`[cancel] ${event.reason}`, "warn");
      els.runStatus.textContent = "Cancelling… (finishing the current step)";
      els.runStatus.className = "run-status st-Cancelled";
      break;
    case "runResult": {
      runHadResult = true;
      els.runStatus.textContent = `${event.status} — see Result`;
      els.runStatus.className = "run-status st-" + event.status;
      renderResult(event);
      setRunning(false);
      endOp();
      break;
    }
    case "unknown":
    default:
      // Forward-compat: ignore quietly (matches the engine renderer).
      break;
  }
}

async function runAssessment() {
  resetView();
  hideAuth();
  resetAuthCapture();
  runHadResult = false;
  processTail = [];
  const tenant = els.tenant.value.trim();
  const modules = selectedModules();
  const deepDives = selectedDeepDives();
  const authMethod = els.authMode.value;
  // "In concert" (plan §1): the run additionally opens a campaign,
  // reusing the privileged roster it already builds.
  const openAccessReview = !!(els.inConcert && els.inConcert.checked);
  lastRunModules = modules;
  if (!tenant) {
    els.runStatus.textContent = "Enter a tenant name before running.";
    els.runStatus.className = "run-status st-Failed";
    return;
  }
  if (!modules.length) {
    els.runStatus.textContent = "Select at least one module before running.";
    els.runStatus.className = "run-status st-Failed";
    return;
  }
  setRunning(true);
  els.runStatus.textContent = "Starting…";
  // Indeterminate banner with live elapsed time. The Phases card
  // below still shows real per-phase ok/running/failed state — the
  // banner just promises "still alive" at the top.
  startOp("Assessment running", {
    sub: "Waiting for the first phase…",
  });
  try {
    await invoke("run_assessment", {
      tenant,
      modules,
      authMethod,
      deepDives,
      openAccessReview,
      campaignDir: campaignDir(),
    });
  } catch (e) {
    els.runStatus.textContent = `Could not start: ${e}`;
    els.runStatus.classList.add("st-Failed");
    setRunning(false);
    endOp();
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  els = {
    tenant: document.querySelector("#tenant"),
    authMode: document.querySelector("#auth-mode"),
    moduleChecks: Array.from(document.querySelectorAll("[data-module]")),
    deepDiveChecks: Array.from(document.querySelectorAll("[data-deepdive]")),
    run: document.querySelector("#btn-run"),
    runStatus: document.querySelector("#run-status"),
    phases: document.querySelector("#phases"),
    log: document.querySelector("#log-pane"),
    banner: document.querySelector("#schema-banner"),
    cancel: document.querySelector("#btn-cancel"),
    authPanel: document.querySelector("#auth-panel"),
    authBody: document.querySelector("#auth-body"),
    resultCard: document.querySelector("#result-card"),
    resultBadge: document.querySelector("#result-badge"),
    resultSummary: document.querySelector("#result-summary"),
    resultSoc2: document.querySelector("#result-soc2"),
    resultArtifacts: document.querySelector("#result-artifacts"),
    resultErrors: document.querySelector("#result-errors"),
    readinessList: document.querySelector("#readiness-list"),
    readinessHint: document.querySelector("#readiness-hint"),
    readinessBtn: document.querySelector("#btn-readiness"),
    inConcert: document.querySelector("#chk-access-review"),
    arDirHint: document.querySelector("#ar-dir-hint"),
    arDir: document.querySelector("#ar-dir"),
    arList: document.querySelector("#ar-list"),
    arCount: document.querySelector("#ar-count"),
    arStatus: document.querySelector("#ar-status"),
    arRefresh: document.querySelector("#btn-ar-refresh"),
    arFolder: document.querySelector("#btn-ar-folder"),
    arOpen: document.querySelector("#btn-ar-open"),
    arWorksheet: document.querySelector("#btn-ar-worksheet"),
    arClose: document.querySelector("#btn-ar-close"),
    arReport: document.querySelector("#btn-ar-report"),
    arRemediate: document.querySelector("#btn-ar-remediate"),
  };
  document.querySelector("#btn-run").addEventListener("click", runAssessment);
  document.querySelector("#btn-cancel").addEventListener("click", cancelRun);
  document.querySelector("#btn-readiness").addEventListener("click", loadReadiness);
  document
    .querySelector("#btn-mod-all")
    .addEventListener("click", () => setModuleSelection("all"));
  document
    .querySelector("#btn-mod-core")
    .addEventListener("click", () => setModuleSelection("core"));
  const ddAllBtn = document.querySelector("#btn-dd-all");
  if (ddAllBtn) {
    ddAllBtn.addEventListener("click", () => setDeepDiveSelection("all"));
  }
  const ddNoneBtn = document.querySelector("#btn-dd-none");
  if (ddNoneBtn) {
    ddNoneBtn.addEventListener("click", () => setDeepDiveSelection("none"));
  }

  if (els.arDir) {
    els.arDir.value = loadCampaignDir() || (await defaultCampaignDir());
    saveCampaignDir(els.arDir.value);
    updateCampaignDirHint();
    // `change` (not `input`): one write and one directory read per edit,
    // not one per keystroke.
    els.arDir.addEventListener("change", () => {
      saveCampaignDir(campaignDir());
      updateCampaignDirHint();
      refreshCampaigns();
    });
  }
  const arActions = [
    ["#btn-ar-refresh", refreshCampaigns],
    ["#btn-ar-folder", openCampaignFolder],
    ["#btn-ar-open", () => runAccessReview("Open")],
    ["#btn-ar-worksheet", openWorksheet],
    ["#btn-ar-close", () => runAccessReview("Close")],
    ["#btn-ar-report", () => runAccessReview("Report")],
    ["#btn-ar-remediate", () => runAccessReview("Remediate")],
  ];
  arActions.forEach(([sel, fn]) => {
    const btn = document.querySelector(sel);
    if (btn) btn.addEventListener("click", fn);
  });

  try {
    supportedMajor = await invoke("supported_schema_major");
  } catch (_) {
    /* keep default */
  }

  listen("run:event", (e) => onEvent(e.payload));
  listen("run:cancelling", () => {
    els.runStatus.textContent = "Cancelling… (finishing the current step)";
    els.runStatus.className = "run-status st-Cancelled";
  });
  listen("run:exit", (e) => {
    const code = Number(e.payload);
    logProcessLine(
      `[process exited ${e.payload}]`,
      code === 0 ? undefined : "warn"
    );
    if (!runHadResult) {
      synthesizeFailedResult(
        code === 0 ? "process.noResult" : "process.exit",
        code === 0
          ? "The assessment finished without producing a final result. The most likely cause is a PowerShell or sign-in error early in the run."
          : `The assessment ended early and didn't produce a result (exit code ${e.payload}).`,
        "Open the Log section below to see what failed, fix the underlying problem (typically a sign-in or missing-module error), then run the assessment again."
      );
    }
    setRunning(false);
    endOp();
    // A campaign action — or an in-concert assessment — may have just
    // created or closed one, so re-read the folder either way.
    refreshCampaigns();
  });
  listen("run:error", (e) => {
    logProcessLine(`[process error] ${e.payload}`, "error");
    synthesizeFailedResult(
      "process.spawnFailed",
      `The PowerShell process could not be started or streamed: ${e.payload}`,
      "Verify PowerShell 7 is installed and the bundled EntraChecks scripts are present."
    );
    setRunning(false);
    endOp();
  });
  listen("run:stderr-line", (e) => {
    // Engine stderr (pwsh exception text, AMSI blocks, anything
    // non-NDJSON). Red so it pops next to the contract events.
    logProcessLine(`[engine-stderr] ${e.payload}`, "error");
  });
  listen("run:stdout-line", (e) => {
    maybeCaptureDeviceCode(e.payload);
    logProcessLine(`[engine] ${e.payload}`);
  });
  listen("run:stdout-fragment", (e) => {
    maybeCaptureDeviceCode(e.payload);
  });
  listen("update:available", (e) => {
    // Defensive: only surface the banner with a valid payload. If
    // some future engine emits a malformed update event, don't show
    // a context-less "Download" button.
    const m = e.payload || {};
    if (!m.version || !m.url) return;
    const text = document.querySelector("#update-text");
    const banner = document.querySelector("#update-banner");
    text.textContent =
      `A newer EntraChecks (v${m.version}) is available` +
      (m.notes ? ` — ${m.notes}` : ".");
    banner.classList.remove("hidden");
    document.querySelector("#btn-update-download").onclick = () =>
      invoke("open_external", { target: m.url }).catch((err) =>
        logLine(`[update] open failed: ${err}`, "warn")
      );
    document.querySelector("#btn-update-dismiss").onclick = () =>
      banner.classList.add("hidden");
  });
  // Silent on failure: invoke with no URL uses DEFAULT_MANIFEST_URL.
  invoke("check_update", { url: null }).catch(() => {
    /* no-op; the policy is silent failure */
  });

  listen("install:line", (e) => {
    // Install-Prerequisites.ps1 emits:
    //   [plan] total=N       — once, up front (drives the bar).
    //   [*] Installing X     — per module, when it starts.
    //   [*] Upgrading X      — same, on upgrade path.
    //   [+] X v... installed successfully   — per module, on done.
    //   [+] X v... already installed - ...  — same, on skip-because-present.
    //   [X] Failed to install X : message   — per module, on fail.
    // Colour-code; advance the progress bar; keep the Log pane as
    // the source of truth.
    const raw = String(e.payload || "");

    // Bar-driving markers (process first so the bar updates promptly).
    const planMatch = raw.match(/^\s*\[plan\]\s+total=(\d+)/);
    if (planMatch) {
      installTotal = parseInt(planMatch[1], 10);
      installDone = 0;
      setOpTotal(installTotal);
      setOpSub(`0 of ${installTotal} modules complete · preparing…`);
    }
    const startMatch = raw.match(
      /^\s*\[\*\]\s+(?:Installing|Upgrading)\s+(\S+)/
    );
    if (startMatch) {
      installCurrent = startMatch[1];
      const total = installTotal ?? "?";
      setOpSub(
        `Installing ${installCurrent} · ${installDone} of ${total} complete`
      );
    }
    const doneMatch = raw.match(
      /^\s*\[\+\]\s+(\S+)\s+v\S+\s+(?:installed successfully|already installed)/
    );
    if (doneMatch) {
      installDone += 1;
      const total = installTotal ?? "?";
      setOpProgress(
        installTotal ? installDone : null,
        `${installDone} of ${total} modules complete · last: ${doneMatch[1]}`
      );
    }

    // Colour-coded log line.
    let cls;
    if (/^\s*\[X\]/.test(raw)) cls = "error";
    else if (/^\s*\[!\]/.test(raw)) cls = "warn";
    else if (/^\s*\[\+\]/.test(raw)) cls = "ok";
    else if (
      raw.toLowerCase().includes("error") ||
      raw.toLowerCase().includes("exception")
    )
      cls = "error";
    logLine(`[install] ${raw}`, cls);
  });
  listen("install:exit", async (e) => {
    logLine(`[install] exited ${e.payload}`, e.payload === 0 ? "ok" : "warn");
    setInstalling(false);
    endOp();
    await refreshWingetAvailability();
    await loadReadiness();
  });
  listen("install:error", (e) => {
    logLine(`[install] error: ${e.payload}`, "error");
    setInstalling(false);
    endOp();
  });

  await refreshWingetAvailability();
  await loadReadiness();
  await refreshCampaigns();
});
