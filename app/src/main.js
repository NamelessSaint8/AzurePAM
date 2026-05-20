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
}

let installing = false;
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
  installing = true;
  logLine("[install] starting pwsh 7 via winget…");
  try {
    await invoke("install_pwsh_via_winget");
  } catch (e) {
    logLine(`[install] could not start: ${e}`, "error");
    installing = false;
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
  installing = true;
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
    installing = false;
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
  const authMethod = els.authMode.value;
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
          ? "The PowerShell process exited without emitting a run.result event."
          : `The PowerShell process exited before the assessment produced a result (exit code ${e.payload}).`,
        "Review the Log output above, then re-run after fixing the underlying PowerShell or authentication error."
      );
    }
    setRunning(false);
    endOp();
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
    installing = false;
    endOp();
    await refreshWingetAvailability();
    await loadReadiness();
  });
  listen("install:error", (e) => {
    logLine(`[install] error: ${e.payload}`, "error");
    installing = false;
    endOp();
  });

  await refreshWingetAvailability();
  await loadReadiness();
});
