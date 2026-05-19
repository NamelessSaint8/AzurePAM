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

  const mods = ev.modulesRun && ev.modulesRun.length
    ? ev.modulesRun.join(", ")
    : "—";
  els.resultSummary.innerHTML =
    metric("Findings", ev.findings) +
    metric("Critical", ev.critical, ev.critical > 0 ? "sev-crit" : "") +
    metric("High", ev.high, ev.high > 0 ? "sev-high" : "") +
    metric("Medium", ev.medium) +
    metric("Low", ev.low) +
    metric("Modules", mods);

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

function setRunning(on) {
  els.run.disabled = on;
  els.cancel.classList.toggle("hidden", !on);
  els.cancel.disabled = false;
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
      resetView();
      hideAuth();
      els.runStatus.textContent = "Running…";
      setRunning(true);
      break;
    case "phaseStarted":
      setPhase(event.phase, "running", "…");
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
      const codeBlock = event.userCode
        ? `<div class="dc-code">${escapeHtml(event.userCode)}</div>`
        : `<p class="muted">The sign-in code is printed on the console
           output below (the Graph SDK owns it).</p>`;
      showAuth(
        `<p>To sign in, open the verification page and enter the code:</p>
         ${codeBlock}
         <p><button id="dc-open" class="link">Open ${escapeHtml(
           event.verificationUri
         )}</button></p>`
      );
      const b = document.querySelector("#dc-open");
      if (b)
        b.addEventListener("click", () =>
          invoke("open_external", { target: event.verificationUri }).catch(
            (e) => logLine(`[auth] could not open browser: ${e}`, "warn")
          )
        );
      logLine(`[auth] device-code sign-in → ${event.verificationUri}`, "warn");
      break;
    }
    case "authSucceeded":
      hideAuth();
      logLine(
        `[auth] signed in${event.account ? " as " + event.account : ""}`,
        "ok"
      );
      break;
    case "authFailed":
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
      els.runStatus.textContent = `${event.status} — see Result`;
      els.runStatus.className = "run-status st-" + event.status;
      renderResult(event);
      setRunning(false);
      break;
    }
    case "unknown":
    default:
      // Forward-compat: ignore quietly (matches the engine renderer).
      break;
  }
}

async function discover() {
  els.pwsh.textContent = "pwsh: checking…";
  try {
    const info = await invoke("discover_pwsh_cmd");
    els.pwsh.textContent = `pwsh: ${info.version} — ${info.path}`;
    els.pwsh.classList.remove("err");
  } catch (e) {
    els.pwsh.textContent = `pwsh: ${e}`;
    els.pwsh.classList.add("err");
  }
}

async function runAssessment() {
  resetView();
  hideAuth();
  setRunning(true);
  els.runStatus.textContent = "Starting…";
  try {
    await invoke("run_assessment", {
      tenant: els.tenant.value,
      skipAuth: els.skipAuth.checked,
    });
  } catch (e) {
    els.runStatus.textContent = `Could not start: ${e}`;
    els.runStatus.classList.add("st-Failed");
    setRunning(false);
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  els = {
    tenant: document.querySelector("#tenant"),
    skipAuth: document.querySelector("#skip-auth"),
    run: document.querySelector("#btn-run"),
    pwsh: document.querySelector("#pwsh-status"),
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
  };
  document.querySelector("#btn-run").addEventListener("click", runAssessment);
  document.querySelector("#btn-cancel").addEventListener("click", cancelRun);
  document.querySelector("#btn-discover").addEventListener("click", discover);

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
    logLine(`[process exited ${e.payload}]`);
    setRunning(false);
  });
  listen("run:error", (e) => {
    logLine(`[process error] ${e.payload}`, "error");
    setRunning(false);
  });

  discover();
});
