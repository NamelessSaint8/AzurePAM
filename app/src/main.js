// Phase 4.2 — sidecar boundary debug UI.
// Drives the two Rust commands and renders the streamed stdout. No
// contract knowledge here yet (that arrives with the 4.3 parser).
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let statusEl;
let paneEl;

function log(line) {
  paneEl.textContent += line + "\n";
  paneEl.scrollTop = paneEl.scrollHeight;
}

async function discover() {
  statusEl.textContent = "pwsh: checking…";
  try {
    const info = await invoke("discover_pwsh_cmd");
    statusEl.textContent = `pwsh: ${info.version} — ${info.path}`;
    statusEl.classList.remove("err");
  } catch (e) {
    statusEl.textContent = `pwsh: ${e}`;
    statusEl.classList.add("err");
  }
}

async function probe() {
  paneEl.textContent = "";
  log("[probe started]");
  try {
    await invoke("run_sidecar_probe");
  } catch (e) {
    log(`[probe could not start] ${e}`);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  statusEl = document.querySelector("#pwsh-status");
  paneEl = document.querySelector("#debug-pane");
  document.querySelector("#btn-discover").addEventListener("click", discover);
  document.querySelector("#btn-probe").addEventListener("click", probe);

  listen("sidecar:line", (e) => log(e.payload));
  listen("sidecar:exit", (e) => log(`[exit ${e.payload}]`));
  listen("sidecar:error", (e) => log(`[error] ${e.payload}`));
});
