# Release Signing Guide (Windows)

How to produce a code-signed EntraChecks desktop build. The Phase 5.4
posture: **the pipeline is wired but artifacts ship unsigned until a
certificate exists**, by design — see
`plans/Native-App-Phase5-Packaging-Signing-Plan.md` §2.2 / §5.

## What is wired today

`app/src-tauri/tauri.conf.json` already carries:

```jsonc
"bundle": {
  "targets": ["nsis"],
  "licenseFile": "../../LICENSE",
  "windows": {
    "digestAlgorithm": "sha256",
    "timestampUrl": "http://timestamp.digicert.com",
    "tsp": true,
    "nsis": { "installMode": "currentUser" }
  }
}
```

What's intentionally absent: `bundle.windows.certificateThumbprint`.
Its absence is the contract — Tauri's NSIS bundler signs only when a
thumbprint is configured. With nothing set, `npm run tauri build`
emits an unsigned `.exe` installer; SmartScreen will warn until that
changes.

`installMode: currentUser` matches the app's no-elevation posture: the
installer writes to `%LOCALAPPDATA%`, no UAC prompt at install time.

## Cert acquisition — pick a class

- **OV (Organisation Validation)** — software-issued; `.pfx` file
  with a password. Cheapest path; SmartScreen reputation must still
  be earned by downloads/feedback.
- **EV (Extended Validation)** — hardware token / HSM-backed; ships
  on a USB token (Yubikey FIPS, SafeNet eToken, …) or as a
  cloud-HSM key (e.g. Azure Key Vault). Higher cost, but **instant
  SmartScreen reputation** for new artifacts — the practical
  difference for a brand-new app.

Either works with what Tauri / `signtool` expect; only the *invocation
mechanics* differ (file path + password vs. token/PIN, or KV signing).

## How to flip the build to signed

### Option A — set the thumbprint locally (one-off / dev)

Find the cert's SHA-1 thumbprint:

```powershell
Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
  Select-Object Subject, Thumbprint, NotAfter
```

Edit `app/src-tauri/tauri.conf.json` and add the thumbprint to the
existing `bundle.windows` block (do NOT commit a real thumbprint —
treat it like a secret):

```jsonc
"windows": {
  "digestAlgorithm": "sha256",
  "timestampUrl": "http://timestamp.digicert.com",
  "tsp": true,
  "certificateThumbprint": "AABBCCDDEEFF...",   // ← add this
  "nsis": { "installMode": "currentUser" }
}
```

Then build as usual:

```
cd app
npm install
npm run tauri build
```

Tauri invokes the Windows SDK's `signtool` with that thumbprint, the
configured digest, and the RFC3161 timestamp URL — both the bundled
binaries *and* the NSIS installer get signed.

### Option B — config overlay (recommended for CI)

Keep the committed `tauri.conf.json` thumbprint-free; pass the secret
through a separate, gitignored overlay merged at build time. Create
`app/src-tauri/tauri.signed.conf.json` on the CI runner (or locally):

```jsonc
{
  "bundle": {
    "windows": {
      "certificateThumbprint": "AABBCCDDEEFF..."
    }
  }
}
```

Build with the overlay:

```
npm run tauri build -- --config src-tauri/tauri.signed.conf.json
```

This is the model the `.github/workflows/desktop.yml` job
(Phase 5.6) uses: the `Stage signing overlay (if secret is set)` step
writes `app/src-tauri/tauri.signed.conf.json` *iff* the
`SIGN_CERT_THUMBPRINT` repo secret is non-empty, then the build runs
under either the *signed* or *unsigned* conditional step. The overlay
filename is gitignored, so a locally-generated one never accidentally
commits. To flip CI to signed: add the secret to the repository's
Settings → Secrets and variables → Actions; no code change needed.

### Option C — post-build `signtool` (manual fallback)

If you'd rather sign the produced artifacts directly (e.g. with a
script not modelled by Tauri's thumbprint field — KV signing, an EV
token PIN entry, etc.):

```
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 ^
  "app\src-tauri\target\release\bundle\nsis\EntraChecks_0.1.0_x64-setup.exe"
```

Sign both the inner `.exe` (`target\release\EntraChecks.exe`) and the
NSIS installer. The Tauri-managed path is preferred when it covers
your cert mechanics; this is the escape hatch.

## Verifying a signed artifact

```powershell
Get-AuthenticodeSignature .\EntraChecks_0.1.0_x64-setup.exe
# Status should be: Valid
# SignerCertificate / TimeStamperCertificate populated
```

Or:

```
signtool verify /pa /v EntraChecks_0.1.0_x64-setup.exe
```

`/pa` selects the default authentication policy; verification should
chain to a trusted root and report a valid timestamp.

## SmartScreen reputation

A fresh signature does not by itself remove SmartScreen's
"unrecognised app" warning — Microsoft accrues reputation over
download volume + lack of negative reports. An **EV** signature gets
this instantly; **OV** earns it over time. Documented as the accepted
interim cost in Phase 5.4 §2.

## What this guide does NOT cover

- **MSIX / Store**: out of scope (master plan §8 / Phase-5 §10).
- **Auto-update signing keypair**: distinct from Authenticode; lands
  when full Tauri-updater is adopted (currently we ship notify-only
  in step 5.6, no update artifact signing required).
- **macOS notarization**: Phase 6.
