# Project Rules - UAP-IW Preparation Tools

## Environment

Windows-first.

Use:
- Python 3
- PowerShell (preferred shell)
- Windows-compatible paths/commands
- `.venv` (optional) and `requirements.txt`

## Target Devices (Non-Negotiable)

Only **Ubiquiti UniFi UAP-IW / U2IW**.

Never use this workflow for:
- UAP-AC-IW
- UAP-AC-IW-PRO
- UAP-IW-HD
- UAP-LR
- UAP-Pro
- UAP-AC-Lite
- UAP-AC-Pro
- any other UniFi model

Default SSH creds for factory-reset UAP-IW/U2IW:
- user: `ubnt`
- pass: `ubnt`

## Model / Firmware Safety Gating

- `/etc/version` is **NOT** a model/platform safety check.
- Model gating must use read-only identification:
  - `cat /etc/board.info`:
    - `board.shortname=U2IW`
    - `board.name=UAP-InWall`
  - and/or `mca-cli-op info`:
    - `Model: UAP-InWall`
- `firmware_family` (e.g. `BZ.qca933x`) is informational only and must not be the primary safety gate.
- Phase 2 must upload/upgrade only when `model_family_status=MODEL_FAMILY_OK`.
- If model is unknown or mismatch, skip (no upload, no upgrade).

## Phases

### Phase 1 (Implemented) — Read-Only Inventory

Allowed:
- read CSV input
- ping sweep (subnet scan)
- ARP/neighbor MAC->IP discovery
- SSH read-only probes
- read-only commands:
  - `cat /etc/version` (version info only)
  - `cat /etc/board.info` (model gate source)
  - `mca-cli-op info` (model gate source)
- write CSV/JSON reports

Forbidden:
- firmware upload
- firmware upgrade commands
- `set-inform`
- reboot
- delete files
- any config change

Windows MAC->IP discovery rules:
- must use `arp -a`
- plus `Get-NetNeighbor` fallback
- `--arp-only` must be supported:
  - read ARP/neighbor only (no subnet ping sweep), then test found IPs

Ping rules:
- ping is diagnostic by default (non-blocking)
- if IP is found and ping fails, still attempt SSH
- `--require-ping` may restore strict legacy behavior (ping fail blocks SSH)
- `--ping-timeout-ms` must be configurable (Windows default should be higher than 500ms)

### Phase 2 (Implemented) — Firmware Update (Gated)

Defaults:
- dry-run by default
- dry-run must be offline / no network side effects:
  - no `pscp`
  - no destructive `plink`
  - no upgrade
  - no reboot
  - no `set-inform`

Execute mode:
- requires explicit `--execute`
- must read a Phase 1 report (JSON/CSV)

Eligible record requirements (execute):
- `ip_found=true`
- `ssh_ok=true`
- `model_family_status=MODEL_FAMILY_OK`
- `hostkey_fingerprint` present and valid `SHA256:...`
- current firmware is not already target

Skip rules (must be explicit statuses):
- already updated -> `SKIPPED_ALREADY_UPDATED`
- SSH not OK -> `SKIPPED_SSH_NOT_OK`
- missing fingerprint -> `SKIPPED_HOSTKEY_FINGERPRINT_MISSING`
- model unknown/mismatch -> skip (no upload/upgrade)

PuTTY tooling rules:
- firmware upload must use `pscp -batch -hostkey SHA256:...`
- SSH commands must use `plink -batch -hostkey SHA256:...`
- no interactive hostkey enrollment
- no `echo y`, no stdin injection, no PuTTY registry/cache writes
- hostkey mismatch is blocking (never auto-accept changed keys)

Upgrade execution rules:
- before upgrade, verify (read-only):
  - `/tmp/fwupdate.bin` exists
  - `/bin/syswrapper.sh` exists
- upgrade command must use:
  - `sh -c '/bin/syswrapper.sh upgrade2 >/tmp/upgrade.log 2>&1 &'`

Reliability:
- one failed AP must not stop the run
- `--workers 1` means sequential updates; prefer this for field operations

### Phase 3 (Planning Only) — set-inform (Not Implemented)

Do not implement Phase 3 until explicitly requested.

Constraints:
- dry-run by default
- execute requires explicit `--execute`
- `--inform-url` must be provided explicitly
- never hardcode controller URL

Eligibility (execute):
- UAP-IW/U2IW verified (same model gate sources as above)
- SSH reachable
- firmware target verified where required (from Phase 2 / Phase 1 data)
- `hostkey_fingerprint` present

Never run set-inform on:
- SSH failed devices
- model mismatch/unknown devices
- missing/invalid hostkey devices

Reporting (Phase 3):
- `inform_url`
- `set_inform_attempted`
- `set_inform_ok`
- `post_inform_status` (if readable)
- `status`
- `error`

Out of scope for Phase 3:
- no factory reset
- no firmware upload
- no reboot

## PuTTY Host Key Handling (Windows)

Required strategy:
- Phase 1:
  - first `plink -batch` probe without `-hostkey` may fail with unknown key
  - parse SHA256 fingerprint from PuTTY output
  - if `--accept-new-hostkeys` is enabled, retry with `plink -batch -hostkey SHA256:...`
  - store `hostkey_fingerprint` in Phase 1 report and set `hostkey_status=HOSTKEY_ACCEPTED_VIA_HOSTKEY_OPTION`
- Phase 2:
  - must reuse `hostkey_fingerprint` for both `plink.exe` and `pscp.exe` via `-hostkey`

Never:
- auto-accept changed/mismatch hostkeys
- use interactive enrollment
- write PuTTY registry/cache as part of automation

## Versioning (Required)

Every executable script must declare:
- `SCRIPT_NAME`
- `SCRIPT_VERSION`
- `SCRIPT_BUILD_DATE`
- `SCRIPT_SUMMARY`

Python scripts:
- must implement `--version` and exit code 0
- must print a startup banner (script/version/build) on normal runs
- CSV/JSON rows must include:
  - `script_name`, `script_version`, `script_build_date`

PowerShell:
- `setup_windows.ps1` must implement `-Version` and exit

## setup_windows.ps1 (Bootstrap Rules)

- must work on Windows without requiring Git
- may download files from the public GitHub repo
- must support Python embeddable fallback
- must support local standalone PuTTY tools under `.\tools\putty`
- must not run discovery/update automatically
- prints ready-to-run commands only

## Reporting (All Phases)

Reports must include at least:
- `script_name`, `script_version`, `script_build_date`
- MAC, location, IP, `ip_found`
- `ping_ok` (diagnostic)
- SSH result fields (`ssh_ok`, backend, errors)
- model identification fields (board/model) and `model_family_status`
- `hostkey_fingerprint` (when available) and hostkey status/error fields
- firmware version fields (version info only)
- `status`, `error`

## Important

Never assume an AP can be modified unless the current phase explicitly allows it.
