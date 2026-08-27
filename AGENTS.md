# AGENTS.md

## Purpose

This file is the primary operating contract for Codex work in this repository.

The long-term project is a Windows-first, vendor-neutral toolkit for safe wireless access-point lifecycle management: discovery, inventory, identification, firmware management, update orchestration, provisioning preparation, reporting, and a future local web interface.

Ubiquiti UniFi is the first and currently only implemented vendor family. This does not imply support for other Ubiquiti families such as airMAX, UISP, EdgeMAX, or Protect. Safety is more important than speed.

## Safety State Model

```text
DISCOVERED
-> IDENTIFIED
-> SUPPORTED
-> MODIFICATION_ELIGIBLE
```

- `DISCOVERED`: the device was found and may be reported.
- `IDENTIFIED`: evidence describes its vendor, model, or platform.
- `SUPPORTED`: explicit implementation and compatibility policy exist for the workflow.
- `MODIFICATION_ELIGIBLE`: every operation-specific gate passed for the exact device and transition.

Discovery, identification, vendor recognition, firmware availability, or archival status never authorizes modification by itself. Unknown, incomplete, ambiguous, contradictory, unsupported, or mismatched evidence blocks every modifying operation.

## Current Executable Support

Current scripts implement Ubiquiti UniFi workflows. UAP-IW / U2IW remain supported through their existing legacy compatibility path. U6+ is supported for the exact data-driven Phase 2 transition declared in `compatibility/ubiquiti_unifi_firmware.json` and for the separately authorized, exact post-Phase-2 Phase 3 policy described below.

Other UniFi devices may be discovered and reported during read-only inventory. They remain ineligible for firmware update, set-inform, provisioning, reboot, upload, or configuration changes until a separately approved patch defines and tests exact model, platform, firmware, host-key, report, and operation gates.

U6+ is not generally modification-eligible. Only exact operation-specific policy may authorize its firmware transition or set-inform workflow. The presence of an MT7981 firmware file, a compatibility profile, an artifact, or an approved firmware transition alone never authorizes another operation.

Adding an adapter, recognizing a model, or adding metadata must not silently broaden eligibility.

## Long-Term Architecture Direction

Implement this architecture only through separately proposed, reviewable patches.

The generic core should eventually provide discovery orchestration, inventory and normalized device models, identification evidence, compatibility evaluation, firmware catalog/resolution/cache/acquisition, integrity verification, update orchestration, reporting, safety policy, and operation planning.

Vendor-specific behavior should eventually live in adapters such as `ubiquiti/unifi`, `tp-link/omada`, Aruba, Cisco, and Ruckus. Adapters—not the generic core—should own `UAPL6`, `BZ.MT7981`, `/etc/board.info`, `mca-cli-op`, UniFi `set-inform`, and vendor-specific upgrade commands.

Operational logic should progressively move away from `argparse` and `print` coupling into reusable services accepting structured inputs and returning structured plans/results. CLI and future local web frontends should use the same services.

## Phase Permissions

### Phase 1: Discovery and Inventory

Phase 1 is read-only.

Allowed:

- Read input CSV files.
- Discover IP addresses and ping devices.
- Attempt SSH authentication.
- Read firmware and model information.
- Report unknown or unsupported devices without granting eligibility.
- Generate local CSV or JSON reports.

Forbidden:

- Firmware upload or update.
- Reboot.
- Set-inform or adoption.
- Device configuration changes.
- File deletion on access points.
- Any command intended to modify an access point.

### Phase 2: Firmware Update

Phase 2 is gated and dry-run by default.

Dry-run may read Phase 1 reports, validate model/firmware evidence, produce a plan, and skip unsafe, unknown, mismatched, unsupported, or incomplete records.

Execute mode is allowed only when the human explicitly requests execution and the command uses `--execute`. It may upload explicitly compatible firmware, start an approved transition, wait for reboot/back-online checks, and perform post-update verification.

Current required gates:

- Device is identified as UAP-IW / U2IW.
- Model family status is safe.
- Firmware matches the expected compatible family and requested target.
- Host-key fingerprint handling is explicit and controlled.
- Unknown, mismatched, or unsupported devices are skipped.

Future vendor/model support must use exact compatibility evidence and preserve default-deny behavior.

### Data-Driven Firmware Compatibility

U6+ is the first data-driven compatibility profile. UAP-IW / U2IW temporarily remain on the legacy compatibility path as deliberate regression-risk containment; a later approved patch may migrate them to the catalog.

Compatibility data must keep these entities separate:

```text
DEVICE PROFILE != FIRMWARE ARTIFACT != TRANSITION RULE
```

A commercial model alone is insufficient compatibility proof. Exact board, hardware, platform, and hardware-revision evidence must be used where reliably available because one commercial model may require different firmware on different revisions. Missing, conflicting, or ambiguous required identity evidence is default-deny.

Adding another approved firmware/version for already-understood hardware should normally require compatibility-catalog changes, not operational Python changes. Operational code should normally change only for new identification behavior, protocols, upgrade mechanisms, validation requirements, or other capabilities.

Firmware compatibility authorization is operation-specific. Catalog presence or firmware-transition approval must never silently grant set-inform, adoption, reboot, configuration, or any other modifying permission. Every modifying workflow requires its own explicit allow policy and live gates.

### Phase 3: Set-Inform

Phase 3 is implemented, gated, and dry-run by default. Set-inform is a UniFi-specific adapter concern in the future architecture.

Dry-run may read Phase 1/2 reports for legacy devices and qualifying Phase 2 reports for declarative devices, validate candidates and the explicitly supplied inform URL, produce a plan, and skip unsafe records. A valid dry-run plan is not modification-eligible and must not perform network operations.

Execute mode is allowed only when explicitly requested and the command uses `--execute`. It may run set-inform and post-checks through two explicit, non-fallback paths:

- `LEGACY_UAP_IW_U2IW`: existing UAP-IW / U2IW behavior and gates.
- `DECLARATIVE_CATALOG`: only profile `ubiquiti-unifi-u6plus-uapl6`, artifact `ubiquiti-unifi-u6plus-6.7.54.15663`, short version `BZ.6.7.54`, and full version `6.7.54.15663`, under the separate Phase 3 operation policy.

Declarative U6+ Phase 3 requires a qualifying Phase 2 `UPDATE_COMPLETED` or exact-evidence `SKIPPED_ALREADY_UPDATED` report. Phase 1 U6+ reports are not eligible. Before set-inform, pinned-hostkey live reads of `/etc/version`, `/etc/board.info`, and `mca-cli-op info` must uniquely reproduce the expected profile, report identity, and exact short/full target firmware. Only then may the row become modification-eligible with `LIVE_PREFLIGHT_OK`.

`--allow-non-target-firmware` retains only its legacy meaning and must never bypass declarative identity, report, profile, artifact, target-version, host-key, or live gates.

The inform URL must never be implicit or hardcoded. Unknown, mismatched, unsupported, or host-key-unsafe devices must be skipped.

## Firmware Policy

Firmware differs from ordinary runtime dependencies. Historical AP firmware may disappear from official sources, so the project ecosystem should support verified preservation.

```text
MAIN SOFTWARE REPOSITORY
- code and vendor adapters
- compatibility and firmware metadata
- reviewed runtime assets
- CLI and future web UI

SECONDARY FIRMWARE ARCHIVE
- preserved redistributable binaries
- historical versions
- metadata, provenance, size, and SHA256
```

The archive may be a separate repository, GitHub Releases, or another multi-vendor storage backend. If redistribution is prohibited, retain metadata, hashes, provenance, and source references without publishing the binary.

Metadata should eventually include vendor, product family, model, hardware/board identifier, firmware family/platform, version, build, filename, size, SHA256, release date, original source, archive date, provenance, and redistribution status.

```text
ARCHIVED / AVAILABLE
!= COMPATIBLE
!= RECOMMENDED
!= ALLOWED FOR THIS TRANSITION
```

Future resolution should distinguish local firmware cache, official vendor source (normally preferred), and verified project archive fallback. Every usable artifact must pass explicit compatibility evaluation and SHA256 verification. Filename, location, source, or archival status alone never authorizes installation.

The two currently tracked firmware binaries and `firmware/.gitkeep` are intentional and must not be removed or relocated without an approved migration.

## Runtime and Local-First Assets

The application should eventually start without Internet availability. Directory semantics:

```text
vendor/      reviewed/versioned third-party runtime assets
downloads/   temporary network download and cache data
tools/       generated, installed, or extracted runtime state
firmware/    local firmware working/cache area
```

```text
versioned local vendor/runtime assets
-> generated/extracted tools
-> network only as an optional fallback
```

Python/bootstrap assets, cached wheels and pinned dependencies, and PuTTY or equivalent utilities should eventually be local. `requirements.txt` alone is not a true offline installation. Strict offline behavior and asset relocation require separate approval. Never commit unreviewed downloaded bootstrap files merely because they exist locally.

## Forbidden Operations

Never suggest or execute firmware update, set-inform, reboot, upload, delete, or configuration-changing operations unless:

- The current phase allows it.
- The human explicitly requests execution.
- Dry-run defaults remain intact.
- The required execution flag is present.
- Exact vendor, model/platform, firmware, host-key, report-evidence, and phase gates pass.

Host-key mismatch must never be auto-accepted. New host-key handling must remain explicit and controlled. Never weaken dry-run defaults or broaden eligibility without explicit approval and matching safety tests.

## Proposal-Before-Patch Workflow

Before implementation, explain:

1. What was understood.
2. What will change.
3. Which files are affected.
4. Risk level.
5. Verification plan.
6. Proposed commit message.

Do not modify code or documentation until the human explicitly approves the proposal. Approval for discussion is not approval for changes.

## Verification Requirements

Every proposal must include verification before repository changes.

- Documentation-only changes normally require markdown review.
- Python changes normally require `python -m py_compile`, focused tests where available, and dry-run commands unless execute-mode work was explicitly authorized.
- PowerShell changes normally require parse validation and `-Version`/no-operation checks where available.
- Never run AP-modifying verification unless explicitly requested and phase-allowed.

## README Synchronization Requirement

Any approved functional, structural, architectural, operational, dependency-related, deployment-related, or user-visible change must update `README.md` in the same task and commit wherever documented behavior is affected.

The README must accurately describe current functionality, supported devices/vendors, architecture, important dependencies, setup and execution, operational behavior and safety constraints, and relevant functional evolution/history.

Invisible micro-refactors that do not alter architecture, behavior, setup, dependencies, commands, supported devices, or user-visible functionality do not require artificial README changes.

## Implementation Rules

Prefer small, reviewable, independently testable changes. Preserve safety behavior unless a safety-changing proposal is explicitly approved. Never run destructive commands or modify real operational data such as `aps.csv`, reports, credentials, production logs, or device-specific secrets.

Do not guess from missing runtime evidence. Ask for the minimum needed evidence: exact command, script version, sanitized report row, relevant stdout/stderr, and whether the run was dry-run or execute mode.

## Post-Implementation Commit and Push Workflow

After an approved implementation is complete and successfully verified:

1. Review `git status` and the final diff.
2. Ensure only approved task files are staged.
3. Never include unrelated pre-existing modifications or untracked files.
4. Stage exact paths; never use `git add .`, `git add -A`, or equivalent broad staging when unrelated state exists.
5. Commit all and only the task changes with a concise implementation message.
6. Push the commit to the current remote branch without force.
7. Verify and report the commit SHA and branch.

Push is part of completing approved work unless explicitly excluded for that task. Never use `--force` or `--force-with-lease`, rewrite published history, or bypass authentication, divergence, branch protection, conflicts, or other Git protections. If commit or push cannot safely complete, stop and report the exact problem. Never push before verification succeeds.

## Legacy TRAE Rules

Files under `.trae/rules/` are historical and non-normative. `AGENTS.md` is authoritative whenever legacy TRAE material differs or conflicts, unless the human explicitly instructs otherwise for a particular task.
