# AGENTS.md

## Purpose

This file is the main operating contract for Codex work in this repository.

The repository contains Windows-first Python and PowerShell tools for safe operational work on Ubiquiti UniFi UAP-IW / U2IW access points.

Safety is more important than speed.

## Target Scope

The only supported target devices are:

- Ubiquiti UniFi UAP-IW
- Ubiquiti UniFi U2IW

Codex must never assume that another device model is safe to modify.

Unknown, incomplete, or mismatched model evidence must block any modifying operation.

## Phase Permissions

### Phase 1: Discovery and Inventory

Phase 1 is read-only.

Allowed operations:

- Read input CSV files.
- Discover IP addresses.
- Ping devices.
- Attempt SSH authentication.
- Read firmware and model information.
- Generate local CSV or JSON reports.

Forbidden operations:

- Firmware upload.
- Firmware update.
- Reboot.
- Set-inform.
- Device configuration changes.
- File deletion on access points.
- Any command intended to modify an access point.

### Phase 2: Firmware Update

Phase 2 is gated and dry-run by default.

Allowed in dry-run mode:

- Read Phase 1 reports.
- Validate model evidence.
- Validate firmware path and target version.
- Produce a planned update report.
- Skip unsafe, unknown, mismatched, or incomplete records.

Allowed in execute mode only when the human explicitly requests execution and the command uses `--execute`:

- Upload compatible firmware.
- Start firmware upgrade.
- Wait for reboot/back-online checks.
- Perform post-update verification.

Required gates:

- Device must be identified as UAP-IW / U2IW.
- Model family status must be safe.
- Firmware must match the expected compatible family.
- Hostkey fingerprint handling must be explicit and controlled.
- Unknown or mismatched devices must be skipped.

### Phase 3: Set-Inform

Phase 3 is gated and dry-run by default.

Allowed in dry-run mode:

- Read Phase 1 or Phase 2 reports.
- Validate candidate devices.
- Validate the inform URL.
- Produce a planned set-inform report.
- Skip unsafe, unknown, mismatched, or incomplete records.

Allowed in execute mode only when the human explicitly requests execution and the command uses `--execute`:

- Run set-inform only on eligible UAP-IW / U2IW devices.
- Perform post-check verification.

Required gates:

- Inform URL must be provided explicitly.
- Inform URL must never be hardcoded as an implicit operation.
- Device must be identified as UAP-IW / U2IW.
- Unknown or mismatched devices must be skipped.
- Hostkey fingerprint handling must be explicit and controlled.

## Forbidden Operations

Codex must never suggest or execute firmware update, set-inform, reboot, upload, delete, or configuration-changing operations unless all of the following are true:

- The current project phase explicitly allows the operation.
- The human explicitly requests execution.
- The implementation preserves dry-run defaults.
- The command uses the required explicit execution flag where applicable.
- Safety gates for model, firmware, hostkey, and report evidence pass.

Hostkey mismatch must never be auto-accepted.

New hostkey handling must remain explicit and controlled.

Codex must never weaken existing dry-run defaults.

Codex must never broaden device eligibility beyond UAP-IW / U2IW without explicit human approval and matching safety tests.

## Proposal-Before-Patch Workflow

Before proposing any implementation, Codex must explain:

1. What it understood.
2. What it intends to change.
3. Which files would be affected.
4. The risk level.
5. How it would test or verify the change.
6. The proposed commit message.

Codex must not modify code or documentation unless the human explicitly approves the implementation proposal.

Approval for discussion is not approval for file changes.

## Verification Requirements

Every implementation proposal must include a verification section before any repository change is made.

For documentation-only changes, markdown review is sufficient unless the human asks for more.

For Python changes, verification should normally include:

- `python -m py_compile` for affected scripts.
- Focused unit tests if tests exist.
- Dry-run commands only, unless the human explicitly requested execute-mode operational work.

For PowerShell changes, verification should normally include:

- Syntax or parse validation where practical.
- `-Version` or no-operation checks where available.
- No AP-modifying commands unless explicitly requested and phase-allowed.

## Implementation Rules

Codex must prefer small, reviewable, independently testable changes.

Codex must preserve existing operational safety behavior unless the human explicitly approves a safety-changing proposal.

Codex must not run destructive commands.

Codex must not create commits or pull requests unless explicitly requested.

Codex must not modify real operational inputs or outputs, including:

- `aps.csv`
- real reports
- credentials
- production logs
- device-specific secrets

Codex must avoid guessing from missing runtime evidence. If evidence is missing, Codex should ask for the minimum needed information, such as:

- exact command run;
- script version;
- sanitized report row;
- relevant stdout/stderr;
- whether the run was dry-run or execute mode.

## Commit Message Requirement

After approved work is completed, Codex must suggest a final commit message.

The commit message should be concise and describe the actual change, for example:

```text
docs: add Codex operating rules
```

## Legacy TRAE Rules

This repository was previously guided by TRAE rules.

`AGENTS.md` is the primary operating contract for future Codex work. Legacy TRAE documents may remain as historical context, but Codex should follow this file first when instructions conflict, unless the human explicitly says otherwise.
