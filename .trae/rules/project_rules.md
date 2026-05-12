# Project Rules - UAP-IW Preparation Tools

## Environment

This project runs on Windows.

Use:
- Python 3
- PowerShell as the preferred shell
- Windows-compatible paths and commands
- virtual environment named `.venv`
- `requirements.txt` for dependencies

The scripts must work primarily on Windows. Linux/macOS compatibility is welcome only if it does not complicate or break Windows behavior.

## Target devices

The target devices are exclusively Ubiquiti UniFi UAP-IW access points, also known as U2IW.

This project must not be used for other UniFi In-Wall models or other UniFi access points.

Do not confuse UAP-IW / U2IW with:
- UAP-AC-IW
- UAP-AC-IW-PRO
- UAP-IW-HD
- UAP-LR
- UAP-Pro
- UAP-AC-Lite
- UAP-AC-Pro
- any other UniFi AP model

Default SSH credentials for factory-reset UAP-IW devices are:

- username: `ubnt`
- password: `ubnt`

## Firmware safety rule

The firmware file:

`BZ.qca933x.v4.3.28.11361.210128.2309.bin`

is intended only for Ubiquiti UniFi UAP-IW / U2IW access points.

This firmware must never be uploaded or installed on any other UniFi model.

Before any future firmware upgrade operation, the script must verify that the device is a UAP-IW / U2IW using read-only identification data (not `/etc/version`).

Primary sources:
- `cat /etc/board.info` (e.g. `board.shortname=U2IW`, `board.name=UAP-InWall`)
- `mca-cli-op info` (e.g. `Model: UAP-InWall`)

If the device cannot be identified as UAP-IW / U2IW, the script must mark the device as:

`MODEL_FAMILY_MISMATCH`

and must not upload or install the firmware.

Notes:
- `/etc/version` may return values like `BZ.v4.3.28` and must not be used as the sole check for model/platform family.
- For Phase 1, this model-family check is only informational and must be reported in the CSV/JSON output.
- For Phase 2, this check will be mandatory and must block the upgrade.

## Safety rules

The project is divided into three phases.

### Phase 1

Phase 1 is inventory-only.

Phase 1 scripts may:
- read CSV files
- scan a subnet
- read ARP table
- ping devices
- test SSH login
- run read-only commands such as `cat /etc/version`
- generate CSV/JSON reports

Phase 1 scripts must NOT:
- upload firmware
- run firmware upgrade commands
- run `set-inform`
- change configuration on access points
- reboot access points
- delete files from access points

Phase 1 scripts should try to collect read-only model/platform information using commands such as:

- `cat /etc/version`
- `cat /etc/board.info`
- `mca-cli-op info`

These commands may not all be available on every firmware version, so failures must be handled gracefully.

Phase 1 must report whether the firmware/platform appears compatible with the expected UAP-IW / U2IW family.

### Phase 2

Phase 2 will handle firmware upload and upgrade, but only when explicitly requested.

### Phase 3

Phase 3 will handle `set-inform`, but only when explicitly requested.

## Code style

Write clear, modular Python code.

Use functions such as:
- `normalize_mac()`
- `read_input_csv()`
- `ping_host()`
- `ping_sweep()`
- `parse_arp_table()`
- `ssh_read_firmware()`
- `write_csv_report()`
- `write_json_report()`
- `main()`

Use:
- `argparse`
- `csv`
- `json`
- `ipaddress`
- `subprocess`
- `concurrent.futures.ThreadPoolExecutor`
- `paramiko`

Handle errors gracefully.

One failed AP must not stop the whole script.

## Reporting

Every script must generate clear output and a final report.

Reports should include:
- MAC address
- location
- IP address
- whether IP was found
- ping result
- SSH result
- firmware version
- firmware family
- whether firmware family matches `BZ.qca933x`
- detected model or board information, if available
- status
- error message

## Important

Never assume the access point can be modified unless the current phase explicitly allows it.

For Phase 1, all operations must be read-only.
