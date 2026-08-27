# NEXT PATCH — Make UniFi discovery truly automatic

## Priority

**MANDATORY / NEXT PATCH**

This patch must be completed before relying on Phase 1 discovery for mixed-generation UniFi deployments (legacy UAP-IW, U6+, and future models).

## Problem observed

During discovery of a factory-reset **U6+**, the current Phase 1 workflow failed to find the device automatically even though it was reachable and responding on the network.

Observed device:

- IP: `192.168.0.2`
- MAC: `0C:EA:14:F0:8E:B2`
- Model: `U6+`
- Board name: `U6+`
- Board shortname: `UAPL6`
- Firmware short: `BZ.6.5.64`
- Firmware full: `6.5.64.14808`
- SSH credentials after reset: `ubnt / ubnt`
- SSH via Paramiko: working

The device was found only after manually testing `192.168.0.2`.

## Root causes

### 1. `--auto-subnet` selected the wrong subnet

The PC reported:

```text
IPv4:    192.168.1.179/24
Gateway: 192.168.0.1
```

The script selected:

```text
192.168.1.0/24
```

but the relevant LAN devices, including the U6+, were on:

```text
192.168.0.0/24
```

The resulting ping sweep found only one host and never touched `192.168.0.2`.

The auto-subnet logic must not blindly derive the scan network from the selected interface IPv4 when the default gateway clearly belongs to another subnet.

### 2. `--discover-ubiquiti` is constrained to one OUI

Current discovery defaults to:

```text
--oui-prefix 80:2A:A8
```

and filters ARP/Neighbor entries before treating them as discovered UniFi candidates.

The U6+ MAC begins with:

```text
0C:EA:14
```

Therefore, even after a correct ping sweep populated ARP/Neighbor, the device would still be rejected by the single-OUI filter.

A command named `--discover-ubiquiti` must not depend on one hardcoded Ubiquiti OUI.

### 3. ARP-only is not sufficient for discovery

`--arp-only` only sees devices already present in the Windows ARP/Neighbor cache.

Before `192.168.0.2` had been contacted, it was absent from that cache.

Therefore automatic discovery must actively probe the selected subnet(s) before relying on ARP/Neighbor.

## Required behavior

The intended user experience should be as simple as:

```cmd
tools\python-embed\python.exe uap_iw_phase1_discovery.py --auto-subnet --discover-ubiquiti --accept-new-hostkeys --out reports\discovery.csv --json reports\discovery.json
```

The user should **not** need to know:

- AP IP addresses;
- AP MAC addresses;
- Ubiquiti OUI prefixes;
- AP generation/model;
- which subnet should be manually scanned.

## Required changes

### A. Improve automatic subnet selection

When `--auto-subnet` is used:

1. Inspect active IPv4 interfaces and default gateway information.
2. Prefer the network that is actually associated with the default gateway / route used to reach the LAN.
3. Detect inconsistent situations such as:
   - interface IP in `192.168.1.0/24`;
   - default gateway in `192.168.0.0/24`.
4. Do not silently scan only a subnet that excludes the default gateway.
5. When ambiguity exists, derive and scan all reasonable directly-reachable candidate LAN subnets, while retaining protection against excessively large scans.
6. Log clearly which subnet(s) were selected and why.

At minimum, the observed case above must result in `192.168.0.0/24` being scanned.

### B. Remove single-OUI dependency from automatic UniFi discovery

Do not use a single OUI as the primary criterion for `--discover-ubiquiti`.

Recommended logic:

1. Active ping sweep of candidate subnet(s).
2. Read refreshed ARP/Neighbor table.
3. Build candidate host list from reachable unicast IPv4 addresses.
4. Identify likely UniFi devices using network/service/device interrogation rather than one vendor prefix.
5. Attempt read-only SSH interrogation with safe credentials/backends when appropriate.
6. Confirm UniFi identity from returned device data such as:
   - `/etc/version`;
   - `/etc/board.info`;
   - `mca-cli-op info`;
   - known UniFi-specific responses / fields.
7. Only after device interrogation classify model/family.

The existing `--oui-prefix` option may remain as an **optional narrowing/filtering tool**, but it must not be required for normal automatic discovery.

### C. Preserve safety guarantees

Phase 1 must remain **strictly read-only**.

The discovery patch must not:

- upload firmware;
- execute upgrades;
- reboot devices;
- run `set-inform`;
- adopt devices;
- reset devices;
- alter SSH configuration;
- change controller configuration.

### D. Keep backward compatibility

Existing workflows must continue to work:

- `--single-ip`
- `--subnet`
- `--arp-only`
- CSV-based discovery
- Paramiko / plink backends
- `--accept-new-hostkeys`
- legacy UAP-IW / U2IW discovery

Do not regress current support while adding U6+ / modern-model discovery.

## Acceptance tests

### Test 1 — U6+ observed case

Given:

```text
PC IPv4: 192.168.1.179/24
Default gateway: 192.168.0.1
U6+: 192.168.0.2
U6+ MAC: 0C:EA:14:F0:8E:B2
```

Running only:

```cmd
tools\python-embed\python.exe uap_iw_phase1_discovery.py --auto-subnet --discover-ubiquiti --accept-new-hostkeys --out reports\discovery.csv --json reports\discovery.json
```

must automatically find `192.168.0.2` and report at least:

```text
ip                  = 192.168.0.2
board_hwaddr        = 0C:EA:14:F0:8E:B2
device_model        = U6+
board_name          = U6+
board_shortname     = UAPL6
firmware_version    = BZ.6.5.64
firmware_full       = 6.5.64.14808
ssh_ok              = true
```

A model-family mismatch is acceptable until U6+ support is separately added to the compatibility layer, but the device itself **must be discovered and identified automatically**.

### Test 2 — No OUI override

The same U6+ must be discovered without passing:

```text
--oui-prefix 0C:EA:14
```

### Test 3 — Legacy compatibility

Existing UAP-IW / U2IW devices must still be discovered and identified as before.

### Test 4 — ARP cache initially empty

Clear or age out the relevant ARP entry before the test.

Automatic discovery must still find the AP by actively probing the LAN before reading ARP/Neighbor.

### Test 5 — Read-only guarantee

Verify that Phase 1 executes no commands capable of modifying AP state.

## Additional cleanup worth including

The current `.gitignore` comment says firmware files should not be committed, but a new firmware such as:

```text
firmware/BZ.MT7981_6.7.54+15663.260513.1738.bin
```

appears as untracked in `git status`.

Consider changing firmware ignore rules so arbitrary local `.bin` firmware files are ignored by default while explicitly versioned exceptions, if any, remain intentional.

This cleanup is secondary to the discovery fixes above and must not distract from the mandatory discovery patch.

## Final objective

Phase 1 must behave as a **real automatic UniFi discovery tool**, not as an OUI-specific legacy scanner.

The operator should be able to connect a factory-reset UniFi AP to the LAN, run one discovery command, and receive its IP, MAC, model, board identity and firmware without manually knowing anything about that AP beforehand.
