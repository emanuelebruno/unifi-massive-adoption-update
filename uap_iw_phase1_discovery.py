import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import paramiko


EXPECTED_FIRMWARE_FAMILY = "BZ.qca933x"


@dataclass(frozen=True)
class APExpected:
    mac: str
    ubicazione: str


def normalize_mac(value: str) -> str:
    if value is None:
        raise ValueError("MAC mancante")
    s = value.strip()
    if not s:
        raise ValueError("MAC vuoto")

    s = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(s) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", s):
        raise ValueError(f"MAC non valido: {value!r}")

    s = s.upper()
    return ":".join(s[i : i + 2] for i in range(0, 12, 2))


def read_input_csv(path: str) -> List[APExpected]:
    aps: List[APExpected] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV senza header")

        fields = {h.strip().lower(): h for h in reader.fieldnames if h}
        if "mac" not in fields:
            raise ValueError("CSV input: colonna richiesta 'mac' non presente")

        mac_field = fields["mac"]
        ubic_field = fields.get("ubicazione")

        for row in reader:
            raw_mac = (row.get(mac_field) or "").strip()
            if not raw_mac:
                continue
            mac = normalize_mac(raw_mac)
            ubic = ((row.get(ubic_field) or "") if ubic_field else "").strip()
            aps.append(APExpected(mac=mac, ubicazione=ubic))

    if not aps:
        raise ValueError("CSV input: nessun AP valido trovato (colonna 'mac')")

    return aps


def ping_host(ip: str) -> bool:
    system = platform.system().lower()
    if system.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if system.startswith("win") else 0),
        )
        return proc.returncode == 0
    except Exception:
        return False


def ping_sweep(subnet: ipaddress.IPv4Network, workers: int) -> int:
    hosts = [str(ip) for ip in subnet.hosts()]
    ok_count = 0
    if not hosts:
        return 0

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(ping_host, ip) for ip in hosts]
        for fut in as_completed(futures):
            try:
                if fut.result():
                    ok_count += 1
            except Exception:
                pass
    return ok_count


def parse_arp_table(arp_output: str) -> Dict[str, str]:
    mac_to_ip: Dict[str, str] = {}

    win_line = re.compile(
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+"
        r"(?P<type>\w+)",
        re.IGNORECASE,
    )
    unix_line = re.compile(
        r"$(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$\s+at\s+"
        r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
        re.IGNORECASE,
    )

    for line in arp_output.splitlines():
        line = line.strip()
        if not line:
            continue

        m = win_line.search(line)
        if not m:
            m = unix_line.search(line)
        if not m:
            continue

        ip = m.group("ip")
        raw_mac = m.group("mac")
        try:
            mac = normalize_mac(raw_mac)
        except ValueError:
            continue

        mac_to_ip[mac] = ip

    return mac_to_ip


def read_arp_table() -> Tuple[Dict[str, str], Optional[str]]:
    system = platform.system().lower()
    cmd = ["arp", "-a"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if system.startswith("win") else 0),
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        mapping = parse_arp_table(out)
        return mapping, None
    except Exception as e:
        return {}, str(e)


def ssh_run_command(
    client: paramiko.SSHClient, command: str, timeout: int
) -> Tuple[str, str, Optional[int], Optional[str]]:
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        channel = stdout.channel
        channel.settimeout(timeout)

        out_b = stdout.read()
        err_b = stderr.read()
        exit_status = None
        try:
            exit_status = channel.recv_exit_status()
        except Exception:
            exit_status = None

        out_s = (out_b.decode(errors="replace") if isinstance(out_b, (bytes, bytearray)) else str(out_b)).strip()
        err_s = (err_b.decode(errors="replace") if isinstance(err_b, (bytes, bytearray)) else str(err_b)).strip()
        return out_s, err_s, exit_status, None
    except Exception as e:
        return "", "", None, str(e)


def extract_firmware_family(firmware_version: str) -> str:
    v = (firmware_version or "").strip()
    if not v:
        return ""
    first_line = v.splitlines()[0].strip()
    token = first_line.split()[0].strip()
    m = re.match(r"^([^.]+\.[^.]+)", token)
    return m.group(1) if m else ""


def parse_board_info(board_info: str) -> Tuple[Optional[str], Optional[str]]:
    board_name = None
    device_model = None

    for raw in (board_info or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k in ("board.name", "board_name", "boardname"):
                board_name = v
            if k in ("board.model", "board_model", "model"):
                device_model = v

    return device_model, board_name


def parse_mca_info(mca_info: str) -> Optional[str]:
    text = (mca_info or "").strip()
    if not text:
        return None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.search(r"\bmodel\b\s*[:=]\s*(.+)$", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()

    m = re.search(r'"model"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return None


def ssh_collect_device_info(
    host: str, user: str, password: str, timeout: int
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "ssh_ok": False,
        "firmware_version": "",
        "firmware_family": "",
        "firmware_family_ok": False,
        "device_model": "",
        "board_name": "",
        "error": "",
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            username=user,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        result["ssh_ok"] = True

        v_out, v_err, v_code, v_exc = ssh_run_command(client, "cat /etc/version", timeout)
        if v_exc:
            result["error"] = f"cat /etc/version: {v_exc}"
            return result
        if v_code not in (0, None) and not v_out:
            result["error"] = f"cat /etc/version failed (exit={v_code}) {v_err}".strip()
            return result

        firmware_version = (v_out.splitlines()[0].strip() if v_out else "")
        result["firmware_version"] = firmware_version
        fam = extract_firmware_family(firmware_version)
        result["firmware_family"] = fam
        result["firmware_family_ok"] = bool(firmware_version.startswith(EXPECTED_FIRMWARE_FAMILY))

        b_out, b_err, b_code, b_exc = ssh_run_command(client, "cat /etc/board.info", timeout)
        if not b_exc and (b_out or b_err):
            model_from_board, board_name = parse_board_info(b_out)
            if model_from_board and not result["device_model"]:
                result["device_model"] = model_from_board
            if board_name:
                result["board_name"] = board_name

        m_out, m_err, m_code, m_exc = ssh_run_command(client, "mca-cli-op info", timeout)
        if not m_exc and (m_out or m_err):
            model = parse_mca_info(m_out)
            if model:
                result["device_model"] = model

        return result
    except paramiko.AuthenticationException:
        result["error"] = "SSH auth failed"
        return result
    except (paramiko.SSHException, OSError, TimeoutError) as e:
        result["error"] = f"SSH error: {e}"
        return result
    except Exception as e:
        result["error"] = f"SSH unexpected error: {e}"
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass


def write_csv_report(path: str, rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    fieldnames = [
        "mac",
        "ubicazione",
        "ip",
        "ip_found",
        "ping_ok",
        "ssh_ok",
        "firmware_version",
        "firmware_family",
        "firmware_family_ok",
        "device_model",
        "board_name",
        "status",
        "error",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def write_json_report(path: str, rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def build_initial_rows(aps: List[APExpected]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for ap in aps:
        rows.append(
            {
                "mac": ap.mac,
                "ubicazione": ap.ubicazione,
                "ip": "",
                "ip_found": False,
                "ping_ok": False,
                "ssh_ok": False,
                "firmware_version": "",
                "firmware_family": "",
                "firmware_family_ok": False,
                "device_model": "",
                "board_name": "",
                "status": "IP_NOT_FOUND",
                "error": "",
            }
        )
    return rows


def process_one_ap(
    base_row: Dict[str, object],
    user: str,
    password: str,
    timeout: int,
) -> Dict[str, object]:
    row = dict(base_row)
    ip = (row.get("ip") or "").strip()
    if not ip:
        row["ip_found"] = False
        row["status"] = "IP_NOT_FOUND"
        return row

    row["ip_found"] = True

    if not ping_host(ip):
        row["ping_ok"] = False
        row["status"] = "PING_FAILED"
        row["error"] = row.get("error") or "Ping failed"
        return row

    row["ping_ok"] = True

    info = ssh_collect_device_info(ip, user=user, password=password, timeout=timeout)
    row["ssh_ok"] = bool(info.get("ssh_ok"))
    row["firmware_version"] = info.get("firmware_version") or ""
    row["firmware_family"] = info.get("firmware_family") or ""
    row["firmware_family_ok"] = bool(info.get("firmware_family_ok"))
    row["device_model"] = info.get("device_model") or ""
    row["board_name"] = info.get("board_name") or ""

    err = info.get("error") or ""
    if err:
        row["error"] = err

    if not row["ssh_ok"]:
        row["status"] = "IP_FOUND_SSH_FAILED"
        return row

    if not row["firmware_version"]:
        row["status"] = "FIRMWARE_READ_FAILED"
        if not row["error"]:
            row["error"] = "Firmware version empty"
        return row

    if not row["firmware_family_ok"]:
        row["status"] = "MODEL_FAMILY_MISMATCH"
        return row

    row["status"] = "IP_FOUND_SSH_OK"
    return row


def print_ap_line(row: Dict[str, object]) -> None:
    mac = row.get("mac") or ""
    ubic = row.get("ubicazione") or ""
    ip = row.get("ip") or ""
    status = row.get("status") or ""
    fw = row.get("firmware_version") or ""
    ssh_ok = row.get("ssh_ok")
    ip_found = row.get("ip_found")
    ping_ok = row.get("ping_ok")

    if not ip_found:
        print(f"[AP] {mac} - {ubic} - IP non trovato - {status}")
        return

    parts = [f"[AP] {mac} - {ubic} - IP {ip}"]
    parts.append("PING OK" if ping_ok else "PING FAIL")
    parts.append("SSH OK" if ssh_ok else "SSH FAIL")
    if fw:
        parts.append(f"Firmware {fw}")
    parts.append(str(status))
    print(" - ".join(parts))


def summarize(rows: List[Dict[str, object]]) -> Dict[str, int]:
    total = len(rows)
    ip_found = sum(1 for r in rows if r.get("ip_found"))
    ping_ok = sum(1 for r in rows if r.get("ping_ok"))
    ssh_ok = sum(1 for r in rows if r.get("ssh_ok"))
    fw_read = sum(1 for r in rows if bool((r.get("firmware_version") or "").strip()))
    fam_ok = sum(1 for r in rows if r.get("firmware_family_ok"))
    mismatch = sum(1 for r in rows if (r.get("status") == "MODEL_FAMILY_MISMATCH"))
    errors = sum(1 for r in rows if bool((r.get("error") or "").strip()))
    return {
        "total": total,
        "ip_found": ip_found,
        "ping_ok": ping_ok,
        "ssh_ok": ssh_ok,
        "fw_read": fw_read,
        "fam_ok": fam_ok,
        "mismatch": mismatch,
        "errors": errors,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="UAP-IW / U2IW Phase 1 discovery (read-only).")
    p.add_argument("--input", required=True, help="CSV input (mac, ubicazione)")
    p.add_argument("--subnet", help="Subnet CIDR (es. 192.168.1.0/24)")
    p.add_argument("--single-ip", dest="single_ip", help="Test singolo IP (bypass ARP discovery)")
    p.add_argument("--user", default="ubnt", help="SSH username (default ubnt)")
    p.add_argument("--password", default="ubnt", help="SSH password (default ubnt)")
    p.add_argument("--out", required=True, help="CSV report output")
    p.add_argument("--json", dest="json_out", help="JSON report output (opzionale)")
    p.add_argument("--timeout", type=int, default=5, help="Timeout SSH (secondi)")
    p.add_argument("--workers", type=int, default=64, help="Worker threads (ping sweep / AP processing)")
    args = p.parse_args(argv)

    aps = read_input_csv(args.input)
    rows = build_initial_rows(aps)

    if args.single_ip:
        ip = args.single_ip.strip()
        if aps:
            rows[0]["ip"] = ip
        else:
            rows = [
                {
                    "mac": "",
                    "ubicazione": "MANUAL_TEST",
                    "ip": ip,
                    "ip_found": True,
                    "ping_ok": False,
                    "ssh_ok": False,
                    "firmware_version": "",
                    "firmware_family": "",
                    "firmware_family_ok": False,
                    "device_model": "",
                    "board_name": "",
                    "status": "",
                    "error": "",
                }
            ]
        print(f"[SCAN] Test singolo IP {ip} (bypass subnet/ARP)")
    else:
        if not args.subnet:
            print("Errore: specificare --subnet oppure --single-ip", file=sys.stderr)
            return 2

        subnet = ipaddress.ip_network(args.subnet, strict=False)
        if subnet.version != 4:
            print("Errore: solo IPv4 supportato", file=sys.stderr)
            return 2

        print(f"[SCAN] Scansione subnet {subnet}...")
        ok_count = ping_sweep(subnet, workers=args.workers)

        arp_map, arp_err = read_arp_table()
        if arp_err:
            print(f"[ARP] Errore lettura tabella ARP: {arp_err}")
        print(f"[SCAN] Ping sweep completato: {ok_count} host rispondono")
        print(f"[ARP] Trovati {len(arp_map)} dispositivi nella tabella ARP")

        for r in rows:
            mac = r["mac"]
            ip = arp_map.get(mac, "")
            if ip:
                r["ip"] = ip
                r["ip_found"] = True
                r["status"] = "IP_FOUND"

    print(f"[AP] Elaborazione AP (workers={max(1, args.workers)})...")
    processed: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = [ex.submit(process_one_ap, r, args.user, args.password, args.timeout) for r in rows]
        for fut in as_completed(futs):
            try:
                processed.append(fut.result())
            except Exception as e:
                processed.append(
                    {
                        "mac": "",
                        "ubicazione": "",
                        "ip": "",
                        "ip_found": False,
                        "ping_ok": False,
                        "ssh_ok": False,
                        "firmware_version": "",
                        "firmware_family": "",
                        "firmware_family_ok": False,
                        "device_model": "",
                        "board_name": "",
                        "status": "ERROR",
                        "error": f"Unhandled exception: {e}",
                    }
                )

    processed.sort(key=lambda r: (r.get("mac") or "", r.get("ubicazione") or ""))

    for r in processed:
        print_ap_line(r)

    write_csv_report(args.out, processed)
    if args.json_out:
        write_json_report(args.json_out, processed)

    s = summarize(processed)
    print("")
    print(f"Totale AP nel CSV: {s['total']}")
    print(f"IP trovati: {s['ip_found']}")
    print(f"Ping OK: {s['ping_ok']}")
    print(f"SSH OK: {s['ssh_ok']}")
    print(f"Firmware letti: {s['fw_read']}")
    print(f"Firmware family OK: {s['fam_ok']}")
    print(f"Mismatch modello/famiglia: {s['mismatch']}")
    print(f"Errori: {s['errors']}")
    print("")
    print(f"[OUT] CSV: {os.path.abspath(args.out)}")
    if args.json_out:
        print(f"[OUT] JSON: {os.path.abspath(args.json_out)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())