import argparse
import csv
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import paramiko


EXPECTED_FIRMWARE_FAMILY = "BZ.qca933x"
COMPATIBLE_BOARD_NAMES = {"UAP-InWall"}
COMPATIBLE_BOARD_SHORTNAMES = {"U2IW"}
COMPATIBLE_DEVICE_MODELS = {"UAP-InWall"}

# Sopprimi log rumorosi di paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


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
        r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
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


def normalize_hwaddr(value: str) -> str:
    s = (value or "").strip()
    if not s:
        return ""
    s_clean = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(s_clean) == 12 and re.fullmatch(r"[0-9A-Fa-f]{12}", s_clean):
        try:
            return normalize_mac(s_clean)
        except ValueError:
            return s
    return s


def parse_board_info_extended(board_info: str) -> Dict[str, str]:
    board_name = ""
    board_shortname = ""
    board_hwaddr = ""

    for raw in (board_info or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "board.name":
            board_name = v
        elif k == "board.shortname":
            board_shortname = v
        elif k == "board.hwaddr":
            board_hwaddr = normalize_hwaddr(v)

    return {
        "board_name": board_name,
        "board_shortname": board_shortname,
        "board_hwaddr": board_hwaddr,
    }


def parse_board_info(board_info: str) -> Tuple[Optional[str], Optional[str]]:
    info = parse_board_info_extended(board_info)
    board_name = info.get("board_name") or None
    return None, board_name


def parse_mca_info_extended(mca_info: str) -> Dict[str, str]:
    text = (mca_info or "").strip()
    if not text:
        return {"device_model": "", "firmware_version_full": ""}

    model = ""
    version = ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^Model\s*:\s*(.+)$", line, re.IGNORECASE)
        if m and not model:
            model = m.group(1).strip()
            continue
        m = re.match(r"^Version\s*:\s*(.+)$", line, re.IGNORECASE)
        if m and not version:
            version = m.group(1).strip()
            continue

    m = re.search(r'"model"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if m and not model:
        model = m.group(1).strip()

    m = re.search(r'"version"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if m and not version:
        version = m.group(1).strip()

    return {"device_model": model, "firmware_version_full": version}


def parse_mca_info(mca_info: str) -> Optional[str]:
    info = parse_mca_info_extended(mca_info)
    model = info.get("device_model") or ""
    return model or None


def evaluate_model_family(board_name: str, board_shortname: str, device_model: str) -> str:
    bn = (board_name or "").strip()
    bs = (board_shortname or "").strip()
    dm = (device_model or "").strip()

    if bn or bs or dm:
        if bs and bs in COMPATIBLE_BOARD_SHORTNAMES:
            return "MODEL_FAMILY_OK"
        if bn and bn in COMPATIBLE_BOARD_NAMES:
            return "MODEL_FAMILY_OK"
        if dm and dm in COMPATIBLE_DEVICE_MODELS:
            return "MODEL_FAMILY_OK"

        if bs and bs not in COMPATIBLE_BOARD_SHORTNAMES:
            return "MODEL_FAMILY_MISMATCH"
        if bn and bn not in COMPATIBLE_BOARD_NAMES:
            return "MODEL_FAMILY_MISMATCH"
        if dm and dm not in COMPATIBLE_DEVICE_MODELS:
            return "MODEL_FAMILY_MISMATCH"

        return "MODEL_FAMILY_UNKNOWN"

    return "MODEL_FAMILY_UNKNOWN"


def ssh_error_type_from_paramiko_exception(e: Exception) -> str:
    msg = str(e or "").lower()
    if "incompatible ssh peer" in msg or "no acceptable host key" in msg or "no matching host key type found" in msg:
        return "SSH_LEGACY_HOSTKEY_UNSUPPORTED_BY_PARAMIKO"
    if isinstance(e, paramiko.AuthenticationException):
        return "SSH_AUTH_FAILED"
    if "timed out" in msg or "timeout" in msg:
        return "SSH_TIMEOUT"
    return "SSH_ERROR"


def clean_plink_output(text: str) -> str:
    lines: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip("\r\n")
        if not line:
            continue
        if line.strip() == "Access granted. Press Return to begin session.":
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def classify_putty_hostkey(stdout: str, stderr: str) -> Tuple[Optional[str], Optional[str]]:
    combined = ((stdout or "") + "\n" + (stderr or "")).lower()

    mismatch_markers = [
        "warning - potential security breach",
        "host key did not match",
        "host key mismatch",
        "remote host identification has changed",
    ]
    for m in mismatch_markers:
        if m in combined:
            return "HOSTKEY_MISMATCH", "SSH_HOSTKEY_MISMATCH"

    unknown_markers = [
        "server's host key is not cached",
        "the server's host key is not cached",
        "host key is not cached",
        "not cached in the registry",
        "store key in cache",
    ]
    for m in unknown_markers:
        if m in combined:
            return "HOSTKEY_UNKNOWN_NOT_ACCEPTED", "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"

    return None, None


def plink_error_type(stdout: str, stderr: str, returncode: Optional[int]) -> str:
    hk_status, hk_error = classify_putty_hostkey(stdout, stderr)
    if hk_error:
        return hk_error

    combined = (stdout or "") + "\n" + (stderr or "")
    s = combined.lower()
    if "access denied" in s or "authentication refused" in s:
        return "SSH_AUTH_FAILED"
    if "network error" in s and "timed out" in s:
        return "SSH_TIMEOUT"
    if "network error" in s or "connection refused" in s or "no route to host" in s:
        return "SSH_UNREACHABLE"
    if returncode not in (0, None):
        return "SSH_ERROR"
    return ""


def run_plink(
    plink_path: str,
    host: str,
    user: str,
    password: str,
    command: str,
    timeout: int,
    batch: bool,
    stdin_data: Optional[str],
) -> Tuple[str, str, Optional[int], Optional[str]]:
    resolved = shutil.which(plink_path) if plink_path else None
    if not resolved:
        return "", "", None, f"plink not found: {plink_path}"

    cmd = [resolved, "-ssh", "-P", "22", "-l", user, "-pw", password]
    if batch:
        cmd.append("-batch")
    cmd.extend([host, command])

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=max(1, timeout),
            check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if platform.system().lower().startswith("win") else 0),
        )
        out = clean_plink_output(proc.stdout or "")
        err = clean_plink_output(proc.stderr or "")
        return out, err, proc.returncode, None
    except subprocess.TimeoutExpired:
        return "", "", None, "timeout"
    except Exception as e:
        return "", "", None, str(e)


def paramiko_collect_device_info(host: str, user: str, password: str, timeout: int) -> Dict[str, object]:
    result: Dict[str, object] = {
        "ssh_ok": False,
        "ssh_backend": "paramiko",
        "ssh_error_type": "",
        "hostkey_status": "HOSTKEY_NOT_APPLICABLE",
        "hostkey_auto_accepted": False,
        "hostkey_error_type": "",
        "firmware_version_short": "",
        "firmware_version_full": "",
        "firmware_version": "",
        "firmware_family": "",
        "firmware_family_ok": False,
        "board_name": "",
        "board_shortname": "",
        "board_hwaddr": "",
        "device_model": "",
        "model_family_status": "MODEL_FAMILY_UNKNOWN",
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
            result["ssh_error_type"] = "SSH_COMMAND_FAILED"
            result["error"] = f"cat /etc/version: {v_exc}"
            return result
        if v_code not in (0, None) and not v_out:
            result["ssh_error_type"] = "SSH_COMMAND_FAILED"
            result["error"] = f"cat /etc/version failed (exit={v_code}) {v_err}".strip()
            return result

        firmware_short = (v_out.splitlines()[0].strip() if v_out else "")
        result["firmware_version_short"] = firmware_short
        result["firmware_version"] = firmware_short
        result["firmware_family"] = extract_firmware_family(firmware_short)

        b_out, b_err, b_code, b_exc = ssh_run_command(client, "cat /etc/board.info", timeout)
        if not b_exc and (b_out or b_err):
            b = parse_board_info_extended(b_out)
            result["board_name"] = b.get("board_name") or ""
            result["board_shortname"] = b.get("board_shortname") or ""
            result["board_hwaddr"] = b.get("board_hwaddr") or ""

        m_out, m_err, m_code, m_exc = ssh_run_command(client, "mca-cli-op info", timeout)
        if not m_exc and (m_out or m_err):
            m = parse_mca_info_extended(m_out)
            if m.get("device_model"):
                result["device_model"] = m.get("device_model") or ""
            if m.get("firmware_version_full"):
                result["firmware_version_full"] = m.get("firmware_version_full") or ""

        result["model_family_status"] = evaluate_model_family(
            result.get("board_name") or "",
            result.get("board_shortname") or "",
            result.get("device_model") or "",
        )
        result["firmware_family_ok"] = result["model_family_status"] == "MODEL_FAMILY_OK"
        return result
    except Exception as e:
        result["ssh_ok"] = False
        result["ssh_error_type"] = ssh_error_type_from_paramiko_exception(e)
        result["error"] = str(e)
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass


def plink_collect_device_info(
    host: str, user: str, password: str, timeout: int, plink_path: str, accept_new_hostkeys: bool
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "ssh_ok": False,
        "ssh_backend": "plink",
        "ssh_error_type": "",
        "hostkey_status": "HOSTKEY_NOT_CHECKED",
        "hostkey_auto_accepted": False,
        "hostkey_error_type": "",
        "firmware_version_short": "",
        "firmware_version_full": "",
        "firmware_version": "",
        "firmware_family": "",
        "firmware_family_ok": False,
        "board_name": "",
        "board_shortname": "",
        "board_hwaddr": "",
        "device_model": "",
        "model_family_status": "MODEL_FAMILY_UNKNOWN",
        "error": "",
    }

    v_out, v_err, v_rc, v_exc = run_plink(
        plink_path=plink_path,
        host=host,
        user=user,
        password=password,
        command="cat /etc/version",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
    )
    if v_exc:
        if v_exc == "timeout":
            result["ssh_error_type"] = "SSH_TIMEOUT"
            result["error"] = "plink timeout"
            return result
        result["ssh_error_type"] = "SSH_PLINK_ERROR"
        result["error"] = v_exc
        return result

    if v_rc != 0:
        hk_status, hk_error = classify_putty_hostkey(v_out, v_err)
        if hk_error == "SSH_HOSTKEY_MISMATCH":
            result["ssh_error_type"] = "SSH_HOSTKEY_MISMATCH"
            result["hostkey_status"] = "HOSTKEY_MISMATCH"
            result["hostkey_auto_accepted"] = False
            result["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
            result["error"] = (v_err or v_out or "HOSTKEY_MISMATCH").strip()
            return result

        if hk_error == "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT":
            result["hostkey_status"] = "HOSTKEY_UNKNOWN_NOT_ACCEPTED"
            result["hostkey_auto_accepted"] = False
            result["hostkey_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"

            if not accept_new_hostkeys:
                result["ssh_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"
                result["error"] = (v_err or v_out or "HOSTKEY_UNKNOWN").strip()
                return result

            enroll_out, enroll_err, enroll_rc, enroll_exc = run_plink(
                plink_path=plink_path,
                host=host,
                user=user,
                password=password,
                command="cat /etc/version",
                timeout=timeout,
                batch=False,
                stdin_data="y\n",
            )
            if enroll_exc:
                if enroll_exc == "timeout":
                    result["ssh_error_type"] = "SSH_TIMEOUT"
                    result["error"] = "plink enroll timeout"
                    result["hostkey_error_type"] = "SSH_TIMEOUT"
                    return result
                result["ssh_error_type"] = "SSH_PLINK_ERROR"
                result["error"] = enroll_exc
                result["hostkey_error_type"] = "SSH_PLINK_ERROR"
                return result

            enroll_hk_status, enroll_hk_error = classify_putty_hostkey(enroll_out, enroll_err)
            if enroll_hk_error == "SSH_HOSTKEY_MISMATCH":
                result["ssh_error_type"] = "SSH_HOSTKEY_MISMATCH"
                result["hostkey_status"] = "HOSTKEY_MISMATCH"
                result["hostkey_auto_accepted"] = False
                result["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
                result["error"] = (enroll_err or enroll_out or "HOSTKEY_MISMATCH").strip()
                return result

            if enroll_rc != 0:
                result["ssh_error_type"] = plink_error_type(enroll_out, enroll_err, enroll_rc) or "SSH_ERROR"
                result["error"] = (enroll_err or enroll_out or "plink enroll failed").strip()
                result["hostkey_error_type"] = result["ssh_error_type"]
                return result

            v_out2, v_err2, v_rc2, v_exc2 = run_plink(
                plink_path=plink_path,
                host=host,
                user=user,
                password=password,
                command="cat /etc/version",
                timeout=timeout,
                batch=True,
                stdin_data="\n",
            )
            if v_exc2:
                if v_exc2 == "timeout":
                    result["ssh_error_type"] = "SSH_TIMEOUT"
                    result["error"] = "plink timeout (after hostkey enroll)"
                    result["hostkey_error_type"] = "SSH_TIMEOUT"
                    return result
                result["ssh_error_type"] = "SSH_PLINK_ERROR"
                result["error"] = v_exc2
                result["hostkey_error_type"] = "SSH_PLINK_ERROR"
                return result

            hk_status2, hk_error2 = classify_putty_hostkey(v_out2, v_err2)
            if hk_error2 == "SSH_HOSTKEY_MISMATCH":
                result["ssh_error_type"] = "SSH_HOSTKEY_MISMATCH"
                result["hostkey_status"] = "HOSTKEY_MISMATCH"
                result["hostkey_auto_accepted"] = False
                result["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
                result["error"] = (v_err2 or v_out2 or "HOSTKEY_MISMATCH").strip()
                return result
            if hk_error2 == "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT":
                result["ssh_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"
                result["hostkey_status"] = "HOSTKEY_UNKNOWN_NOT_ACCEPTED"
                result["hostkey_auto_accepted"] = False
                result["hostkey_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"
                result["error"] = (v_err2 or v_out2 or "HOSTKEY_UNKNOWN").strip()
                return result

            if v_rc2 != 0:
                result["ssh_error_type"] = plink_error_type(v_out2, v_err2, v_rc2) or "SSH_ERROR"
                result["error"] = (v_err2 or v_out2 or "plink command failed (after hostkey enroll)").strip()
                result["hostkey_status"] = "HOSTKEY_ACCEPTED_NEW"
                result["hostkey_auto_accepted"] = True
                result["hostkey_error_type"] = ""
                return result

            result["hostkey_status"] = "HOSTKEY_ACCEPTED_NEW"
            result["hostkey_auto_accepted"] = True
            result["hostkey_error_type"] = ""
            v_out, v_err, v_rc = v_out2, v_err2, v_rc2
        else:
            result["ssh_error_type"] = plink_error_type(v_out, v_err, v_rc) or "SSH_ERROR"
            result["error"] = (v_err or v_out or "plink command failed").strip()
            return result

    result["ssh_ok"] = True
    if result.get("hostkey_status") == "HOSTKEY_NOT_CHECKED":
        result["hostkey_status"] = "HOSTKEY_ALREADY_CACHED"
        result["hostkey_auto_accepted"] = False
        result["hostkey_error_type"] = ""
    firmware_short = (v_out.splitlines()[0].strip() if v_out else "")
    result["firmware_version_short"] = firmware_short
    result["firmware_version"] = firmware_short
    result["firmware_family"] = extract_firmware_family(firmware_short)

    b_out, b_err, b_rc, b_exc = run_plink(
        plink_path=plink_path,
        host=host,
        user=user,
        password=password,
        command="cat /etc/board.info",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
    )
    if not b_exc and b_rc == 0 and b_out:
        b = parse_board_info_extended(b_out)
        result["board_name"] = b.get("board_name") or ""
        result["board_shortname"] = b.get("board_shortname") or ""
        result["board_hwaddr"] = b.get("board_hwaddr") or ""

    m_out, m_err, m_rc, m_exc = run_plink(
        plink_path=plink_path,
        host=host,
        user=user,
        password=password,
        command="mca-cli-op info",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
    )
    if not m_exc and m_rc == 0 and m_out:
        m = parse_mca_info_extended(m_out)
        if m.get("device_model"):
            result["device_model"] = m.get("device_model") or ""
        if m.get("firmware_version_full"):
            result["firmware_version_full"] = m.get("firmware_version_full") or ""

    result["model_family_status"] = evaluate_model_family(
        result.get("board_name") or "",
        result.get("board_shortname") or "",
        result.get("device_model") or "",
    )
    result["firmware_family_ok"] = result["model_family_status"] == "MODEL_FAMILY_OK"
    return result


def ssh_collect_device_info(
    host: str,
    user: str,
    password: str,
    timeout: int,
    ssh_backend: str,
    plink_path: str,
    accept_new_hostkeys: bool,
) -> Dict[str, object]:
    backend = (ssh_backend or "auto").strip().lower()
    if backend not in {"auto", "paramiko", "plink"}:
        backend = "auto"

    if backend == "paramiko":
        return paramiko_collect_device_info(host, user=user, password=password, timeout=timeout)
    if backend == "plink":
        return plink_collect_device_info(
            host, user=user, password=password, timeout=timeout, plink_path=plink_path, accept_new_hostkeys=accept_new_hostkeys
        )

    res = paramiko_collect_device_info(host, user=user, password=password, timeout=timeout)
    if not res.get("ssh_ok") and res.get("ssh_error_type") == "SSH_LEGACY_HOSTKEY_UNSUPPORTED_BY_PARAMIKO":
        return plink_collect_device_info(
            host, user=user, password=password, timeout=timeout, plink_path=plink_path, accept_new_hostkeys=accept_new_hostkeys
        )
    return res


def write_csv_report(path: str, rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    fieldnames = [
        "mac",
        "ubicazione",
        "ip",
        "ip_found",
        "ping_ok",
        "ssh_ok",
        "ssh_backend",
        "ssh_error_type",
        "hostkey_status",
        "hostkey_auto_accepted",
        "hostkey_error_type",
        "firmware_version_short",
        "firmware_version_full",
        "firmware_version",
        "firmware_family",
        "firmware_family_ok",
        "board_name",
        "board_shortname",
        "board_hwaddr",
        "device_model",
        "model_family_status",
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
                "ssh_backend": "",
                "ssh_error_type": "",
                "hostkey_status": "",
                "hostkey_auto_accepted": False,
                "hostkey_error_type": "",
                "firmware_version_short": "",
                "firmware_version_full": "",
                "firmware_version": "",
                "firmware_family": "",
                "firmware_version_full": "",
                "firmware_version": "",
                "firmware_family": "",
                "firmware_family_ok": False,
                "device_model": "",
                "board_name": "",
                "board_shortname": "",
                "board_hwaddr": "",
                "model_family_status": "MODEL_FAMILY_UNKNOWN",
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
    ssh_backend: str,
    plink_path: str,
    accept_new_hostkeys: bool,
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

    info = ssh_collect_device_info(
        ip,
        user=user,
        password=password,
        timeout=timeout,
        ssh_backend=ssh_backend,
        plink_path=plink_path,
        accept_new_hostkeys=accept_new_hostkeys,
    )
    row["ssh_ok"] = bool(info.get("ssh_ok"))
    row["ssh_backend"] = info.get("ssh_backend") or ""
    row["ssh_error_type"] = info.get("ssh_error_type") or ""
    row["hostkey_status"] = info.get("hostkey_status") or ""
    row["hostkey_auto_accepted"] = bool(info.get("hostkey_auto_accepted"))
    row["hostkey_error_type"] = info.get("hostkey_error_type") or ""
    row["firmware_version_short"] = info.get("firmware_version_short") or ""
    row["firmware_version_full"] = info.get("firmware_version_full") or ""
    row["firmware_version"] = info.get("firmware_version") or ""
    row["firmware_family"] = info.get("firmware_family") or ""
    row["firmware_family_ok"] = bool(info.get("firmware_family_ok"))
    row["device_model"] = info.get("device_model") or ""
    row["board_name"] = info.get("board_name") or ""
    row["board_shortname"] = info.get("board_shortname") or ""
    row["board_hwaddr"] = info.get("board_hwaddr") or ""
    row["model_family_status"] = info.get("model_family_status") or "MODEL_FAMILY_UNKNOWN"

    err = info.get("error") or ""
    if err:
        row["error"] = err

    if not row["ssh_ok"]:
        row["status"] = "IP_FOUND_SSH_FAILED"
        return row

    if not (row.get("firmware_version_short") or "").strip():
        row["status"] = "FIRMWARE_READ_FAILED"
        if not row["error"]:
            row["error"] = "Firmware version empty"
        return row

    if row.get("model_family_status") == "MODEL_FAMILY_MISMATCH":
        row["status"] = "MODEL_FAMILY_MISMATCH"
        return row

    if row.get("model_family_status") == "MODEL_FAMILY_UNKNOWN":
        row["status"] = "MODEL_FAMILY_UNKNOWN"
        return row

    row["status"] = "IP_FOUND_SSH_OK"
    return row


def print_ap_line(row: Dict[str, object]) -> None:
    mac = row.get("mac") or ""
    ubic = row.get("ubicazione") or ""
    ip = row.get("ip") or ""
    status = row.get("status") or ""
    fw = row.get("firmware_version_short") or row.get("firmware_version") or ""
    ssh_ok = row.get("ssh_ok")
    ssh_backend = row.get("ssh_backend") or ""
    ip_found = row.get("ip_found")
    ping_ok = row.get("ping_ok")

    if not ip_found:
        print(f"[AP] {mac} - {ubic} - IP non trovato - {status}")
        return

    parts = [f"[AP] {mac} - {ubic} - IP {ip}"]
    parts.append("PING OK" if ping_ok else "PING FAIL")
    parts.append(("SSH OK" if ssh_ok else "SSH FAIL") + (f" ({ssh_backend})" if ssh_backend else ""))
    if fw:
        parts.append(f"Firmware {fw}")
    parts.append(str(status))
    print(" - ".join(parts))


def summarize(rows: List[Dict[str, object]]) -> Dict[str, int]:
    total = len(rows)
    ip_found = sum(1 for r in rows if r.get("ip_found"))
    ping_ok = sum(1 for r in rows if r.get("ping_ok"))
    ssh_ok = sum(1 for r in rows if r.get("ssh_ok"))
    fw_read = sum(1 for r in rows if bool((r.get("firmware_version_short") or "").strip()))
    fam_ok = sum(1 for r in rows if (r.get("model_family_status") == "MODEL_FAMILY_OK"))
    mismatch = sum(1 for r in rows if (r.get("model_family_status") == "MODEL_FAMILY_MISMATCH"))
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
    p.add_argument("--ssh-backend", dest="ssh_backend", default="auto", choices=["auto", "paramiko", "plink"])
    p.add_argument("--plink-path", dest="plink_path", default="plink.exe", help="Path plink.exe (default: plink.exe)")
    p.add_argument(
        "--accept-new-hostkeys",
        dest="accept_new_hostkeys",
        action="store_true",
        help="Accetta automaticamente solo nuove host key PuTTY (solo backend plink; non accetta mismatch)",
    )
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
                    "ssh_backend": "",
                    "ssh_error_type": "",
                    "hostkey_status": "",
                    "hostkey_auto_accepted": False,
                    "hostkey_error_type": "",
                    "firmware_version_short": "",
                    "firmware_version_full": "",
                    "firmware_version": "",
                    "firmware_family": "",
                    "firmware_family_ok": False,
                    "device_model": "",
                    "board_name": "",
                    "board_shortname": "",
                    "board_hwaddr": "",
                    "model_family_status": "MODEL_FAMILY_UNKNOWN",
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
        futs = [
            ex.submit(
                process_one_ap,
                r,
                args.user,
                args.password,
                args.timeout,
                args.ssh_backend,
                args.plink_path,
                args.accept_new_hostkeys,
            )
            for r in rows
        ]
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
                        "ssh_backend": "",
                        "ssh_error_type": "",
                        "hostkey_status": "",
                        "hostkey_auto_accepted": False,
                        "hostkey_error_type": "",
                        "firmware_version_short": "",
                        "firmware_version_full": "",
                        "firmware_version": "",
                        "firmware_family": "",
                        "firmware_family_ok": False,
                        "device_model": "",
                        "board_name": "",
                        "board_shortname": "",
                        "board_hwaddr": "",
                        "model_family_status": "MODEL_FAMILY_UNKNOWN",
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
