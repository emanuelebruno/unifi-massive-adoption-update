import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple


SCRIPT_NAME = "uap_iw_phase2_firmware_update.py"
SCRIPT_VERSION = "0.4.2"
SCRIPT_BUILD_DATE = "2026-05-13"
SCRIPT_SUMMARY = "Phase 2 firmware update with fixed remote upgrade command and plink/pscp -hostkey support"

COMPATIBLE_BOARD_NAMES = {"UAP-InWall"}
COMPATIBLE_BOARD_SHORTNAMES = {"U2IW"}
COMPATIBLE_DEVICE_MODELS = {"UAP-InWall"}


def coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    s = str(value).strip().lower()
    return s in {"1", "true", "yes", "y", "ok"}


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


def resolve_executable(path_or_name: str) -> Optional[str]:
    if not path_or_name:
        return None
    if os.path.isabs(path_or_name) or os.path.sep in path_or_name or (os.path.altsep and os.path.altsep in path_or_name):
        return path_or_name if os.path.exists(path_or_name) else None
    return shutil.which(path_or_name)


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


def clean_putty_output(text: str) -> str:
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
        "not cached in the registry",
        "store key in cache",
    ]
    for m in unknown_markers:
        if m in combined:
            return "HOSTKEY_UNKNOWN_NOT_ACCEPTED", "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"

    return None, None


def classify_putty_error(stdout: str, stderr: str, returncode: Optional[int]) -> str:
    hk_status, hk_error = classify_putty_hostkey(stdout, stderr)
    if hk_error:
        return hk_error
    combined = ((stdout or "") + "\n" + (stderr or "")).lower()
    if "access denied" in combined or "authentication refused" in combined:
        return "SSH_AUTH_FAILED"
    if "network error" in combined and "timed out" in combined:
        return "SSH_TIMEOUT"
    if "network error" in combined or "connection refused" in combined or "no route to host" in combined:
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
    hostkey_fingerprint: Optional[str] = None,
) -> Tuple[str, str, Optional[int], Optional[str]]:
    resolved = resolve_executable(plink_path)
    if not resolved:
        return "", "", None, f"plink not found: {plink_path}"

    cmd = [resolved, "-ssh", "-P", "22", "-l", user, "-pw", password]
    if batch:
        cmd.append("-batch")
    if hostkey_fingerprint:
        cmd.extend(["-hostkey", hostkey_fingerprint])
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
        out = clean_putty_output(proc.stdout or "")
        err = clean_putty_output(proc.stderr or "")
        return out, err, proc.returncode, None
    except subprocess.TimeoutExpired:
        return "", "", None, "timeout"
    except Exception as e:
        return "", "", None, str(e)


def run_pscp_upload(
    pscp_path: str,
    host: str,
    user: str,
    password: str,
    local_file: str,
    remote_path: str,
    timeout: int,
    hostkey_fingerprint: Optional[str] = None,
) -> Tuple[str, str, Optional[int], Optional[str]]:
    resolved = resolve_executable(pscp_path)
    if not resolved:
        return "", "", None, f"pscp not found: {pscp_path}"

    cmd = [
        resolved,
        "-batch",
        "-P",
        "22",
        "-scp",
        "-pw",
        password,
    ]
    if hostkey_fingerprint:
        cmd.extend(["-hostkey", hostkey_fingerprint])
    cmd.extend(
        [
        local_file,
        f"{user}@{host}:{remote_path}",
        ]
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(1, timeout),
            check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if platform.system().lower().startswith("win") else 0),
        )
        out = clean_putty_output(proc.stdout or "")
        err = clean_putty_output(proc.stderr or "")
        return out, err, proc.returncode, None
    except subprocess.TimeoutExpired:
        return "", "", None, "timeout"
    except Exception as e:
        return "", "", None, str(e)


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


def read_input_report(path: str) -> List[Dict[str, object]]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON report: atteso array di oggetti")
        return [dict(x) for x in data]

    if ext == ".csv":
        rows: List[Dict[str, object]] = []
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV report: header mancante")
            for row in reader:
                rows.append(dict(row))
        return rows

    raise ValueError("Input report: estensione non supportata (usare .json o .csv)")


def ensure_required_fields(records: List[Dict[str, object]]) -> None:
    required = {"mac", "ubicazione", "ip", "ip_found", "ping_ok", "ssh_ok", "model_family_status"}
    missing_any = []
    for i, r in enumerate(records):
        missing = [k for k in required if k not in r]
        if missing:
            missing_any.append((i, missing))
            if len(missing_any) >= 5:
                break
    if missing_any:
        msg = "; ".join([f"row#{idx} missing {','.join(m)}" for idx, m in missing_any])
        raise ValueError(f"Report Fase 1: campi mancanti: {msg}")


def decide_version_action(
    firmware_version_full: str,
    firmware_version_short: str,
    target_full: str,
    target_short: str,
) -> Tuple[str, str]:
    full = (firmware_version_full or "").strip()
    short = (firmware_version_short or "").strip()
    if full and full == target_full:
        return "NOOP", "SKIPPED_ALREADY_UPDATED"
    if not full and short and short == target_short:
        return "NOOP", "SKIPPED_VERSION_FULL_UNKNOWN_BUT_SHORT_MATCHES"
    return "UPDATE", "UPDATE_REQUIRED"


def is_candidate_model(rec: Dict[str, object]) -> bool:
    board_shortname = (rec.get("board_shortname") or "").strip()
    board_name = (rec.get("board_name") or "").strip()
    device_model = (rec.get("device_model") or "").strip()
    if board_shortname in COMPATIBLE_BOARD_SHORTNAMES:
        return True
    if board_name in COMPATIBLE_BOARD_NAMES:
        return True
    if device_model in COMPATIBLE_DEVICE_MODELS:
        return True
    return False


def init_phase2_row(rec: Dict[str, object]) -> Dict[str, object]:
    return {
        "script_name": SCRIPT_NAME,
        "script_version": SCRIPT_VERSION,
        "script_build_date": SCRIPT_BUILD_DATE,
        "mac": (rec.get("mac") or "").strip(),
        "ubicazione": (rec.get("ubicazione") or "").strip(),
        "ip": (rec.get("ip") or "").strip(),
        "pre_firmware_version_short": (rec.get("firmware_version_short") or rec.get("firmware_version") or "").strip(),
        "pre_firmware_version_full": (rec.get("firmware_version_full") or "").strip(),
        "post_firmware_version_short": "",
        "post_firmware_version_full": "",
        "board_name": (rec.get("board_name") or "").strip(),
        "board_shortname": (rec.get("board_shortname") or "").strip(),
        "device_model": (rec.get("device_model") or "").strip(),
        "model_family_status": (rec.get("model_family_status") or "").strip(),
        "hostkey_status": (rec.get("hostkey_status") or "HOSTKEY_NOT_CHECKED").strip(),
        "hostkey_auto_accepted": False,
        "hostkey_error_type": "",
        "hostkey_fingerprint": (rec.get("hostkey_fingerprint") or "").strip(),
        "action": "",
        "upload_ok": False,
        "upgrade_started": False,
        "reboot_detected": False,
        "device_back_online": False,
        "post_check_ok": False,
        "status": "",
        "error": "",
    }


def plink_probe(
    plink_path: str, ip: str, user: str, password: str, timeout: int, hostkey_fingerprint: Optional[str]
) -> Tuple[bool, str, str, str]:
    out, err, rc, exc = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="echo PROBE_OK",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if exc:
        if exc == "timeout":
            return False, "HOSTKEY_NOT_CHECKED", "SSH_TIMEOUT", "plink timeout"
        return False, "HOSTKEY_NOT_CHECKED", "SSH_PLINK_ERROR", exc

    if rc == 0:
        return True, "HOSTKEY_ALREADY_CACHED", "", ""

    hk_status, hk_error = classify_putty_hostkey(out, err)
    if hk_error:
        return False, hk_status or "HOSTKEY_NOT_CHECKED", hk_error, (err or out or "").strip()

    err_type = classify_putty_error(out, err, rc)
    return False, "HOSTKEY_NOT_CHECKED", err_type or "SSH_ERROR", (err or out or "").strip()


def confirm_board_info(
    plink_path: str,
    ip: str,
    user: str,
    password: str,
    timeout: int,
    hostkey_fingerprint: Optional[str],
) -> Tuple[bool, Dict[str, str], str, str]:
    out, err, rc, exc = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="cat /etc/board.info",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if exc:
        if exc == "timeout":
            return False, {}, "SSH_TIMEOUT", "plink board.info timeout"
        return False, {}, "SSH_PLINK_ERROR", exc
    if rc != 0:
        err_type = classify_putty_error(out, err, rc)
        return False, {}, err_type or "SSH_ERROR", (err or out or "").strip()
    info = parse_board_info_extended(out)
    return True, info, "", ""


def read_post_info(
    plink_path: str,
    ip: str,
    user: str,
    password: str,
    timeout: int,
    hostkey_fingerprint: Optional[str],
) -> Tuple[Dict[str, str], Optional[str]]:
    out_v, err_v, rc_v, exc_v = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="cat /etc/version",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if exc_v or rc_v != 0:
        err_type = classify_putty_error(out_v, err_v, rc_v)
        msg = exc_v or (err_v or out_v or "").strip()
        return {}, err_type or msg or "post version read failed"
    short = (out_v.splitlines()[0].strip() if out_v else "")

    out_b, err_b, rc_b, exc_b = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="cat /etc/board.info",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    board = {}
    if not exc_b and rc_b == 0 and out_b:
        board = parse_board_info_extended(out_b)

    out_m, err_m, rc_m, exc_m = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="mca-cli-op info",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    mca = {}
    if not exc_m and rc_m == 0 and out_m:
        mca = parse_mca_info_extended(out_m)

    return {
        "post_firmware_version_short": short,
        "post_firmware_version_full": (mca.get("firmware_version_full") or "").strip(),
        "post_board_name": (board.get("board_name") or "").strip(),
        "post_board_shortname": (board.get("board_shortname") or "").strip(),
        "post_device_model": (mca.get("device_model") or "").strip(),
    }, None


def wait_for_reboot_and_back_online(
    ip: str,
    timeout_seconds: int,
    plink_path: str,
    user: str,
    password: str,
    per_command_timeout: int,
    hostkey_fingerprint: Optional[str],
) -> Tuple[bool, bool, str]:
    deadline = time.monotonic() + max(1, timeout_seconds)
    reboot_detected = False

    initial_ok = ping_host(ip)
    if not initial_ok:
        reboot_detected = True

    down_deadline = min(deadline, time.monotonic() + max(10, min(90, timeout_seconds // 3 or 90)))
    while time.monotonic() < down_deadline:
        if not ping_host(ip):
            reboot_detected = True
            break
        time.sleep(2)

    while time.monotonic() < deadline:
        if not ping_host(ip):
            time.sleep(2)
            continue

        ok, _, err_type, err = plink_probe(
            plink_path,
            ip,
            user=user,
            password=password,
            timeout=per_command_timeout,
            hostkey_fingerprint=hostkey_fingerprint,
        )
        if ok:
            return reboot_detected, True, ""
        if err_type in {"SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT", "SSH_HOSTKEY_MISMATCH"}:
            return reboot_detected, False, err_type
        time.sleep(3)

    return reboot_detected, False, "UPDATE_FAILED_DEVICE_NOT_BACK_ONLINE"


def write_csv_report(path: str, rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    fieldnames = [
        "script_name",
        "script_version",
        "script_build_date",
        "mac",
        "ubicazione",
        "ip",
        "pre_firmware_version_short",
        "pre_firmware_version_full",
        "post_firmware_version_short",
        "post_firmware_version_full",
        "board_name",
        "board_shortname",
        "device_model",
        "model_family_status",
        "hostkey_status",
        "hostkey_auto_accepted",
        "hostkey_error_type",
        "hostkey_fingerprint",
        "action",
        "upload_ok",
        "upgrade_started",
        "reboot_detected",
        "device_back_online",
        "post_check_ok",
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


def process_one_ap(
    rec: Dict[str, object],
    firmware_path: str,
    target_full: str,
    target_short: str,
    user: str,
    password: str,
    plink_path: str,
    pscp_path: str,
    timeout: int,
    reboot_timeout: int,
    accept_new_hostkeys: bool,
    execute: bool,
) -> Dict[str, object]:
    row = init_phase2_row(rec)
    ip = row["ip"]
    row["action"] = "NOOP"

    try:
        if row["mac"]:
            row["mac"] = normalize_mac(row["mac"])
    except Exception:
        pass

    ip_found = coerce_bool(rec.get("ip_found"))
    ping_ok = coerce_bool(rec.get("ping_ok"))
    ssh_ok = coerce_bool(rec.get("ssh_ok"))
    model_family_status = (rec.get("model_family_status") or "").strip()

    if not ip_found or not ip:
        row["status"] = "SKIPPED_IP_NOT_FOUND"
        row["error"] = "IP_NOT_FOUND"
        return row

    try:
        ipaddress.ip_address(ip)
    except Exception:
        row["status"] = "SKIPPED_IP_NOT_FOUND"
        row["error"] = "IP_INVALID"
        return row

    if not ping_ok:
        row["status"] = "SKIPPED_SSH_NOT_OK"
        row["error"] = "PING_NOT_OK"
        return row

    if not ssh_ok:
        row["status"] = "SKIPPED_SSH_NOT_OK"
        row["error"] = "SSH_NOT_OK"
        return row

    if model_family_status == "MODEL_FAMILY_MISMATCH":
        row["status"] = "SKIPPED_MODEL_FAMILY_MISMATCH"
        row["error"] = "MODEL_FAMILY_MISMATCH"
        return row

    if model_family_status == "MODEL_FAMILY_UNKNOWN" or not model_family_status:
        row["status"] = "SKIPPED_MODEL_FAMILY_UNKNOWN"
        row["error"] = "MODEL_FAMILY_UNKNOWN"
        return row

    if model_family_status != "MODEL_FAMILY_OK":
        row["status"] = "SKIPPED_MODEL_FAMILY_UNKNOWN"
        row["error"] = f"MODEL_FAMILY_STATUS_UNEXPECTED={model_family_status}"
        return row

    if not is_candidate_model(rec):
        row["status"] = "SKIPPED_MODEL_FAMILY_MISMATCH"
        row["error"] = "MODEL_FIELDS_NOT_MATCHING_UAP_IW_U2IW"
        return row

    action, version_status = decide_version_action(
        firmware_version_full=row["pre_firmware_version_full"],
        firmware_version_short=row["pre_firmware_version_short"],
        target_full=target_full,
        target_short=target_short,
    )

    if version_status == "SKIPPED_ALREADY_UPDATED":
        row["status"] = "SKIPPED_ALREADY_UPDATED"
        row["action"] = "NOOP"
        return row

    if version_status == "SKIPPED_VERSION_FULL_UNKNOWN_BUT_SHORT_MATCHES":
        row["status"] = "SKIPPED_VERSION_FULL_UNKNOWN_BUT_SHORT_MATCHES"
        row["action"] = "NOOP"
        return row

    hostkey_fingerprint = (row.get("hostkey_fingerprint") or "").strip()
    if not hostkey_fingerprint:
        row["status"] = "SKIPPED_HOSTKEY_FINGERPRINT_MISSING"
        row["error"] = "HOSTKEY_FINGERPRINT_MISSING"
        row["action"] = "NOOP"
        return row

    if not execute and not hostkey_fingerprint.startswith("SHA256:"):
        row["status"] = "SKIPPED_HOSTKEY_FINGERPRINT_MISSING"
        row["error"] = f"HOSTKEY_FINGERPRINT_INVALID={hostkey_fingerprint!r}"
        row["action"] = "NOOP"
        return row

    if not execute:
        row["status"] = "DRY_RUN_UPDATE_REQUIRED"
        row["action"] = "UPDATE"
        return row

    row["action"] = "UPDATE"

    if not hostkey_fingerprint.startswith("SHA256:"):
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = f"HOSTKEY_FINGERPRINT_INVALID={hostkey_fingerprint!r}"
        return row

    plink_resolved = resolve_executable(plink_path)
    pscp_resolved = resolve_executable(pscp_path)
    if not plink_resolved:
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = f"plink not found: {plink_path}"
        return row
    if not pscp_resolved:
        row["status"] = "UPDATE_FAILED_UPLOAD"
        row["error"] = f"pscp not found: {pscp_path}"
        return row

    ok_probe, hk_status, hk_error, hk_errmsg = plink_probe(
        plink_path, ip, user=user, password=password, timeout=timeout, hostkey_fingerprint=hostkey_fingerprint
    )
    if ok_probe:
        if not row.get("hostkey_status") or row.get("hostkey_status") == "HOSTKEY_NOT_CHECKED":
            row["hostkey_status"] = "HOSTKEY_ACCEPTED_VIA_HOSTKEY_OPTION"
        row["hostkey_auto_accepted"] = False
        row["hostkey_error_type"] = ""
    else:
        if hk_error == "SSH_HOSTKEY_MISMATCH":
            row["hostkey_status"] = "HOSTKEY_MISMATCH"
            row["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
            row["status"] = "SKIPPED_HOSTKEY_MISMATCH"
            row["error"] = hk_errmsg or "HOSTKEY_MISMATCH"
            return row

        row["hostkey_status"] = row.get("hostkey_status") or "HOSTKEY_NOT_CHECKED"
        row["hostkey_error_type"] = hk_error or "SSH_ERROR"
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = hk_errmsg or "SSH_PROBE_FAILED"
        return row

    board_ok, board_info, board_err_type, board_err = confirm_board_info(
        plink_path, ip, user=user, password=password, timeout=timeout, hostkey_fingerprint=hostkey_fingerprint
    )
    if not board_ok:
        if board_err_type == "SSH_HOSTKEY_MISMATCH":
            row["hostkey_status"] = "HOSTKEY_MISMATCH"
            row["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
            row["status"] = "SKIPPED_HOSTKEY_MISMATCH"
            row["error"] = board_err or "HOSTKEY_MISMATCH"
            return row
        if board_err_type == "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT":
            row["hostkey_status"] = "HOSTKEY_UNKNOWN_NOT_ACCEPTED"
            row["hostkey_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"
            row["status"] = "SKIPPED_HOSTKEY_UNKNOWN_NOT_ACCEPTED"
            row["error"] = board_err or "HOSTKEY_UNKNOWN"
            return row
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = board_err or board_err_type or "BOARD_INFO_READ_FAILED"
        return row

    bn = board_info.get("board_name") or ""
    bs = board_info.get("board_shortname") or ""
    mf = evaluate_model_family(bn, bs, row.get("device_model") or "")
    if mf != "MODEL_FAMILY_OK":
        row["board_name"] = bn
        row["board_shortname"] = bs
        row["model_family_status"] = mf
        row["status"] = "SKIPPED_MODEL_FAMILY_MISMATCH" if mf == "MODEL_FAMILY_MISMATCH" else "SKIPPED_MODEL_FAMILY_UNKNOWN"
        row["error"] = f"MODEL_RECHECK={mf}"
        return row

    row["board_name"] = bn
    row["board_shortname"] = bs

    local_fw = os.path.abspath(firmware_path)
    upload_out, upload_err, upload_rc, upload_exc = run_pscp_upload(
        pscp_path=pscp_path,
        host=ip,
        user=user,
        password=password,
        local_file=local_fw,
        remote_path="/tmp/fwupdate.bin",
        timeout=max(10, timeout),
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if upload_exc:
        row["status"] = "UPDATE_FAILED_UPLOAD"
        row["error"] = "pscp timeout" if upload_exc == "timeout" else upload_exc
        return row
    if upload_rc != 0:
        err_type = classify_putty_error(upload_out, upload_err, upload_rc)
        if err_type == "SSH_HOSTKEY_MISMATCH":
            row["hostkey_status"] = "HOSTKEY_MISMATCH"
            row["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
        if err_type == "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT":
            row["hostkey_status"] = "HOSTKEY_UNKNOWN_NOT_ACCEPTED"
            row["hostkey_error_type"] = "SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT"
        row["status"] = "UPDATE_FAILED_UPLOAD"
        row["error"] = (upload_err or upload_out or "pscp failed").strip()
        return row

    row["upload_ok"] = True

    chk_out, chk_err, chk_rc, chk_exc = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="ls -l /tmp/fwupdate.bin /bin/syswrapper.sh",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if chk_exc:
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = "plink timeout" if chk_exc == "timeout" else chk_exc
        return row
    if chk_rc != 0:
        combined = ((chk_out or "") + "\n" + (chk_err or "")).lower()
        fw_missing = ("/tmp/fwupdate.bin" in combined) and ("no such file" in combined or "not found" in combined)
        sys_missing = ("/bin/syswrapper.sh" in combined) and ("no such file" in combined or "not found" in combined)
        if fw_missing:
            row["status"] = "UPDATE_FAILED_UPLOAD"
            row["error"] = "FWUPDATE_BIN_MISSING"
            return row
        if sys_missing:
            row["status"] = "UPDATE_FAILED_COMMAND"
            row["error"] = "SYSWRAPPER_MISSING"
            return row
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = (chk_err or chk_out or "PRE_UPGRADE_CHECK_FAILED").strip()
        return row

    up_out, up_err, up_rc, up_exc = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="sh -c '/bin/syswrapper.sh upgrade2 >/tmp/upgrade.log 2>&1 &'",
        timeout=timeout,
        batch=True,
        stdin_data="\n",
        hostkey_fingerprint=hostkey_fingerprint,
    )
    if up_exc:
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = "plink timeout" if up_exc == "timeout" else up_exc
        return row
    if up_rc != 0:
        err_type = classify_putty_error(up_out, up_err, up_rc)
        if err_type == "SSH_HOSTKEY_MISMATCH":
            row["hostkey_status"] = "HOSTKEY_MISMATCH"
            row["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
            row["status"] = "SKIPPED_HOSTKEY_MISMATCH"
            row["error"] = (up_err or up_out or "plink hostkey mismatch").strip()
            return row
        row["status"] = "UPDATE_FAILED_COMMAND"
        row["error"] = (up_err or up_out or "upgrade command failed").strip()
        return row

    row["upgrade_started"] = True
    row["status"] = "UPDATE_STARTED"

    reboot_detected, back_online, back_error = wait_for_reboot_and_back_online(
        ip=ip,
        timeout_seconds=reboot_timeout,
        plink_path=plink_path,
        user=user,
        password=password,
        per_command_timeout=timeout,
        hostkey_fingerprint=hostkey_fingerprint,
    )
    row["reboot_detected"] = reboot_detected
    row["device_back_online"] = back_online

    if not back_online:
        if back_error == "SSH_HOSTKEY_MISMATCH":
            row["hostkey_status"] = "HOSTKEY_MISMATCH"
            row["hostkey_error_type"] = "SSH_HOSTKEY_MISMATCH"
            row["status"] = "SKIPPED_HOSTKEY_MISMATCH"
            row["error"] = "HOSTKEY_MISMATCH_AFTER_REBOOT"
            return row
        row["status"] = "UPDATE_FAILED_DEVICE_NOT_BACK_ONLINE"
        row["error"] = back_error or "DEVICE_NOT_BACK_ONLINE"
        return row

    post, post_err = read_post_info(
        plink_path, ip, user=user, password=password, timeout=timeout, hostkey_fingerprint=hostkey_fingerprint
    )
    if post_err:
        row["status"] = "UPDATE_FAILED_POST_CHECK"
        row["error"] = post_err
        return row

    row["post_firmware_version_short"] = post.get("post_firmware_version_short") or ""
    row["post_firmware_version_full"] = post.get("post_firmware_version_full") or ""

    post_bn = post.get("post_board_name") or row.get("board_name") or ""
    post_bs = post.get("post_board_shortname") or row.get("board_shortname") or ""
    post_dm = post.get("post_device_model") or row.get("device_model") or ""
    row["board_name"] = post_bn
    row["board_shortname"] = post_bs
    row["device_model"] = post_dm
    row["model_family_status"] = evaluate_model_family(post_bn, post_bs, post_dm)

    post_full = (row["post_firmware_version_full"] or "").strip()
    post_short = (row["post_firmware_version_short"] or "").strip()

    if post_full and post_full == target_full:
        row["post_check_ok"] = True
        row["status"] = "UPDATE_COMPLETED"
        return row

    if not post_full and post_short and post_short == target_short:
        row["post_check_ok"] = True
        row["status"] = "UPDATE_COMPLETED_UNVERIFIED_FULL"
        return row

    row["status"] = "UPDATE_FAILED_POST_CHECK"
    row["error"] = f"POST_VERSION_MISMATCH full={post_full!r} short={post_short!r}"
    return row


def main(argv: Optional[List[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    if "--version" in argv_list:
        print(f"Script: {SCRIPT_NAME}")
        print(f"Version: {SCRIPT_VERSION}")
        print(f"Build: {SCRIPT_BUILD_DATE}")
        print(f"Summary: {SCRIPT_SUMMARY}")
        return 0

    p = argparse.ArgumentParser(description="UAP-IW / U2IW Phase 2 firmware update (safe gated).")
    p.add_argument("--version", action="store_true", help="Stampa versione script ed esce")
    p.add_argument("--verbose", action="store_true", help="Stampa dettagli aggiuntivi (incl. traceback su errori non gestiti)")
    p.add_argument("--input", required=True, help="Report Fase 1 (.json preferito, oppure .csv)")
    p.add_argument("--firmware", required=True, help="Firmware file path (.bin)")
    p.add_argument("--target-version-full", required=True)
    p.add_argument("--target-version-short", required=True)
    p.add_argument("--user", default="ubnt")
    p.add_argument("--password", default="ubnt")
    p.add_argument("--plink-path", default="plink.exe")
    p.add_argument("--pscp-path", default="pscp.exe")
    p.add_argument("--out", required=True, help="CSV report output")
    p.add_argument("--json", dest="json_out", help="JSON report output (opzionale)")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--reboot-timeout", type=int, default=300)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--accept-new-hostkeys", action="store_true")
    p.add_argument("--execute", action="store_true")
    args = p.parse_args(argv_list)

    print(f"[PHASE2] Script: {SCRIPT_NAME} | Version: {SCRIPT_VERSION} | Build: {SCRIPT_BUILD_DATE}")

    firmware_path = args.firmware
    if not os.path.exists(firmware_path):
        print(f"Errore: firmware file non trovato: {firmware_path}", file=sys.stderr)
        return 2
    if not os.path.isfile(firmware_path):
        print(f"Errore: firmware path non è un file: {firmware_path}", file=sys.stderr)
        return 2
    if not os.path.basename(firmware_path).startswith("BZ.qca933x"):
        print("Errore: firmware file non compatibile (atteso prefisso BZ.qca933x)", file=sys.stderr)
        return 2

    if args.execute:
        if not resolve_executable(args.plink_path):
            print(f"Errore: plink non disponibile: {args.plink_path}", file=sys.stderr)
            return 2
        if not resolve_executable(args.pscp_path):
            print(f"Errore: pscp non disponibile: {args.pscp_path}", file=sys.stderr)
            return 2

    records = read_input_report(args.input)
    ensure_required_fields(records)

    mode = "EXECUTE" if args.execute else "DRY-RUN"
    print(f"[PHASE2] Mode: {mode} (workers={max(1, args.workers)})")
    print(f"[PHASE2] Input: {os.path.abspath(args.input)}")
    print(f"[PHASE2] Firmware: {os.path.abspath(firmware_path)}")
    print(f"[PHASE2] Target full: {args.target_version_full} | Target short: {args.target_version_short}")

    processed: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        fut_to_rec = {}
        for rec in records:
            fut = ex.submit(
                process_one_ap,
                rec,
                firmware_path,
                args.target_version_full,
                args.target_version_short,
                args.user,
                args.password,
                args.plink_path,
                args.pscp_path,
                args.timeout,
                args.reboot_timeout,
                args.accept_new_hostkeys,
                args.execute,
            )
            fut_to_rec[fut] = rec

        for fut in as_completed(list(fut_to_rec.keys())):
            try:
                processed.append(fut.result())
            except Exception as e:
                rec = fut_to_rec.get(fut) or {}
                row = init_phase2_row(rec)
                if "action" in rec and (rec.get("action") or "").strip():
                    row["action"] = (rec.get("action") or "").strip()
                row["status"] = "ERROR"
                row["error"] = f"Unhandled exception: {type(e).__name__}: {e}"
                processed.append(row)

                mac = (row.get("mac") or "").strip()
                ip = (row.get("ip") or "").strip()
                print(f"[PHASE2][ERROR] Unhandled exception for mac={mac} ip={ip}: {type(e).__name__}: {e}", file=sys.stderr)
                if args.verbose:
                    print(traceback.format_exc().strip(), file=sys.stderr)

    processed.sort(key=lambda r: (r.get("mac") or "", r.get("ip") or ""))

    for r in processed:
        mac = r.get("mac") or ""
        ubic = r.get("ubicazione") or ""
        ip = r.get("ip") or ""
        status = r.get("status") or ""
        action = r.get("action") or ""
        hk = r.get("hostkey_status") or ""
        print(f"[AP] {mac} - {ubic} - IP {ip} - {action} - {hk} - {status}")

    write_csv_report(args.out, processed)
    if args.json_out:
        write_json_report(args.json_out, processed)

    counts: Dict[str, int] = {}
    for r in processed:
        s = r.get("status") or "UNKNOWN"
        counts[s] = counts.get(s, 0) + 1

    print("")
    print(f"Totale record: {len(processed)}")
    for k in sorted(counts.keys()):
        print(f"{k}: {counts[k]}")
    print("")
    print(f"[OUT] CSV: {os.path.abspath(args.out)}")
    if args.json_out:
        print(f"[OUT] JSON: {os.path.abspath(args.json_out)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
