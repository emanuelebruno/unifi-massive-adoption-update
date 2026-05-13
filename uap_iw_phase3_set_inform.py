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


SCRIPT_NAME = "uap_iw_phase3_set_inform.py"
SCRIPT_VERSION = "0.1.0"
SCRIPT_BUILD_DATE = "2026-05-13"
SCRIPT_SUMMARY = "Phase 3 set-inform for verified UAP-IW devices using plink -hostkey"


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


def resolve_executable(path_or_name: str) -> Optional[str]:
    if not path_or_name:
        return None
    if os.path.isabs(path_or_name) or os.path.sep in path_or_name or (os.path.altsep and os.path.altsep in path_or_name):
        return path_or_name if os.path.exists(path_or_name) else None
    return shutil.which(path_or_name)


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
    hostkey_fingerprint: str,
) -> Tuple[str, str, Optional[int], Optional[str]]:
    resolved = resolve_executable(plink_path)
    if not resolved:
        return "", "", None, f"plink not found: {plink_path}"

    cmd = [
        resolved,
        "-ssh",
        "-P",
        "22",
        "-l",
        user,
        "-pw",
        password,
        "-batch",
        "-hostkey",
        hostkey_fingerprint,
        host,
        command,
    ]

    try:
        proc = subprocess.run(
            cmd,
            input="\n",
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


def normalize_mac(value: str) -> str:
    if value is None:
        raise ValueError("MAC missing")
    s = value.strip()
    if not s:
        raise ValueError("MAC empty")
    s = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(s) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", s):
        raise ValueError(f"MAC invalid: {value!r}")
    s = s.upper()
    return ":".join(s[i : i + 2] for i in range(0, 12, 2))


def parse_board_info_extended(board_info: str) -> Dict[str, str]:
    board_name = ""
    board_shortname = ""
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
    return {"board_name": board_name, "board_shortname": board_shortname}


def parse_mca_info_extended(mca_info: str) -> Dict[str, str]:
    text = (mca_info or "").strip()
    if not text:
        return {"device_model": "", "firmware_version_full": "", "inform_status": ""}

    model = ""
    version = ""
    status = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("model:"):
            model = line.split(":", 1)[1].strip()
        elif line.lower().startswith("version:"):
            version = line.split(":", 1)[1].strip()
        elif line.lower().startswith("status:"):
            status = line.split(":", 1)[1].strip()
    return {"device_model": model, "firmware_version_full": version, "inform_status": status}


def evaluate_model_family(board_name: str, board_shortname: str, device_model: str) -> str:
    bn = (board_name or "").strip()
    bs = (board_shortname or "").strip()
    dm = (device_model or "").strip()

    if bs and bs in COMPATIBLE_BOARD_SHORTNAMES:
        return "MODEL_FAMILY_OK"
    if bn and bn in COMPATIBLE_BOARD_NAMES:
        return "MODEL_FAMILY_OK"
    if dm and dm in COMPATIBLE_DEVICE_MODELS:
        return "MODEL_FAMILY_OK"

    if bn or bs or dm:
        return "MODEL_FAMILY_MISMATCH"
    return "MODEL_FAMILY_UNKNOWN"


def sh_single_quote(s: str) -> str:
    return "'" + (s or "").replace("'", "'\"'\"'") + "'"


def build_set_inform_command(inform_url: str) -> str:
    inner = f"mca-cli-op set-inform {sh_single_quote(inform_url)}"
    return f"sh -c {sh_single_quote(inner)}"


def validate_inform_url(url: str) -> Optional[str]:
    u = (url or "").strip()
    if not u:
        return "inform-url missing"
    ul = u.lower()
    if not (ul.startswith("http://") or ul.startswith("https://")):
        return "inform-url must start with http:// or https://"
    if "/inform" not in ul:
        return "inform-url must contain /inform"
    return None


def read_input_report(path: str) -> List[Dict[str, object]]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON report: expected array of objects")
        return [dict(x) for x in data]

    if ext == ".csv":
        rows: List[Dict[str, object]] = []
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV report: missing header")
            for row in reader:
                rows.append(dict(row))
        return rows

    raise ValueError("Input report: unsupported extension (use .json or .csv)")


def detect_report_kind(records: List[Dict[str, object]]) -> str:
    for r in records:
        if any(k in r for k in ("post_check_ok", "device_back_online", "upgrade_started", "upload_ok", "post_firmware_version_full")):
            return "phase2"
    for r in records:
        if any(k in r for k in ("ssh_backend", "firmware_version_short", "firmware_version_full", "ping_ok")):
            return "phase1"
    return "unknown"


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


def init_phase3_row(rec: Dict[str, object], inform_url: str, target_version_full: str, dry_run: bool) -> Dict[str, object]:
    mac = (rec.get("mac") or "").strip()
    if mac:
        try:
            mac = normalize_mac(mac)
        except Exception:
            pass

    row: Dict[str, object] = {
        "script_name": SCRIPT_NAME,
        "script_version": SCRIPT_VERSION,
        "script_build_date": SCRIPT_BUILD_DATE,
        "mac": mac,
        "ubicazione": (rec.get("ubicazione") or "").strip(),
        "ip": (rec.get("ip") or "").strip(),
        "hostkey_fingerprint": (rec.get("hostkey_fingerprint") or "").strip(),
        "device_model": (rec.get("device_model") or "").strip(),
        "board_name": (rec.get("board_name") or "").strip(),
        "board_shortname": (rec.get("board_shortname") or "").strip(),
        "pre_firmware_version_short": "",
        "pre_firmware_version_full": "",
        "target_version_full": target_version_full,
        "inform_url": inform_url,
        "action": "NOOP",
        "dry_run": bool(dry_run),
        "set_inform_attempted": False,
        "set_inform_ok": False,
        "pre_inform_status": "",
        "post_inform_status": "",
        "status": "",
        "error": "",
    }

    if "pre_firmware_version_short" in rec:
        row["pre_firmware_version_short"] = (rec.get("pre_firmware_version_short") or "").strip()
    else:
        row["pre_firmware_version_short"] = (rec.get("firmware_version_short") or rec.get("firmware_version") or "").strip()

    if "pre_firmware_version_full" in rec:
        row["pre_firmware_version_full"] = (rec.get("pre_firmware_version_full") or "").strip()
    else:
        row["pre_firmware_version_full"] = (rec.get("firmware_version_full") or "").strip()

    return row


def decide_phase3(
    rec: Dict[str, object],
    kind: str,
    target_version_full: str,
    allow_non_target_firmware: bool,
) -> Tuple[bool, str, str]:
    ip = (rec.get("ip") or "").strip()
    if not ip:
        return False, "SKIPPED_IP_NOT_FOUND", "IP_NOT_FOUND"
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return False, "SKIPPED_IP_NOT_FOUND", "IP_INVALID"

    hk = (rec.get("hostkey_fingerprint") or "").strip()
    if not hk or not hk.startswith("SHA256:"):
        return False, "SKIPPED_HOSTKEY_FINGERPRINT_MISSING", "HOSTKEY_FINGERPRINT_MISSING"

    if (rec.get("model_family_status") or "").strip() != "MODEL_FAMILY_OK":
        return False, "SKIPPED_MODEL_FAMILY_NOT_OK", "MODEL_FAMILY_NOT_OK"

    if not is_candidate_model(rec):
        return False, "SKIPPED_MODEL_FAMILY_NOT_OK", "MODEL_FIELDS_NOT_MATCHING_UAP_IW_U2IW"

    if kind == "phase2":
        st = (rec.get("status") or "").strip()
        if st in {"UPDATE_COMPLETED", "SKIPPED_ALREADY_UPDATED"}:
            pass
        else:
            if st.startswith("UPDATE_FAILED"):
                return False, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"
            if st.startswith("SKIPPED_SSH_NOT_OK") or st == "SKIPPED_SSH_NOT_OK":
                return False, "SKIPPED_SSH_NOT_OK", "SSH_NOT_OK"
            if st.startswith("SKIPPED_HOSTKEY") or st.startswith("SKIPPED_MODEL") or st == "ERROR":
                return False, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"
            return False, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"

        post_full = (rec.get("post_firmware_version_full") or "").strip()
        if post_full and post_full != target_version_full and not allow_non_target_firmware:
            return False, "SKIPPED_FIRMWARE_NOT_TARGET", f"POST_FIRMWARE_NOT_TARGET={post_full}"

        return True, "DRY_RUN_SET_INFORM_REQUIRED", ""

    if kind == "phase1":
        st = (rec.get("status") or "").strip()
        ssh_ok = coerce_bool(rec.get("ssh_ok"))
        if st != "IP_FOUND_SSH_OK" or not ssh_ok:
            return False, "SKIPPED_SSH_NOT_OK", f"PHASE1_STATUS={st or 'UNKNOWN'}"

        fw_full = (rec.get("firmware_version_full") or "").strip()
        if fw_full and fw_full != target_version_full and not allow_non_target_firmware:
            return False, "SKIPPED_FIRMWARE_NOT_TARGET", f"FIRMWARE_NOT_TARGET={fw_full}"

        return True, "DRY_RUN_SET_INFORM_REQUIRED", ""

    return False, "ERROR", "INPUT_REPORT_KIND_UNKNOWN"


def probe_read_only(
    row: Dict[str, object],
    plink_path: str,
    user: str,
    password: str,
    timeout: int,
    verbose: bool,
) -> Tuple[Dict[str, object], Optional[str]]:
    ip = (row.get("ip") or "").strip()
    hk = (row.get("hostkey_fingerprint") or "").strip()

    out_v, err_v, rc_v, exc_v = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="cat /etc/version",
        timeout=timeout,
        hostkey_fingerprint=hk,
    )
    if exc_v or rc_v != 0:
        msg = exc_v or (err_v or out_v or "").strip()
        if verbose:
            print(f"[PROBE] cat /etc/version rc={rc_v} exc={exc_v} msg={msg}")
        return {}, msg or "probe version failed"
    fw_short = (out_v.splitlines()[0].strip() if out_v else "")

    out_b, err_b, rc_b, exc_b = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="cat /etc/board.info",
        timeout=timeout,
        hostkey_fingerprint=hk,
    )
    if exc_b or rc_b != 0:
        msg = exc_b or (err_b or out_b or "").strip()
        if verbose:
            print(f"[PROBE] cat /etc/board.info rc={rc_b} exc={exc_b} msg={msg}")
        return {"pre_firmware_version_short": fw_short}, msg or "probe board.info failed"
    board = parse_board_info_extended(out_b)

    out_m, err_m, rc_m, exc_m = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="mca-cli-op info",
        timeout=timeout,
        hostkey_fingerprint=hk,
    )
    if exc_m or rc_m != 0:
        msg = exc_m or (err_m or out_m or "").strip()
        if verbose:
            print(f"[PROBE] mca-cli-op info rc={rc_m} exc={exc_m} msg={msg}")
        return {
            "pre_firmware_version_short": fw_short,
            "board_name": (board.get("board_name") or "").strip(),
            "board_shortname": (board.get("board_shortname") or "").strip(),
        }, msg or "probe mca-cli-op info failed"

    mca = parse_mca_info_extended(out_m)

    res = {
        "pre_firmware_version_short": fw_short,
        "pre_firmware_version_full": (mca.get("firmware_version_full") or "").strip(),
        "board_name": (board.get("board_name") or "").strip(),
        "board_shortname": (board.get("board_shortname") or "").strip(),
        "device_model": (mca.get("device_model") or "").strip(),
        "pre_inform_status": (mca.get("inform_status") or "").strip(),
    }
    return res, None


def post_check_info(
    row: Dict[str, object],
    plink_path: str,
    user: str,
    password: str,
    timeout: int,
    verbose: bool,
) -> Tuple[str, Optional[str]]:
    ip = (row.get("ip") or "").strip()
    hk = (row.get("hostkey_fingerprint") or "").strip()
    out_m, err_m, rc_m, exc_m = run_plink(
        plink_path=plink_path,
        host=ip,
        user=user,
        password=password,
        command="mca-cli-op info",
        timeout=timeout,
        hostkey_fingerprint=hk,
    )
    if exc_m or rc_m != 0:
        msg = exc_m or (err_m or out_m or "").strip()
        if verbose:
            print(f"[POST] mca-cli-op info rc={rc_m} exc={exc_m} msg={msg}")
        return "", msg or "post-check mca-cli-op info failed"
    mca = parse_mca_info_extended(out_m)
    return (mca.get("inform_status") or "").strip(), None


def execute_one_ap(
    rec: Dict[str, object],
    kind: str,
    inform_url: str,
    target_version_full: str,
    allow_non_target_firmware: bool,
    plink_path: str,
    user: str,
    password: str,
    timeout: int,
    post_check_delay: int,
    post_check_attempts: int,
    execute: bool,
    verbose: bool,
) -> Dict[str, object]:
    dry_run = not execute
    row = init_phase3_row(rec, inform_url, target_version_full, dry_run=dry_run)
    eligible, status, reason = decide_phase3(rec, kind, target_version_full, allow_non_target_firmware)
    if not eligible:
        row["status"] = status
        row["error"] = reason
        row["action"] = "NOOP"
        return row

    row["action"] = "SET_INFORM"
    row["status"] = "DRY_RUN_SET_INFORM_REQUIRED"
    if dry_run:
        return row

    probe, probe_err = probe_read_only(row, plink_path, user, password, timeout, verbose)
    if probe:
        for k in ("board_name", "board_shortname", "device_model", "pre_firmware_version_short", "pre_firmware_version_full", "pre_inform_status"):
            if k in probe and (probe.get(k) or "") != "":
                row[k] = probe.get(k) or ""
    if probe_err:
        row["status"] = "SET_INFORM_FAILED_COMMAND"
        row["error"] = probe_err
        return row

    mf = evaluate_model_family(row.get("board_name") or "", row.get("board_shortname") or "", row.get("device_model") or "")
    if mf != "MODEL_FAMILY_OK":
        row["status"] = "SKIPPED_MODEL_FAMILY_NOT_OK"
        row["error"] = f"MODEL_RECHECK={mf}"
        return row

    fw_full = (row.get("pre_firmware_version_full") or "").strip()
    if fw_full and fw_full != target_version_full and not allow_non_target_firmware:
        row["status"] = "SKIPPED_FIRMWARE_NOT_TARGET"
        row["error"] = f"FIRMWARE_NOT_TARGET={fw_full}"
        return row

    cmd = build_set_inform_command(inform_url)
    out_s, err_s, rc_s, exc_s = run_plink(
        plink_path=plink_path,
        host=row["ip"],
        user=user,
        password=password,
        command=cmd,
        timeout=timeout,
        hostkey_fingerprint=row["hostkey_fingerprint"],
    )
    row["set_inform_attempted"] = True

    if exc_s:
        row["status"] = "SET_INFORM_FAILED_COMMAND"
        row["error"] = "plink timeout" if exc_s == "timeout" else exc_s
        return row
    if rc_s != 0:
        err_type = classify_putty_error(out_s, err_s, rc_s)
        msg = (err_s or out_s or "set-inform failed").strip()
        row["status"] = "SET_INFORM_FAILED_COMMAND"
        row["error"] = err_type + (f": {msg}" if msg else "") if err_type else msg
        return row

    row["set_inform_ok"] = True

    attempts = max(1, int(post_check_attempts))
    delay = max(0, int(post_check_delay))
    last_err = ""
    for i in range(attempts):
        if delay and i > 0:
            time.sleep(delay)
        st, err = post_check_info(row, plink_path, user, password, timeout, verbose)
        if err:
            last_err = err
            continue
        row["post_inform_status"] = st
        row["status"] = "SET_INFORM_COMPLETED"
        row["error"] = ""
        return row

    row["status"] = "SET_INFORM_FAILED_POST_CHECK"
    row["error"] = last_err or "post-check failed"
    return row


def write_csv_report(path: str, rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    fieldnames = [
        "script_name",
        "script_version",
        "script_build_date",
        "mac",
        "ubicazione",
        "ip",
        "hostkey_fingerprint",
        "device_model",
        "board_name",
        "board_shortname",
        "pre_firmware_version_short",
        "pre_firmware_version_full",
        "target_version_full",
        "inform_url",
        "action",
        "dry_run",
        "set_inform_attempted",
        "set_inform_ok",
        "pre_inform_status",
        "post_inform_status",
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


def main(argv: Optional[List[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    if "--version" in argv_list:
        print(f"Script: {SCRIPT_NAME}")
        print(f"Version: {SCRIPT_VERSION}")
        print(f"Build: {SCRIPT_BUILD_DATE}")
        print(f"Summary: {SCRIPT_SUMMARY}")
        return 0

    p = argparse.ArgumentParser(description="UAP-IW / U2IW Phase 3 set-inform (gated; dry-run default).")
    p.add_argument("--version", action="store_true", help="Print script version and exit")
    p.add_argument("--input", required=True, help="Phase 2 (preferred) or Phase 1 report (.json or .csv)")
    p.add_argument("--inform-url", required=True, dest="inform_url")
    p.add_argument("--target-version-full", default="4.3.28.11361", dest="target_version_full")
    p.add_argument("--target-version-short", default="BZ.v4.3.28", dest="target_version_short")
    p.add_argument("--allow-non-target-firmware", action="store_true", dest="allow_non_target_firmware")
    p.add_argument("--user", default="ubnt")
    p.add_argument("--password", default="ubnt")
    p.add_argument("--plink-path", default="plink.exe", dest="plink_path")
    p.add_argument("--out", required=True, help="CSV report output")
    p.add_argument("--json", dest="json_out", help="JSON report output (optional)")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--post-check-delay", type=int, default=3, dest="post_check_delay")
    p.add_argument("--post-check-attempts", type=int, default=1, dest="post_check_attempts")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv_list)

    print(f"[PHASE3] Script: {SCRIPT_NAME} | Version: {SCRIPT_VERSION} | Build: {SCRIPT_BUILD_DATE}")

    url_err = validate_inform_url(args.inform_url)
    if url_err:
        print(f"Errore: --inform-url non valido: {url_err}", file=sys.stderr)
        return 2

    if args.execute:
        if not resolve_executable(args.plink_path):
            print(f"Errore: plink non disponibile: {args.plink_path}", file=sys.stderr)
            return 2

    records = read_input_report(args.input)
    kind = detect_report_kind(records)
    mode = "EXECUTE" if args.execute else "DRY-RUN"
    print(f"[PHASE3] Mode: {mode} (workers={max(1, args.workers)})")
    print(f"[PHASE3] Input kind: {kind}")
    print(f"[PHASE3] Input: {os.path.abspath(args.input)}")
    print(f"[PHASE3] Inform URL: {args.inform_url}")
    print(f"[PHASE3] Target full: {args.target_version_full} | Target short: {args.target_version_short}")
    if args.allow_non_target_firmware:
        print("[PHASE3] WARNING: --allow-non-target-firmware enabled")

    processed: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        fut_to_rec = {}
        for rec in records:
            fut = ex.submit(
                execute_one_ap,
                rec,
                kind,
                args.inform_url,
                args.target_version_full,
                args.allow_non_target_firmware,
                args.plink_path,
                args.user,
                args.password,
                args.timeout,
                args.post_check_delay,
                args.post_check_attempts,
                args.execute,
                args.verbose,
            )
            fut_to_rec[fut] = rec

        for fut in as_completed(list(fut_to_rec.keys())):
            try:
                processed.append(fut.result())
            except Exception as e:
                rec = fut_to_rec.get(fut) or {}
                row = init_phase3_row(rec, args.inform_url, args.target_version_full, dry_run=not args.execute)
                row["status"] = "ERROR"
                row["error"] = f"Unhandled exception: {type(e).__name__}: {e}"
                processed.append(row)
                if args.verbose:
                    print(traceback.format_exc().strip(), file=sys.stderr)

    processed.sort(key=lambda r: (r.get("mac") or "", r.get("ip") or ""))

    for r in processed:
        mac = r.get("mac") or ""
        ubic = r.get("ubicazione") or ""
        ip = r.get("ip") or ""
        status = r.get("status") or ""
        action = r.get("action") or ""
        print(f"[AP] {mac} - {ubic} - IP {ip} - {action} - {status}")

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

