import argparse
import base64
import csv
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)

from unifi_firmware_compatibility import (
    CompatibilityError,
    CompatibilityResolutionError,
    load_catalog,
    resolve_transition,
)


SCRIPT_NAME = "uap_iw_phase3_set_inform.py"
SCRIPT_VERSION = "0.2.0"
SCRIPT_BUILD_DATE = "2026-08-27"
SCRIPT_SUMMARY = "Phase 3 set-inform with legacy and operation-gated declarative compatibility paths"


COMPATIBLE_BOARD_NAMES = {"UAP-InWall"}
COMPATIBLE_BOARD_SHORTNAMES = {"U2IW"}
COMPATIBLE_DEVICE_MODELS = {"UAP-InWall"}

LEGACY_COMPATIBILITY_PATH = "LEGACY_UAP_IW_U2IW"
DECLARATIVE_COMPATIBILITY_PATH = "DECLARATIVE_CATALOG"
DECLARATIVE_PHASE3_ALLOW_POLICIES = {
    "ubiquiti-unifi-u6plus-uapl6": {
        "profile_id": "ubiquiti-unifi-u6plus-uapl6",
        "artifact_id": "ubiquiti-unifi-u6plus-6.7.54.15663",
        "firmware_platform": "BZ.MT7981",
        "target_version_short": "BZ.6.7.54",
        "target_version_full": "6.7.54.15663",
        "completed_transition_id": "u6plus-uapl6-6.5.64.14808-to-6.7.54.15663",
        "completed_transition_status": "approved",
    }
}


@dataclass(frozen=True)
class Phase3AuthorizationPlan:
    compatibility_path: str
    profile_id: str = ""
    artifact_id: str = ""
    target_version_short: str = ""
    target_version_full: str = ""
    identity_evidence: str = ""

PRINT_LOCK = threading.Lock()


def now_hhmmss() -> str:
    return time.strftime("%H:%M:%S", time.localtime())


def progress_print(
    enabled: bool,
    ap_index: int,
    ap_total: int,
    mac: str,
    ip: str,
    ubicazione: str,
    message: str,
) -> None:
    if not enabled:
        return
    prefix = f"[{now_hhmmss()}] [AP {ap_index}/{ap_total}] {mac} - {ip} - {ubicazione} - {message}"
    with PRINT_LOCK:
        print(prefix, flush=True)


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


def init_phase3_row(
    rec: Dict[str, object],
    inform_url: str,
    target_version_short: str,
    target_version_full: str,
    dry_run: bool,
) -> Dict[str, object]:
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
        "compatibility_path": (rec.get("compatibility_path") or "").strip(),
        "device_profile_id": (rec.get("device_profile_id") or "").strip(),
        "device_identification_status": (rec.get("device_identification_status") or "").strip(),
        "identity_evidence": (rec.get("identity_evidence") or "").strip(),
        "target_artifact_id": (rec.get("target_artifact_id") or "").strip(),
        "target_version_short": target_version_short,
        "target_version_full": target_version_full,
        "modification_eligible": False,
        "eligibility_reason": "",
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


def _valid_sha256_hostkey(value: object) -> bool:
    fingerprint = str(value or "").strip()
    match = re.fullmatch(r"SHA256:([A-Za-z0-9+/]{43})", fingerprint)
    if not match:
        return False
    try:
        return len(base64.b64decode(match.group(1) + "=", validate=True)) == 32
    except (ValueError, TypeError):
        return False


def _record_identity(rec: Dict[str, object]) -> Dict[str, str]:
    return {
        "device_model": str(rec.get("device_model") or "").strip(),
        "board_name": str(rec.get("board_name") or "").strip(),
        "board_shortname": str(rec.get("board_shortname") or "").strip(),
    }


def _canonical_identity(evidence: Dict[str, str]) -> str:
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"))


def _identity_evidence_is_coherent(rec: Dict[str, object], evidence: Dict[str, str]) -> bool:
    raw = rec.get("identity_evidence")
    if not isinstance(raw, str) or not raw.strip():
        return False
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return False
    if not isinstance(parsed, dict):
        return False
    return all(str(parsed.get(key) or "").strip() == value for key, value in evidence.items())


def _authorize_legacy_phase3(
    rec: Dict[str, object],
    kind: str,
    target_version_full: str,
    allow_non_target_firmware: bool,
) -> Tuple[Optional[Phase3AuthorizationPlan], str, str]:
    hk = (rec.get("hostkey_fingerprint") or "").strip()
    if not hk or not hk.startswith("SHA256:"):
        return None, "SKIPPED_HOSTKEY_FINGERPRINT_MISSING", "HOSTKEY_FINGERPRINT_MISSING"

    if (rec.get("model_family_status") or "").strip() != "MODEL_FAMILY_OK":
        return None, "SKIPPED_MODEL_FAMILY_NOT_OK", "MODEL_FAMILY_NOT_OK"

    if not is_candidate_model(rec):
        return None, "SKIPPED_MODEL_FAMILY_NOT_OK", "MODEL_FIELDS_NOT_MATCHING_UAP_IW_U2IW"

    if kind == "phase2":
        st = (rec.get("status") or "").strip()
        if st in {"UPDATE_COMPLETED", "SKIPPED_ALREADY_UPDATED"}:
            pass
        else:
            if st.startswith("UPDATE_FAILED"):
                return None, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"
            if st.startswith("SKIPPED_SSH_NOT_OK") or st == "SKIPPED_SSH_NOT_OK":
                return None, "SKIPPED_SSH_NOT_OK", "SSH_NOT_OK"
            if st.startswith("SKIPPED_HOSTKEY") or st.startswith("SKIPPED_MODEL") or st == "ERROR":
                return None, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"
            return None, "SKIPPED_SSH_NOT_OK", f"PHASE2_STATUS={st}"

        post_full = (rec.get("post_firmware_version_full") or "").strip()
        if post_full and post_full != target_version_full and not allow_non_target_firmware:
            return None, "SKIPPED_FIRMWARE_NOT_TARGET", f"POST_FIRMWARE_NOT_TARGET={post_full}"

        return Phase3AuthorizationPlan(compatibility_path=LEGACY_COMPATIBILITY_PATH), "DRY_RUN_SET_INFORM_REQUIRED", ""

    if kind == "phase1":
        st = (rec.get("status") or "").strip()
        ssh_ok = coerce_bool(rec.get("ssh_ok"))
        if st != "IP_FOUND_SSH_OK" or not ssh_ok:
            return None, "SKIPPED_SSH_NOT_OK", f"PHASE1_STATUS={st or 'UNKNOWN'}"

        fw_full = (rec.get("firmware_version_full") or "").strip()
        if fw_full and fw_full != target_version_full and not allow_non_target_firmware:
            return None, "SKIPPED_FIRMWARE_NOT_TARGET", f"FIRMWARE_NOT_TARGET={fw_full}"

        return Phase3AuthorizationPlan(compatibility_path=LEGACY_COMPATIBILITY_PATH), "DRY_RUN_SET_INFORM_REQUIRED", ""

    return None, "ERROR", "INPUT_REPORT_KIND_UNKNOWN"


def _authorize_declarative_phase3(
    rec: Dict[str, object],
    kind: str,
    target_version_short: str,
    target_version_full: str,
) -> Tuple[Optional[Phase3AuthorizationPlan], str, str]:
    if kind != "phase2":
        return None, "SKIPPED_DECLARATIVE_PHASE2_REQUIRED", "DECLARATIVE_PHASE3_REQUIRES_PHASE2_REPORT"
    if str(rec.get("compatibility_path") or "").strip() != DECLARATIVE_COMPATIBILITY_PATH:
        return None, "SKIPPED_DECLARATIVE_PATH_REQUIRED", "COMPATIBILITY_PATH_NOT_DECLARATIVE_CATALOG"

    profile_id = str(rec.get("device_profile_id") or "").strip()
    policy = DECLARATIVE_PHASE3_ALLOW_POLICIES.get(profile_id)
    if not policy:
        return None, "SKIPPED_PHASE3_OPERATION_NOT_ALLOWED", "PHASE3_PROFILE_NOT_EXPLICITLY_ALLOWED"

    if target_version_short != policy["target_version_short"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", f"CLI_TARGET_SHORT_NOT_ALLOWED={target_version_short}"
    if target_version_full != policy["target_version_full"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", f"CLI_TARGET_FULL_NOT_ALLOWED={target_version_full}"

    artifact_id = str(rec.get("target_artifact_id") or "").strip()
    if artifact_id != policy["artifact_id"]:
        return None, "SKIPPED_TARGET_ARTIFACT_MISMATCH", f"TARGET_ARTIFACT_NOT_ALLOWED={artifact_id or 'MISSING'}"

    evidence = _record_identity(rec)
    if not all(evidence.values()):
        return None, "SKIPPED_DEVICE_PROFILE_NOT_FOUND", "IDENTITY_EVIDENCE_INCOMPLETE"
    if not _identity_evidence_is_coherent(rec, evidence):
        return None, "SKIPPED_IDENTITY_EVIDENCE_MISMATCH", "IDENTITY_EVIDENCE_REPORT_FIELDS_DISAGREE"

    status = str(rec.get("status") or "").strip()
    source_short = str(rec.get("pre_firmware_version_short") or "").strip()
    source_full = str(rec.get("pre_firmware_version_full") or "").strip()
    if status not in {"UPDATE_COMPLETED", "SKIPPED_ALREADY_UPDATED"}:
        return None, "SKIPPED_PHASE2_STATUS_NOT_ELIGIBLE", f"PHASE2_STATUS={status or 'MISSING'}"

    try:
        catalog = load_catalog()
        resolved = resolve_transition(
            evidence=evidence,
            source_short=source_short,
            source_full=source_full,
            target_short=target_version_short,
            target_full=target_version_full,
            catalog=catalog,
        )
    except CompatibilityResolutionError as exc:
        return None, f"SKIPPED_{exc.code}", f"{exc.code}: {exc}"
    except CompatibilityError as exc:
        return None, "FAILED_COMPATIBILITY_CATALOG_INVALID", str(exc)

    profile = resolved.profile
    artifact = resolved.artifact
    if str(profile.get("id") or "") != policy["profile_id"] or profile_id != policy["profile_id"]:
        return None, "SKIPPED_DEVICE_PROFILE_MISMATCH", "PROFILE_ID_POLICY_CATALOG_MISMATCH"
    if str(profile.get("firmware_platform") or "") != policy["firmware_platform"]:
        return None, "SKIPPED_DEVICE_PROFILE_MISMATCH", "PROFILE_PLATFORM_POLICY_MISMATCH"
    if str(artifact.get("id") or "") != policy["artifact_id"]:
        return None, "SKIPPED_TARGET_ARTIFACT_MISMATCH", "ARTIFACT_ID_POLICY_CATALOG_MISMATCH"
    if str(artifact.get("firmware_platform") or "") != policy["firmware_platform"]:
        return None, "SKIPPED_TARGET_ARTIFACT_MISMATCH", "ARTIFACT_PLATFORM_POLICY_MISMATCH"
    if str(artifact.get("version_short") or "") != policy["target_version_short"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", "ARTIFACT_TARGET_SHORT_POLICY_MISMATCH"
    if str(artifact.get("version_full") or "") != policy["target_version_full"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", "ARTIFACT_TARGET_FULL_POLICY_MISMATCH"

    if str(rec.get("target_firmware_version_short") or "").strip() != policy["target_version_short"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", "REPORT_TARGET_SHORT_MISMATCH"
    if str(rec.get("target_firmware_version_full") or "").strip() != policy["target_version_full"]:
        return None, "SKIPPED_FIRMWARE_NOT_TARGET", "REPORT_TARGET_FULL_MISMATCH"
    for field in ("firmware_filename_match", "firmware_size_match", "firmware_sha256_match"):
        if not coerce_bool(rec.get(field)):
            return None, "SKIPPED_FIRMWARE_ARTIFACT_NOT_VERIFIED", f"{field.upper()}_NOT_TRUE"
    if not _valid_sha256_hostkey(rec.get("hostkey_fingerprint")):
        return None, "SKIPPED_HOSTKEY_FINGERPRINT_MISSING", "HOSTKEY_FINGERPRINT_INVALID_OR_MISSING"

    if status == "UPDATE_COMPLETED":
        if not coerce_bool(rec.get("modification_eligible")):
            return None, "SKIPPED_PHASE2_EVIDENCE_NOT_ELIGIBLE", "PHASE2_MODIFICATION_ELIGIBLE_NOT_TRUE"
        if str(rec.get("eligibility_reason") or "").strip() != "LIVE_PREFLIGHT_OK":
            return None, "SKIPPED_PHASE2_EVIDENCE_NOT_ELIGIBLE", "PHASE2_ELIGIBILITY_REASON_NOT_LIVE_PREFLIGHT_OK"
        if not coerce_bool(rec.get("post_check_ok")):
            return None, "SKIPPED_PHASE2_POST_CHECK_NOT_OK", "PHASE2_POST_CHECK_NOT_OK"
        if not coerce_bool(rec.get("device_back_online")):
            return None, "SKIPPED_PHASE2_DEVICE_NOT_ONLINE", "PHASE2_DEVICE_NOT_BACK_ONLINE"
        if str(rec.get("post_firmware_version_short") or "").strip() != policy["target_version_short"]:
            return None, "SKIPPED_FIRMWARE_NOT_TARGET", "POST_FIRMWARE_SHORT_NOT_TARGET"
        if str(rec.get("post_firmware_version_full") or "").strip() != policy["target_version_full"]:
            return None, "SKIPPED_FIRMWARE_NOT_TARGET", "POST_FIRMWARE_FULL_NOT_TARGET"
        if resolved.already_installed or not resolved.transition:
            return None, "SKIPPED_TRANSITION_MISMATCH", "COMPLETED_REPORT_DID_NOT_RESOLVE_SOURCE_TRANSITION"
        if str(rec.get("transition_id") or "").strip() != policy["completed_transition_id"]:
            return None, "SKIPPED_TRANSITION_MISMATCH", "PHASE2_TRANSITION_ID_MISMATCH"
        if str(rec.get("transition_status") or "").strip() != policy["completed_transition_status"]:
            return None, "SKIPPED_TRANSITION_MISMATCH", "PHASE2_TRANSITION_STATUS_MISMATCH"
        if str(resolved.transition.get("id") or "") != policy["completed_transition_id"]:
            return None, "SKIPPED_TRANSITION_MISMATCH", "CATALOG_TRANSITION_ID_POLICY_MISMATCH"
        if str(resolved.transition.get("support_status") or "") != policy["completed_transition_status"]:
            return None, "SKIPPED_TRANSITION_MISMATCH", "CATALOG_TRANSITION_STATUS_POLICY_MISMATCH"
    else:
        if not resolved.already_installed or resolved.transition is not None:
            return None, "SKIPPED_TRANSITION_MISMATCH", "ALREADY_UPDATED_REPORT_NOT_AT_EXACT_TARGET"
        if str(rec.get("transition_status") or "").strip() != "ALREADY_INSTALLED":
            return None, "SKIPPED_TRANSITION_MISMATCH", "PHASE2_TRANSITION_STATUS_NOT_ALREADY_INSTALLED"
        if source_short != policy["target_version_short"] or source_full != policy["target_version_full"]:
            return None, "SKIPPED_FIRMWARE_NOT_TARGET", "CURRENT_FIRMWARE_NOT_EXACT_TARGET"

    return (
        Phase3AuthorizationPlan(
            compatibility_path=DECLARATIVE_COMPATIBILITY_PATH,
            profile_id=policy["profile_id"],
            artifact_id=policy["artifact_id"],
            target_version_short=policy["target_version_short"],
            target_version_full=policy["target_version_full"],
            identity_evidence=_canonical_identity(evidence),
        ),
        "DRY_RUN_SET_INFORM_REQUIRED",
        "DRY_RUN_PLAN_VALID_LIVE_RECHECK_REQUIRED",
    )


def authorize_phase3(
    rec: Dict[str, object],
    kind: str,
    target_version_short: str,
    target_version_full: str,
    allow_non_target_firmware: bool,
) -> Tuple[Optional[Phase3AuthorizationPlan], str, str]:
    ip = str(rec.get("ip") or "").strip()
    if not ip:
        return None, "SKIPPED_IP_NOT_FOUND", "IP_NOT_FOUND"
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return None, "SKIPPED_IP_NOT_FOUND", "IP_INVALID"

    declared_path = str(rec.get("compatibility_path") or "").strip()
    if declared_path == DECLARATIVE_COMPATIBILITY_PATH:
        return _authorize_declarative_phase3(rec, kind, target_version_short, target_version_full)
    if declared_path == LEGACY_COMPATIBILITY_PATH or is_candidate_model(rec):
        return _authorize_legacy_phase3(rec, kind, target_version_full, allow_non_target_firmware)
    return _authorize_declarative_phase3(rec, kind, target_version_short, target_version_full)


def decide_phase3(
    rec: Dict[str, object],
    kind: str,
    target_version_full: str,
    allow_non_target_firmware: bool,
    target_version_short: str = "BZ.v4.3.28",
) -> Tuple[bool, str, str]:
    plan, status, reason = authorize_phase3(
        rec,
        kind,
        target_version_short,
        target_version_full,
        allow_non_target_firmware,
    )
    return plan is not None, status, reason


def probe_read_only(
    row: Dict[str, object],
    plink_path: str,
    user: str,
    password: str,
    timeout: int,
    verbose: bool,
    progress_enabled: bool,
    ap_index: int,
    ap_total: int,
    mac: str,
    ubicazione: str,
) -> Tuple[Dict[str, object], Optional[str]]:
    ip = (row.get("ip") or "").strip()
    hk = (row.get("hostkey_fingerprint") or "").strip()

    progress_print(progress_enabled, ap_index, ap_total, mac, ip, ubicazione, "cat /etc/version")
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

    progress_print(progress_enabled, ap_index, ap_total, mac, ip, ubicazione, "cat /etc/board.info")
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

    progress_print(progress_enabled, ap_index, ap_total, mac, ip, ubicazione, "mca-cli-op info pre")
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
) -> Dict[str, str]:
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
        return {"inform_status": "", "raw_info": (out_m or "").strip(), "error": msg or "post-check mca-cli-op info failed"}
    mca = parse_mca_info_extended(out_m)
    return {
        "inform_status": (mca.get("inform_status") or "").strip(),
        "raw_info": (out_m or "").strip(),
        "error": "",
    }


def validate_declarative_live_preflight(
    probe: Dict[str, object],
    plan: Phase3AuthorizationPlan,
) -> Tuple[bool, str, str]:
    live_evidence = _record_identity(probe)
    if not all(live_evidence.values()):
        return False, "SKIPPED_LIVE_IDENTITY_MISMATCH", "LIVE_IDENTITY_EVIDENCE_INCOMPLETE"
    if _canonical_identity(live_evidence) != plan.identity_evidence:
        return False, "SKIPPED_LIVE_IDENTITY_MISMATCH", "LIVE_REPORT_IDENTITY_DISAGREEMENT"
    live_short = str(probe.get("pre_firmware_version_short") or "").strip()
    live_full = str(probe.get("pre_firmware_version_full") or "").strip()
    if live_short != plan.target_version_short:
        return False, "SKIPPED_LIVE_FIRMWARE_NOT_TARGET", f"LIVE_FIRMWARE_SHORT_NOT_TARGET={live_short or 'MISSING'}"
    if live_full != plan.target_version_full:
        return False, "SKIPPED_LIVE_FIRMWARE_NOT_TARGET", f"LIVE_FIRMWARE_FULL_NOT_TARGET={live_full or 'MISSING'}"
    try:
        resolved = resolve_transition(
            evidence=live_evidence,
            source_short=live_short,
            source_full=live_full,
            target_short=plan.target_version_short,
            target_full=plan.target_version_full,
            catalog=load_catalog(),
        )
    except CompatibilityResolutionError as exc:
        return False, f"SKIPPED_LIVE_{exc.code}", f"LIVE_{exc.code}: {exc}"
    except CompatibilityError as exc:
        return False, "FAILED_COMPATIBILITY_CATALOG_INVALID", str(exc)
    if not resolved.already_installed or resolved.transition is not None:
        return False, "SKIPPED_LIVE_TRANSITION_MISMATCH", "LIVE_DEVICE_NOT_RESOLVED_AS_EXACT_TARGET"
    if str(resolved.profile.get("id") or "") != plan.profile_id:
        return False, "SKIPPED_LIVE_IDENTITY_MISMATCH", "LIVE_PROFILE_ID_MISMATCH"
    if str(resolved.artifact.get("id") or "") != plan.artifact_id:
        return False, "SKIPPED_LIVE_FIRMWARE_NOT_TARGET", "LIVE_ARTIFACT_ID_MISMATCH"
    return True, "", ""


def execute_one_ap(
    rec: Dict[str, object],
    kind: str,
    inform_url: str,
    target_version_short: str,
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
    ap_index: int,
    ap_total: int,
    progress_enabled: bool,
    progress_interval: int,
) -> Dict[str, object]:
    dry_run = not execute
    row = init_phase3_row(rec, inform_url, target_version_short, target_version_full, dry_run=dry_run)
    enabled = bool(progress_enabled) and bool(execute)
    mac = (row.get("mac") or "").strip()
    ip = (row.get("ip") or "").strip()
    ubicazione = (row.get("ubicazione") or "").strip()

    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, "START")
    plan, status, reason = authorize_phase3(
        rec,
        kind,
        target_version_short,
        target_version_full,
        allow_non_target_firmware,
    )
    if plan is None:
        row["status"] = status
        row["error"] = reason
        row["eligibility_reason"] = reason
        row["action"] = "NOOP"
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"SKIP {status} ({reason})")
        return row

    row["compatibility_path"] = plan.compatibility_path
    row["device_profile_id"] = plan.profile_id
    row["device_identification_status"] = "DEVICE_PROFILE_IDENTIFIED" if plan.profile_id else ""
    row["identity_evidence"] = plan.identity_evidence
    row["target_artifact_id"] = plan.artifact_id
    row["target_version_short"] = target_version_short
    row["target_version_full"] = target_version_full
    row["action"] = "SET_INFORM"
    row["status"] = "DRY_RUN_SET_INFORM_REQUIRED"
    row["modification_eligible"] = False
    row["eligibility_reason"] = reason
    if dry_run:
        return row

    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, "probe read-only started")
    probe, probe_err = probe_read_only(
        row,
        plink_path,
        user,
        password,
        timeout,
        verbose,
        enabled,
        ap_index,
        ap_total,
        mac,
        ubicazione,
    )
    if probe:
        for k in ("board_name", "board_shortname", "device_model", "pre_firmware_version_short", "pre_firmware_version_full", "pre_inform_status"):
            if k in probe and (probe.get(k) or "") != "":
                row[k] = probe.get(k) or ""
    if probe_err:
        row["status"] = "SET_INFORM_FAILED_COMMAND"
        row["error"] = probe_err
        row["eligibility_reason"] = f"LIVE_PREFLIGHT_FAILED={probe_err}"
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"FAILED {row['status']} ({row['error']})")
        return row

    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, "model/firmware recheck")
    if plan.compatibility_path == DECLARATIVE_COMPATIBILITY_PATH:
        live_ok, live_status, live_reason = validate_declarative_live_preflight(probe, plan)
        if not live_ok:
            row["status"] = live_status
            row["error"] = live_reason
            row["eligibility_reason"] = live_reason
            progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"SKIP {row['status']} ({row['error']})")
            return row
    else:
        mf = evaluate_model_family(row.get("board_name") or "", row.get("board_shortname") or "", row.get("device_model") or "")
        if mf != "MODEL_FAMILY_OK":
            row["status"] = "SKIPPED_MODEL_FAMILY_NOT_OK"
            row["error"] = f"MODEL_RECHECK={mf}"
            row["eligibility_reason"] = row["error"]
            progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"SKIP {row['status']} ({row['error']})")
            return row

        fw_full = (row.get("pre_firmware_version_full") or "").strip()
        if fw_full and fw_full != target_version_full and not allow_non_target_firmware:
            row["status"] = "SKIPPED_FIRMWARE_NOT_TARGET"
            row["error"] = f"FIRMWARE_NOT_TARGET={fw_full}"
            row["eligibility_reason"] = row["error"]
            progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"SKIP {row['status']} ({row['error']})")
            return row

    row["modification_eligible"] = True
    row["eligibility_reason"] = "LIVE_PREFLIGHT_OK"

    cmd = build_set_inform_command(inform_url)
    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, "starting set-inform")
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
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"set-inform failed ({row['error']})")
        return row
    if rc_s != 0:
        err_type = classify_putty_error(out_s, err_s, rc_s)
        msg = (err_s or out_s or "set-inform failed").strip()
        row["status"] = "SET_INFORM_FAILED_COMMAND"
        row["error"] = err_type + (f": {msg}" if msg else "") if err_type else msg
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"set-inform failed ({row['error']})")
        return row

    row["set_inform_ok"] = True
    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, "set-inform command completed")

    attempts = max(1, int(post_check_attempts))
    delay = max(0, int(post_check_delay))
    last_err = ""
    last_status = ""
    for i in range(attempts):
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"post-check attempt {i+1}/{attempts}...")
        info = post_check_info(row, plink_path, user, password, timeout, verbose)
        err = (info.get("error") or "").strip()
        st = (info.get("inform_status") or "").strip()
        raw = (info.get("raw_info") or "").strip()
        if err:
            last_err = err
            progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"post-check attempt failed: {err}")
            if delay and i < (attempts - 1):
                progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"waiting {delay}s before next post-check...")
                time.sleep(delay)
            continue

        last_status = st
        row["post_inform_status"] = st
        confirmed = (inform_url in st) or (inform_url in raw)
        if not confirmed:
            progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"post-check not confirmed yet: status={st}")
            if delay and i < (attempts - 1):
                progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"waiting {delay}s before next post-check...")
                time.sleep(delay)
            continue

        row["status"] = "SET_INFORM_COMPLETED"
        row["error"] = ""
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"post-check OK: inform URL confirmed; status={st}")
        progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"completed {row['status']}")
        return row

    row["status"] = "SET_INFORM_FAILED_POST_CHECK"
    row["error"] = "INFORM_URL_NOT_CONFIRMED"
    if last_status:
        row["post_inform_status"] = last_status
    progress_print(
        enabled,
        ap_index,
        ap_total,
        mac,
        ip,
        ubicazione,
        f"post-check failed: inform URL not confirmed; last_status={row.get('post_inform_status') or ''}",
    )
    progress_print(enabled, ap_index, ap_total, mac, ip, ubicazione, f"FAILED {row['status']} ({row['error']})")
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
        "compatibility_path",
        "device_profile_id",
        "device_identification_status",
        "identity_evidence",
        "target_artifact_id",
        "target_version_short",
        "target_version_full",
        "modification_eligible",
        "eligibility_reason",
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

    p = argparse.ArgumentParser(description="UniFi Phase 3 set-inform (legacy/catalog gated; dry-run default).")
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
    p.add_argument("--post-check-delay", type=int, default=5, dest="post_check_delay")
    p.add_argument("--post-check-attempts", type=int, default=5, dest="post_check_attempts")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--progress", action="store_true", help="Enable live progress (execute: default ON)")
    p.add_argument("--no-progress", action="store_true", help="Disable live progress (execute)")
    p.add_argument("--progress-interval", dest="progress_interval", type=int, default=5)
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

    progress_enabled = False
    if args.no_progress:
        progress_enabled = False
    elif args.progress:
        progress_enabled = True
    elif args.execute:
        progress_enabled = True

    progress_interval = max(1, int(args.progress_interval))
    if args.execute:
        print(f"[PHASE3] Progress: {'ON' if progress_enabled else 'OFF'} (interval={progress_interval}s)")

    processed: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        fut_to_rec = {}
        total = len(records)
        for idx, rec in enumerate(records, start=1):
            fut = ex.submit(
                execute_one_ap,
                rec,
                kind,
                args.inform_url,
                args.target_version_short,
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
                idx,
                total,
                progress_enabled,
                progress_interval,
            )
            fut_to_rec[fut] = (rec, idx, total)

        for fut in as_completed(list(fut_to_rec.keys())):
            try:
                processed.append(fut.result())
            except Exception as e:
                rec, idx, total = fut_to_rec.get(fut) or ({}, 0, 0)
                row = init_phase3_row(
                    rec,
                    args.inform_url,
                    args.target_version_short,
                    args.target_version_full,
                    dry_run=not args.execute,
                )
                row["status"] = "ERROR"
                row["error"] = f"Unhandled exception: {type(e).__name__}: {e}"
                processed.append(row)
                progress_print(
                    progress_enabled and bool(args.execute),
                    int(idx or 0),
                    int(total or 0),
                    (row.get("mac") or "").strip(),
                    (row.get("ip") or "").strip(),
                    (row.get("ubicazione") or "").strip(),
                    f"FAILED ERROR ({row['error']})",
                )
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
