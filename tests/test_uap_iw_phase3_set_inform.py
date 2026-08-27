import copy
import json
import os
import sys
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import uap_iw_phase3_set_inform as phase3


INFORM_URL = "http://192.168.0.10:8080/inform"
HOSTKEY = "SHA256:R2ma2fH01CWwIcIyheMTq/NY5OK9uk+aL2qeU8GAkgs"
TARGET_SHORT = "BZ.6.7.54"
TARGET_FULL = "6.7.54.15663"
PROFILE_ID = "ubiquiti-unifi-u6plus-uapl6"
ARTIFACT_ID = "ubiquiti-unifi-u6plus-6.7.54.15663"
TRANSITION_ID = "u6plus-uapl6-6.5.64.14808-to-6.7.54.15663"


def identity_json(model="U6+", board_name="U6+", shortname="UAPL6"):
    return json.dumps(
        {"device_model": model, "board_name": board_name, "board_shortname": shortname},
        sort_keys=True,
        separators=(",", ":"),
    )


def completed_record():
    return {
        "mac": "0C:EA:14:F0:8E:B2",
        "ip": "192.168.0.2",
        "hostkey_fingerprint": HOSTKEY,
        "device_model": "U6+",
        "board_name": "U6+",
        "board_shortname": "UAPL6",
        "model_family_status": "MODEL_FAMILY_MISMATCH",
        "compatibility_path": "DECLARATIVE_CATALOG",
        "device_profile_id": PROFILE_ID,
        "device_identification_status": "DEVICE_PROFILE_IDENTIFIED",
        "identity_evidence": identity_json(),
        "target_artifact_id": ARTIFACT_ID,
        "target_firmware_version_short": TARGET_SHORT,
        "target_firmware_version_full": TARGET_FULL,
        "transition_id": TRANSITION_ID,
        "transition_status": "approved",
        "pre_firmware_version_short": "BZ.6.5.64",
        "pre_firmware_version_full": "6.5.64.14808",
        "post_firmware_version_short": TARGET_SHORT,
        "post_firmware_version_full": TARGET_FULL,
        "firmware_filename_match": True,
        "firmware_size_match": True,
        "firmware_sha256_match": True,
        "modification_eligible": True,
        "eligibility_reason": "LIVE_PREFLIGHT_OK",
        "post_check_ok": True,
        "device_back_online": True,
        "status": "UPDATE_COMPLETED",
    }


def already_updated_record():
    rec = completed_record()
    rec.update(
        {
            "status": "SKIPPED_ALREADY_UPDATED",
            "transition_id": "",
            "transition_status": "ALREADY_INSTALLED",
            "pre_firmware_version_short": TARGET_SHORT,
            "pre_firmware_version_full": TARGET_FULL,
            "post_firmware_version_short": "",
            "post_firmware_version_full": "",
            "modification_eligible": False,
            "eligibility_reason": "",
            "post_check_ok": False,
            "device_back_online": False,
        }
    )
    return rec


def legacy_phase2_record():
    return {
        "mac": "00:11:22:33:44:55",
        "ip": "192.168.0.3",
        "hostkey_fingerprint": HOSTKEY,
        "device_model": "UAP-InWall",
        "board_name": "UAP-InWall",
        "board_shortname": "U2IW",
        "model_family_status": "MODEL_FAMILY_OK",
        "status": "UPDATE_COMPLETED",
        "post_firmware_version_full": "4.3.28.11361",
    }


def run_one(rec, *, execute=False, target_short=TARGET_SHORT, target_full=TARGET_FULL, allow=False):
    return phase3.execute_one_ap(
        rec=rec,
        kind=phase3.detect_report_kind([rec]),
        inform_url=INFORM_URL,
        target_version_short=target_short,
        target_version_full=target_full,
        allow_non_target_firmware=allow,
        plink_path="plink.exe",
        user="ubnt",
        password="ubnt",
        timeout=1,
        post_check_delay=0,
        post_check_attempts=1,
        execute=execute,
        verbose=False,
        ap_index=1,
        ap_total=1,
        progress_enabled=False,
        progress_interval=1,
    )


def successful_plink(responses=None):
    calls = []

    def fake(**kwargs):
        command = kwargs["command"]
        calls.append(command)
        if responses and command in responses:
            return responses[command]
        if command == "cat /etc/version":
            return TARGET_SHORT, "", 0, None
        if command == "cat /etc/board.info":
            return "board.name=U6+\nboard.shortname=UAPL6", "", 0, None
        if command == "mca-cli-op info":
            count = sum(1 for item in calls if item == "mca-cli-op info")
            status = "Unknown" if count == 1 else f"Connected ({INFORM_URL})"
            return f"Model: U6+\nVersion: {TARGET_FULL}\nStatus: {status}", "", 0, None
        if "set-inform" in command:
            return "", "", 0, None
        raise AssertionError(f"unexpected command: {command}")

    return calls, fake


class Phase3LegacyRegressionTests(unittest.TestCase):
    def test_legacy_phase2_eligibility_and_path_unchanged(self):
        plan, status, reason = phase3.authorize_phase3(
            legacy_phase2_record(), "phase2", "BZ.v4.3.28", "4.3.28.11361", False
        )
        self.assertIsNotNone(plan)
        self.assertEqual(plan.compatibility_path, "LEGACY_UAP_IW_U2IW")
        self.assertEqual(status, "DRY_RUN_SET_INFORM_REQUIRED")
        self.assertEqual(reason, "")

    def test_failed_legacy_gate_never_falls_through_to_catalog(self):
        rec = legacy_phase2_record()
        rec["model_family_status"] = "MODEL_FAMILY_MISMATCH"
        plan, status, _ = phase3.authorize_phase3(rec, "phase2", "BZ.v4.3.28", "4.3.28.11361", False)
        self.assertIsNone(plan)
        self.assertEqual(status, "SKIPPED_MODEL_FAMILY_NOT_OK")

    def test_legacy_allow_non_target_behavior_is_preserved(self):
        rec = legacy_phase2_record()
        rec["post_firmware_version_full"] = "4.3.27.0"
        denied, _, _ = phase3.authorize_phase3(rec, "phase2", "BZ.v4.3.28", "4.3.28.11361", False)
        allowed, _, _ = phase3.authorize_phase3(rec, "phase2", "BZ.v4.3.28", "4.3.28.11361", True)
        self.assertIsNone(denied)
        self.assertIsNotNone(allowed)


class Phase3DeclarativeOfflineTests(unittest.TestCase):
    def test_exact_completed_report_dry_run_is_plan_only_and_offline(self):
        with mock.patch.object(phase3, "run_plink", side_effect=AssertionError("network called")):
            row = run_one(completed_record())
        self.assertEqual(row["compatibility_path"], "DECLARATIVE_CATALOG")
        self.assertEqual(row["device_profile_id"], PROFILE_ID)
        self.assertEqual(row["target_artifact_id"], ARTIFACT_ID)
        self.assertEqual(row["action"], "SET_INFORM")
        self.assertEqual(row["status"], "DRY_RUN_SET_INFORM_REQUIRED")
        self.assertFalse(row["modification_eligible"])
        self.assertEqual(row["eligibility_reason"], "DRY_RUN_PLAN_VALID_LIVE_RECHECK_REQUIRED")

    def test_phase1_u6plus_is_denied(self):
        rec = {
            "mac": "0C:EA:14:F0:8E:B2",
            "ip": "192.168.0.2",
            "hostkey_fingerprint": HOSTKEY,
            "device_model": "U6+",
            "board_name": "U6+",
            "board_shortname": "UAPL6",
            "model_family_status": "MODEL_FAMILY_MISMATCH",
            "compatibility_path": "DECLARATIVE_CATALOG",
            "device_profile_id": PROFILE_ID,
            "identity_evidence": identity_json(),
            "target_artifact_id": ARTIFACT_ID,
            "ssh_backend": "paramiko",
            "ssh_ok": True,
            "status": "IP_FOUND_SSH_OK",
            "firmware_version_short": TARGET_SHORT,
            "firmware_version_full": TARGET_FULL,
        }
        row = run_one(rec)
        self.assertEqual(row["status"], "SKIPPED_DECLARATIVE_PHASE2_REQUIRED")

    def test_completed_report_required_evidence(self):
        mutations = {
            "missing_profile": ("device_profile_id", ""),
            "wrong_profile": ("device_profile_id", "other-profile"),
            "wrong_model": ("device_model", "U6-Pro"),
            "wrong_board": ("board_name", "U6-Pro"),
            "wrong_shortname": ("board_shortname", "OTHER"),
            "missing_artifact": ("target_artifact_id", ""),
            "wrong_artifact": ("target_artifact_id", "other-artifact"),
            "wrong_report_target_short": ("target_firmware_version_short", "BZ.6.7.53"),
            "wrong_report_target_full": ("target_firmware_version_full", "6.7.53.0"),
            "wrong_post_short": ("post_firmware_version_short", "BZ.6.7.53"),
            "wrong_post_full": ("post_firmware_version_full", "6.7.53.0"),
            "post_check_false": ("post_check_ok", False),
            "back_online_false": ("device_back_online", False),
            "missing_hostkey": ("hostkey_fingerprint", ""),
            "invalid_hostkey": ("hostkey_fingerprint", "SHA256:not valid="),
            "filename_unverified": ("firmware_filename_match", False),
            "size_unverified": ("firmware_size_match", False),
            "hash_unverified": ("firmware_sha256_match", False),
            "phase2_not_eligible": ("modification_eligible", False),
            "wrong_phase2_reason": ("eligibility_reason", "OTHER"),
            "wrong_transition_id": ("transition_id", "other-transition"),
            "wrong_transition_status": ("transition_status", "experimental"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                rec = completed_record()
                rec[field] = value
                row = run_one(rec)
                self.assertEqual(row["action"], "NOOP")
                self.assertFalse(row["modification_eligible"])

        for field in ("modification_eligible", "eligibility_reason", "transition_id", "transition_status"):
            with self.subTest(missing=field):
                rec = completed_record()
                rec.pop(field)
                self.assertEqual(run_one(rec)["action"], "NOOP")

    def test_identity_evidence_disagreement_denies(self):
        rec = completed_record()
        rec["identity_evidence"] = identity_json(board_name="U6-Pro")
        row = run_one(rec)
        self.assertEqual(row["status"], "SKIPPED_IDENTITY_EVIDENCE_MISMATCH")

    def test_declared_catalog_record_with_legacy_alias_cannot_enter_legacy_path(self):
        rec = completed_record()
        rec["board_name"] = "UAP-InWall"
        rec["identity_evidence"] = identity_json(board_name="UAP-InWall")
        rec["model_family_status"] = "MODEL_FAMILY_OK"
        row = run_one(rec)
        self.assertEqual(row["action"], "NOOP")
        self.assertEqual(row["compatibility_path"], "DECLARATIVE_CATALOG")

    def test_already_updated_exact_evidence_is_supported_without_prior_eligibility(self):
        row = run_one(already_updated_record())
        self.assertEqual(row["status"], "DRY_RUN_SET_INFORM_REQUIRED")
        self.assertFalse(row["modification_eligible"])

    def test_already_updated_missing_exact_evidence_denies(self):
        fields = (
            "transition_status",
            "pre_firmware_version_short",
            "pre_firmware_version_full",
            "firmware_filename_match",
            "firmware_size_match",
            "firmware_sha256_match",
        )
        for field in fields:
            with self.subTest(field=field):
                rec = already_updated_record()
                rec[field] = "" if "version" in field or field == "transition_status" else False
                self.assertEqual(run_one(rec)["action"], "NOOP")

    def test_wrong_short_cli_denies_even_with_correct_full_and_allow_flag(self):
        row = run_one(completed_record(), target_short="BZ.6.7.53", target_full=TARGET_FULL, allow=True)
        self.assertEqual(row["action"], "NOOP")
        self.assertIn("CLI_TARGET_SHORT", row["eligibility_reason"])

    def test_wrong_full_cli_denies_even_with_correct_short_and_allow_flag(self):
        row = run_one(completed_record(), target_short=TARGET_SHORT, target_full="6.7.53.0", allow=True)
        self.assertEqual(row["action"], "NOOP")
        self.assertIn("CLI_TARGET_FULL", row["eligibility_reason"])

    def test_catalog_entry_without_operation_policy_cannot_authorize(self):
        rec = completed_record()
        rec["device_profile_id"] = "catalog-only-profile"
        rec["target_artifact_id"] = "catalog-only-artifact"
        with mock.patch.object(phase3, "load_catalog") as catalog_loader:
            row = run_one(rec)
        catalog_loader.assert_not_called()
        self.assertEqual(row["status"], "SKIPPED_PHASE3_OPERATION_NOT_ALLOWED")

    def test_ambiguous_catalog_identity_denies(self):
        catalog = phase3.load_catalog()
        duplicate = copy.deepcopy(catalog["device_profiles"][0])
        duplicate["id"] = "duplicate-u6plus-profile"
        catalog["device_profiles"].append(duplicate)
        with mock.patch.object(phase3, "load_catalog", return_value=catalog):
            row = run_one(completed_record())
        self.assertEqual(row["status"], "SKIPPED_DEVICE_PROFILE_AMBIGUOUS")

    def test_missing_or_invalid_catalog_denies_declarative_path(self):
        with mock.patch.object(phase3, "load_catalog", side_effect=phase3.CompatibilityError("catalog unavailable")):
            row = run_one(completed_record())
        self.assertEqual(row["status"], "FAILED_COMPATIBILITY_CATALOG_INVALID")


class Phase3DeclarativeExecuteTests(unittest.TestCase):
    def test_exact_live_preflight_enables_set_inform_and_exact_postcheck(self):
        calls, fake = successful_plink()
        with mock.patch.object(phase3, "run_plink", side_effect=fake):
            row = run_one(completed_record(), execute=True)
        self.assertEqual(row["status"], "SET_INFORM_COMPLETED")
        self.assertTrue(row["modification_eligible"])
        self.assertEqual(row["eligibility_reason"], "LIVE_PREFLIGHT_OK")
        self.assertTrue(row["set_inform_attempted"])
        self.assertEqual(sum("set-inform" in command for command in calls), 1)

    def test_live_identity_mismatch_blocks_set_inform(self):
        calls, fake = successful_plink(
            {"cat /etc/board.info": ("board.name=U6-Pro\nboard.shortname=UAPL6", "", 0, None)}
        )
        with mock.patch.object(phase3, "run_plink", side_effect=fake):
            row = run_one(completed_record(), execute=True)
        self.assertEqual(row["status"], "SKIPPED_LIVE_IDENTITY_MISMATCH")
        self.assertFalse(row["modification_eligible"])
        self.assertFalse(any("set-inform" in command for command in calls))

    def test_wrong_live_short_blocks_set_inform_even_when_full_is_correct(self):
        calls, fake = successful_plink({"cat /etc/version": ("BZ.6.7.53", "", 0, None)})
        with mock.patch.object(phase3, "run_plink", side_effect=fake):
            row = run_one(completed_record(), execute=True, allow=True)
        self.assertEqual(row["status"], "SKIPPED_LIVE_FIRMWARE_NOT_TARGET")
        self.assertFalse(any("set-inform" in command for command in calls))

    def test_wrong_live_full_blocks_set_inform(self):
        calls, fake = successful_plink(
            {"mca-cli-op info": ("Model: U6+\nVersion: 6.7.53.0\nStatus: Unknown", "", 0, None)}
        )
        with mock.patch.object(phase3, "run_plink", side_effect=fake):
            row = run_one(completed_record(), execute=True)
        self.assertEqual(row["status"], "SKIPPED_LIVE_FIRMWARE_NOT_TARGET")
        self.assertFalse(any("set-inform" in command for command in calls))

    def test_hostkey_probe_failure_blocks_set_inform(self):
        calls = []

        def fail(**kwargs):
            calls.append(kwargs["command"])
            return "", "host key did not match", 1, None

        with mock.patch.object(phase3, "run_plink", side_effect=fail):
            row = run_one(completed_record(), execute=True)
        self.assertEqual(row["status"], "SET_INFORM_FAILED_COMMAND")
        self.assertFalse(row["modification_eligible"])
        self.assertFalse(any("set-inform" in command for command in calls))

    def test_failed_inform_url_confirmation_remains_fail_closed(self):
        calls, fake = successful_plink()

        def no_confirmation(**kwargs):
            result = fake(**kwargs)
            if kwargs["command"] == "mca-cli-op info" and sum(1 for item in calls if item == "mca-cli-op info") > 1:
                return "Model: U6+\nVersion: 6.7.54.15663\nStatus: Unknown", "", 0, None
            return result

        with mock.patch.object(phase3, "run_plink", side_effect=no_confirmation):
            row = run_one(completed_record(), execute=True)
        self.assertEqual(row["status"], "SET_INFORM_FAILED_POST_CHECK")
        self.assertEqual(row["error"], "INFORM_URL_NOT_CONFIRMED")


class Phase3SetupTests(unittest.TestCase):
    def test_setup_provisions_compiles_and_prints_phase3_dry_run(self):
        with open(os.path.join(ROOT, "setup_windows.ps1"), "r", encoding="utf-8-sig") as handle:
            setup = handle.read()
        self.assertIn("'uap_iw_phase3_set_inform.py'", setup)
        self.assertIn("-m py_compile .\\uap_iw_phase3_set_inform.py", setup)
        self.assertIn("--inform-url http://CONTROLLER_IP:8080/inform", setup)
        self.assertIn("--target-version-short BZ.6.7.54", setup)
        self.assertIn("--target-version-full 6.7.54.15663", setup)


if __name__ == "__main__":
    unittest.main()
