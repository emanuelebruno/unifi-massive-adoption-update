import base64
import copy
import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import uap_iw_phase1_discovery as phase1
import uap_iw_phase2_firmware_update as phase2
from unifi_firmware_compatibility import (
    CompatibilityError,
    CompatibilityResolutionError,
    identify_device_profile,
    load_catalog,
    resolve_transition,
    validate_catalog,
)


CATALOG_PATH = os.path.join(ROOT, "compatibility", "ubiquiti_unifi_firmware.json")
U6_FIRMWARE = os.path.join(ROOT, "firmware", "BZ.MT7981_6.7.54+15663.260513.1738.bin")
LEGACY_FIRMWARE = os.path.join(ROOT, "firmware", "BZ.qca933x.v4.3.28.11361.210128.2309.bin")


def u6_record():
    return {
        "mac": "0C:EA:14:F0:8E:B2",
        "ubicazione": "TEST",
        "ip": "192.0.2.10",
        "ip_found": True,
        "ping_ok": True,
        "ssh_ok": True,
        "device_model": "U6+",
        "board_name": "U6+",
        "board_shortname": "UAPL6",
        "board_hwaddr": "0C:EA:14:F0:8E:B2",
        "model_family_status": "MODEL_FAMILY_MISMATCH",
        "device_profile_id": "ubiquiti-unifi-u6plus-uapl6",
        "device_identification_status": "DEVICE_PROFILE_IDENTIFIED",
        "firmware_version_short": "BZ.6.5.64",
        "firmware_version_full": "6.5.64.14808",
        "hostkey_status": "HOSTKEY_OBSERVED_PARAMIKO",
        "hostkey_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }


def legacy_record():
    return {
        "mac": "80:2A:A8:00:00:01",
        "ubicazione": "LEGACY",
        "ip": "192.0.2.11",
        "ip_found": True,
        "ping_ok": True,
        "ssh_ok": True,
        "device_model": "UAP-InWall",
        "board_name": "UAP-InWall",
        "board_shortname": "U2IW",
        "model_family_status": "MODEL_FAMILY_OK",
        "firmware_version_short": "BZ.v4.3.20",
        "firmware_version_full": "4.3.20.11298",
        "hostkey_status": "HOSTKEY_ALREADY_CACHED",
        "hostkey_fingerprint": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    }


def process(record, firmware, execute=False, compatibility_file=CATALOG_PATH):
    return phase2.process_one_ap(
        record,
        firmware,
        "6.7.54.15663" if record.get("device_model") == "U6+" else "4.3.28.11361",
        "BZ.6.7.54" if record.get("device_model") == "U6+" else "BZ.v4.3.28",
        "ubnt",
        "ubnt",
        "plink.exe",
        "pscp.exe",
        10,
        120,
        1,
        300,
        False,
        execute,
        1,
        1,
        False,
        5,
        compatibility_file,
    )


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog(CATALOG_PATH)

    def test_exact_profile_and_transition(self):
        evidence = {"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6"}
        resolved = resolve_transition(evidence, "BZ.6.5.64", "6.5.64.14808", "BZ.6.7.54", "6.7.54.15663", self.catalog)
        self.assertEqual(resolved.profile["id"], "ubiquiti-unifi-u6plus-uapl6")
        self.assertEqual(resolved.transition["operation"], "ssh_syswrapper_upgrade2")
        self.assertEqual(resolved.artifact["size"], 13253291)
        self.assertEqual(resolved.artifact["sha256"].upper(), "7211A694FA8C23998A551B99DC073E729B3067D94295DE6728F7019178B7D560")

    def test_commercial_model_alone_is_insufficient(self):
        with self.assertRaises(CompatibilityResolutionError):
            identify_device_profile({"device_model": "U6+"}, self.catalog)

    def test_hwaddr_does_not_participate(self):
        evidence = {"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6", "board_hwaddr": "00:00:00:00:00:00"}
        self.assertEqual(identify_device_profile(evidence, self.catalog)["id"], "ubiquiti-unifi-u6plus-uapl6")

    def test_wrong_source_and_target_are_denied(self):
        evidence = {"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6"}
        with self.assertRaises(CompatibilityResolutionError):
            resolve_transition(evidence, "BZ.6.5.63", "6.5.63.1", "BZ.6.7.54", "6.7.54.15663", self.catalog)
        with self.assertRaises(CompatibilityResolutionError):
            resolve_transition(evidence, "BZ.6.5.64", "6.5.64.14808", "BZ.6.7.55", "6.7.55.1", self.catalog)

    def test_exact_target_already_installed_is_noop(self):
        evidence = {"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6"}
        resolved = resolve_transition(evidence, "BZ.6.7.54", "6.7.54.15663", "BZ.6.7.54", "6.7.54.15663", self.catalog)
        self.assertTrue(resolved.already_installed)
        self.assertIsNone(resolved.transition)

    def test_invalid_and_ambiguous_catalogs_fail(self):
        invalid = copy.deepcopy(self.catalog)
        invalid["firmware_artifacts"][0]["sha256"] = "bad"
        with self.assertRaises(CompatibilityError):
            validate_catalog(invalid)
        ambiguous = copy.deepcopy(self.catalog)
        duplicate = copy.deepcopy(ambiguous["device_profiles"][0])
        duplicate["id"] = "duplicate-profile"
        ambiguous["device_profiles"].append(duplicate)
        validated = validate_catalog(ambiguous)
        with self.assertRaises(CompatibilityResolutionError) as raised:
            identify_device_profile({"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6"}, validated)
        self.assertEqual(raised.exception.code, "DEVICE_PROFILE_AMBIGUOUS")


class Phase1Tests(unittest.TestCase):
    def test_paramiko_fingerprint_uses_remote_key_blob(self):
        key_blob = b"actual-remote-public-key"
        key = mock.Mock()
        key.asbytes.return_value = key_blob
        transport = mock.Mock()
        transport.get_remote_server_key.return_value = key
        client = mock.Mock()
        client.get_transport.return_value = transport
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
        self.assertEqual(phase1.paramiko_server_fingerprint(client), expected)

    @mock.patch.object(phase1, "ssh_run_command")
    @mock.patch.object(phase1.paramiko, "SSHClient")
    def test_paramiko_collection_marks_fingerprint_observed(self, ssh_client, run_command):
        key = mock.Mock()
        key.asbytes.return_value = b"server-key"
        transport = mock.Mock()
        transport.get_remote_server_key.return_value = key
        client = ssh_client.return_value
        client.get_transport.return_value = transport
        run_command.side_effect = [
            ("BZ.6.5.64", "", 0, None),
            ("board.name=U6+\nboard.shortname=UAPL6", "", 0, None),
            ("Model: U6+\nVersion: 6.5.64.14808", "", 0, None),
        ]
        result = phase1.paramiko_collect_device_info("192.0.2.10", "ubnt", "ubnt", 5)
        self.assertEqual(result["hostkey_status"], "HOSTKEY_OBSERVED_PARAMIKO")
        self.assertTrue(str(result["hostkey_fingerprint"]).startswith("SHA256:"))
        self.assertEqual(result["device_profile_id"], "ubiquiti-unifi-u6plus-uapl6")
        self.assertEqual(result["model_family_status"], "MODEL_FAMILY_MISMATCH")

    def test_u6_identification_does_not_grant_legacy_model_ok(self):
        evidence = {"device_model": "U6+", "board_name": "U6+", "board_shortname": "UAPL6"}
        identified = phase1.identify_catalog_device(evidence)
        self.assertEqual(identified["device_identification_status"], "DEVICE_PROFILE_IDENTIFIED")
        self.assertEqual(identified["firmware_update_support_status"], "TRANSITION_DEPENDENT")
        self.assertEqual(phase1.evaluate_model_family("U6+", "UAPL6", "U6+"), "MODEL_FAMILY_MISMATCH")


class Phase2DispatchTests(unittest.TestCase):
    def test_u6_model_family_mismatch_dispatches_to_catalog(self):
        row = process(u6_record(), U6_FIRMWARE)
        self.assertEqual(row["compatibility_path"], "DECLARATIVE_CATALOG")
        self.assertEqual(row["status"], "DRY_RUN_UPDATE_REQUIRED")
        self.assertTrue(row["firmware_sha256_match"])
        self.assertFalse(row["modification_eligible"])
        self.assertEqual(row["eligibility_reason"], "DRY_RUN_PLAN_VALID_LIVE_RECHECK_REQUIRED")

    def test_u6_exact_target_already_installed_is_noop(self):
        record = u6_record()
        record["firmware_version_short"] = "BZ.6.7.54"
        record["firmware_version_full"] = "6.7.54.15663"
        row = process(record, U6_FIRMWARE)
        self.assertEqual(row["status"], "SKIPPED_ALREADY_UPDATED")
        self.assertEqual(row["action"], "NOOP")

    def test_legacy_path_ignores_missing_catalog(self):
        row = process(legacy_record(), LEGACY_FIRMWARE, compatibility_file=os.path.join(ROOT, "missing.json"))
        self.assertEqual(row["compatibility_path"], "LEGACY_UAP_IW_U2IW")
        self.assertEqual(row["status"], "DRY_RUN_UPDATE_REQUIRED")

    def test_legacy_path_ignores_invalid_and_ambiguous_catalog(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            handle.write("{invalid")
            invalid_path = handle.name
        try:
            row = process(legacy_record(), LEGACY_FIRMWARE, compatibility_file=invalid_path)
            self.assertEqual(row["compatibility_path"], "LEGACY_UAP_IW_U2IW")
            self.assertEqual(row["status"], "DRY_RUN_UPDATE_REQUIRED")
        finally:
            os.unlink(invalid_path)

    def test_missing_catalog_blocks_u6(self):
        row = process(u6_record(), U6_FIRMWARE, compatibility_file=os.path.join(ROOT, "missing.json"))
        self.assertEqual(row["status"], "FAILED_COMPATIBILITY_CATALOG_INVALID")
        self.assertFalse(row["upload_ok"])

    @mock.patch.object(phase2, "write_json_report")
    @mock.patch.object(phase2, "write_csv_report")
    @mock.patch.object(phase2, "read_input_report")
    def test_main_allows_catalog_artifact_past_global_dispatch(self, read_report, _csv, _json):
        read_report.return_value = [u6_record()]
        rc = phase2.main([
            "--input", "unused.json",
            "--firmware", U6_FIRMWARE,
            "--target-version-full", "6.7.54.15663",
            "--target-version-short", "BZ.6.7.54",
            "--out", "unused.csv",
        ])
        self.assertEqual(rc, 0)

    @mock.patch.object(phase2, "read_input_report")
    def test_main_preserves_legacy_qca933x_global_rejection(self, read_report):
        read_report.return_value = [legacy_record()]
        rc = phase2.main([
            "--input", "unused.json",
            "--firmware", U6_FIRMWARE,
            "--target-version-full", "4.3.28.11361",
            "--target-version-short", "BZ.v4.3.28",
            "--out", "unused.csv",
        ])
        self.assertEqual(rc, 2)

    @mock.patch.object(phase2, "read_live_preflight_info")
    @mock.patch.object(phase2, "plink_probe")
    @mock.patch.object(phase2, "run_pscp_upload")
    @mock.patch.object(phase2, "verify_artifact")
    def test_wrong_hash_has_zero_network_operations(self, verify, upload, probe, live):
        verify.return_value = {
            "firmware_filename_expected": os.path.basename(U6_FIRMWARE),
            "firmware_filename_actual": os.path.basename(U6_FIRMWARE),
            "firmware_filename_match": True,
            "firmware_size_expected": 13253291,
            "firmware_size_actual": 13253291,
            "firmware_size_match": True,
            "firmware_sha256_expected": "expected",
            "firmware_sha256_actual": "wrong",
            "firmware_sha256_match": False,
        }
        row = process(u6_record(), U6_FIRMWARE, execute=True)
        self.assertEqual(row["status"], "SKIPPED_FIRMWARE_SHA256_MISMATCH")
        upload.assert_not_called()
        probe.assert_not_called()
        live.assert_not_called()

    @mock.patch.object(phase2, "run_pscp_upload")
    @mock.patch.object(phase2, "read_live_preflight_info")
    @mock.patch.object(phase2, "plink_probe")
    @mock.patch.object(phase2, "resolve_executable", return_value="tool.exe")
    @mock.patch.object(phase2, "verify_artifact")
    def test_report_live_mismatch_has_zero_upload(self, verify, _resolve, probe, live, upload):
        verify.return_value = {
            "firmware_filename_expected": os.path.basename(U6_FIRMWARE),
            "firmware_filename_actual": os.path.basename(U6_FIRMWARE),
            "firmware_filename_match": True,
            "firmware_size_expected": 13253291,
            "firmware_size_actual": 13253291,
            "firmware_size_match": True,
            "firmware_sha256_expected": "expected",
            "firmware_sha256_actual": "expected",
            "firmware_sha256_match": True,
        }
        probe.return_value = (True, "HOSTKEY_ALREADY_CACHED", "", "")
        live.return_value = (True, {
            "device_model": "U6+",
            "board_name": "DIFFERENT",
            "board_shortname": "UAPL6",
            "firmware_version_short": "BZ.6.5.64",
            "firmware_version_full": "6.5.64.14808",
        }, "", "")
        row = process(u6_record(), U6_FIRMWARE, execute=True)
        self.assertEqual(row["status"], "SKIPPED_LIVE_IDENTITY_MISMATCH")
        upload.assert_not_called()


class SetupTests(unittest.TestCase):
    def test_setup_provisions_and_validates_compatibility_runtime(self):
        with open(os.path.join(ROOT, "setup_windows.ps1"), "r", encoding="utf-8-sig") as handle:
            setup = handle.read()
        self.assertIn("unifi_firmware_compatibility.py", setup)
        self.assertIn("compatibility/ubiquiti_unifi_firmware.json", setup)
        self.assertIn("Ensure-Directory -Path '.\\compatibility'", setup)
        self.assertIn("validate_default_catalog", setup)


if __name__ == "__main__":
    unittest.main()
