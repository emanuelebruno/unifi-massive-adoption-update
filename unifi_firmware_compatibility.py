import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


SCHEMA_VERSION = 1
DEFAULT_CATALOG_RELATIVE_PATH = os.path.join("compatibility", "ubiquiti_unifi_firmware.json")


class CompatibilityError(ValueError):
    pass


class CompatibilityResolutionError(CompatibilityError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ResolvedTransition:
    profile: Dict[str, object]
    artifact: Dict[str, object]
    transition: Optional[Dict[str, object]]
    already_installed: bool


def default_catalog_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_CATALOG_RELATIVE_PATH)


def _require_string(obj: Dict[str, object], key: str, context: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CompatibilityError(f"{context}.{key} must be a non-empty string")
    return value.strip()


def _validate_unique_ids(items: object, section: str) -> List[Dict[str, object]]:
    if not isinstance(items, list) or not items:
        raise CompatibilityError(f"{section} must be a non-empty array")
    result: List[Dict[str, object]] = []
    seen = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise CompatibilityError(f"{section}[{index}] must be an object")
        item_id = _require_string(item, "id", f"{section}[{index}]")
        if item_id in seen:
            raise CompatibilityError(f"duplicate {section} id: {item_id}")
        seen.add(item_id)
        result.append(item)
    return result


def validate_catalog(data: object) -> Dict[str, object]:
    if not isinstance(data, dict):
        raise CompatibilityError("catalog root must be an object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise CompatibilityError(f"unsupported schema_version: {data.get('schema_version')!r}")
    _require_string(data, "vendor", "catalog")
    _require_string(data, "product_family", "catalog")

    profiles = _validate_unique_ids(data.get("device_profiles"), "device_profiles")
    artifacts = _validate_unique_ids(data.get("firmware_artifacts"), "firmware_artifacts")
    transitions = _validate_unique_ids(data.get("transition_rules"), "transition_rules")
    profile_ids = {str(x["id"]) for x in profiles}
    artifact_ids = {str(x["id"]) for x in artifacts}

    for index, profile in enumerate(profiles):
        context = f"device_profiles[{index}]"
        _require_string(profile, "vendor", context)
        _require_string(profile, "product_family", context)
        _require_string(profile, "commercial_model", context)
        _require_string(profile, "firmware_platform", context)
        identity = profile.get("identity")
        required = profile.get("required_identity_fields")
        if not isinstance(identity, dict) or not identity:
            raise CompatibilityError(f"{context}.identity must be a non-empty object")
        if not isinstance(required, list) or not required:
            raise CompatibilityError(f"{context}.required_identity_fields must be a non-empty array")
        for field in required:
            if not isinstance(field, str) or not field:
                raise CompatibilityError(f"{context}.required_identity_fields contains an invalid field")
            _require_string(identity, field, f"{context}.identity")

    for index, artifact in enumerate(artifacts):
        context = f"firmware_artifacts[{index}]"
        for key in ("vendor", "firmware_platform", "version_short", "version_full", "filename", "sha256"):
            _require_string(artifact, key, context)
        if not isinstance(artifact.get("size"), int) or int(artifact["size"]) <= 0:
            raise CompatibilityError(f"{context}.size must be a positive integer")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(artifact["sha256"])):
            raise CompatibilityError(f"{context}.sha256 must be 64 hexadecimal characters")

    for index, transition in enumerate(transitions):
        context = f"transition_rules[{index}]"
        profile_id = _require_string(transition, "device_profile_id", context)
        artifact_id = _require_string(transition, "target_artifact_id", context)
        _require_string(transition, "operation", context)
        _require_string(transition, "support_status", context)
        if profile_id not in profile_ids:
            raise CompatibilityError(f"{context} references unknown profile: {profile_id}")
        if artifact_id not in artifact_ids:
            raise CompatibilityError(f"{context} references unknown artifact: {artifact_id}")
        sources = transition.get("allowed_sources")
        if not isinstance(sources, list) or not sources:
            raise CompatibilityError(f"{context}.allowed_sources must be a non-empty array")
        for source_index, source in enumerate(sources):
            if not isinstance(source, dict):
                raise CompatibilityError(f"{context}.allowed_sources[{source_index}] must be an object")
            _require_string(source, "version_short", f"{context}.allowed_sources[{source_index}]")
            _require_string(source, "version_full", f"{context}.allowed_sources[{source_index}]")
    return data


def load_catalog(path: Optional[str] = None) -> Dict[str, object]:
    catalog_path = os.path.abspath(path or default_catalog_path())
    try:
        with open(catalog_path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"cannot load compatibility catalog {catalog_path}: {exc}") from exc
    return validate_catalog(data)


def _clean_evidence(evidence: Dict[str, object]) -> Dict[str, str]:
    return {str(key): str(value or "").strip() for key, value in evidence.items()}


def profile_matches(profile: Dict[str, object], evidence: Dict[str, object]) -> bool:
    normalized = _clean_evidence(evidence)
    identity = profile["identity"]
    required = profile["required_identity_fields"]
    return all(normalized.get(str(field), "") == str(identity[str(field)]).strip() for field in required)


def identify_device_profile(evidence: Dict[str, object], catalog: Dict[str, object]) -> Dict[str, object]:
    matches = [profile for profile in catalog["device_profiles"] if profile_matches(profile, evidence)]
    if not matches:
        raise CompatibilityResolutionError("DEVICE_PROFILE_NOT_FOUND", "no exact device profile matched")
    if len(matches) != 1:
        raise CompatibilityResolutionError("DEVICE_PROFILE_AMBIGUOUS", f"{len(matches)} device profiles matched")
    return matches[0]


def resolve_transition(
    evidence: Dict[str, object],
    source_short: str,
    source_full: str,
    target_short: str,
    target_full: str,
    catalog: Dict[str, object],
) -> ResolvedTransition:
    profile = identify_device_profile(evidence, catalog)
    artifacts = [
        artifact
        for artifact in catalog["firmware_artifacts"]
        if str(artifact["version_short"]).strip() == target_short.strip()
        and str(artifact["version_full"]).strip() == target_full.strip()
        and str(artifact["firmware_platform"]).strip() == str(profile["firmware_platform"]).strip()
    ]
    if not artifacts:
        raise CompatibilityResolutionError("TARGET_ARTIFACT_NOT_FOUND", "no exact target artifact matched")
    if len(artifacts) != 1:
        raise CompatibilityResolutionError("TARGET_ARTIFACT_AMBIGUOUS", f"{len(artifacts)} target artifacts matched")
    artifact = artifacts[0]

    if source_short.strip() == target_short.strip() and source_full.strip() == target_full.strip():
        return ResolvedTransition(profile=profile, artifact=artifact, transition=None, already_installed=True)

    matches = []
    for transition in catalog["transition_rules"]:
        if transition["device_profile_id"] != profile["id"] or transition["target_artifact_id"] != artifact["id"]:
            continue
        if transition["support_status"] != "approved":
            continue
        if any(
            str(source["version_short"]).strip() == source_short.strip()
            and str(source["version_full"]).strip() == source_full.strip()
            for source in transition["allowed_sources"]
        ):
            matches.append(transition)
    if not matches:
        raise CompatibilityResolutionError("TRANSITION_NOT_FOUND", "no approved exact source transition matched")
    if len(matches) != 1:
        raise CompatibilityResolutionError("TRANSITION_AMBIGUOUS", f"{len(matches)} approved transitions matched")
    return ResolvedTransition(profile=profile, artifact=artifact, transition=matches[0], already_installed=False)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_artifact(path: str, artifact: Dict[str, object]) -> Dict[str, object]:
    expected_filename = str(artifact["filename"])
    expected_size = int(artifact["size"])
    expected_sha256 = str(artifact["sha256"]).lower()
    actual_filename = os.path.basename(path)
    actual_size = os.path.getsize(path)
    actual_sha256 = sha256_file(path)
    return {
        "firmware_filename_expected": expected_filename,
        "firmware_filename_actual": actual_filename,
        "firmware_filename_match": actual_filename == expected_filename,
        "firmware_size_expected": expected_size,
        "firmware_size_actual": actual_size,
        "firmware_size_match": actual_size == expected_size,
        "firmware_sha256_expected": expected_sha256,
        "firmware_sha256_actual": actual_sha256,
        "firmware_sha256_match": actual_sha256.lower() == expected_sha256,
    }


def validate_default_catalog() -> str:
    load_catalog()
    return default_catalog_path()
