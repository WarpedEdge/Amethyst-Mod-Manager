"""Correlated, read-only verification of FFTIC launch readiness."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

try:
    from .fftic_artifacts import INTERNAL_FILES, validate_file
    from .fftic_detection import InstallStatus, InstallationDetection, VERIFIED_HASHES
    from .fftic_generation import (
        MANAGED_ARTIFACTS, content_manifest, manifest_digest,
        read_profile_mods, verify_private_generation,
    )
    from .fftic_pac import PacLaunchEvidence, pac_ownership, PacObservation, PacOwnershipState
    from .fftic_prerequisites import PrefixPrerequisites, PrerequisiteState
    from .fftic_receipts import PREFIX_CONFIGURATION_PATH, Receipt, validate_receipt
    from .fftic_reloaded_config import MANAGED_ORDER, generate_bootstrap_configuration
    from .fftic_steam_path import SteamPathResolution, resolve_prefix_generation_path, resolve_steam_s_path
    from .fftic_steam_requirements import (
        REQUIRED_OPTIONS_SHA256, SteamOptionsAnalysis, SteamOptionsStatus,
        analyze_steam_launch_options,
    )
    from .fftic_transaction_executor import file_sha256
except ImportError:
    from fftic_artifacts import INTERNAL_FILES, validate_file
    from fftic_detection import InstallStatus, InstallationDetection, VERIFIED_HASHES
    from fftic_generation import (
        MANAGED_ARTIFACTS, content_manifest, manifest_digest,
        read_profile_mods, verify_private_generation,
    )
    from fftic_pac import PacLaunchEvidence, pac_ownership, PacObservation, PacOwnershipState
    from fftic_prerequisites import PrefixPrerequisites, PrerequisiteState
    from fftic_receipts import PREFIX_CONFIGURATION_PATH, Receipt, validate_receipt
    from fftic_reloaded_config import MANAGED_ORDER, generate_bootstrap_configuration
    from fftic_steam_path import SteamPathResolution, resolve_prefix_generation_path, resolve_steam_s_path
    from fftic_steam_requirements import (
        REQUIRED_OPTIONS_SHA256, SteamOptionsAnalysis, SteamOptionsStatus,
        analyze_steam_launch_options,
    )
    from fftic_transaction_executor import file_sha256

SUPPORTED_PROTON_RUNNER = "experimental-11.0-20260924-x86_64"
_VERIFICATION_TOKEN = object()


class ReadinessAspect(str, Enum):
    READY = "ready"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class ReadinessEvidence:
    receipt: Receipt
    installation: InstallationDetection
    steam_path: SteamPathResolution
    app_manifest: Path
    runner_identity: str
    active_state_file: Path
    profile_dir: Path
    staging_root: Path
    prerequisites: PrefixPrerequisites
    steam_options: SteamOptionsAnalysis
    pac_launch_evidence: tuple[PacLaunchEvidence, ...] = ()


@dataclass(frozen=True)
class ReadinessVerification:
    install_status: InstallStatus
    steam_status: SteamOptionsStatus
    game: ReadinessAspect
    artifacts: ReadinessAspect
    generation: ReadinessAspect
    prefix: ReadinessAspect
    prerequisites: ReadinessAspect
    bootstrap: ReadinessAspect
    steam_options: ReadinessAspect
    profile: ReadinessAspect
    recovery: ReadinessAspect
    issues: tuple[str, ...]
    _attestation: object = field(default=None, init=False, repr=False, compare=False)

    @property
    def attested(self) -> bool:
        return self._attestation is _VERIFICATION_TOKEN

    @property
    def ready(self) -> bool:
        return self.attested and not self.issues and all(
            value == ReadinessAspect.READY for value in (
                self.game, self.artifacts, self.generation, self.prefix,
                self.prerequisites, self.bootstrap, self.steam_options,
                self.profile, self.recovery))


def profile_fingerprint(user_packages: list[dict]) -> str:
    payload = json.dumps(user_packages, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_active_state(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("active generation state is missing or linked")
    data = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schema_version", "active_generation", "generation_root",
              "previous_generation", "manifest_sha256"}
    if not isinstance(data, dict) or set(data) != fields or data["schema_version"] != 1:
        raise ValueError("active generation state schema is invalid")
    return data


def _current_profile_records(profile_dir: Path, staging_root: Path) -> list[dict]:
    profile_dir = Path(profile_dir)
    staging_root = Path(staging_root)
    for root, label in ((profile_dir, "profile"), (staging_root, "staging")):
        absolute = root.absolute()
        if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != absolute:
            raise ValueError(f"Current Amethyst {label} root is missing, linked, or non-canonical: {root}")
    modlist = profile_dir / "modlist.txt"
    if modlist.is_symlink() or not modlist.is_file():
        raise ValueError(f"Current Amethyst modlist is missing or linked: {modlist}")
    mods = read_profile_mods(profile_dir, staging_root)
    return [{
        "mod_id": mod.mod_id,
        "enabled": mod.enabled,
        "priority": mod.amethyst_priority,
        "classification": mod.classification.value,
        "content_identity": manifest_digest(content_manifest(mod.package_location)),
    } for mod in mods]


def _compare_profile_records(label: str, expected: list[dict], observed: list[dict],
                             reject) -> None:
    expected_by_id = {item["mod_id"].casefold(): item for item in expected}
    observed_by_id = {item["mod_id"].casefold(): item for item in observed}
    for key in sorted(expected_by_id.keys() - observed_by_id.keys()):
        reject("profile", f"{label} is missing mod {expected_by_id[key]['mod_id']}")
    for key in sorted(observed_by_id.keys() - expected_by_id.keys()):
        reject("profile", f"{label} has added mod {observed_by_id[key]['mod_id']}")
    for key in sorted(expected_by_id.keys() & observed_by_id.keys()):
        expected_item = expected_by_id[key]
        observed_item = observed_by_id[key]
        for field_name in ("enabled", "priority", "classification", "content_identity"):
            if observed_item[field_name] != expected_item[field_name]:
                reject(
                    "profile",
                    f"{label} mod {expected_item['mod_id']} field {field_name} differs")


def verify_launch_readiness(evidence: ReadinessEvidence) -> ReadinessVerification:
    """Correlate a valid receipt with current inspector and filesystem evidence."""
    issues: list[str] = []
    states = {name: ReadinessAspect.READY for name in (
        "game", "artifacts", "generation", "prefix", "prerequisites",
        "bootstrap", "steam_options", "profile", "recovery")}

    def reject(aspect: str, message: str, *, missing: bool = False) -> None:
        states[aspect] = ReadinessAspect.MISSING if missing else ReadinessAspect.INVALID
        issues.append(message)

    def result() -> ReadinessVerification:
        verified = ReadinessVerification(
            install_status=evidence.installation.status,
            steam_status=evidence.steam_options.status,
            **states, issues=tuple(issues))
        object.__setattr__(verified, "_attestation", _VERIFICATION_TOKEN)
        return verified

    try:
        receipt = validate_receipt(evidence.receipt.data)
    except Exception as exc:
        reject("recovery", f"Receipt schema is invalid: {exc}")
        return result()

    game = receipt["game_root_identity"]
    prefix = receipt["prefix_identity"]
    compatibility = receipt["compatibility_tuple"]
    installation = evidence.installation
    if (installation.status != InstallStatus.EXACT_VERIFIED
            or installation.game_root is None
            or installation.game_root.resolve() != Path(game["path"]).resolve()
            or dict(installation.executable_hashes) != VERIFIED_HASHES
            or installation.steam_build != compatibility["steam_build"]
            or installation.ui_version != compatibility["ui_version"]):
        reject("game", "Current installation evidence does not match the receipt")
    try:
        observed_path = resolve_steam_s_path(
            steam_library=evidence.steam_path.steam_library,
            app_manifest=evidence.app_manifest,
            game_root=evidence.steam_path.game_root,
            prefix=evidence.steam_path.prefix)
        if (observed_path != evidence.steam_path
                or observed_path.game_root != Path(game["path"]).resolve()
                or observed_path.steam_library != Path(game["steam_library"]).resolve()
                or observed_path.installed_directory != game["installed_directory"]
                or observed_path.prefix != Path(prefix["path"]).resolve()):
            reject("prefix", "Steam library, manifest, game root, prefix, or S: identity changed")
    except Exception as exc:
        reject("prefix", f"Steam path identity is not currently verified: {exc}")
    if (prefix["runner_identity"] != compatibility["proton_runner"]
            or evidence.runner_identity != prefix["runner_identity"]
            or evidence.runner_identity != SUPPORTED_PROTON_RUNNER):
        reject("prefix", "Runner identity does not match the supported compatibility tuple")

    generation_identity = receipt["active_generation_identity"]
    generation_root = Path(generation_identity["root"])
    manifest = None
    try:
        if generation_root.is_symlink() or generation_root.resolve(strict=True) != generation_root:
            raise ValueError("recorded generation root is moved, linked, or non-canonical")
        manifest_hash = verify_private_generation(
            generation_root, generation_identity["generation_id"])
        if manifest_hash != generation_identity["manifest_sha256"]:
            raise ValueError("generation manifest hash differs from receipt")
        manifest = json.loads((generation_root / "amethyst-generation.json").read_text(
            encoding="utf-8"))
        if verify_private_generation(generation_root, generation_identity["generation_id"]) != manifest_hash:
            raise ValueError("generation changed during readiness inspection")
        state = _read_active_state(Path(evidence.active_state_file))
        expected_state = {
            "active_generation": generation_identity["generation_id"],
            "generation_root": str(generation_root),
            "manifest_sha256": manifest_hash,
        }
        if any(state[key] != value for key, value in expected_state.items()):
            raise ValueError("active generation state disagrees with receipt")
    except Exception as exc:
        reject("generation", f"Active generation is not verified: {exc}",
               missing=not os.path.lexists(generation_root))

    if manifest is not None:
        artifacts = {item["artifact_id"]: item for item in manifest["artifact_inputs"]}
        managed_receipt = {item["mod_id"]: item for item in receipt["managed_packages"]}
        for mod_id in MANAGED_ORDER:
            artifact = artifacts.get(MANAGED_ARTIFACTS[mod_id])
            if artifact is None or managed_receipt[mod_id]["content_identity"] != artifact["content_identity"]:
                reject("artifacts", f"Managed package identity differs for {mod_id}")
        expected_users = [{
            "mod_id": item["mod_id"], "enabled": item["enabled"], "priority": item["priority"],
            "classification": item["classification"],
            "content_identity": item["content_manifest_sha256"],
        } for item in manifest["user_packages"]]
        _compare_profile_records(
            "Receipt", expected_users, receipt["user_packages"], reject)
        try:
            current_users = _current_profile_records(
                evidence.profile_dir, evidence.staging_root)
        except Exception as exc:
            reject("profile", f"Current Amethyst profile cannot be verified: {exc}")
        else:
            _compare_profile_records(
                "Current Amethyst profile", expected_users, current_users, reject)
            _compare_profile_records(
                "Current Amethyst profile versus receipt",
                receipt["user_packages"], current_users, reject)
        hashes = manifest["configuration"]["hashes"]
        if (receipt["configuration_hashes"]["classic_app"] !=
                hashes["Apps/fft_classic.exe/AppConfig.json"]
                or receipt["configuration_hashes"]["enhanced_app"] !=
                hashes["Apps/fft_enhanced.exe/AppConfig.json"]
                or manifest["configuration"]["windows_game_path"] !=
                evidence.steam_path.windows_game_path.value):
            reject("generation", "Generation configuration identity differs from the receipt")

    target_records = {item["relative_path"]: item for item in receipt["owned_game_targets"]}
    for relative, pin_id in (("version.dll", "version-dll"),
                             ("Reloaded.Mod.Loader.Bootstrapper.asi", "reloaded-bootstrapper-asi")):
        record = target_records[relative]
        target = evidence.steam_path.game_root / relative
        if record["expected_hash"] != INTERNAL_FILES[pin_id].sha256 or not validate_file(
                INTERNAL_FILES[pin_id], target):
            reject("bootstrap", f"Current {relative} is not the reviewed owned file",
                   missing=not os.path.lexists(target))
        if record["prior_state"] == "owned exact":
            backup = Path(record["backup_path"])
            if backup.is_symlink() or not backup.is_file() or file_sha256(backup) != record["prior_hash"]:
                reject("bootstrap", f"Prior backup for {relative} is missing or changed")

    config_record = receipt["prefix_owned_configuration"][0]
    try:
        windows_root = resolve_prefix_generation_path(
            prefix=evidence.steam_path.prefix, host_generation_root=generation_root)
        generated = generate_bootstrap_configuration(windows_root)
        generated_hash = hashlib.sha256(generated).hexdigest()
        config_path = evidence.steam_path.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
        if (config_record["relative_path"] != PREFIX_CONFIGURATION_PATH
                or config_record["expected_hash"] != generated_hash
                or receipt["configuration_hashes"]["bootstrap"] != generated_hash
                or config_path.is_symlink() or not config_path.is_file()
                or file_sha256(config_path) != generated_hash):
            raise ValueError("prefix bootstrap configuration identity differs")
        if config_record["prior_state"] == "owned exact":
            backup = Path(config_record["backup_path"])
            if backup.is_symlink() or not backup.is_file() or file_sha256(backup) != config_record["prior_hash"]:
                raise ValueError("prefix configuration backup is missing or changed")
    except Exception as exc:
        reject("bootstrap", f"Prefix bootstrap configuration is not verified: {exc}")

    observed_prerequisites = (evidence.prerequisites.dotnet_desktop,
                              evidence.prerequisites.vc_runtime)
    if evidence.prerequisites.prefix.resolve() != evidence.steam_path.prefix:
        reject("prerequisites", "Prerequisite evidence belongs to another prefix")
    receipt_prerequisites = {item["component"]: item for item in receipt["shared_prerequisites"]}
    for observed in observed_prerequisites:
        expected = receipt_prerequisites.get(observed.component)
        if (observed.state != PrerequisiteState.SUFFICIENT or expected is None
                or expected["state"] != observed.state.value
                or expected["observed_version"] != observed.observed_version
                or expected["required_version"] != observed.required_version):
            reject("prerequisites", f"Prerequisite observation differs for {observed.component}")

    steam = receipt["steam_launch_options"]
    current_steam = analyze_steam_launch_options(evidence.steam_options.original)
    if (steam["required_sha256"] != REQUIRED_OPTIONS_SHA256
            or steam["observed_sha256"] != hashlib.sha256(
                current_steam.original.encode("utf-8")).hexdigest()
            or evidence.steam_options != current_steam
            or steam["status"] != current_steam.status.value
            or current_steam.status != SteamOptionsStatus.CONFIGURED):
        reject("steam_options", "Current Steam Launch Options differ from the receipt")

    expected_profile = profile_fingerprint(receipt["user_packages"])
    launches = {(item.generation_id, item.profile_fingerprint, item.launch_id,
                 item.transaction_id) for item in evidence.pac_launch_evidence}
    for item in receipt["generated_pac_observations"]:
        identity = (item["generation_id"], item["profile_fingerprint"],
                    item["launch_id"], item["transaction_id"])
        observation = PacObservation(**item)
        if (item["generation_id"] != generation_identity["generation_id"]
                or item["profile_fingerprint"] != expected_profile
                or identity not in launches
                or pac_ownership(evidence.steam_path.game_root, item["relative_path"], observation)
                != PacOwnershipState.OWNED_EXACT):
            reject("profile", f"PAC observation is not owned by current launch evidence: {item['relative_path']}")
    if receipt["incomplete_operation"] is not None:
        reject("recovery", "Receipt records an incomplete operation")

    return result()
