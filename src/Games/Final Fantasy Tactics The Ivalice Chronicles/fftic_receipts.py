"""Versioned fail-closed ownership receipts for the FFTIC lifecycle."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path

try:
    from .fftic_artifacts import ARTIFACTS, INTERNAL_FILES
    from .fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from .fftic_reloaded_config import MANAGED_ORDER
    from .fftic_steam_requirements import REQUIRED_OPTIONS_SHA256
except ImportError:
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES
    from fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from fftic_reloaded_config import MANAGED_ORDER
    from fftic_steam_requirements import REQUIRED_OPTIONS_SHA256

SCHEMA_VERSION = 1
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PREFIX_CONFIGURATION_PATH = (
    "users/steamuser/AppData/Roaming/Reloaded-Mod-Loader-II/ReloadedII.json")
_REQUIRED = {
    "schema_version", "transaction_id", "created_at", "updated_at", "steam_app_id",
    "game_root_identity", "prefix_identity", "executable_hashes", "evidence_authority",
    "compatibility_tuple",
    "active_generation_identity", "artifacts", "managed_packages", "configuration_hashes",
    "user_packages", "owned_game_targets", "prefix_owned_configuration",
    "shared_prerequisites", "steam_launch_options", "generated_pac_observations",
    "last_successful_operation", "incomplete_operation", "recovery_instructions",
}


class ReceiptError(RuntimeError):
    pass


class ReceiptCorruptError(ReceiptError):
    pass


@dataclass(frozen=True)
class Receipt:
    data: dict

    @property
    def transaction_id(self) -> str:
        return self.data["transaction_id"]


def _fail(field: str) -> None:
    raise ReceiptCorruptError(f"FFTIC receipt {field} is invalid")


def _exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(label)
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        _fail(label)
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail(label)
    return value


def _timestamp(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(label)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(label)
    if parsed.tzinfo != timezone.utc:
        _fail(label)


def _path(value: object, label: str) -> str:
    if (not isinstance(value, str) or not value or "\x00" in value
            or any(part == ".." for part in value.replace("\\", "/").split("/"))):
        _fail(label)
    return value


def _absolute_path(value: object, label: str) -> str:
    value = _path(value, label)
    if not Path(value).is_absolute():
        _fail(label)
    return value


def validate_receipt(data: object) -> dict:
    if not isinstance(data, dict):
        raise ReceiptCorruptError("FFTIC receipt root must be an object")
    missing = sorted(_REQUIRED - set(data))
    extra = sorted(set(data) - _REQUIRED)
    if missing or extra:
        raise ReceiptCorruptError(f"FFTIC receipt fields differ (missing={missing}, extra={extra})")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ReceiptCorruptError(f"Unsupported FFTIC receipt schema {data['schema_version']!r}")
    if data["steam_app_id"] != "1004640":
        raise ReceiptCorruptError("FFTIC receipt has the wrong Steam app ID")
    _identifier(data["transaction_id"], "transaction_id")
    _timestamp(data["created_at"], "created_at")
    _timestamp(data["updated_at"], "updated_at")
    game = _exact(data["game_root_identity"],
                  {"path", "steam_library", "installed_directory"}, "game_root_identity")
    _absolute_path(game["path"], "game_root_identity.path")
    _absolute_path(game["steam_library"], "game_root_identity.steam_library")
    if not isinstance(game["installed_directory"], str) or not game["installed_directory"]:
        _fail("game_root_identity.installed_directory")
    prefix = _exact(data["prefix_identity"], {"path", "runner_identity"}, "prefix_identity")
    _absolute_path(prefix["path"], "prefix_identity.path")
    _identifier(prefix["runner_identity"], "prefix_identity.runner_identity")
    executables = _exact(data["executable_hashes"], {"classic", "enhanced"}, "executable_hashes")
    for key, value in executables.items():
        _hash(value, f"executable_hashes.{key}")
    authority = data["evidence_authority"]
    if authority == "reviewed-production":
        if executables != VERIFIED_HASHES:
            _fail("executable_hashes reviewed identities")
    elif not (isinstance(authority, str)
              and authority.startswith("isolated-fixture:")
              and len(authority) <= 128):
        _fail("evidence_authority")
    compatibility = _exact(data["compatibility_tuple"], {
        "steam_build", "ui_version", "proton_runner", "reloaded", "sigscan",
        "shared_hooks", "nenkai",
    }, "compatibility_tuple")
    if not all(isinstance(value, str) and value for value in compatibility.values()):
        _fail("compatibility_tuple")
    if (compatibility["steam_build"] != VERIFIED_STEAM_BUILD
            or compatibility["ui_version"] != VERIFIED_UI_VERSION
            or compatibility["reloaded"] != "1.31.0"
            or compatibility["sigscan"] != "1.2.14"
            or compatibility["shared_hooks"] != "1.16.3"
            or compatibility["nenkai"] != "1.7.3"):
        _fail("compatibility_tuple reviewed identities")
    if prefix["runner_identity"] != compatibility["proton_runner"]:
        _fail("prefix/compatibility runner identity")
    generation = _exact(data["active_generation_identity"],
                        {"generation_id", "root", "manifest_sha256"},
                        "active_generation_identity")
    _identifier(generation["generation_id"], "active_generation_identity.generation_id")
    _absolute_path(generation["root"], "active_generation_identity.root")
    _hash(generation["manifest_sha256"], "active_generation_identity.manifest_sha256")

    expected_artifacts = {"reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks",
                          "dotnet-desktop-runtime", "vc-runtime"}
    artifacts = data["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_artifacts):
        _fail("artifacts")
    artifact_ids = []
    for index, item in enumerate(artifacts):
        item = _exact(item, {"artifact_id", "version", "url", "size", "sha256"},
                      f"artifacts[{index}]")
        artifact_ids.append(_identifier(item["artifact_id"], f"artifacts[{index}].artifact_id"))
        if (not isinstance(item["version"], str) or not item["version"]
                or not isinstance(item["url"], str) or not item["url"].startswith("https://")
                or not isinstance(item["size"], int) or item["size"] <= 0):
            _fail(f"artifacts[{index}]")
        _hash(item["sha256"], f"artifacts[{index}].sha256")
        if item["artifact_id"] not in ARTIFACTS:
            _fail(f"artifacts[{index}].artifact_id")
        pin = ARTIFACTS[item["artifact_id"]]
        if any((item["version"] != pin.version, item["url"] != pin.url,
                item["size"] != pin.size, item["sha256"] != pin.sha256)):
            _fail(f"artifacts[{index}] reviewed identity")
    if set(artifact_ids) != expected_artifacts or len(set(artifact_ids)) != len(artifact_ids):
        _fail("artifacts identities")

    managed = data["managed_packages"]
    expected_managed = {"Reloaded.Memory.SigScan.ReloadedII", "reloaded.sharedlib.hooks",
                        "fftivc.utility.modloader"}
    if not isinstance(managed, list) or len(managed) != 3:
        _fail("managed_packages")
    managed_ids = []
    for index, item in enumerate(managed):
        item = _exact(item, {"mod_id", "version", "content_identity"},
                      f"managed_packages[{index}]")
        managed_ids.append(_identifier(item["mod_id"], f"managed_packages[{index}].mod_id"))
        if not isinstance(item["version"], str) or not item["version"]:
            _fail(f"managed_packages[{index}].version")
        _hash(item["content_identity"], f"managed_packages[{index}].content_identity")
    if set(managed_ids) != expected_managed or len(set(managed_ids)) != 3:
        _fail("managed_packages identities")
    expected_versions = {
        "Reloaded.Memory.SigScan.ReloadedII": "1.2.14",
        "reloaded.sharedlib.hooks": "1.16.3",
        "fftivc.utility.modloader": "1.7.3",
    }
    if any(item["version"] != expected_versions[item["mod_id"]] for item in managed):
        _fail("managed_packages reviewed versions")

    configurations = _exact(data["configuration_hashes"],
                            {"bootstrap", "classic_app", "enhanced_app"},
                            "configuration_hashes")
    for key, value in configurations.items():
        _hash(value, f"configuration_hashes.{key}")
    if not isinstance(data["user_packages"], list):
        _fail("user_packages")
    seen_users = set()
    for index, item in enumerate(data["user_packages"]):
        item = _exact(item, {"mod_id", "enabled", "priority", "classification", "content_identity"},
                      f"user_packages[{index}]")
        identity = _identifier(item["mod_id"], f"user_packages[{index}].mod_id").casefold()
        if (identity in seen_users or identity in {value.casefold() for value in MANAGED_ORDER}
                or not isinstance(item["enabled"], bool) or type(item["priority"]) is not int):
            _fail(f"user_packages[{index}]")
        seen_users.add(identity)
        if item["classification"] not in {
                "Classic content mod", "Enhanced content mod", "dual-mode content mod"}:
            _fail(f"user_packages[{index}].classification")
        _hash(item["content_identity"], f"user_packages[{index}].content_identity")

    targets = data["owned_game_targets"]
    if not isinstance(targets, list):
        _fail("owned_game_targets")
    target_paths = []
    for index, item in enumerate(targets):
        item = _exact(item, {"relative_path", "expected_hash", "prior_state", "prior_hash", "backup_path"},
                      f"owned_game_targets[{index}]")
        target_paths.append(_path(item["relative_path"], f"owned_game_targets[{index}].relative_path"))
        _hash(item["expected_hash"], f"owned_game_targets[{index}].expected_hash")
        if item["prior_state"] not in {"absent", "owned exact"}:
            _fail(f"owned_game_targets[{index}].prior_state")
        if item["prior_hash"] is not None:
            _hash(item["prior_hash"], f"owned_game_targets[{index}].prior_hash")
        if item["backup_path"] is not None:
            _absolute_path(item["backup_path"], f"owned_game_targets[{index}].backup_path")
        if ((item["prior_state"] == "absent" and
             (item["prior_hash"] is not None or item["backup_path"] is not None))
                or (item["prior_state"] == "owned exact" and
                    (item["prior_hash"] is None or item["backup_path"] is None))):
            _fail(f"owned_game_targets[{index}] prior ownership")
    if set(target_paths) != {"version.dll", "Reloaded.Mod.Loader.Bootstrapper.asi"}:
        _fail("owned_game_targets identities")
    expected_target_hashes = {
        "version.dll": INTERNAL_FILES["version-dll"].sha256,
        "Reloaded.Mod.Loader.Bootstrapper.asi":
            INTERNAL_FILES["reloaded-bootstrapper-asi"].sha256,
    }
    if any(item["expected_hash"] != expected_target_hashes[item["relative_path"]]
           for item in targets):
        _fail("owned_game_targets reviewed identities")

    prefix_config = data["prefix_owned_configuration"]
    if not isinstance(prefix_config, list) or len(prefix_config) != 1:
        _fail("prefix_owned_configuration")
    config = _exact(prefix_config[0], {"relative_path", "expected_hash", "prior_state", "prior_hash", "backup_path"},
                    "prefix_owned_configuration[0]")
    if (_path(config["relative_path"], "prefix_owned_configuration[0].relative_path")
            != PREFIX_CONFIGURATION_PATH):
        _fail("prefix_owned_configuration[0].relative_path")
    _hash(config["expected_hash"], "prefix_owned_configuration[0].expected_hash")
    if config["prior_state"] not in {"absent", "owned exact"}:
        _fail("prefix_owned_configuration[0].prior_state")
    for key in ("prior_hash",):
        if config[key] is not None:
            _hash(config[key], f"prefix_owned_configuration[0].{key}")
    if config["backup_path"] is not None:
        _absolute_path(config["backup_path"], "prefix_owned_configuration[0].backup_path")
    if ((config["prior_state"] == "absent" and
         (config["prior_hash"] is not None or config["backup_path"] is not None))
            or (config["prior_state"] == "owned exact" and
                (config["prior_hash"] is None or config["backup_path"] is None))):
        _fail("prefix_owned_configuration[0] prior ownership")

    prerequisites = data["shared_prerequisites"]
    if not isinstance(prerequisites, list) or len(prerequisites) != 2:
        _fail("shared_prerequisites")
    names = []
    for index, item in enumerate(prerequisites):
        item = _exact(item, {"component", "state", "observed_version", "required_version"},
                      f"shared_prerequisites[{index}]")
        names.append(item["component"])
        if (item["state"] != "sufficient" or not isinstance(item["observed_version"], str)
                or not isinstance(item["required_version"], str)):
            _fail(f"shared_prerequisites[{index}]")
    if set(names) != {".NET Desktop Runtime", "VC++ 2015-2022 x64 Runtime"} or len(set(names)) != 2:
        _fail("shared_prerequisites identities")
    required_versions = {
        ".NET Desktop Runtime": "9.0.20",
        "VC++ 2015-2022 x64 Runtime": "14.30.0.0",
    }
    for index, item in enumerate(prerequisites):
        if item["required_version"] != required_versions[item["component"]]:
            _fail(f"shared_prerequisites[{index}].required_version")
        try:
            observed = tuple(int(part) for part in item["observed_version"].split("."))
            required = tuple(int(part) for part in item["required_version"].split("."))
        except ValueError:
            _fail(f"shared_prerequisites[{index}].observed_version")
        if observed < required:
            _fail(f"shared_prerequisites[{index}].observed_version")

    steam = _exact(data["steam_launch_options"],
                   {"status", "required_sha256", "observed_sha256"},
                   "steam_launch_options")
    if steam["status"] not in {"Configured", "Missing", "Different", "Conflict"}:
        _fail("steam_launch_options.status")
    if (_hash(steam["required_sha256"], "steam_launch_options.required_sha256")
            != REQUIRED_OPTIONS_SHA256):
        _fail("steam_launch_options.required_sha256")
    _hash(steam["observed_sha256"], "steam_launch_options.observed_sha256")
    pacs = data["generated_pac_observations"]
    if not isinstance(pacs, list):
        _fail("generated_pac_observations")
    seen_pacs = set()
    allowed_pacs = {
        "data/classic/modded.pac", "data/classic/modded.en.pac",
        "data/enhanced/modded.pac", "data/enhanced/modded.en.pac",
    }
    for index, item in enumerate(pacs):
        item = _exact(item, {"relative_path", "sha256", "generation_id", "profile_fingerprint",
                             "launch_id", "transaction_id", "before_state", "before_sha256"},
                      f"generated_pac_observations[{index}]")
        relative = _path(item["relative_path"], f"generated_pac_observations[{index}].relative_path")
        if (relative not in allowed_pacs or relative in seen_pacs
                or item["before_state"] not in {"absent", "owned exact"}):
            _fail(f"generated_pac_observations[{index}]")
        seen_pacs.add(relative)
        _hash(item["sha256"], f"generated_pac_observations[{index}].sha256")
        for key in ("generation_id", "profile_fingerprint", "launch_id", "transaction_id"):
            _identifier(item[key], f"generated_pac_observations[{index}].{key}")
        if item["before_sha256"] is not None:
            _hash(item["before_sha256"], f"generated_pac_observations[{index}].before_sha256")
        if ((item["before_state"] == "absent" and item["before_sha256"] is not None)
                or (item["before_state"] == "owned exact" and item["before_sha256"] is None)):
            _fail(f"generated_pac_observations[{index}].before_sha256")
    _identifier(data["last_successful_operation"], "last_successful_operation")
    incomplete = data["incomplete_operation"]
    if incomplete is not None:
        incomplete = _exact(incomplete, {"operation", "step", "state", "write_ahead_at"},
                            "incomplete_operation")
        _identifier(incomplete["operation"], "incomplete_operation.operation")
        if type(incomplete["step"]) is not int or incomplete["step"] < 0 or incomplete["state"] not in {
                "write-ahead", "recovery-required"}:
            _fail("incomplete_operation")
        _timestamp(incomplete["write_ahead_at"], "incomplete_operation.write_ahead_at")
    recovery = data["recovery_instructions"]
    if not isinstance(recovery, list) or not recovery or not all(isinstance(x, str) and x for x in recovery):
        _fail("recovery_instructions")
    return data


def _safe_receipt_path(receipts_root: Path, name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", name) or ".." in name:
        raise ReceiptError(f"Unsafe receipt filename: {name!r}")
    root = Path(receipts_root).resolve()
    path = root / name
    if path.parent.resolve() != root:
        raise ReceiptError("Receipt path escapes its configured root")
    return path


def serialize_receipt(data: dict) -> bytes:
    validate_receipt(data)
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def read_receipt(receipts_root: Path, name: str = "fftic-receipt.json") -> Receipt | None:
    path = _safe_receipt_path(receipts_root, name)
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise ReceiptCorruptError(f"FFTIC receipt is not a regular file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptCorruptError(f"FFTIC receipt is corrupt; preserve it for recovery: {exc}") from exc
    return Receipt(validate_receipt(data))


def write_receipt(receipts_root: Path, data: dict, name: str = "fftic-receipt.json") -> Path:
    """Atomically replace only an absent or already-valid receipt."""
    path = _safe_receipt_path(receipts_root, name)
    payload = serialize_receipt(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        read_receipt(receipts_root, name)  # fail closed; never bury corrupt state
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return path
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)
