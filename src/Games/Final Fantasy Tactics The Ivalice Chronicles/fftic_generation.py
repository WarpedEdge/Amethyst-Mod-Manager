"""Deterministic private Reloaded generation assembly and profile snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    from .fftic_mod_state import ModWorkingPolicy, contract_for, transition_copy
    from .fftic_color_state import ColorWorkingPolicy, working_baseline, _COLOR_ID
    from .fftic_artifacts import ARTIFACTS, INTERNAL_FILES, loader_pin, loader_pin_from_digest
    from .fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from .fftic_packages import PackageClassification, inspect_package
    from .fftic_reloaded_config import (
        MANAGED_ORDER, Mode, UserMod, ValidatedSteamPath, _compatible,
        generate_reloaded_configuration,
    )
    from .fftic_extraction import (
        ExtractionLimits, VerifiedArtifactTree, extract_archive, verify_internal_file,
    )
except ImportError:
    from fftic_mod_state import ModWorkingPolicy, contract_for, transition_copy
    from fftic_color_state import ColorWorkingPolicy, working_baseline, _COLOR_ID
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES, loader_pin, loader_pin_from_digest
    from fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from fftic_packages import PackageClassification, inspect_package
    from fftic_reloaded_config import (
        MANAGED_ORDER, Mode, UserMod, ValidatedSteamPath, _compatible,
        generate_reloaded_configuration,
    )
    from fftic_extraction import (
        ExtractionLimits, VerifiedArtifactTree, extract_archive, verify_internal_file,
    )

COMPONENT_VERSIONS = {
    "reloaded-ii": "1.31.0",
    "Reloaded.Memory.SigScan.ReloadedII": "1.2.14",
    "reloaded.sharedlib.hooks": "1.16.3",
    "fftivc.utility.modloader": "1.7.3",
}
COMPATIBILITY_SET = {
    "schema": 1,
    "steam_build": VERIFIED_STEAM_BUILD,
    "ui_version": VERIFIED_UI_VERSION,
    "executables": VERIFIED_HASHES,
    "artifacts": {key: {"version": pin.version, "size": pin.size, "sha256": pin.sha256}
                  for key, pin in ARTIFACTS.items()},
    "internal_files": {key: {"size": pin.size, "sha256": pin.sha256}
                       for key, pin in INTERNAL_FILES.items()},
}


def component_versions_for(loader):
    return dict(COMPONENT_VERSIONS, **{"fftivc.utility.modloader": loader.version})


def compatibility_set_for(loader):
    result = dict(COMPATIBILITY_SET)
    result["artifacts"] = dict(COMPATIBILITY_SET["artifacts"])
    result["artifacts"]["nenkai-loader"] = {
        "version": loader.version, "size": loader.size, "sha256": loader.sha256}
    return result
MANAGED_ARTIFACTS = {
    "Reloaded.Memory.SigScan.ReloadedII": "sigscan",
    "reloaded.sharedlib.hooks": "shared-hooks",
    "fftivc.utility.modloader": "nenkai-loader",
}
MANAGED_MOD_CONFIG_VALUES = {
    identity: {"CanUnload": False, "HasExports": True}
    for identity in MANAGED_ARTIFACTS
}
_LEGACY_RELOADED_NORMALIZATION = {
    "Mods/fftivc.utility.modloader/ModConfig.json": (
        "c0fd45d11363e51da689845fb35bbd3675b1452bcb210cf2b8236aae39a2d90c",
        "f46aad9d10995141ec3d5f298096fa25580b3e45c8a2ba9395f54e39e2d458c3",
    ),
    "Mods/Reloaded.Memory.SigScan.ReloadedII/ModConfig.json": (
        "5105a83e54b339e07b16c2b59de08a133db12a813c825b492259517d773b463e",
        "dee6033f306b279347054ca31deb2b6154e3ed9a2d4b11a5ad01234f520230b0",
    ),
    "Mods/reloaded.sharedlib.hooks/ModConfig.json": (
        "a0204b7eaea3a0b1faa086ab38f349a014782d41f2608c9989cd0075fe74f4a1",
        "ed086fa604a40472596638f549a541ed02b254f4b62afb33e88c371dee719cfd",
    ),
}
_LEGACY_SERIALIZER_DEFAULTS = {
    "fftivc.utility.modloader": {},
    "Reloaded.Memory.SigScan.ReloadedII": {
        "Tags": [], "IgnoreRegexes": [".*\\.json"],
        "IncludeRegexes": ["\\.deps\\.json", "\\.runtimeconfig\\.json", "ModConfig\\.json"],
    },
    "reloaded.sharedlib.hooks": {
        "Tags": [], "IgnoreRegexes": [".*\\.json"],
        "IncludeRegexes": ["\\.deps\\.json", "\\.runtimeconfig\\.json", "ModConfig\\.json"],
        "ProjectUrl": "",
    },
}
MANIFEST_FIELDS = {
    "schema_version", "generation_id", "components", "compatibility_set",
    "artifact_inputs", "managed_packages", "user_packages", "configuration", "files",
}
NESTED_ASI_ARCHIVE_SIZE = 6_297_308
NESTED_ASI_ARCHIVE_SHA256 = "812a7317799baa0001e68446d72592a3f8d83fb8f977dbbef3525ebe7396f380"
_HASH = re.compile(r"^[0-9a-f]{64}$")


class GenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class GenerationResult:
    generation_id: str
    root: Path
    manifest_sha256: str
    previous_generation: str | None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in [*sorted(directories, reverse=True), root]:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def content_manifest(root: Path, *, exclude: tuple[str, ...] = ()) -> tuple[dict, ...]:
    root = Path(root).resolve()
    excluded = {value.casefold() for value in exclude}
    records: list[dict] = []
    seen: dict[str, str] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative.casefold() in excluded:
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise GenerationError(f"Link or special file is not allowed in a generation: {path}")
        key = relative.casefold()
        if key in seen and seen[key] != relative:
            raise GenerationError(
                f"Case-fold path collision in generation source: {seen[key]!r} and {relative!r}")
        seen[key] = relative
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise GenerationError(f"Hardlinked generation file is not private: {path}")
            records.append({"path": relative, "size": info.st_size, "sha256": _sha256(path)})
    return tuple(sorted(records, key=lambda item: (item["path"].casefold(), item["path"])))


def manifest_digest(records: tuple[dict, ...]) -> str:
    payload = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _artifact_tree_digest(records: list[dict] | tuple[dict, ...]) -> str:
    payload = "".join(f"{item['path']}\0{item['size']}\0{item['sha256']}\n" for item in records)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _copy_tree_exact(source: Path, destination: Path, cancel=None) -> None:
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise GenerationError(f"Generation source is not a regular directory: {source}")
    destination.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix().casefold()):
        if cancel is not None and cancel.is_set():
            raise GenerationError("Generation assembly cancelled")
        relative = path.relative_to(source)
        target = destination / relative
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise GenerationError(f"Source contains a link or special file: {path}")
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def _verify_copied_evidence(destination: Path, evidence: VerifiedArtifactTree) -> None:
    observed = tuple((item["path"], item["size"], item["sha256"])
                     for item in content_manifest(destination))
    expected = tuple((item.path, item.size, item.sha256) for item in evidence.files)
    if observed != expected:
        raise GenerationError(f"Copied artifact bytes changed during assembly: {evidence.pin.artifact_id}")


def _managed_identity(package: Path) -> str:
    configs = [path for path in package.rglob("ModConfig.json") if path.is_file()]
    if configs != [package / "ModConfig.json"]:
        raise GenerationError(
            f"Managed package must contain exactly one root ModConfig.json: {package}")
    try:
        data = json.loads((package / "ModConfig.json").read_text(encoding="utf-8"))
        identity = data["ModId"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise GenerationError(f"Managed package has no valid ModConfig.json: {package}: {exc}") from exc
    if not isinstance(identity, str):
        raise GenerationError(f"Managed package ID is not a string: {package}")
    return identity


def normalized_managed_mod_config(payload: bytes, expected_identity: str) -> bytes:
    """Add only Reloaded's two deterministic managed export fields."""
    if expected_identity not in MANAGED_MOD_CONFIG_VALUES:
        raise GenerationError(f"Managed ModConfig normalization is not allowed for {expected_identity}")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GenerationError(f"Managed ModConfig is invalid for {expected_identity}: {exc}") from exc
    if (not isinstance(data, dict) or data.get("ModId") != expected_identity):
        raise GenerationError(f"Managed ModConfig identity differs for {expected_identity}")
    for field, expected in MANAGED_MOD_CONFIG_VALUES[expected_identity].items():
        if field in data and data[field] not in {None, expected}:
            raise GenerationError(
                f"Managed ModConfig {expected_identity} has unexpected {field}={data[field]!r}")
        data[field] = expected
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def is_exact_reloaded_semantic_transition(before: bytes, after: bytes,
                                           expected_identity: str) -> bool:
    """Recognize only Reloaded 1.31.0's observed managed metadata transition."""
    if expected_identity not in _LEGACY_SERIALIZER_DEFAULTS:
        return False
    try:
        original = json.loads(before.decode("utf-8"))
        observed = json.loads(after.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if (not isinstance(original, dict) or not isinstance(observed, dict)
            or original.get("ModId") != expected_identity):
        return False
    expected = dict(original)
    if expected.get("CanUnload") is not None or expected.get("HasExports") is not None:
        return False
    expected.update(CanUnload=False, HasExports=True)
    for key, value in _LEGACY_SERIALIZER_DEFAULTS[expected_identity].items():
        if key not in expected:
            expected[key] = value
    return observed == expected


def _normalized_artifact_input(evidence: VerifiedArtifactTree) -> dict:
    files = [{"path": item.path, "size": item.size, "sha256": item.sha256}
             for item in evidence.files]
    managed = next((identity for identity, artifact_id in MANAGED_ARTIFACTS.items()
                    if artifact_id == evidence.pin.artifact_id), None)
    if managed is not None:
        record = next((item for item in files if item["path"] == "ModConfig.json"), None)
        if record is None:
            raise GenerationError(f"Managed package {managed} lacks ModConfig.json evidence")
        payload = normalized_managed_mod_config(
            (evidence.root / "ModConfig.json").read_bytes(), managed)
        record.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    return {
        "artifact_id": evidence.pin.artifact_id,
        "archive_size": evidence.pin.size,
        "archive_sha256": evidence.pin.sha256,
        "content_identity": _artifact_tree_digest(files),
        "files": files,
    }


def verify_legacy_reloaded_normalization(root: Path,
                                         expected_generation_id: str | None = None) -> str:
    """Accept only the exact three-file normalization observed in production."""
    root = Path(root)
    manifest_path = root / "amethyst-generation.json"
    if root.is_symlink() or not root.is_dir() or manifest_path.is_symlink():
        raise GenerationError("Legacy generation root or manifest is missing or linked")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GenerationError(f"Legacy generation manifest is unreadable: {exc}") from exc
    manifest = _exact_dict(manifest, MANIFEST_FIELDS, "manifest")
    if (expected_generation_id is not None
            and manifest.get("generation_id") != expected_generation_id):
        raise GenerationError("Legacy generation identity differs")
    expected = {item["path"]: item for item in _valid_file_records(manifest["files"])}
    observed = {item["path"]: item for item in content_manifest(
        root, exclude=("amethyst-generation.json",))}
    if set(expected) != set(observed):
        raise GenerationError("Legacy generation contains missing or added files")
    changed = {path for path in expected if expected[path] != observed[path]}
    if changed != set(_LEGACY_RELOADED_NORMALIZATION):
        raise GenerationError("Generation drift is not the exact Reloaded normalization set")
    for relative, (before_hash, after_hash) in _LEGACY_RELOADED_NORMALIZATION.items():
        if (expected[relative]["sha256"] != before_hash
                or observed[relative]["sha256"] != after_hash):
            raise GenerationError(f"Unexpected Reloaded normalization at {relative}")
    return verify_private_generation(
        root, expected_generation_id, _allow_legacy_normalization=True)


def generation_identity(*, artifact_inputs: tuple[dict, ...], user_records: tuple[dict, ...],
                        windows_game_path: str, color_working_copy: dict | None = None, mod_working_copies: list | None = None) -> str:
    loader_record = next(item for item in artifact_inputs
                         if item["artifact_id"] == "nenkai-loader")
    loader = loader_pin_from_digest(loader_record["archive_sha256"])
    compatibility = {
        "compatibility_set": compatibility_set_for(loader),
        "artifact_inputs": artifact_inputs,
        "user_packages": user_records,
        "windows_game_path": windows_game_path,
    }
    if color_working_copy is not None:
        compatibility["color_working_copy"] = color_working_copy
    if mod_working_copies:
        compatibility["mod_working_copies"] = mod_working_copies
    digest = hashlib.sha256(json.dumps(
        compatibility, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"fftic-r2-{digest[:24]}"


def _exact_dict(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise GenerationError(f"Generation {label} schema is invalid")
    return value


def _valid_file_records(value: object) -> tuple[dict, ...]:
    if not isinstance(value, list):
        raise GenerationError("Generation file manifest is invalid")
    result = []
    seen = set()
    for item in value:
        item = _exact_dict(item, {"path", "size", "sha256"}, "file record")
        if (not isinstance(item["path"], str) or not isinstance(item["size"], int)
                or item["size"] < 0 or not isinstance(item["sha256"], str)
                or not _HASH.fullmatch(item["sha256"])):
            raise GenerationError("Generation file record is invalid")
        pure = PurePosixPath(item["path"])
        key = item["path"].casefold()
        if (pure.is_absolute() or "\\" in item["path"] or any(part in ("", ".", "..")
                for part in pure.parts) or key in seen):
            raise GenerationError("Generation file record path is unsafe or duplicated")
        seen.add(key)
        result.append(item)
    expected_order = sorted(result, key=lambda item: (item["path"].casefold(), item["path"]))
    if result != expected_order:
        raise GenerationError("Generation file records are not in canonical order")
    return tuple(result)


def verify_private_generation(root: Path, expected_generation_id: str | None = None,
                              *, _allow_legacy_normalization: bool = False) -> str:
    """Verify an already-published generation from its complete file manifest."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise GenerationError(f"Generation root is missing or linked: {root}")
    manifest_path = root / "amethyst-generation.json"
    if manifest_path.is_symlink():
        raise GenerationError(f"Generation manifest is a symbolic link: {root}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GenerationError(f"Generation manifest is unreadable: {root}: {exc}") from exc
    working = manifest.get("color_working_copy")
    bindings = manifest.get("mod_working_copies", [])
    manifest = _exact_dict(manifest, MANIFEST_FIELDS | ({"color_working_copy"} if working else set())
                           | ({"mod_working_copies"} if bindings else set()), "manifest")
    if manifest["schema_version"] not in {1, 2, 3} or not isinstance(manifest["generation_id"], str):
        raise GenerationError(f"Generation manifest schema is invalid: {root}")
    if manifest['schema_version'] != (3 if bindings else 2 if working else 1):
        raise GenerationError('Working-copy schema and binding disagree')
    _valid_file_records(manifest["files"])
    baseline = working_baseline(manifest)
    policies = {}
    policy = None
    if working:
        _exact_dict(working, {'profile', 'revision'}, 'working-copy binding')
        if (not isinstance(working['profile'], str) or not Path(working['profile']).is_absolute()
                or working['revision'] is not None and not _HASH.fullmatch(working['revision'])):
            raise GenerationError('Invalid working-copy profile/revision')
        _valid_file_records(manifest['files'])
        baseline = working_baseline(manifest)
        policy = ColorWorkingPolicy.from_baseline(baseline)
        policy.inspect(root, baseline)
        policies[_COLOR_ID] = policy
    if not isinstance(bindings, list):
        raise GenerationError('Invalid mod working-copy bindings')
    for binding in bindings:
        _exact_dict(binding, {'profile', 'revision', 'contract', 'transfer'}, 'mod working-copy binding')
        if (not isinstance(binding['profile'], str) or not Path(binding['profile']).is_absolute()
                or binding['revision'] is not None and not _HASH.fullmatch(binding['revision'])):
            raise GenerationError('Invalid mod working-copy profile/revision')
        contract = binding['contract']
        policy = ModWorkingPolicy(contract, baseline)
        if contract['mod_id'] in policies:
            raise GenerationError('Duplicate working-copy identity')
        config = json.loads((root / policy.mod / 'ModConfig.json').read_text())
        expected_metadata = {'mod_id': config.get('ModId'), 'version': config.get('ModVersion'),
            'applications': config.get('SupportedAppId', []), 'dependencies': config.get('ModDependencies', []),
            'optional_dependencies': config.get('OptionalDependencies', []),
            'entry_points': [[k, config[k]] for k in ('ModDll', 'ModR2RManagedDll32', 'ModR2RManagedDll64',
                             'ModNativeDll32', 'ModNativeDll64') if config.get(k)]}
        if any(contract.get(k) != v for k, v in expected_metadata.items()):
            raise GenerationError('Working-copy metadata differs from immutable manifest')
        if binding['transfer'] is not None:
            transfer = _exact_dict(binding['transfer'], {'contract', 'revision'}, 'version transfer')
            if not _HASH.fullmatch(transfer['revision']) or transfer['contract']['mod_id'] != contract['mod_id']:
                raise GenerationError('Invalid version transfer identity')
        policy.inspect(root, baseline)
        policies[contract['mod_id']] = policy
    if bindings != sorted(bindings, key=lambda b: b['contract']['mod_id']):
        raise GenerationError('Working-copy bindings are not canonical')
    try:
        loader_record = next(item for item in manifest["artifact_inputs"]
                             if item["artifact_id"] == "nenkai-loader")
        selected_loader = loader_pin_from_digest(loader_record["archive_sha256"])
    except (KeyError, StopIteration, TypeError, ValueError):
        raise GenerationError("Generation loader identity is invalid")
    if manifest["compatibility_set"] != compatibility_set_for(selected_loader):
        raise GenerationError(f"Generation compatibility metadata is not the reviewed set: {root}")
    if manifest["components"] != component_versions_for(selected_loader):
        raise GenerationError(f"Generation component versions are not the reviewed set: {root}")
    if manifest["managed_packages"] != list(MANAGED_ORDER):
        raise GenerationError(f"Generation managed package identities are invalid: {root}")
    artifacts = manifest["artifact_inputs"]
    users = manifest["user_packages"]
    configuration = _exact_dict(manifest["configuration"],
                                {"windows_game_path", "hashes"}, "configuration")
    if (not isinstance(artifacts, list) or not isinstance(users, list)
            or not isinstance(configuration["windows_game_path"], str)
            or not isinstance(configuration["hashes"], dict)):
        raise GenerationError(f"Generation identity inputs are invalid: {root}")
    expected_artifact_ids = {"reloaded-ii", *MANAGED_ARTIFACTS.values()}
    artifact_ids = []
    for item in artifacts:
        item = _exact_dict(item, {"artifact_id", "archive_size", "archive_sha256",
                                  "content_identity", "files"}, "artifact input")
        artifact_id = item["artifact_id"]
        if artifact_id not in expected_artifact_ids:
            raise GenerationError("Generation artifact input identity is invalid")
        pin = selected_loader if artifact_id == "nenkai-loader" else ARTIFACTS[artifact_id]
        if (item["archive_size"] != pin.size or item["archive_sha256"] != pin.sha256
                or not isinstance(item["content_identity"], str)
                or not _HASH.fullmatch(item["content_identity"])):
            raise GenerationError("Generation artifact input metadata is invalid")
        artifact_files = _valid_file_records(item["files"])
        if _artifact_tree_digest(artifact_files) != item["content_identity"]:
            raise GenerationError("Generation artifact content identity is not reproducible")
        base = root if artifact_id == "reloaded-ii" else root / "Mods" / next(
            identity for identity, mapped in MANAGED_ARTIFACTS.items() if mapped == artifact_id)
        for record in artifact_files:
            target = base / record["path"]
            exact = (not target.is_symlink() and target.is_file()
                     and target.stat().st_size == record["size"]
                     and _sha256(target) == record["sha256"])
            relative = target.relative_to(root).as_posix()
            transition = _LEGACY_RELOADED_NORMALIZATION.get(relative)
            legacy_exact = bool(
                _allow_legacy_normalization and transition
                and record["sha256"] == transition[0]
                and target.is_file() and not target.is_symlink()
                and _sha256(target) == transition[1])
            if not exact and not legacy_exact:
                raise GenerationError(f"Generation artifact content is incomplete: {artifact_id}")
        artifact_ids.append(artifact_id)
    if set(artifact_ids) != expected_artifact_ids or len(artifact_ids) != len(set(artifact_ids)):
        raise GenerationError("Generation artifact input set is incomplete or duplicated")
    if artifact_ids != sorted(artifact_ids):
        raise GenerationError("Generation artifact inputs are not in canonical order")
    user_ids = set()
    managed_ids = {identity.casefold() for identity in MANAGED_ORDER}
    for item in users:
        item = _exact_dict(item, {"mod_id", "enabled", "priority", "classification",
                                  "content_manifest_sha256"}, "user package")
        if (not isinstance(item["mod_id"], str) or not isinstance(item["enabled"], bool)
                or type(item["priority"]) is not int or not isinstance(item["classification"], str)
                or not isinstance(item["content_manifest_sha256"], str)
                or not _HASH.fullmatch(item["content_manifest_sha256"])):
            raise GenerationError("Generation user package metadata is invalid")
        key = item["mod_id"].casefold()
        if key in user_ids or key in managed_ids:
            raise GenerationError("Generation user package identities overlap or are duplicated")
        user_ids.add(key)
        package = root / "Mods" / item["mod_id"]
        if package.is_symlink() or not package.is_dir():
            raise GenerationError(f"Generation user package root is missing or linked: {package}")
        prefix = f"Mods/{item['mod_id']}/"
        records = (tuple(dict(path=p[len(prefix):], size=v[0], sha256=v[1])
                         for p, v in sorted(baseline[0].items(), key=lambda item: (item[0].casefold(), item[0]))
                         if p.startswith(prefix))
                   if item['mod_id'] in policies else content_manifest(package))
        if manifest_digest(records) != item["content_manifest_sha256"]:
            raise GenerationError(f"Generation user package content identity changed: {item['mod_id']}")
    if not set(policies) <= {item['mod_id'] for item in users}:
        raise GenerationError('Working-copy binding has no matching package')
    if users != sorted(users, key=lambda item: (item["priority"], item["mod_id"].casefold())):
        raise GenerationError("Generation user packages are not in canonical order")
    expected_config_paths = {
        "Apps/fft_classic.exe/AppConfig.json", "Apps/fft_enhanced.exe/AppConfig.json"}
    if set(configuration["hashes"]) != expected_config_paths:
        raise GenerationError("Generation configuration identity set is invalid")
    try:
        fixture_mods = tuple(UserMod(
            item["mod_id"], root / "Mods" / item["mod_id"],
            PackageClassification(item["classification"]),
            item["enabled"], item["priority"],
        ) for item in users)
        regenerated = generate_reloaded_configuration(
            private_generation_root=root.resolve(),
            windows_game_path=ValidatedSteamPath.from_resolver(configuration["windows_game_path"]),
            managed_package_locations={identity: (root / "Mods" / identity).resolve()
                                       for identity in MANAGED_ORDER},
            user_mods=fixture_mods,
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise GenerationError(f"Generation configuration inputs are invalid: {exc}") from exc
    regenerated_hashes = {
        relative: hashlib.sha256(payload).hexdigest()
        for relative, payload in regenerated.files.items()
        if relative.endswith("AppConfig.json")
    }
    if configuration["hashes"] != regenerated_hashes:
        raise GenerationError("Generation configuration identity is not reproducible")
    recomputed = generation_identity(
        artifact_inputs=tuple(artifacts), user_records=tuple(users),
        windows_game_path=configuration["windows_game_path"], color_working_copy=working, mod_working_copies=bindings)
    if recomputed != manifest["generation_id"]:
        raise GenerationError(f"Generation declared identity is not reproducible: {root}")
    if expected_generation_id is not None and manifest["generation_id"] != expected_generation_id:
        raise GenerationError(f"Generation identity mismatch at {root}")
    expected = _valid_file_records(manifest["files"])
    observed = content_manifest(root, exclude=("amethyst-generation.json",))
    if policies:
        expected = tuple(record for record in expected if not any(p.mutable(record['path']) for p in policies.values()))
        observed = tuple(record for record in observed if not any(p.mutable(record['path']) for p in policies.values()))
    if tuple(expected) != observed:
        if not _allow_legacy_normalization:
            raise GenerationError(f"Generation content drift or incompleteness detected: {root}")
        expected_by_path = {item["path"]: item for item in expected}
        observed_by_path = {item["path"]: item for item in observed}
        changed = {path for path in expected_by_path
                   if expected_by_path.get(path) != observed_by_path.get(path)}
        if (set(expected_by_path) != set(observed_by_path)
                or changed != set(_LEGACY_RELOADED_NORMALIZATION)
                or any(expected_by_path[path]["sha256"] != hashes[0]
                       or observed_by_path[path]["sha256"] != hashes[1]
                       for path, hashes in _LEGACY_RELOADED_NORMALIZATION.items())):
            raise GenerationError(
                f"Generation drift is not the exact Reloaded normalization: {root}")
    if (root / "ReloadedPortable.txt").exists() or not (root / "portable.txt").is_file():
        raise GenerationError(f"Generation portable marker is invalid: {root}")
    for relative, expected_hash in configuration["hashes"].items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str) or not _HASH.fullmatch(expected_hash):
            raise GenerationError("Generation configuration hashes are invalid")
        target = root / relative
        if not target.is_file() or _sha256(target) != expected_hash:
            raise GenerationError(f"Generation configuration identity mismatch: {relative}")
    return _sha256(manifest_path)


def build_private_generation(
    *,
    generations_root: Path,
    verified_inputs: dict[str, VerifiedArtifactTree],
    user_mods: tuple[UserMod, ...],
    windows_game_path: ValidatedSteamPath,
    cancel=None,
    previous_generation: str | None = None,
    failure_injector=None,
    color_working_copy: dict | None = None,
    color_store=None,
    mod_working_copies=None,
    mod_stores=None,
    transfer_stores=None,
) -> GenerationResult:
    """Publish the reviewed runtime and isolated per-profile user-mod working copies."""
    expected_ids = {"reloaded-ii", *MANAGED_ARTIFACTS.values()}
    validate_user_dependencies(user_mods)
    if set(verified_inputs) != expected_ids:
        raise GenerationError("All and only the reviewed verified artifact trees are required")
    for artifact_id, evidence in verified_inputs.items():
        expected_pin = (loader_pin(evidence.pin.version) if artifact_id == "nenkai-loader"
                        else ARTIFACTS[artifact_id])
        if not isinstance(evidence, VerifiedArtifactTree) or evidence.pin != expected_pin:
            raise GenerationError(f"Artifact {artifact_id} lacks reviewed extraction provenance")
        try:
            evidence.revalidate()
        except Exception as exc:
            raise GenerationError(f"Artifact {artifact_id} provenance failed revalidation: {exc}") from exc
    reloaded_root = verified_inputs["reloaded-ii"].root
    canonical: dict[str, Path] = {}
    identities: dict[str, str] = {}
    for expected in MANAGED_ORDER:
        package = verified_inputs[MANAGED_ARTIFACTS[expected]].root
        observed = _managed_identity(package)
        if observed.casefold() != expected.casefold():
            raise GenerationError(f"Managed package identity mismatch: expected {expected}, found {observed}")
        if observed.casefold() in identities:
            raise GenerationError(f"Duplicate managed package ID: {observed}")
        identities[observed.casefold()] = observed
        canonical[expected] = package

    artifact_inputs = tuple(
        _normalized_artifact_input(evidence)
        for _artifact_id, evidence in sorted(verified_inputs.items()))

    user_records = tuple({
        "mod_id": mod.mod_id,
        "enabled": mod.enabled,
        "priority": mod.amethyst_priority,
        "classification": mod.classification.value,
        "content_manifest_sha256": manifest_digest(content_manifest(mod.package_location)),
    } for mod in sorted(user_mods, key=lambda value: (value.amethyst_priority, value.mod_id.casefold())))
    has_color = bool(color_working_copy)
    mod_working_copies = mod_working_copies or []
    mod_stores = mod_stores or {}
    transfer_stores = transfer_stores or {}
    expected_working = set()
    for mod in user_mods:
        inspected = inspect_package(mod.package_location)
        if not inspected.is_user_content or inspected.manifest is None:
            raise GenerationError(f'Invalid user package: {mod.mod_id}: {inspected.diagnostics}')
        if inspected.manifest.managed_native_declarations:
            expected_working.add(mod.mod_id)
    if expected_working != set(mod_stores) | ({_COLOR_ID} if has_color else set()):
        raise GenerationError("Managed user mods require their per-profile working-state contracts")
    if set(mod_stores) != {b["contract"]["mod_id"] for b in mod_working_copies}:
        raise GenerationError("Working stores and bindings differ")
    for binding in mod_working_copies:
        key = binding["contract"]["mod_id"]
        store = mod_stores[key]
        mod = next(m for m in user_mods if m.mod_id == key)
        head = store.head()
        if (binding["contract"] != contract_for(mod.package_location)
                or binding["contract"] != store.policy.contract
                or Path(binding["profile"]) != store.profile
                or binding["revision"] != (head["revision"] if head else None)):
            raise GenerationError("Working-state binding does not belong to package/profile/head")
        transfer = transfer_stores.get(key)
        if binding["transfer"] != ({"contract": transfer.policy.contract, "revision": transfer.head()["revision"]} if transfer else None):
            raise GenerationError("Version transfer binding differs")
    if has_color != bool(color_working_copy) or has_color != bool(color_store):
        raise GenerationError('Color Customizer requires a profile-owned working copy')
    if has_color:
        _exact_dict(color_working_copy, {'profile', 'revision'}, 'working-copy binding')
        head = color_store.head()
        if (Path(color_working_copy['profile']) != color_store.profile
                or color_working_copy['revision'] != (head['revision'] if head else None)):
            raise GenerationError('Working-copy restoration does not belong to its profile/head')
    generation_id = generation_identity(
        artifact_inputs=artifact_inputs, user_records=user_records,
        windows_game_path=windows_game_path.value, color_working_copy=color_working_copy, mod_working_copies=mod_working_copies)
    generations_root = Path(generations_root)
    generations_root.mkdir(parents=True, exist_ok=True)
    final = generations_root / generation_id
    if os.path.lexists(final):
        if final.is_symlink() or not final.is_dir():
            raise GenerationError(f"Existing generation target is not an owned directory: {final}")
        digest = verify_private_generation(final, generation_id)
        return GenerationResult(generation_id, final, digest, previous_generation)
    stage = Path(tempfile.mkdtemp(prefix=f".{generation_id}.build-", dir=generations_root))
    inject = failure_injector or (lambda _stage: None)
    try:
        # mkdtemp creates the root; copy its contents without overlaying another generation.
        for child in sorted(Path(reloaded_root).iterdir(), key=lambda value: value.name.casefold()):
            if cancel is not None and cancel.is_set():
                raise GenerationError("Generation assembly cancelled")
            if child.is_symlink():
                raise GenerationError(f"Reloaded source contains a symlink: {child}")
            target = stage / child.name
            if child.is_dir():
                _copy_tree_exact(child, target, cancel)
            elif child.is_file():
                shutil.copyfile(child, target)
            else:
                raise GenerationError(f"Reloaded source contains a special file: {child}")
        _verify_copied_evidence(stage, verified_inputs["reloaded-ii"])
        for required in (
            "Reloaded-II.exe", "Loader/Asi/UltimateAsiLoader.7z",
            "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll",
            "Loader/X64/Reloaded.Mod.Loader.dll",
        ):
            if not (stage / required).is_file():
                raise GenerationError(f"Reloaded source is missing required member {required}")
        bootstrap_pin = INTERNAL_FILES["reloaded-bootstrapper-asi"]
        verify_internal_file(
            stage / "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll",
            size=bootstrap_pin.size, sha256=bootstrap_pin.sha256)
        nested = stage / "Loader/Asi/UltimateAsiLoader.7z"
        if nested.stat().st_size != NESTED_ASI_ARCHIVE_SIZE or _sha256(nested) != NESTED_ASI_ARCHIVE_SHA256:
            raise GenerationError("Reloaded internal Ultimate ASI archive identity is invalid")
        nested_root = stage / ".amethyst-asi-check"
        extracted_nested = extract_archive(
            nested, nested_root, cancel=cancel,
            required_members=("ASILoader64.dll",),
            limits=ExtractionLimits(2, 9_029_424, 5_413_776))
        asi_pin = INTERNAL_FILES["version-dll"]
        verify_internal_file(extracted_nested.root / "ASILoader64.dll",
                             size=asi_pin.size, sha256=asi_pin.sha256)
        shutil.rmtree(nested_root)
        if (stage / "ReloadedPortable.txt").exists():
            raise GenerationError("ReloadedPortable.txt must not exist in the private generation")
        (stage / "portable.txt").write_bytes(b"")
        (stage / "Mods").mkdir(exist_ok=True)
        managed_locations: dict[str, Path] = {}
        for identity in MANAGED_ORDER:
            target = stage / "Mods" / identity
            if target.exists():
                raise GenerationError(f"Reloaded archive unexpectedly contains managed package {identity}")
            _copy_tree_exact(canonical[identity], target, cancel)
            _verify_copied_evidence(target, verified_inputs[MANAGED_ARTIFACTS[identity]])
            config = target / "ModConfig.json"
            config.write_bytes(normalized_managed_mod_config(config.read_bytes(), identity))
            managed_locations[identity] = target.resolve()
        snapshots: list[UserMod] = []
        (stage / "User" / "Mods").mkdir(parents=True, exist_ok=True)
        for mod in user_mods:
            inspected = inspect_package(mod.package_location)
            if not inspected.is_user_content or inspected.manifest is None:
                diagnostic = inspected.diagnostics[0] if inspected.diagnostics else inspected.classification.value
                raise GenerationError(f"Mod {mod.mod_id} at {mod.package_location} blocked synchronization: {diagnostic}")
            if inspected.manifest.mod_id.casefold() != mod.mod_id.casefold():
                raise GenerationError(f"Mod {mod.mod_id} identity changed at {mod.package_location}")
            target = stage / "Mods" / mod.mod_id
            _copy_tree_exact(mod.package_location, target, cancel)
            snapshots.append(UserMod(mod.mod_id, target.resolve(), inspected.classification,
                                     mod.enabled, mod.amethyst_priority))
        generated = generate_reloaded_configuration(
            private_generation_root=stage.resolve(), windows_game_path=windows_game_path,
            managed_package_locations=managed_locations,
            user_mods=tuple(snapshots),
        )
        for relative, payload in generated.files.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and relative != "portable.txt":
                raise GenerationError(f"Reloaded archive collides with generated configuration: {relative}")
            target.write_bytes(payload)
        records = content_manifest(stage, exclude=("amethyst-generation.json",))
        configuration_hashes = {
            relative: hashlib.sha256(payload).hexdigest()
            for relative, payload in generated.files.items()
            if relative.endswith("AppConfig.json")
        }
        manifest = {
            "schema_version": 3 if mod_working_copies else 2 if has_color else 1,
            **({"mod_working_copies": mod_working_copies} if mod_working_copies else {}),
            **({"color_working_copy": color_working_copy} if has_color else {}),
            "generation_id": generation_id,
            "components": component_versions_for(verified_inputs["nenkai-loader"].pin),
            "compatibility_set": compatibility_set_for(verified_inputs["nenkai-loader"].pin),
            "artifact_inputs": list(artifact_inputs),
            "managed_packages": list(MANAGED_ORDER),
            "user_packages": list(user_records),
            "configuration": {
                "windows_game_path": windows_game_path.value,
                "hashes": configuration_hashes,
            },
            "files": list(records),
        }
        manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
        (stage / "amethyst-generation.json").write_bytes(manifest_bytes)
        if has_color and color_working_copy['revision'] is not None:
            verify_private_generation(stage, generation_id)
            baseline = working_baseline(manifest)
            policy = ColorWorkingPolicy.from_baseline(baseline)
            snapshot, payload = color_store.read(color_working_copy['revision'])
            policy.check_migration(snapshot)
            policy.restore(snapshot, payload, stage, baseline)
            policy.migrate_private_copy(stage)
        for binding in mod_working_copies:
            key = binding['contract']['mod_id']
            baseline = working_baseline(manifest)
            policy = ModWorkingPolicy(binding['contract'], baseline)
            if binding['revision'] is not None:
                snapshot, payload = mod_stores[key].read(binding['revision'])
                policy.restore(snapshot, payload, stage, baseline)
            elif key in transfer_stores:
                transition_copy(transfer_stores[key], policy, stage)
        verify_private_generation(stage, generation_id)
        inject("before_publish")
        _fsync_tree(stage)
        os.replace(stage, final)
        parent_fd = os.open(generations_root, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return GenerationResult(
            generation_id, final, hashlib.sha256(manifest_bytes).hexdigest(), previous_generation)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def read_profile_mods(profile_dir: Path, staging_root: Path) -> tuple[UserMod, ...]:
    """Translate Amethyst's existing modlist API into validated FFTIC packages."""
    from Utils.mods.modlist import read_modlist
    profile_dir, staging_root = Path(profile_dir), Path(staging_root)
    staging_resolved = staging_root.resolve()
    result: list[UserMod] = []
    seen: dict[str, str] = {}
    for priority, entry in enumerate(read_modlist(profile_dir / "modlist.txt")):
        if entry.is_separator:
            continue
        if (not entry.name or entry.name in (".", "..") or "/" in entry.name
                or "\\" in entry.name or "\x00" in entry.name):
            raise GenerationError(f"Modlist entry has an unsafe folder name: {entry.name!r}")
        package = staging_root / entry.name
        try:
            package_resolved = package.resolve(strict=True)
        except OSError:
            package_resolved = package.resolve()
        if (not package_resolved.is_relative_to(staging_resolved)
                or package.is_symlink() or not package.is_dir()):
            raise GenerationError(f"Mod {entry.name} is missing or linked at {package}")
        inspected = inspect_package(package)
        if not inspected.is_user_content or inspected.manifest is None:
            diagnostic = inspected.diagnostics[0] if inspected.diagnostics else inspected.classification.value
            raise GenerationError(f"Mod {entry.name} at {package} blocked synchronization: {diagnostic}")
        identity = inspected.manifest.mod_id
        prior = seen.get(identity.casefold())
        if prior is not None:
            raise GenerationError(f"Duplicate FFTIC mod ID {identity!r} in {prior!r} and {entry.name!r}")
        seen[identity.casefold()] = entry.name
        result.append(UserMod(identity, package_resolved, inspected.classification,
                              entry.enabled, priority))
    validate_user_dependencies(tuple(result))
    return tuple(result)


def validate_user_dependencies(mods: tuple[UserMod, ...]) -> None:
    """Require enabled dependencies in each applicable FFTIC application."""
    by_id = {mod.mod_id.casefold(): mod for mod in mods}
    if len(by_id) != len(mods):
        raise GenerationError("Duplicate FFTIC user mod IDs")
    internal = {identity.casefold() for identity in MANAGED_ORDER}
    for mod in mods:
        if not mod.enabled:
            continue
        inspected = inspect_package(mod.package_location)
        if not inspected.is_user_content or inspected.manifest is None:
            raise GenerationError(f"Mod {mod.mod_id} at {mod.package_location} is no longer valid")
        for mode in (Mode.CLASSIC, Mode.ENHANCED):
            if not _compatible(mod.classification, mode):
                continue
            for dependency in inspected.manifest.dependencies:
                key = dependency.casefold()
                target = by_id.get(key)
                if key not in internal and (target is None or not target.enabled
                        or not _compatible(target.classification, mode)):
                    raise GenerationError(
                        f"{inspected.manifest.name} ({mod.mod_id}) at {mod.package_location}: "
                        f"required dependency {dependency!r} is missing, disabled, or "
                        f"incompatible with {mode.value}.")
