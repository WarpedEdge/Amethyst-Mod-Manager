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
    from .fftic_artifacts import ARTIFACTS, INTERNAL_FILES
    from .fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from .fftic_packages import PackageClassification, inspect_package
    from .fftic_reloaded_config import (
        MANAGED_ORDER, UserMod, ValidatedSteamPath,
        generate_reloaded_configuration,
    )
    from .fftic_extraction import (
        ExtractionLimits, VerifiedArtifactTree, extract_archive, verify_internal_file,
    )
except ImportError:
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES
    from fftic_detection import VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION
    from fftic_packages import PackageClassification, inspect_package
    from fftic_reloaded_config import (
        MANAGED_ORDER, UserMod, ValidatedSteamPath,
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
MANAGED_ARTIFACTS = {
    "Reloaded.Memory.SigScan.ReloadedII": "sigscan",
    "reloaded.sharedlib.hooks": "shared-hooks",
    "fftivc.utility.modloader": "nenkai-loader",
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


def generation_identity(*, artifact_inputs: tuple[dict, ...], user_records: tuple[dict, ...],
                        windows_game_path: str) -> str:
    compatibility = {
        "compatibility_set": COMPATIBILITY_SET,
        "artifact_inputs": artifact_inputs,
        "user_packages": user_records,
        "windows_game_path": windows_game_path,
    }
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


def verify_private_generation(root: Path, expected_generation_id: str | None = None) -> str:
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
    manifest = _exact_dict(manifest, MANIFEST_FIELDS, "manifest")
    if manifest["schema_version"] != 1 or not isinstance(manifest["generation_id"], str):
        raise GenerationError(f"Generation manifest schema is invalid: {root}")
    if manifest["compatibility_set"] != COMPATIBILITY_SET:
        raise GenerationError(f"Generation compatibility metadata is not the reviewed set: {root}")
    if manifest["components"] != COMPONENT_VERSIONS:
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
        pin = ARTIFACTS[artifact_id]
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
            if (target.is_symlink() or not target.is_file()
                    or target.stat().st_size != record["size"]
                    or _sha256(target) != record["sha256"]):
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
        if manifest_digest(content_manifest(package)) != item["content_manifest_sha256"]:
            raise GenerationError(f"Generation user package content identity changed: {item['mod_id']}")
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
        windows_game_path=configuration["windows_game_path"])
    if recomputed != manifest["generation_id"]:
        raise GenerationError(f"Generation declared identity is not reproducible: {root}")
    if expected_generation_id is not None and manifest["generation_id"] != expected_generation_id:
        raise GenerationError(f"Generation identity mismatch at {root}")
    expected = _valid_file_records(manifest["files"])
    observed = content_manifest(root, exclude=("amethyst-generation.json",))
    if tuple(expected) != observed:
        raise GenerationError(f"Generation content drift or incompleteness detected: {root}")
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
) -> GenerationResult:
    """Build and atomically publish a complete immutable generation."""
    expected_ids = {"reloaded-ii", *MANAGED_ARTIFACTS.values()}
    if set(verified_inputs) != expected_ids:
        raise GenerationError("All and only the reviewed verified artifact trees are required")
    for artifact_id, evidence in verified_inputs.items():
        if not isinstance(evidence, VerifiedArtifactTree) or evidence.pin != ARTIFACTS[artifact_id]:
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

    artifact_inputs = tuple({
        "artifact_id": artifact_id,
        "archive_size": evidence.pin.size,
        "archive_sha256": evidence.pin.sha256,
        "content_identity": evidence.content_identity,
        "files": [{"path": item.path, "size": item.size, "sha256": item.sha256}
                  for item in evidence.files],
    } for artifact_id, evidence in sorted(verified_inputs.items()))

    user_records = tuple({
        "mod_id": mod.mod_id,
        "enabled": mod.enabled,
        "priority": mod.amethyst_priority,
        "classification": mod.classification.value,
        "content_manifest_sha256": manifest_digest(content_manifest(mod.package_location)),
    } for mod in sorted(user_mods, key=lambda value: (value.amethyst_priority, value.mod_id.casefold())))
    generation_id = generation_identity(
        artifact_inputs=artifact_inputs, user_records=user_records,
        windows_game_path=windows_game_path.value)
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
            "schema_version": 1,
            "generation_id": generation_id,
            "components": COMPONENT_VERSIONS,
            "compatibility_set": COMPATIBILITY_SET,
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
    return tuple(result)
