"""Isolated Phase C2 lifecycle checks. No live Amethyst, Steam, or game paths."""

from __future__ import annotations

import hashlib
import io
import json
import os
import copy
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from dataclasses import replace
from pathlib import Path

_SANDBOX = tempfile.TemporaryDirectory(prefix="amethyst-fftic-c2-")
ROOT = Path(_SANDBOX.name).resolve()
for name in ("config", "data", "cache", "profiles", "steam", "game", "prefix",
             "generations", "receipts", "quarantine", "logs"):
    (ROOT / name).mkdir()
os.environ["XDG_CONFIG_HOME"] = str(ROOT / "config")
os.environ["XDG_DATA_HOME"] = str(ROOT / "data")
os.environ["XDG_CACHE_HOME"] = str(ROOT / "cache")
os.environ["MOD_MANAGER_PROFILES_DIR"] = str(ROOT / "profiles")

SRC = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))
sys.path.append(str(HERE))

from fftic_artifact_service import (  # noqa: E402
    ArtifactCancelled, ArtifactError, acquire_artifact,
)
import fftic_extraction as extraction_module  # noqa: E402
from fftic_artifacts import ARTIFACTS, INTERNAL_FILES  # noqa: E402
from fftic_detection import (  # noqa: E402
    InstallStatus, InstallationDetection, VERIFIED_HASHES,
    VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
)
from fftic_extraction import (  # noqa: E402
    ArchiveMember, ExtractionError, ExtractionLimits, extract_archive,
    extract_verified_artifact, validate_archive_members, verify_internal_file,
)
from fftic_generation import (  # noqa: E402
    MANAGED_ARTIFACTS, GenerationError, build_private_generation, content_manifest, manifest_digest,
    is_exact_reloaded_semantic_transition, normalized_managed_mod_config,
    read_profile_mods, verify_private_generation,
)
from fftic_lifecycle import LifecycleState, compose_lifecycle_status  # noqa: E402
from fftic_packages import (  # noqa: E402
    CLASSIC_APP_ID, ENHANCED_APP_ID, PackageClassification,
)
from fftic_pac import (  # noqa: E402
    PacLaunchEvidence, PacOwnershipState, capture_generated_pacs,
    capture_pac_baseline, pac_ownership,
)
from fftic_prerequisites import (  # noqa: E402
    DOTNET_COMPONENT, VC_COMPONENT, PrefixPrerequisites, PrerequisiteState, classify_prerequisite,
    inspect_prefix_prerequisites, plan_installer,
)
from fftic_receipts import (  # noqa: E402
    PREFIX_CONFIGURATION_PATH, Receipt, ReceiptCorruptError, read_receipt,
    serialize_receipt, validate_receipt, write_receipt,
)
from fftic_readiness import (  # noqa: E402
    SUPPORTED_PROTON_RUNNER, ReadinessAspect, ReadinessEvidence,
    ReadinessVerification, profile_fingerprint, verify_launch_readiness,
)
from fftic_reloaded_config import (  # noqa: E402
    MANAGED_ORDER, ValidatedSteamPath, ValidatedWindowsGenerationPath,
    generate_bootstrap_configuration,
)
from fftic_steam_path import (  # noqa: E402
    SteamPathError, resolve_prefix_generation_path, resolve_steam_s_path,
)
from fftic_steam_requirements import (  # noqa: E402
    COPY_READY_OPTIONS, REQUIRED_OPTIONS_SHA256, SteamOptionsStatus,
    analyze_steam_launch_options,
)
from fftic_transaction_executor import (  # noqa: E402
    FileTransactionJournal, FfticTransactionExecutor, TransactionCancelled,
    TransactionDrift, TransactionError,
    activate_generation, file_sha256,
)
from fftic_transactions import TargetObservation, plan_owned_file_install  # noqa: E402


def _pin(payload: bytes, filename: str = "artifact.bin"):
    return replace(
        ARTIFACTS["reloaded-ii"], filename=filename,
        url="https://example.invalid/pinned/artifact.bin", size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest())


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, *, url="https://cdn.example.invalid/artifact.bin",
                 length: int | None = None):
        super().__init__(payload)
        self.url = url
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class _Transport:
    def __init__(self, factory):
        self.factory = factory
        self.calls = 0

    def open(self, url):
        self.calls += 1
        return self.factory(url)


class _Journal:
    durable = True

    def __init__(self, hook=None):
        self.records = []
        self.hook = hook

    def record(self, **values):
        self.records.append(values)
        if self.hook:
            self.hook(values)


def test_artifact_acquisition() -> None:
    payload = b"reviewed artifact bytes"
    pin = _pin(payload)
    cache = ROOT / "cache" / "artifacts"
    transport = _Transport(lambda _url: _Response(payload, length=len(payload)))
    progress = []
    first = acquire_artifact(pin, cache, transport=transport,
                             progress=lambda *values: progress.append(values))
    assert not first.reused and first.path.read_bytes() == payload and progress
    second = acquire_artifact(pin, cache, transport=transport)
    assert second.reused and transport.calls == 1

    cases = (
        (b"short", len(payload), "truncated"),
        (payload + b"oversized", None, "exceeded"),
        (b"x" * len(payload), len(payload), "SHA-256"),
        (payload, len(payload) + 1, "declared"),
    )
    for index, (body, length, message) in enumerate(cases):
        local_pin = replace(pin, filename=f"bad-{index}.bin")
        try:
            acquire_artifact(local_pin, cache,
                             transport=_Transport(lambda _url, b=body, n=length: _Response(b, length=n)))
        except ArtifactError as exc:
            assert message in str(exc)
        else:
            raise AssertionError(f"Acquisition case {index} was accepted")
        assert not (cache / local_pin.filename).exists()

    cancel = threading.Event()
    cancel.set()
    try:
        acquire_artifact(replace(pin, filename="cancel.bin"), cache,
                         transport=_Transport(lambda _url: _Response(payload)), cancel=cancel)
    except ArtifactCancelled:
        pass
    else:
        raise AssertionError("Cancelled download was accepted")

    interrupted = cache / f".{pin.filename}.part-stale"
    interrupted.write_bytes(b"partial")
    acquire_artifact(pin, cache, transport=transport)
    assert not interrupted.exists()
    # Force a re-download under another filename so stale processing is tested.
    interrupted_pin = replace(pin, filename="interrupted.bin")
    stale = cache / ".interrupted.bin.part-stale"
    stale.write_bytes(b"partial")
    acquire_artifact(interrupted_pin, cache,
                     transport=_Transport(lambda _url: _Response(payload)))
    assert not stale.exists() and any((cache / "quarantine").glob("*.interrupted.*"))

    redirected = replace(pin, filename="redirect.bin")
    try:
        acquire_artifact(redirected, cache,
                         transport=_Transport(lambda _url: _Response(payload, url="http://bad.test/file")))
    except ArtifactError as exc:
        assert "not HTTPS" in str(exc)
    else:
        raise AssertionError("Insecure redirect was accepted")

    mismatch = replace(pin, filename="mismatch.bin")
    (cache / mismatch.filename).write_bytes(b"foreign")
    acquired = acquire_artifact(mismatch, cache,
                                transport=_Transport(lambda _url: _Response(payload)))
    assert acquired.path.read_bytes() == payload
    assert any((cache / "quarantine").glob("mismatch.bin.mismatch.*"))
    assert not list(cache.glob("*.part-*"))


def _zip(path: Path, entries: dict[str, bytes], *, symlink: str | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "target")


def test_safe_extraction() -> None:
    archive = ROOT / "cache" / "safe.zip"
    _zip(archive, {"folder/file.txt": b"safe", "root.bin": b"root"})
    result = extract_archive(archive, ROOT / "data" / "safe-extract",
                             required_members=("folder/file.txt",))
    assert result.files == ("folder/file.txt", "root.bin")
    assert (result.root / "folder/file.txt").read_bytes() == b"safe"
    pinned = _pin(archive.read_bytes(), "safe.zip")
    verified = extract_verified_artifact(
        pinned, archive, ROOT / "data" / "verified-safe",
        required_members=("folder/file.txt",), limits=ExtractionLimits(2, 8, 4))
    verified.revalidate()
    (verified.root / "root.bin").write_bytes(b"evil")
    try:
        verified.revalidate()
    except ExtractionError as exc:
        assert "tree changed" in str(exc)
    else:
        raise AssertionError("Modified extracted tree retained verified provenance")

    for limits in (ExtractionLimits(1, 8, 4), ExtractionLimits(2, 7, 4),
                   ExtractionLimits(2, 8, 3)):
        target = ROOT / "data" / f"limited-{limits.member_count}-{limits.total_expanded_size}-{limits.largest_member_size}"
        try:
            extract_archive(archive, target, limits=limits)
        except ExtractionError:
            pass
        else:
            raise AssertionError("Archive expansion bound was ignored")

    changed = ROOT / "cache" / "identity-change.zip"
    shutil.copyfile(archive, changed)
    changed_pin = _pin(changed.read_bytes(), changed.name)
    changed.write_bytes(changed.read_bytes() + b"replacement")
    try:
        extract_verified_artifact(changed_pin, changed, ROOT / "data" / "changed",
                                  limits=ExtractionLimits(2, 8, 4))
    except ExtractionError as exc:
        assert "pinned identity" in str(exc)
    else:
        raise AssertionError("Changed archive identity was accepted")

    cancel = threading.Event()
    cancel.set()
    cancelled_destination = ROOT / "data" / "cancelled-extraction"
    try:
        extract_archive(archive, cancelled_destination, cancel=cancel,
                        limits=ExtractionLimits(2, 8, 4))
    except Exception as exc:
        assert "cancelled" in str(exc).casefold()
    else:
        raise AssertionError("Cancelled extraction was accepted")
    assert not cancelled_destination.exists()

    linked_parent = ROOT / "data" / "linked-extraction-parent"
    linked_parent.symlink_to(ROOT / "cache", target_is_directory=True)
    try:
        extract_archive(archive, linked_parent / "output",
                        limits=ExtractionLimits(2, 8, 4))
    except ExtractionError as exc:
        assert "symbolic link" in str(exc)
    else:
        raise AssertionError("Symlinked extraction ancestor was accepted")

    race_archive = ROOT / "cache" / "race.zip"
    shutil.copyfile(archive, race_archive)
    race_pin = _pin(race_archive.read_bytes(), race_archive.name)
    original_extract = extraction_module.extract_archive
    def replace_after_snapshot(snapshot, destination, **kwargs):
        race_archive.write_bytes(b"replacement")
        return original_extract(snapshot, destination, **kwargs)
    extraction_module.extract_archive = replace_after_snapshot
    race_destination = ROOT / "data" / "race-extract"
    try:
        try:
            extract_verified_artifact(race_pin, race_archive, race_destination,
                                      limits=ExtractionLimits(2, 8, 4))
        except ExtractionError as exc:
            assert "identity changed" in str(exc)
        else:
            raise AssertionError("Archive replacement during extraction was accepted")
    finally:
        extraction_module.extract_archive = original_extract
    assert not race_destination.exists()

    rejected = (
        ArchiveMember("/absolute"), ArchiveMember("C:/drive"),
        ArchiveMember("../traversal"), ArchiveMember("back\\slash"),
        ArchiveMember("link", "symlink"), ArchiveMember("hard", "hardlink"),
        ArchiveMember("device", "device"), ArchiveMember("pipe", "fifo"),
        ArchiveMember("sock", "socket"),
    )
    for member in rejected:
        try:
            validate_archive_members((member,))
        except ExtractionError:
            pass
        else:
            raise AssertionError(f"Unsafe member accepted: {member}")
    for pair in ((ArchiveMember("same"), ArchiveMember("same")),
                 (ArchiveMember("Case"), ArchiveMember("case"))):
        try:
            validate_archive_members(pair)
        except ExtractionError:
            pass
        else:
            raise AssertionError("Duplicate/case collision accepted")

    evil = ROOT / "cache" / "evil.zip"
    _zip(evil, {"ok": b"ok"}, symlink="linked")
    try:
        extract_archive(evil, ROOT / "data" / "evil-extract")
    except ExtractionError:
        pass
    else:
        raise AssertionError("ZIP symlink was extracted")
    assert not (ROOT / "data" / "evil-extract").exists()

    seven = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if seven:
        source = ROOT / "data" / "seven-source"
        source.mkdir()
        (source / "member.txt").write_text("seven", encoding="utf-8")
        seven_archive = ROOT / "cache" / "synthetic.7z"
        subprocess.run([seven, "a", os.fspath(seven_archive), "member.txt"], cwd=source,
                       stdout=subprocess.DEVNULL, check=True)
        extracted = extract_archive(seven_archive, ROOT / "data" / "seven-extract",
                                    seven_zip_tool=seven, required_members=("member.txt",))
        assert (extracted.root / "member.txt").read_text() == "seven"


def _manifest(mod_id: str, apps: list[str]) -> dict:
    return {
        "ModId": mod_id, "ModName": mod_id, "ModAuthor": "Test", "ModVersion": "1.0",
        "ModDependencies": ["fftivc.utility.modloader"], "OptionalDependencies": [],
        "SupportedAppId": apps, "ModDll": "", "ModR2RManagedDll32": "",
        "ModR2RManagedDll64": "", "ModNativeDll32": "", "ModNativeDll64": "",
    }


def _package(path: Path, mod_id: str, apps: list[str], payload: bytes) -> Path:
    path.mkdir(parents=True)
    (path / "ModConfig.json").write_text(json.dumps(_manifest(mod_id, apps)), encoding="utf-8")
    content = path / "FFTIVC" / "data" / ("combined" if len(apps) == 2 else "enhanced") / "same.nxd"
    content.parent.mkdir(parents=True)
    content.write_bytes(payload)
    return path


def _official_verified_inputs() -> dict:
    source_root = Path("/var/mnt/game_drive/github/fftic-phase-a-artifacts-20260928/downloads")
    source_names = {
        "reloaded-ii": "Reloaded-II-1.31.0-Release.zip",
        "nenkai-loader": "fftivc.utility.modloader-1.7.3.7z",
        "sigscan": "Reloaded.Memory.SigScan.ReloadedII-1.2.14.7z",
        "shared-hooks": "Reloaded.SharedLib.Hooks.ReloadedII-1.16.3.7z",
    }
    result = {}
    for artifact_id, source_name in source_names.items():
        pin = ARTIFACTS[artifact_id]
        archive = ROOT / "cache" / "reviewed" / pin.filename
        archive.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / source_name, archive)
        result[artifact_id] = extract_verified_artifact(
            pin, archive, ROOT / "data" / "reviewed" / artifact_id)
    return result


def test_generation_and_profile_sync() -> None:
    verified_inputs = _official_verified_inputs()
    arbitrary = ROOT / "data" / "arbitrary-reloaded"
    arbitrary.mkdir()
    (arbitrary / "arbitrary.bin").write_bytes(b"not Reloaded")
    substituted = dict(verified_inputs)
    substituted["reloaded-ii"] = replace(verified_inputs["reloaded-ii"], root=arbitrary)
    try:
        build_private_generation(
            generations_root=ROOT / "generations", verified_inputs=substituted,
            user_mods=(), windows_game_path=ValidatedSteamPath.from_resolver(
                r"S:\steamapps\common\FFTIC"))
    except GenerationError as exc:
        assert "provenance" in str(exc)
    else:
        raise AssertionError("An arbitrary tree was blessed by archive hash metadata")

    for artifact_id in ("reloaded-ii", "sigscan"):
        evidence = verified_inputs[artifact_id]
        target = evidence.root / evidence.files[0].path
        original = target.read_bytes()
        target.write_bytes(original + b"drift")
        try:
            build_private_generation(
                generations_root=ROOT / "generations", verified_inputs=verified_inputs,
                user_mods=(), windows_game_path=ValidatedSteamPath.from_resolver(
                    r"S:\steamapps\common\FFTIC"))
        except GenerationError as exc:
            assert "provenance" in str(exc)
        else:
            raise AssertionError(f"Modified {artifact_id} bytes were accepted")
        target.write_bytes(original)

    bootstrap_path = (verified_inputs["reloaded-ii"].root /
                      "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll")
    bootstrap_pin = INTERNAL_FILES["reloaded-bootstrapper-asi"]
    verify_internal_file(bootstrap_path, size=bootstrap_pin.size, sha256=bootstrap_pin.sha256)
    altered_bootstrap = ROOT / "data" / "altered-bootstrap.dll"
    altered_bootstrap.write_bytes(bootstrap_path.read_bytes() + b"drift")
    try:
        verify_internal_file(altered_bootstrap, size=bootstrap_pin.size, sha256=bootstrap_pin.sha256)
    except ExtractionError:
        pass
    else:
        raise AssertionError("Modified reviewed bootstrap bytes were accepted")
    profile = ROOT / "profiles" / "active"
    staging = profile / "mods"
    high = _package(staging / "High Folder", "test.high", [ENHANCED_APP_ID], b"winner")
    low = _package(staging / "Low Folder", "test.low",
                   [CLASSIC_APP_ID, ENHANCED_APP_ID], b"loser")
    disabled = _package(staging / "Disabled Folder", "test.disabled", [ENHANCED_APP_ID], b"off")
    profile.mkdir(exist_ok=True)
    (profile / "modlist.txt").write_text(
        "+High Folder\n-Low Folder\n-Disabled Folder\n", encoding="utf-8")
    mods = read_profile_mods(profile, staging)
    assert [mod.mod_id for mod in mods] == ["test.high", "test.low", "test.disabled"]
    # Enable low for two-mod ordering; disabled remains excluded.
    mods = tuple(replace(mod, enabled=True) if mod.mod_id == "test.low" else mod for mod in mods)
    windows = ValidatedSteamPath.from_resolver(r"S:\steamapps\common\FFTIC")
    first = build_private_generation(
        generations_root=ROOT / "generations", verified_inputs=verified_inputs,
        user_mods=mods, windows_game_path=windows)
    second = build_private_generation(
        generations_root=ROOT / "generations", verified_inputs=verified_inputs,
        user_mods=mods, windows_game_path=windows)
    assert first.generation_id == second.generation_id
    assert first.manifest_sha256 == second.manifest_sha256
    assert verify_private_generation(first.root, first.generation_id) == first.manifest_sha256
    assert (first.root / "portable.txt").is_file()
    assert not (first.root / "ReloadedPortable.txt").exists()
    serializer_defaults = {
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
    for identity, artifact_id in MANAGED_ARTIFACTS.items():
        original_bytes = (verified_inputs[artifact_id].root / "ModConfig.json").read_bytes()
        original = json.loads(original_bytes)
        stable_bytes = (first.root / "Mods" / identity / "ModConfig.json").read_bytes()
        stable = json.loads(stable_bytes)
        assert stable["CanUnload"] is False and stable["HasExports"] is True
        assert stable == json.loads(normalized_managed_mod_config(original_bytes, identity))
        legacy = dict(original)
        legacy.update(CanUnload=False, HasExports=True)
        for key, value in serializer_defaults[identity].items():
            legacy.setdefault(key, value)
        legacy_bytes = json.dumps(legacy).encode()
        assert is_exact_reloaded_semantic_transition(
            original_bytes, legacy_bytes, identity)
        wrong = dict(legacy, HasExports=False)
        assert not is_exact_reloaded_semantic_transition(
            original_bytes, json.dumps(wrong).encode(), identity)
        extra = dict(legacy, UnexpectedField=True)
        assert not is_exact_reloaded_semantic_transition(
            original_bytes, json.dumps(extra).encode(), identity)
    enhanced = json.loads((first.root / "Apps" / ENHANCED_APP_ID / "AppConfig.json").read_text())
    assert enhanced["EnabledMods"][-2:] == ["test.low", "test.high"]
    assert "test.disabled" not in enhanced["EnabledMods"]
    classic = json.loads((first.root / "Apps" / CLASSIC_APP_ID / "AppConfig.json").read_text())
    assert "test.high" not in classic["SortedMods"]
    assert (first.root / "Mods" / "test.high" / "FFTIVC/data/enhanced/same.nxd").read_bytes() == b"winner"
    high.joinpath("FFTIVC/data/enhanced/same.nxd").write_bytes(b"mutated source")
    assert (first.root / "Mods" / "test.high" / "FFTIVC/data/enhanced/same.nxd").read_bytes() == b"winner"

    updated_mods = tuple(replace(mod, package_location=high) if mod.mod_id == "test.high" else mod
                         for mod in mods)
    moved_windows = ValidatedSteamPath.from_resolver(r"S:\steamapps\common\FFTIC Moved")
    moved = build_private_generation(
        generations_root=ROOT / "generations", verified_inputs=verified_inputs,
        user_mods=mods, windows_game_path=moved_windows)
    assert moved.generation_id != first.generation_id
    moved_app = (moved.root / "Apps" / ENHANCED_APP_ID / "AppConfig.json").read_text()
    assert "FFTIC Moved" in moved_app
    updated = build_private_generation(
        generations_root=ROOT / "generations", verified_inputs=verified_inputs,
        user_mods=updated_mods, windows_game_path=windows,
        previous_generation=first.generation_id)
    assert updated.generation_id != first.generation_id and first.root.exists()
    state = ROOT / "data" / "current.json"
    activate_generation(state, updated.generation_id, updated.root, journal=_Journal(),
                        transaction_id="activate-updated",
                        previous_generation=first.generation_id)
    activate_generation(state, first.generation_id, first.root, journal=_Journal(),
                        transaction_id="activate-first",
                        previous_generation=updated.generation_id)
    assert json.loads(state.read_text())["active_generation"] == first.generation_id

    # Activation revalidates the whole generation and all manifest metadata.
    broken = ROOT / "generations" / "broken-empty"
    shutil.copytree(first.root, broken)
    (broken / "amethyst-generation.json").write_text("{}", encoding="utf-8")
    try:
        activate_generation(state, "broken-empty", broken, journal=_Journal(),
                            transaction_id="activate-broken")
    except TransactionError:
        pass
    else:
        raise AssertionError("An empty generation manifest activated")
    for label, mutate in (
        ("compatibility", lambda data: data["compatibility_set"].update({"steam_build": "changed"})),
        ("identity", lambda data: data.update({"generation_id": "fftic-r2-wrong"})),
    ):
        target = ROOT / "generations" / f"broken-{label}"
        shutil.copytree(first.root, target)
        manifest_path = target / "amethyst-generation.json"
        data = json.loads(manifest_path.read_text())
        mutate(data)
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        try:
            activate_generation(state, first.generation_id, target, journal=_Journal(),
                                transaction_id=f"activate-broken-{label}")
        except TransactionError:
            pass
        else:
            raise AssertionError(f"Generation with changed {label} activated")

    prefix = ROOT / "prefix" / "generation-map"
    host_generation = prefix / "drive_c" / "Amethyst" / "FFTIC" / "generation"
    host_generation.mkdir(parents=True)
    bootstrap_config = json.loads(generate_bootstrap_configuration(
        resolve_prefix_generation_path(prefix=prefix, host_generation_root=host_generation)))
    assert bootstrap_config["NuGetFeeds"] == []
    assert bootstrap_config["LoaderPath64"].endswith(
        r"Loader\X64\Reloaded.Mod.Loader.dll")
    try:
        resolve_prefix_generation_path(prefix=prefix, host_generation_root=ROOT / "generations")
    except SteamPathError:
        pass
    else:
        raise AssertionError("Generation path outside the selected prefix was accepted")
    forged = ValidatedWindowsGenerationPath(
        r"C:\arbitrary", prefix, host_generation, object())
    try:
        generate_bootstrap_configuration(forged)
    except ValueError as exc:
        assert "resolver evidence" in str(exc)
    else:
        raise AssertionError("A Windows-looking path bypassed prefix mapping proof")

    cancel = threading.Event()
    cancel.set()
    try:
        build_private_generation(
            generations_root=ROOT / "generations", verified_inputs=verified_inputs,
            user_mods=(), windows_game_path=windows, cancel=cancel)
    except GenerationError as exc:
        assert "cancelled" in str(exc)
    else:
        raise AssertionError("Cancelled generation was published")
    assert not list((ROOT / "generations").glob("*.build-*"))

    try:
        build_private_generation(
            generations_root=ROOT / "generations", verified_inputs=verified_inputs,
            user_mods=(), windows_game_path=windows,
            failure_injector=lambda stage: (_ for _ in ()).throw(RuntimeError(stage)))
    except RuntimeError as exc:
        assert str(exc) == "before_publish"
    else:
        raise AssertionError("Generation publication failure was not injected")
    assert not list((ROOT / "generations").glob("*.build-*"))

    drift_target = first.root / "Reloaded-II.exe"
    prior_bytes = drift_target.read_bytes()
    drift_target.write_bytes(b"drift")
    try:
        verify_private_generation(first.root, first.generation_id)
    except GenerationError as exc:
        assert "incomplete" in str(exc) or "drift" in str(exc)
    else:
        raise AssertionError("Generation drift was accepted")
    try:
        activate_generation(state, first.generation_id, first.root, journal=_Journal(),
                            transaction_id="activate-drift")
    except TransactionError:
        pass
    else:
        raise AssertionError("Generation content drift activated")
    drift_target.write_bytes(prior_bytes)

    # A broad file-manifest rewrite cannot conceal changed user-package content.
    user_drift = ROOT / "generations" / "user-content-drift"
    shutil.copytree(first.root, user_drift)
    changed_user = user_drift / "Mods" / "test.high" / "FFTIVC/data/enhanced/same.nxd"
    changed_user.write_bytes(b"changed copied user content")
    manifest_path = user_drift / "amethyst-generation.json"
    manifest = json.loads(manifest_path.read_text())
    relative = changed_user.relative_to(user_drift).as_posix()
    for record in manifest["files"]:
        if record["path"] == relative:
            record.update(size=changed_user.stat().st_size, sha256=file_sha256(changed_user))
            break
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        verify_private_generation(user_drift, first.generation_id)
    except GenerationError as exc:
        assert "user package content identity" in str(exc)
    else:
        raise AssertionError("Rewritten broad manifest concealed changed user content")
    try:
        activate_generation(state, first.generation_id, user_drift, journal=_Journal(),
                            transaction_id="activate-user-drift")
    except TransactionError:
        pass
    else:
        raise AssertionError("Generation with changed declared user content activated")

    wrong = dict(verified_inputs)
    wrong["sigscan"] = verified_inputs["shared-hooks"]
    try:
        build_private_generation(
            generations_root=ROOT / "generations", verified_inputs=wrong,
            user_mods=(), windows_game_path=windows)
    except GenerationError as exc:
        assert "provenance" in str(exc)
    else:
        raise AssertionError("Managed identity mismatch was accepted")

    generation_executor = FfticTransactionExecutor(
        allowed_roots=(ROOT,), lock_path=ROOT / "data" / "generation-remove.lock",
        journal=_Journal())
    quarantined = generation_executor.quarantine_owned_generation(
        generation_root=updated.root, generation_id=updated.generation_id,
        quarantine_root=ROOT / "quarantine" / "generations",
        transaction_id="remove-generation")
    assert quarantined.is_dir() and not updated.root.exists() and first.root.exists()


def test_s_resolver() -> None:
    library = ROOT / "steam" / "second-library"
    steamapps = library / "steamapps"
    game = steamapps / "common" / "FFTIC Installed"
    game.mkdir(parents=True)
    for name in ("FFT_classic.exe", "FFT_enhanced.exe"):
        (game / name).write_bytes(b"exe")
    manifest = steamapps / "appmanifest_1004640.acf"
    manifest.write_text('"AppState"\n{\n"appid" "1004640"\n"installdir" "FFTIC Installed"\n}\n')
    prefix = ROOT / "prefix" / "pfx"
    (prefix / "dosdevices").mkdir(parents=True)
    (prefix / "dosdevices" / "s:").symlink_to(library, target_is_directory=True)
    result = resolve_steam_s_path(steam_library=library, app_manifest=manifest,
                                  game_root=game, prefix=prefix)
    assert result.windows_game_path.value == r"S:\steamapps\common\FFTIC Installed"
    (prefix / "dosdevices" / "s:").unlink()
    try:
        resolve_steam_s_path(steam_library=library, app_manifest=manifest,
                             game_root=game, prefix=prefix)
    except SteamPathError as exc:
        assert "no verified S:" in str(exc)
    else:
        raise AssertionError("Missing S: mapping was accepted")
    (prefix / "dosdevices" / "s:").symlink_to(ROOT / "steam", target_is_directory=True)
    try:
        resolve_steam_s_path(steam_library=library, app_manifest=manifest,
                             game_root=game, prefix=prefix)
    except SteamPathError as exc:
        assert "not the selected Steam library" in str(exc)
    else:
        raise AssertionError("Wrong S: mapping was accepted")


def _receipt(transaction="tx") -> dict:
    h = "a" * 64
    return {
        "schema_version": 1, "transaction_id": transaction,
        "created_at": "2026-09-29T00:00:00Z", "updated_at": "2026-09-29T00:00:00Z",
        "steam_app_id": "1004640",
        "game_root_identity": {"path": "/sandbox/game", "steam_library": "/sandbox/steam",
                               "installed_directory": "FFTIC"},
        "prefix_identity": {"path": "/sandbox/prefix", "runner_identity": SUPPORTED_PROTON_RUNNER},
        "executable_hashes": dict(VERIFIED_HASHES),
        "evidence_authority": "reviewed-production",
        "compatibility_tuple": {
            "steam_build": "24304444", "ui_version": "v1.5.2",
            "proton_runner": SUPPORTED_PROTON_RUNNER,
            "reloaded": "1.31.0", "sigscan": "1.2.14", "shared_hooks": "1.16.3",
            "nenkai": "1.7.3"},
        "active_generation_identity": {
            "generation_id": "fftic-r2-fixture", "root": "/sandbox/generation",
            "manifest_sha256": h},
        "artifacts": [{
            "artifact_id": pin.artifact_id, "version": pin.version, "url": pin.url,
            "size": pin.size, "sha256": pin.sha256,
        } for pin in ARTIFACTS.values()],
        "managed_packages": [
            {"mod_id": MANAGED_ORDER[0], "version": "1.2.14", "content_identity": h},
            {"mod_id": MANAGED_ORDER[1], "version": "1.16.3", "content_identity": h},
            {"mod_id": MANAGED_ORDER[2], "version": "1.7.3", "content_identity": h},
        ],
        "configuration_hashes": {"bootstrap": h, "classic_app": h, "enhanced_app": h},
        "user_packages": [],
        "owned_game_targets": [
            {"relative_path": "version.dll", "expected_hash": INTERNAL_FILES["version-dll"].sha256,
             "prior_state": "absent",
             "prior_hash": None, "backup_path": None},
            {"relative_path": "Reloaded.Mod.Loader.Bootstrapper.asi",
             "expected_hash": INTERNAL_FILES["reloaded-bootstrapper-asi"].sha256,
             "prior_state": "absent", "prior_hash": None, "backup_path": None},
        ],
        "prefix_owned_configuration": [{
            "relative_path": PREFIX_CONFIGURATION_PATH,
            "expected_hash": h, "prior_state": "absent", "prior_hash": None,
            "backup_path": None}],
        "shared_prerequisites": [
            {"component": DOTNET_COMPONENT, "state": "sufficient",
             "observed_version": "9.0.20", "required_version": "9.0.20"},
            {"component": VC_COMPONENT, "state": "sufficient",
             "observed_version": "14.44.35211.0", "required_version": "14.30.0.0"},
        ],
        "steam_launch_options": {
            "status": "Configured", "required_sha256": REQUIRED_OPTIONS_SHA256,
            "observed_sha256": hashlib.sha256(
                COPY_READY_OPTIONS.encode("utf-8")).hexdigest()},
        "generated_pac_observations": [], "last_successful_operation": "test",
        "incomplete_operation": None, "recovery_instructions": ["Use the sandbox receipt."],
    }


def _readiness_fixture(fixture_name: str) -> tuple[dict, ReadinessEvidence]:
    source_generation = None
    manifest = None
    for candidate in (ROOT / "generations").iterdir():
        if not candidate.is_dir() or not candidate.name.startswith("fftic-r2-"):
            continue
        try:
            verify_private_generation(candidate, candidate.name)
            candidate_manifest = json.loads(
                (candidate / "amethyst-generation.json").read_text(encoding="utf-8"))
        except GenerationError:
            continue
        if (candidate_manifest["user_packages"]
                and candidate_manifest["configuration"]["windows_game_path"] ==
                r"S:\steamapps\common\FFTIC"):
            source_generation, manifest = candidate, candidate_manifest
            break
    assert source_generation is not None and manifest is not None

    base = ROOT / "data" / fixture_name
    library = ROOT / "steam" / f"{fixture_name}-library"
    game = library / "steamapps" / "common" / "FFTIC"
    game.mkdir(parents=True)
    for executable in ("FFT_classic.exe", "FFT_enhanced.exe"):
        (game / executable).write_bytes(b"isolated executable placeholder")
    app_manifest = library / "steamapps" / "appmanifest_1004640.acf"
    app_manifest.write_text(
        '"AppState"\n{\n"appid" "1004640"\n"installdir" "FFTIC"\n}\n',
        encoding="utf-8")
    prefix = ROOT / "prefix" / fixture_name
    (prefix / "dosdevices").mkdir(parents=True)
    (prefix / "dosdevices" / "s:").symlink_to(library, target_is_directory=True)
    generation = prefix / "drive_c" / "Amethyst" / "FFTIC" / "generations" / source_generation.name
    generation.parent.mkdir(parents=True)
    shutil.copytree(source_generation, generation)
    manifest_hash = verify_private_generation(generation, generation.name)

    nested = generation / "Loader" / "Asi" / "UltimateAsiLoader.7z"
    asi = extract_archive(
        nested, base / "asi", required_members=("ASILoader64.dll",),
        limits=ExtractionLimits(2, 9_029_424, 5_413_776))
    shutil.copyfile(asi.root / "ASILoader64.dll", game / "version.dll")
    shutil.copyfile(
        generation / "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll",
        game / "Reloaded.Mod.Loader.Bootstrapper.asi")

    resolved = resolve_steam_s_path(
        steam_library=library, app_manifest=app_manifest, game_root=game, prefix=prefix)
    bootstrap = generate_bootstrap_configuration(resolve_prefix_generation_path(
        prefix=prefix, host_generation_root=generation))
    config_path = prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
    config_path.parent.mkdir(parents=True)
    config_path.write_bytes(bootstrap)
    bootstrap_hash = hashlib.sha256(bootstrap).hexdigest()
    active_state = base / "active-generation.json"
    activate_generation(
        active_state, generation.name, generation, journal=_Journal(),
        transaction_id="readiness-activation")

    dotnet = classify_prerequisite(
        component=DOTNET_COMPONENT, required_version="9.0.20",
        observed_version="9.0.20", healthy=True, present=True)
    vc = classify_prerequisite(
        component=VC_COMPONENT, required_version="14.30.0.0",
        observed_version="14.44.35211.0", healthy=True, present=True)
    receipt = _receipt("readiness")
    receipt["game_root_identity"] = {
        "path": str(game.resolve()), "steam_library": str(library.resolve()),
        "installed_directory": "FFTIC"}
    receipt["prefix_identity"] = {
        "path": str(prefix.resolve()), "runner_identity": SUPPORTED_PROTON_RUNNER}
    receipt["active_generation_identity"] = {
        "generation_id": generation.name, "root": str(generation.resolve()),
        "manifest_sha256": manifest_hash}
    artifact_inputs = {item["artifact_id"]: item for item in manifest["artifact_inputs"]}
    receipt["managed_packages"] = [{
        "mod_id": mod_id,
        "version": receipt["compatibility_tuple"][{
            MANAGED_ORDER[0]: "sigscan", MANAGED_ORDER[1]: "shared_hooks",
            MANAGED_ORDER[2]: "nenkai"}[mod_id]],
        "content_identity": artifact_inputs[MANAGED_ARTIFACTS[mod_id]]["content_identity"],
    } for mod_id in MANAGED_ORDER]
    receipt["user_packages"] = [{
        "mod_id": item["mod_id"], "enabled": item["enabled"], "priority": item["priority"],
        "classification": item["classification"],
        "content_identity": item["content_manifest_sha256"],
    } for item in manifest["user_packages"]]
    receipt["configuration_hashes"] = {
        "bootstrap": bootstrap_hash,
        "classic_app": manifest["configuration"]["hashes"][
            "Apps/fft_classic.exe/AppConfig.json"],
        "enhanced_app": manifest["configuration"]["hashes"][
            "Apps/fft_enhanced.exe/AppConfig.json"],
    }
    receipt["prefix_owned_configuration"][0]["expected_hash"] = bootstrap_hash
    receipt["shared_prerequisites"] = [{
        "component": item.component, "state": item.state.value,
        "observed_version": item.observed_version, "required_version": item.required_version,
    } for item in (dotnet, vc)]
    validated = Receipt(validate_receipt(receipt))
    detection = InstallationDetection(
        InstallStatus.EXACT_VERIFIED, game.resolve(), VERIFIED_STEAM_BUILD,
        "v1.0.0", VERIFIED_UI_VERSION, tuple(VERIFIED_HASHES.items()), (), ())
    profile = ROOT / "profiles" / fixture_name
    staging = profile / "mods"
    staging.mkdir(parents=True)
    modlist_lines = []
    for item in manifest["user_packages"]:
        shutil.copytree(generation / "Mods" / item["mod_id"], staging / item["mod_id"])
        modlist_lines.append(("+" if item["enabled"] else "-") + item["mod_id"])
    (profile / "modlist.txt").write_text("\n".join(modlist_lines) + "\n", encoding="utf-8")
    evidence = ReadinessEvidence(
        validated, detection, resolved, app_manifest, SUPPORTED_PROTON_RUNNER,
        active_state, profile.resolve(), staging.resolve(),
        PrefixPrerequisites(prefix.resolve(), dotnet, vc),
        analyze_steam_launch_options(COPY_READY_OPTIONS))
    return receipt, evidence


def test_cross_field_readiness() -> None:
    receipt, evidence = _readiness_fixture("cross-field-readiness")
    verified = verify_launch_readiness(evidence)
    assert verified.ready, verified.issues
    status = compose_lifecycle_status(verified)
    assert status.ready and LifecycleState.READY_TO_LAUNCH in status.states

    forged = ReadinessVerification(
        InstallStatus.EXACT_VERIFIED, SteamOptionsStatus.CONFIGURED,
        *(ReadinessAspect.READY for _ in range(9)), issues=())
    assert not forged.ready and not forged.attested
    forged_status = compose_lifecycle_status(forged)
    assert not forged_status.ready
    assert forged_status.states == (LifecycleState.RECOVERY_REQUIRED,)
    assert LifecycleState.READY_TO_LAUNCH not in forged_status.states
    replaced = replace(verified)
    assert not replaced.attested and not replaced.ready

    for mutation in (
        lambda value: value["prefix_identity"].update(runner_identity="runner-A"),
        lambda value: value["steam_launch_options"].update(required_sha256="a" * 64),
        lambda value: value["owned_game_targets"][0].update(expected_hash="a" * 64),
        lambda value: value["owned_game_targets"][0].update(prior_hash="a" * 64),
        lambda value: value["prefix_owned_configuration"][0].update(relative_path="arbitrary.json"),
    ):
        candidate = copy.deepcopy(receipt)
        mutation(candidate)
        try:
            validate_receipt(candidate)
        except ReceiptCorruptError:
            pass
        else:
            raise AssertionError("Cross-field-invalid receipt passed schema validation")

    unsupported = copy.deepcopy(receipt)
    unsupported["prefix_identity"]["runner_identity"] = "unsupported-runner"
    unsupported["compatibility_tuple"]["proton_runner"] = "unsupported-runner"
    result = verify_launch_readiness(replace(
        evidence, receipt=Receipt(validate_receipt(unsupported)),
        runner_identity="unsupported-runner"))
    assert not result.ready and result.prefix.value == "invalid"

    missing = copy.deepcopy(receipt)
    missing["active_generation_identity"]["root"] = str(ROOT / "data" / "missing-generation")
    result = verify_launch_readiness(replace(
        evidence, receipt=Receipt(validate_receipt(missing))))
    assert not result.ready and result.generation.value == "missing"

    wrong_hash = copy.deepcopy(receipt)
    wrong_hash["active_generation_identity"]["manifest_sha256"] = "b" * 64
    result = verify_launch_readiness(replace(
        evidence, receipt=Receipt(validate_receipt(wrong_hash))))
    assert not result.ready and result.generation.value == "invalid"

    state_bytes = evidence.active_state_file.read_bytes()
    state = json.loads(state_bytes)
    state["active_generation"] = "fftic-r2-other"
    evidence.active_state_file.write_text(json.dumps(state), encoding="utf-8")
    try:
        assert not verify_launch_readiness(evidence).ready
    finally:
        evidence.active_state_file.write_bytes(state_bytes)

    profile = copy.deepcopy(receipt)
    profile["user_packages"][0]["enabled"] = not profile["user_packages"][0]["enabled"]
    result = verify_launch_readiness(replace(
        evidence, receipt=Receipt(validate_receipt(profile))))
    assert not result.ready and result.profile.value == "invalid"

    changed_dotnet = replace(
        evidence.prerequisites.dotnet_desktop, observed_version="9.0.21")
    result = verify_launch_readiness(replace(
        evidence, prerequisites=replace(evidence.prerequisites,
                                        dotnet_desktop=changed_dotnet)))
    assert not result.ready and result.prerequisites.value == "invalid"

    result = verify_launch_readiness(replace(
        evidence, steam_options=analyze_steam_launch_options(None)))
    assert not result.ready and result.steam_options.value == "invalid"

    pac_receipt = copy.deepcopy(receipt)
    pac_path = evidence.steam_path.game_root / "data/enhanced/modded.pac"
    pac_path.parent.mkdir(parents=True, exist_ok=True)
    pac_path.write_bytes(b"isolated generated PAC")
    fingerprint = profile_fingerprint(pac_receipt["user_packages"])
    pac_receipt["generated_pac_observations"] = [{
        "relative_path": "data/enhanced/modded.pac", "sha256": file_sha256(pac_path),
        "generation_id": "fftic-r2-other", "profile_fingerprint": fingerprint,
        "launch_id": "launch-other", "transaction_id": "transaction-other",
        "before_state": "absent", "before_sha256": None,
    }]
    launch = PacLaunchEvidence(
        "fftic-r2-other", fingerprint, "launch-other", "transaction-other")
    result = verify_launch_readiness(replace(
        evidence, receipt=Receipt(validate_receipt(pac_receipt)),
        pac_launch_evidence=(launch,)))
    assert not result.ready and result.profile.value == "invalid"


def test_current_profile_correlation() -> None:
    _receipt_data, evidence = _readiness_fixture("profile-correlation")
    profile = evidence.profile_dir
    staging = evidence.staging_root
    modlist = profile / "modlist.txt"
    original_modlist = modlist.read_bytes()
    lines = original_modlist.decode("utf-8").splitlines()
    assert len(lines) >= 2

    baseline = verify_launch_readiness(evidence)
    assert baseline.ready, baseline.issues

    first_id = lines[0][1:]
    toggled = ("-" if lines[0][0] == "+" else "+") + first_id
    modlist.write_text("\n".join((toggled, *lines[1:])) + "\n", encoding="utf-8")
    result = verify_launch_readiness(evidence)
    assert not result.ready
    assert any(first_id in issue and "field enabled" in issue for issue in result.issues)
    modlist.write_bytes(original_modlist)

    modlist.write_text("\n".join((lines[1], lines[0], *lines[2:])) + "\n", encoding="utf-8")
    result = verify_launch_readiness(evidence)
    assert not result.ready
    assert any("field priority" in issue for issue in result.issues)
    modlist.write_bytes(original_modlist)

    modlist.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    result = verify_launch_readiness(evidence)
    assert not result.ready
    assert any("missing mod" in issue and first_id in issue for issue in result.issues)
    modlist.write_bytes(original_modlist)

    added_folder = "Added Folder"
    _package(staging / added_folder, "test.added", [ENHANCED_APP_ID], b"added")
    modlist.write_text(original_modlist.decode("utf-8") + f"+{added_folder}\n", encoding="utf-8")
    result = verify_launch_readiness(evidence)
    assert not result.ready
    assert any("added mod test.added" in issue for issue in result.issues)
    modlist.write_bytes(original_modlist)
    shutil.rmtree(staging / added_folder)

    first_package = staging / first_id
    parked_package = staging / f".{first_id}.missing"
    os.replace(first_package, parked_package)
    try:
        result = verify_launch_readiness(evidence)
        assert not result.ready
        assert any(first_id in issue and "cannot be verified" in issue
                   for issue in result.issues)
    finally:
        os.replace(parked_package, first_package)

    staged_content = next(path for path in first_package.rglob("*.nxd"))
    original_content = staged_content.read_bytes()
    staged_content.write_bytes(b"changed staged package content")
    try:
        result = verify_launch_readiness(evidence)
        assert not result.ready
        assert any(first_id in issue and "field content_identity" in issue
                   for issue in result.issues)
    finally:
        staged_content.write_bytes(original_content)

    config = first_package / "ModConfig.json"
    original_config = config.read_bytes()
    changed_config = json.loads(original_config)
    changed_config["ModId"] = "test.changed-identity"
    config.write_text(json.dumps(changed_config), encoding="utf-8")
    try:
        result = verify_launch_readiness(evidence)
        assert not result.ready
        assert any("test.changed-identity" in issue and "added mod" in issue
                   for issue in result.issues)
        assert any(first_id in issue and "missing mod" in issue for issue in result.issues)
    finally:
        config.write_bytes(original_config)

    restored = verify_launch_readiness(evidence)
    assert restored.ready, restored.issues


def test_receipts_and_transactions() -> None:
    receipts = ROOT / "receipts"
    payload = serialize_receipt(_receipt())
    assert payload == serialize_receipt(_receipt())
    malformed = []
    for mutation in (
        lambda x: x.update(created_at="not-a-time"),
        lambda x: x["game_root_identity"].update(path="../escape"),
        lambda x: x["prefix_identity"].update(runner_identity=""),
        lambda x: x["active_generation_identity"].update(manifest_sha256="bad"),
        lambda x: x["artifacts"][0].update(size=-1),
        lambda x: x["managed_packages"][0].update(mod_id="wrong"),
        lambda x: x["owned_game_targets"][0].update(prior_state="foreign"),
        lambda x: x["shared_prerequisites"].pop(),
        lambda x: x["steam_launch_options"].update(status="Ready-ish"),
        lambda x: x.update(generated_pac_observations=[{"relative_path": "bad"}]),
        lambda x: x.update(incomplete_operation={"operation": "x"}),
        lambda x: x.update(recovery_instructions=[]),
    ):
        candidate = copy.deepcopy(_receipt())
        mutation(candidate)
        malformed.append(candidate)
    for candidate in malformed:
        try:
            validate_receipt(candidate)
        except ReceiptCorruptError:
            pass
        else:
            raise AssertionError("Malformed nested receipt field was accepted")
    path = write_receipt(receipts, _receipt())
    assert read_receipt(receipts).transaction_id == "tx"
    write_receipt(receipts, _receipt("tx2"))
    assert read_receipt(receipts).transaction_id == "tx2" and not list(receipts.glob("*.tmp-*"))
    path.write_text("{broken", encoding="utf-8")
    try:
        write_receipt(receipts, _receipt("must-not-replace"))
    except ReceiptCorruptError:
        pass
    else:
        raise AssertionError("Corrupt receipt was silently replaced")
    assert path.read_text() == "{broken"

    txroot = ROOT / "data" / "transactions"
    source_root, game_root, quarantine = txroot / "source", txroot / "game", txroot / "quarantine"
    source_root.mkdir(parents=True)
    game_root.mkdir()
    source = source_root / "version.dll"
    source.write_bytes(b"v1")
    expected = file_sha256(source)
    destination = game_root / "version.dll"
    plan = plan_owned_file_install(
        transaction_id="install", source=source, destination=destination,
        expected_source_hash=expected, ownership_identity="fftic:version",
        observed=TargetObservation(False))
    journal = _Journal()
    executor = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "operation.lock",
        journal=journal)
    result = executor.execute(plan)
    assert result.completed_steps == 2 and destination.read_bytes() == b"v1" and journal.records
    assert [item["state"] for item in journal.records[:3]] == ["durable", "write-ahead", "durable"]
    durable_file = txroot / "durable-journal.json"
    file_journal = FileTransactionJournal(durable_file)
    file_journal.record(transaction_id="fixture", state="write-ahead")
    assert json.loads(durable_file.read_text())["events"][0]["state"] == "write-ahead"

    try:
        FfticTransactionExecutor(allowed_roots=(txroot,), lock_path=txroot / "missing-journal.lock")
    except ValueError as exc:
        assert "journal" in str(exc)
    else:
        raise AssertionError("A mutating executor accepted no durable journal")

    destination.write_bytes(b"drift")
    try:
        executor.remove_exact_owned(target=destination, expected_hash=expected,
                                    quarantine_root=quarantine, transaction_id="remove")
    except TransactionDrift:
        pass
    else:
        raise AssertionError("Drifted file was removed")
    destination.write_bytes(b"v1")
    moved = executor.remove_exact_owned(target=destination, expected_hash=expected,
                                        quarantine_root=quarantine, transaction_id="remove")
    assert moved.read_bytes() == b"v1" and not destination.exists()

    destination.write_bytes(b"v1")
    post_mutation_journal = _Journal(
        lambda values: (_ for _ in ()).throw(OSError("durable journal failure"))
        if values.get("state") == "durable" else None)
    post_mutation = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "post-mutation.lock",
        journal=post_mutation_journal)
    try:
        post_mutation.remove_exact_owned(
            target=destination, expected_hash=expected, quarantine_root=quarantine,
            transaction_id="post-mutation")
    except TransactionError as exc:
        assert "recovery required" in str(exc)
    else:
        raise AssertionError("Post-mutation journal failure was hidden")
    recovery = [item for item in post_mutation_journal.records
                if item.get("state") == "recovery-required"]
    assert recovery and Path(recovery[-1]["destination"]).is_file()

    # Cancellation after a durable copy rolls back that exact copy.
    destination2 = game_root / "bootstrap.asi"
    cancel_plan = plan_owned_file_install(
        transaction_id="cancel", source=source, destination=destination2,
        expected_source_hash=expected, ownership_identity="fftic:bootstrap",
        observed=TargetObservation(False))
    # The plan ends after the copy, so inject a failure to force rollback instead.
    failing = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "fail.lock",
        journal=_Journal(),
        failure_injector=lambda when, index, _op: (_ for _ in ()).throw(RuntimeError("injected"))
        if when == "after" and index == 1 else None)
    try:
        failing.execute(cancel_plan)
    except RuntimeError as exc:
        assert "injected" in str(exc)
    else:
        raise AssertionError("Injected failure did not fire")
    assert not destination2.exists()
    # The same plan is safe to retry after rollback.
    assert executor.execute(cancel_plan).completed_steps == 2
    destination2.unlink()

    # Cancellation after the first publication is observed before the next
    # safe step and rolls the published file back.
    from fftic_transactions import TransactionPlan
    first_plan = plan_owned_file_install(
        transaction_id="multi", source=source, destination=destination2,
        expected_source_hash=expected, ownership_identity="fftic:first",
        observed=TargetObservation(False))
    third = game_root / "third.dll"
    second_plan = plan_owned_file_install(
        transaction_id="multi", source=source, destination=third,
        expected_source_hash=expected, ownership_identity="fftic:second",
        observed=TargetObservation(False))
    combined = TransactionPlan("multi", first_plan.operations + second_plan.operations)
    cancel_after_copy = threading.Event()
    cancelling = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "multi.lock",
        journal=_Journal(lambda values: cancel_after_copy.set()
                         if values.get("step") == 1 and values.get("state") == "durable" else None))
    try:
        cancelling.execute(combined, cancel=cancel_after_copy)
    except TransactionCancelled:
        pass
    else:
        raise AssertionError("Cancellation between safe steps was ignored")
    assert not destination2.exists() and not third.exists()

    # A process appearing after one durable mutation blocks the next mutation
    # and the first exact write is rolled back.
    running = {"value": False}
    process_journal = _Journal(lambda values: running.update(value=True)
                               if values.get("state") == "durable" and values.get("step") == 1
                               else None)
    process_executor = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "process.lock",
        process_running=lambda: running["value"], journal=process_journal)
    try:
        process_executor.execute(combined)
    except TransactionError as exc:
        assert "started before" in str(exc)
    else:
        raise AssertionError("Process start between transaction steps was ignored")
    assert not destination2.exists() and not third.exists()

    # If exact rollback becomes impossible, recovery-required state and the
    # failed action survive in the durable journal.
    rollback_journal = _Journal()
    def break_rollback(when, index, _operation):
        if when == "after" and index == 1:
            destination2.write_bytes(b"external drift")
            raise RuntimeError("trigger rollback")
    rollback_executor = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=txroot / "rollback.lock",
        journal=rollback_journal, failure_injector=break_rollback)
    try:
        rollback_executor.execute(cancel_plan)
    except TransactionError as exc:
        assert "requires recovery" in str(exc)
    else:
        raise AssertionError("Rollback failure was not surfaced")
    assert any(item.get("state") == "recovery-required" and item.get("failed_actions")
               for item in rollback_journal.records)
    destination2.unlink()

    replacement_lock = txroot / "replacement.lock"
    def replace_lock(when, index, _operation):
        if when == "before" and index == 0:
            replacement_lock.unlink()
            replacement_lock.write_text("other-owner", encoding="utf-8")
            raise RuntimeError("lock replaced")
    replacing = FfticTransactionExecutor(
        allowed_roots=(txroot,), lock_path=replacement_lock,
        journal=_Journal(), failure_injector=replace_lock)
    try:
        replacing.execute(cancel_plan)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Lock replacement fixture did not fire")
    assert replacement_lock.read_text() == "other-owner"
    replacement_lock.unlink()

    if Path("/dev/shm").is_dir() and Path("/dev/shm").stat().st_dev != txroot.stat().st_dev:
        with tempfile.TemporaryDirectory(prefix="fftic-crossfs-", dir="/dev/shm") as other_fs:
            destination.write_bytes(b"v1")
            cross_executor = FfticTransactionExecutor(
                allowed_roots=(txroot, Path(other_fs)), lock_path=txroot / "cross.lock",
                journal=_Journal())
            try:
                cross_executor.remove_exact_owned(
                    target=destination, expected_hash=expected,
                    quarantine_root=Path(other_fs) / "quarantine", transaction_id="cross")
            except TransactionError as exc:
                assert "same filesystem" in str(exc)
            else:
                raise AssertionError("Cross-filesystem quarantine was attempted")
            assert destination.read_bytes() == b"v1"
            destination.unlink()

    outside = ROOT.parent / "fftic-forbidden-target"
    try:
        executor.remove_exact_owned(target=outside, expected_hash=expected,
                                    quarantine_root=quarantine, transaction_id="outside")
    except Exception as exc:
        assert "outside explicit allowed roots" in str(exc)
    else:
        raise AssertionError("Allowed-root escape was accepted")
    link = game_root / "linked"
    link.symlink_to(source)
    try:
        executor.remove_exact_owned(target=link, expected_hash=expected,
                                    quarantine_root=quarantine, transaction_id="link")
    except Exception as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("Symlink target was accepted")

    generation = next(path for path in (ROOT / "generations").iterdir()
                      if path.is_dir() and path.name.startswith("fftic-r2-"))
    activation_journal = _Journal(
        lambda values: (_ for _ in ()).throw(OSError("activation journal failure"))
        if values.get("state") == "durable" else None)
    activation_state = txroot / "activation-state.json"
    try:
        activate_generation(
            activation_state, generation.name, generation, journal=activation_journal,
            transaction_id="activation-failure")
    except TransactionError as exc:
        assert "recovery required" in str(exc) and str(activation_state) in str(exc)
    else:
        raise AssertionError("Post-activation journal failure was hidden")
    assert activation_state.is_file()
    assert any(item.get("state") == "recovery-required"
               for item in activation_journal.records)


def test_pac_prerequisites_and_lifecycle() -> None:
    game = ROOT / "game"
    pac = game / "data" / "enhanced" / "modded.pac"
    pac.parent.mkdir(parents=True, exist_ok=True)
    pac.write_bytes(b"generated")
    assert pac_ownership(game, "data/enhanced/modded.pac", None) == PacOwnershipState.UNKNOWN
    evidence = PacLaunchEvidence(
        "generation", "profile", "launch-1", "transaction-1",
        "activation-1", "a" * 64, "b" * 64)
    preexisting = capture_pac_baseline(game)
    assert not capture_generated_pacs(game, baseline=preexisting, evidence=evidence)
    pac.unlink()
    baseline = capture_pac_baseline(game)
    pac.write_bytes(b"generated")
    observations = capture_generated_pacs(game, baseline=baseline, evidence=evidence)
    assert len(observations) == 1
    assert pac_ownership(game, observations[0].relative_path, observations[0]) == PacOwnershipState.OWNED_EXACT
    owned_baseline = capture_pac_baseline(game, prior_observations=observations)
    pac.write_bytes(b"regenerated")
    replaced = capture_generated_pacs(
        game, baseline=owned_baseline,
        evidence=PacLaunchEvidence(
            "generation-2", "profile-2", "launch-2", "transaction-2",
            "activation-2", "c" * 64, "d" * 64))
    assert len(replaced) == 1 and replaced[0].before_state == PacOwnershipState.OWNED_EXACT.value
    pac.write_bytes(b"drift")
    assert pac_ownership(game, replaced[0].relative_path, replaced[0]) == PacOwnershipState.DRIFT
    assert pac.read_bytes() == b"drift"

    missing = classify_prerequisite(component=".NET", required_version="9.0.20",
                                    observed_version=None, healthy=True, present=False)
    sufficient = classify_prerequisite(component=VC_COMPONENT, required_version="14.30.0.0",
                                       observed_version="14.44.35211", healthy=True, present=True)
    insufficient = classify_prerequisite(component=".NET", required_version="9.0.20",
                                         observed_version="9.0.10", healthy=True, present=True)
    unknown = classify_prerequisite(component=".NET", required_version="9.0.20",
                                    observed_version=None, healthy=None, present=True)
    unhealthy = classify_prerequisite(component=".NET", required_version="9.0.20",
                                      observed_version=None, healthy=False, present=True)
    assert [item.state for item in (missing, sufficient, insufficient, unknown, unhealthy)] == [
        PrerequisiteState.MISSING, PrerequisiteState.SUFFICIENT,
        PrerequisiteState.INSUFFICIENT, PrerequisiteState.UNKNOWN,
        PrerequisiteState.UNHEALTHY]
    plan = plan_installer(
        artifact_id="dotnet-desktop-runtime", installer_path=ROOT / "cache" / "dotnet.exe",
        prefix=ROOT / "prefix", runner_identity="fixture-runner", health=missing)
    assert plan.arguments == ("/install", "/quiet", "/norestart")
    assert plan.success_exit_codes == (0,) and plan.restart_exit_codes == (3010, 194)
    assert not plan.snapshot_required and plan.shared_runtime_retained_on_removal
    assert plan_installer(
        artifact_id="vc-runtime", installer_path=ROOT / "cache" / "vc.exe",
        prefix=ROOT / "prefix", runner_identity="fixture-runner", health=sufficient) is None
    inspected = inspect_prefix_prerequisites(ROOT / "prefix" / "empty-fixture")
    assert inspected.dotnet_desktop.state == PrerequisiteState.UNHEALTHY
    assert inspected.vc_runtime.state == PrerequisiteState.UNHEALTHY

def test_no_live_paths() -> None:
    prohibited = (
        Path.home() / ".var/app/io.github.Amethyst.ModManager",
        Path.home() / "Games/Amethyst",
        Path("/var/mnt/game_drive/SteamLibrary"),
        Path("/var/mnt/game_drive/github/fftic-phase-a-artifacts-20260928"),
        Path("/var/mnt/game_drive/github/fftic-phase-b-proof-20260929"),
        Path("/var/mnt/game_drive/github/fftic-phase-b2-launch-handoff-20260929"),
    )
    for path in ROOT.rglob("*"):
        resolved = path.resolve()
        assert not any(resolved == root or resolved.is_relative_to(root) for root in prohibited)
    for env in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "MOD_MANAGER_PROFILES_DIR"):
        assert Path(os.environ[env]).resolve().is_relative_to(ROOT)


def main() -> None:
    tests = (
        test_artifact_acquisition, test_safe_extraction,
        test_generation_and_profile_sync, test_s_resolver,
        test_receipts_and_transactions, test_pac_prerequisites_and_lifecycle,
        test_cross_field_readiness, test_current_profile_correlation,
        test_no_live_paths,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC Phase C2 isolated checks passed.")


if __name__ == "__main__":
    main()
