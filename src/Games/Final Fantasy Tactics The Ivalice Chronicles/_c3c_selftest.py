"""Phase C3C lifecycle checks in one disposable, fully isolated root."""

from __future__ import annotations

import json
import hashlib
import shutil
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

from fftic_artifacts import ARTIFACTS
from fftic_detection import (
    InstallStatus, InstallationDetection, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
)
from fftic_managed_executor import (
    ManagedLifecycleExecutor, ManagedOperationCancelled, OperationState,
    ProcessRequest, ProcessResult, RecoveryRequiredError, RecoveryState,
    StagedLifecycleOperations,
)
from fftic_orchestration import (
    FFTIC_GAME_ID, OperationBinding, OperationKind, OperationPlan, OperationStep,
)
from fftic_packages import CLASSIC_APP_ID, ENHANCED_APP_ID
from fftic_prerequisites import (
    DOTNET_COMPONENT, VC_COMPONENT, PrefixPrerequisites,
    classify_prerequisite,
)
from fftic_pac import PacLaunchEvidence
from fftic_readiness import SUPPORTED_PROTON_RUNNER, profile_fingerprint
from fftic_receipts import (
    PREFIX_CONFIGURATION_PATH, read_receipt, serialize_receipt,
)
from fftic_steam_requirements import COPY_READY_OPTIONS, analyze_steam_launch_options
from fftic_workflows import (
    CurrentInstallationEvidence, FfticLifecycleComposition, ReviewedCandidateSet,
    WorkflowError, WorkflowInputs,
)

SOURCE_ARCHIVES = Path(
    "/var/mnt/game_drive/github/fftic-phase-a-artifacts-20260928/downloads")
SOURCE_NAMES = {
    "reloaded-ii": "Reloaded-II-1.31.0-Release.zip",
    "nenkai-loader": "fftivc.utility.modloader-1.7.3.7z",
    "sigscan": "Reloaded.Memory.SigScan.ReloadedII-1.2.14.7z",
    "shared-hooks": "Reloaded.SharedLib.Hooks.ReloadedII-1.16.3.7z",
    "dotnet-desktop-runtime": "windowsdesktop-runtime-9.0.20-win-x64.exe",
    "vc-runtime": "vc_redist.x64.exe",
}
FIXTURE_ROOTS: list[Path] = []


def _manifest(mod_id: str, apps: list[str]) -> dict:
    return {
        "ModId": mod_id, "ModName": mod_id, "ModAuthor": "Fixture",
        "ModVersion": "1.0", "ModDependencies": ["fftivc.utility.modloader"],
        "OptionalDependencies": [], "SupportedAppId": apps, "ModDll": "",
        "ModR2RManagedDll32": "", "ModR2RManagedDll64": "",
        "ModNativeDll32": "", "ModNativeDll64": "",
    }


def _package(root: Path, folder: str, mod_id: str, payload: bytes,
             apps=(ENHANCED_APP_ID,)) -> None:
    package = root / folder
    package.mkdir(parents=True)
    (package / "ModConfig.json").write_text(
        json.dumps(_manifest(mod_id, list(apps))), encoding="utf-8")
    content = package / "FFTIVC/data/combined/same.nxd"
    content.parent.mkdir(parents=True)
    content.write_bytes(payload)


class Fixture:
    def __init__(self, name: str, *, missing_dotnet: bool = False,
                 failure_injector=None, process_runner=None,
                 request_factory=None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"amethyst-fftic-c3c-{name}-")).resolve()
        FIXTURE_ROOTS.append(self.root)
        self.library = self.root / "steam-library"
        self.game = self.library / "steamapps/common/FFTIC"
        self.prefix = self.root / "prefix"
        self.profile = self.root / "profiles/default"
        self.staging = self.root / "staging"
        self.cache = self.root / "cache"
        for path in (
                self.game, self.prefix / "dosdevices", self.prefix / "drive_c",
                self.profile, self.staging, self.cache, self.root / "extract",
                self.root / "backups", self.root / "quarantine",
                self.root / "receipts", self.root / "logs"):
            path.mkdir(parents=True, exist_ok=True)
        for executable in ("FFT_classic.exe", "FFT_enhanced.exe"):
            (self.game / executable).write_bytes(b"isolated executable identity fixture")
        self.fixture_hashes = tuple(
            (name, hashlib.sha256((self.game / executable).read_bytes()).hexdigest())
            for name, executable in (("classic", "FFT_classic.exe"),
                                     ("enhanced", "FFT_enhanced.exe")))
        self.manifest = self.library / "steamapps/appmanifest_1004640.acf"
        self.manifest.write_text(
            '"AppState"\n{\n"appid" "1004640"\n"installdir" "FFTIC"\n'
            f'"buildid" "{VERIFIED_STEAM_BUILD}"\n}}\n', encoding="utf-8")
        (self.prefix / "dosdevices/s:").symlink_to(
            self.library, target_is_directory=True)
        (self.prefix / "user.reg").write_text("fixture", encoding="utf-8")
        _package(self.staging, "High", "fixture.high", b"high")
        _package(self.staging, "Low", "fixture.low", b"low",
                 (CLASSIC_APP_ID, ENHANCED_APP_ID))
        _package(self.staging, "Disabled", "fixture.disabled", b"disabled")
        (self.profile / "modlist.txt").write_text(
            "+High\n+Low\n-Disabled\n", encoding="utf-8")
        for artifact_id, source_name in SOURCE_NAMES.items():
            shutil.copyfile(SOURCE_ARCHIVES / source_name,
                            self.cache / ARTIFACTS[artifact_id].filename)
        self._missing_dotnet = missing_dotnet
        self.steam_options_text = COPY_READY_OPTIONS
        generations = self.prefix / "drive_c/Amethyst/FFTIC/generations"
        candidates = ReviewedCandidateSet(tuple(
            (artifact_id, self.cache / pin.filename)
            for artifact_id, pin in ARTIFACTS.items()))
        self.inputs = WorkflowInputs(
            isolation_root=self.root, game_root=self.game,
            steam_library=self.library, app_manifest=self.manifest,
            prefix=self.prefix, profile_dir=self.profile,
            staging_root=self.staging, artifact_cache=self.cache,
            extraction_root=self.root / "extract", generations_root=generations,
            backup_root=self.root / "backups", quarantine_root=self.root / "quarantine",
            receipts_root=self.root / "receipts",
            active_state_file=self.prefix / "drive_c/Amethyst/FFTIC/active-generation.json",
            journal_file=self.root / "journal/lifecycle.json",
            log_root=self.root / "logs", runner_reader=lambda: SUPPORTED_PROTON_RUNNER,
            installation_reader=self.installation_evidence,
            steam_options_reader=lambda: analyze_steam_launch_options(
                self.steam_options_text),
            prerequisite_reader=self.prerequisites,
            process_request_factory=request_factory, process_runner=process_runner,
            setup_candidates=candidates,
            failure_injector=failure_injector)
        self.composition = FfticLifecycleComposition(
            self.inputs, plan_validator=lambda _plan: True)
        self.executor = ManagedLifecycleExecutor(self.composition)

    def installation_evidence(self) -> CurrentInstallationEvidence:
        return CurrentInstallationEvidence(
            InstallationDetection(
                InstallStatus.UNVERIFIED, self.game, VERIFIED_STEAM_BUILD,
                "v1.0.0", None, self.fixture_hashes, (), ("isolated fixture bytes",)),
            "isolated-fixture:c3c-selftest")

    def prerequisites(self, _prefix: Path) -> PrefixPrerequisites:
        dotnet = classify_prerequisite(
            component=DOTNET_COMPONENT, required_version="9.0.20",
            observed_version=None if self._missing_dotnet else "9.0.20",
            healthy=True, present=not self._missing_dotnet)
        vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version="14.44.35211.0", healthy=True, present=True)
        return PrefixPrerequisites(self.prefix, dotnet, vc)

    def plan(self, kind: OperationKind) -> OperationPlan:
        binding = OperationBinding(
            FFTIC_GAME_ID, "default", str(self.game), str(self.prefix),
            str(self.profile), str(self.staging), 0, "fixture", "fixture")
        return OperationPlan(
            kind, "default", (OperationStep("fixture", kind.value, str(self.root)),),
            binding=binding)

    def run(self, kind: OperationKind, cancel=None):
        return self.executor.execute(self.plan(kind), cancel)

    def recompose(self, **changes) -> None:
        self.inputs = replace(self.inputs, **changes)
        self.composition = FfticLifecycleComposition(
            self.inputs, plan_validator=lambda _plan: True)
        self.executor = ManagedLifecycleExecutor(self.composition)


def _rewrite_receipt(fixture: Fixture, change) -> dict:
    path = fixture.inputs.receipts_root / "fftic-receipt.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_bytes(serialize_receipt(data))
    return data


def _tree(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    if not root.exists():
        return {}
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ("link", str(path.readlink()))
        elif path.is_file():
            result[relative] = ("file", path.read_bytes())
    return result


def _filesystem_state(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    result = {".": ("dir", None)}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ("link", str(path.readlink()))
        elif path.is_file():
            result[relative] = ("file", path.read_bytes())
        elif path.is_dir():
            result[relative] = ("dir", None)
    return result


def _owned_state(fixture: Fixture) -> dict:
    return {
        "receipt": (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
        if (fixture.inputs.receipts_root / "fftic-receipt.json").exists() else None,
        "active": fixture.inputs.active_state_file.read_bytes()
        if fixture.inputs.active_state_file.exists() else None,
        "bootstrap": {name: (fixture.game / name).read_bytes()
                      if (fixture.game / name).exists() else None
                      for name in ("version.dll", "Reloaded.Mod.Loader.Bootstrapper.asi")},
        "config": (fixture.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH).read_bytes()
        if (fixture.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH).exists() else None,
        "backups": _tree(fixture.inputs.backup_root),
        "pacs": _tree(fixture.game / "data"),
        "generations": _tree(fixture.inputs.generations_root),
        "prerequisites": fixture.prerequisites(fixture.prefix),
    }


def test_complete_setup_repair_synchronize_update_and_remove() -> None:
    fixture = Fixture("lifecycle")
    result = fixture.run(OperationKind.SETUP)
    assert result.state == OperationState.SUCCEEDED
    receipt = read_receipt(fixture.inputs.receipts_root)
    assert receipt is not None
    first_generation = receipt.data["active_generation_identity"]["generation_id"]
    generation_root = Path(receipt.data["active_generation_identity"]["root"])
    enhanced = json.loads((generation_root / f"Apps/{ENHANCED_APP_ID}/AppConfig.json").read_text())
    assert enhanced["EnabledMods"][-2:] == ["fixture.low", "fixture.high"]
    assert "fixture.disabled" not in enhanced["EnabledMods"]
    assert all(path.is_relative_to(fixture.root) for path in (
        fixture.inputs.game_root, fixture.inputs.prefix, fixture.inputs.profile_dir,
        fixture.inputs.staging_root, fixture.inputs.artifact_cache,
        fixture.inputs.generations_root, fixture.inputs.receipts_root,
        fixture.inputs.journal_file, fixture.inputs.log_root))

    (fixture.game / "version.dll").unlink()
    assert fixture.run(OperationKind.REPAIR).state == OperationState.SUCCEEDED
    assert (fixture.game / "version.dll").is_file()
    try:
        fixture.run(OperationKind.REPAIR)
    except WorkflowError as exc:
        assert "no missing" in str(exc)
    else:
        raise AssertionError("No-op repair reported a successful mutation")

    (fixture.profile / "modlist.txt").write_text(
        "-High\n+Low\n-Disabled\n", encoding="utf-8")
    assert fixture.run(OperationKind.SYNCHRONIZE).state == OperationState.SUCCEEDED
    synchronized = read_receipt(fixture.inputs.receipts_root)
    synchronized_id = synchronized.data["active_generation_identity"]["generation_id"]
    assert synchronized_id != first_generation
    assert not (fixture.inputs.generations_root / first_generation).exists()
    synced_app = json.loads((Path(synchronized.data["active_generation_identity"]["root"])
                             / f"Apps/{ENHANCED_APP_ID}/AppConfig.json").read_text())
    assert "fixture.high" not in synced_app["EnabledMods"]
    assert synced_app["EnabledMods"][-1] == "fixture.low"
    try:
        fixture.run(OperationKind.SYNCHRONIZE)
    except WorkflowError as exc:
        assert "no changed" in str(exc)
    else:
        raise AssertionError("No-op synchronization reported a successful mutation")

    (fixture.staging / "Low/FFTIVC/data/combined/same.nxd").write_bytes(b"updated")
    receipt_before_update = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    try:
        fixture.run(OperationKind.UPDATE)
    except WorkflowError as exc:
        assert "unavailable" in str(exc) and "synchronize" in str(exc)
    else:
        raise AssertionError("Profile synchronization was mislabeled as runtime update")
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_before_update
    assert (fixture.inputs.generations_root / synchronized_id).is_dir()
    assert fixture.run(OperationKind.SYNCHRONIZE).state == OperationState.SUCCEEDED

    dotnet_marker = fixture.prefix / "drive_c/shared-dotnet-retained.txt"
    vc_marker = fixture.prefix / "drive_c/shared-vc-retained.txt"
    dotnet_marker.write_text("shared", encoding="utf-8")
    vc_marker.write_text("shared", encoding="utf-8")
    assert fixture.run(OperationKind.REMOVE).state == OperationState.SUCCEEDED
    assert read_receipt(fixture.inputs.receipts_root) is None
    assert not fixture.inputs.active_state_file.exists()
    assert not (fixture.game / "version.dll").exists()
    assert not (fixture.game / "Reloaded.Mod.Loader.Bootstrapper.asi").exists()
    assert not (fixture.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH).exists()
    assert dotnet_marker.read_text() == vc_marker.read_text() == "shared"


def test_collisions_drift_duplicates_and_missing_inputs_fail_closed() -> None:
    collision = Fixture("collision")
    (collision.game / "version.dll").write_bytes(b"unowned")
    before = (collision.game / "version.dll").read_bytes()
    try:
        collision.run(OperationKind.SETUP)
    except WorkflowError:
        pass
    else:
        raise AssertionError("Unowned collision was replaced")
    assert (collision.game / "version.dll").read_bytes() == before
    assert read_receipt(collision.inputs.receipts_root) is None

    duplicate = Fixture("duplicate")
    _package(duplicate.staging, "Case Duplicate", "FIXTURE.HIGH", b"duplicate")
    (duplicate.profile / "modlist.txt").write_text(
        "+High\n+Case Duplicate\n", encoding="utf-8")
    try:
        duplicate.run(OperationKind.SETUP)
    except Exception as exc:
        assert "Duplicate FFTIC mod ID" in str(exc)
    else:
        raise AssertionError("Case-only duplicate ID was accepted")

    missing = Fixture("unavailable-update")
    try:
        missing.run(OperationKind.UPDATE)
    except WorkflowError as exc:
        assert "unavailable" in str(exc) and "synchronize" in str(exc)
    else:
        raise AssertionError("Unavailable update reported success")

    drift = Fixture("drift")
    drift.run(OperationKind.SETUP)
    (drift.game / "version.dll").write_bytes(b"user drift")
    try:
        drift.run(OperationKind.REPAIR)
    except WorkflowError as exc:
        assert "drift" in str(exc)
    else:
        raise AssertionError("Drifted owned file was overwritten")
    assert (drift.game / "version.dll").read_bytes() == b"user drift"
    try:
        drift.run(OperationKind.REMOVE)
    except RecoveryRequiredError as exc:
        assert "drift" in str(exc) or "unverified" in str(exc)
    else:
        raise AssertionError("Unsafe drifted removal did not require recovery")
    assert (drift.game / "version.dll").read_bytes() == b"user drift"
    assert StagedLifecycleOperations.recovery_state(
        drift.composition.journal.read_events()) == RecoveryState.RECOVERY_REQUIRED


def test_cancellation_failure_rollback_and_restart_evidence() -> None:
    assert StagedLifecycleOperations.recovery_state(({
        "attempt_id": "started-only", "state": "operation-started"},)) == RecoveryState.STARTED
    cancelled = Fixture("cancel-before")
    cancel = threading.Event(); cancel.set()
    try:
        cancelled.run(OperationKind.SETUP, cancel)
    except ManagedOperationCancelled:
        pass
    else:
        raise AssertionError("Cancellation before mutation was ignored")
    assert not cancelled.inputs.journal_file.exists()

    holder = {}
    def cancel_between(name, _kind):
        if name == "generation":
            holder["cancel"].set()
    between = Fixture("cancel-between", failure_injector=cancel_between)
    holder["cancel"] = threading.Event()
    try:
        between.run(OperationKind.SETUP, holder["cancel"])
    except ManagedOperationCancelled:
        pass
    else:
        raise AssertionError("Cancellation between mutations was ignored")
    assert read_receipt(between.inputs.receipts_root) is None
    assert not (between.game / "version.dll").exists()
    events = between.composition.journal.read_events()
    assert StagedLifecycleOperations.recovery_state(events) == RecoveryState.ROLLBACK_VERIFIED

    for point in ("generation", "bootstrap:version.dll",
                  "bootstrap:Reloaded.Mod.Loader.Bootstrapper.asi",
                  "prefix-configuration", "activation", "receipt"):
        def fail(name, _kind, selected=point):
            if name == selected:
                raise RuntimeError(f"injected after {selected}")
        failed = Fixture("failure-" + point.replace(":", "-"), failure_injector=fail)
        try:
            failed.run(OperationKind.SETUP)
        except RuntimeError as exc:
            assert point in str(exc)
        else:
            raise AssertionError(f"Failure after {point} reported success")
        assert read_receipt(failed.inputs.receipts_root) is None
        assert not (failed.game / "version.dll").exists()
        assert not failed.inputs.active_state_file.exists()

    restart = Fixture("restart")
    restart.composition.journal.record(
        plan_fingerprint="x", attempt_id="incomplete", operation="setup",
        step=0, phase="generation", state="mutation-attempted")
    try:
        FfticLifecycleComposition(restart.inputs, plan_validator=lambda _plan: True)
    except RecoveryRequiredError as exc:
        assert "mutation attempted" in str(exc)
    else:
        raise AssertionError("Fresh composition ignored durable incomplete evidence")

    interrupted_remove = Fixture("interrupted-remove")
    interrupted_remove.run(OperationKind.SETUP)
    interrupted_remove.composition.journal.record(
        plan_fingerprint="remove-plan", attempt_id="interrupted-remove",
        operation="remove", step=0, phase="version.dll",
        state="mutation-attempted")
    try:
        FfticLifecycleComposition(
            interrupted_remove.inputs, plan_validator=lambda _plan: True)
    except RecoveryRequiredError:
        pass
    else:
        raise AssertionError("Boolean-free composition resumed an unproved removal")
    assert read_receipt(interrupted_remove.inputs.receipts_root) is not None


def test_prerequisite_failure_requires_repair_without_prefix_rollback_claim() -> None:
    blocked = Fixture("missing-prerequisite", missing_dotnet=True)
    baseline = sorted(path.relative_to(blocked.prefix).as_posix()
                      for path in blocked.prefix.rglob("*"))
    try:
        blocked.run(OperationKind.SETUP)
    except WorkflowError as exc:
        assert "no authorized prerequisite runner" in str(exc)
    else:
        raise AssertionError("Missing prerequisite ran without an injected runner")
    assert baseline == sorted(path.relative_to(blocked.prefix).as_posix()
                              for path in blocked.prefix.rglob("*"))

    failing = Fixture("fake-prerequisite-failure", missing_dotnet=True)
    runner_path = failing.root / "tools/proton"
    runner_path.parent.mkdir()
    runner_path.write_bytes(b"fake runner boundary")
    requests = []

    class FakeRunner:
        def run(self, request, cancel=None, progress=None):
            requests.append(request)
            (failing.prefix / "drive_c/fake-installer-mutation.txt").write_text(
                "mutated", encoding="utf-8")
            return ProcessResult(0, False, request.log_path)

    def request_factory(plan):
        return ProcessRequest(
            plan=plan, executable=plan.installer_path,
            executable_pin=plan.artifact, runner=runner_path,
            runner_identity=SUPPORTED_PROTON_RUNNER, prefix=failing.prefix,
            arguments=plan.arguments,
            environment=(("STEAM_COMPAT_DATA_PATH", str(failing.prefix)),
                         ("STEAM_COMPAT_CLIENT_INSTALL_PATH", str(failing.library))),
            log_path=failing.root / "logs/prerequisite.log",
            working_directory=failing.root / "logs",
            accepted_exit_codes=plan.success_exit_codes,
            restart_exit_codes=plan.restart_exit_codes,
            timeout_seconds=60, allow_flatpak_host_spawn=False,
            post_install_health_check=lambda _plan, _prefix: False)

    failing.inputs = replace(
        failing.inputs, process_runner=FakeRunner(),
        process_request_factory=request_factory)
    failing.composition = FfticLifecycleComposition(
        failing.inputs, plan_validator=lambda _plan: True)
    failing.executor = ManagedLifecycleExecutor(failing.composition)
    prefix_before = {
        path.relative_to(failing.prefix).as_posix():
        (path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in failing.prefix.rglob("*")
    }
    diagnostic = None
    try:
        failing.run(OperationKind.SETUP)
    except RecoveryRequiredError as exc:
        diagnostic = str(exc)
        assert "setup or repair" in diagnostic
        assert str(failing.root / "logs/prerequisite.log") in diagnostic
    else:
        raise AssertionError("Fake prerequisite failure reported success")
    assert len(requests) == 1
    request = requests[0]
    assert request.plan.artifact == ARTIFACTS["dotnet-desktop-runtime"]
    assert request.arguments == ("/install", "/quiet", "/norestart")
    assert request.prefix == failing.prefix
    assert prefix_before != {
        path.relative_to(failing.prefix).as_posix():
        (path.read_bytes() if path.is_file() and not path.is_symlink() else None)
        for path in failing.prefix.rglob("*")
    }
    assert (failing.prefix / "drive_c/fake-installer-mutation.txt").read_text() == "mutated"
    assert read_receipt(failing.inputs.receipts_root) is None
    assert StagedLifecycleOperations.recovery_state(
        failing.composition.journal.read_events()) == RecoveryState.RECOVERY_REQUIRED


def test_prepare_is_read_only_and_executable_inputs_are_regular() -> None:
    fixture = Fixture("read-only-prepare")
    before = _filesystem_state(fixture.root)
    fixture.composition._prepare(fixture.plan(OperationKind.SETUP), OperationKind.SETUP)
    assert _filesystem_state(fixture.root) == before

    linked = Fixture("linked-executable")
    classic = linked.game / "FFT_classic.exe"
    classic.unlink()
    classic.symlink_to(linked.game / "FFT_enhanced.exe")
    try:
        linked.run(OperationKind.SETUP)
    except WorkflowError as exc:
        assert "missing, linked, or outside" in str(exc)
    else:
        raise AssertionError("Linked FFTIC executable was hashed as installation evidence")
    assert read_receipt(linked.inputs.receipts_root) is None


def test_current_evidence_mutation_fails_closed() -> None:
    executable = Fixture("executable-mutation")
    plan = executable.plan(OperationKind.SETUP)
    (executable.game / "FFT_classic.exe").write_bytes(b"changed after planning")
    try:
        executable.executor.execute(plan)
    except WorkflowError as exc:
        assert "bytes differ" in str(exc)
    else:
        raise AssertionError("Executable mutation after planning was accepted")
    assert read_receipt(executable.inputs.receipts_root) is None

    steam = Fixture("steam-options-mutation")
    steam.run(OperationKind.SETUP)
    baseline = _owned_state(steam)
    plan = steam.plan(OperationKind.REPAIR)
    steam.steam_options_text = COPY_READY_OPTIONS + " -windowed"
    try:
        steam.executor.execute(plan)
    except WorkflowError:
        pass
    else:
        raise AssertionError("Steam Launch Options mutation was accepted")
    assert _owned_state(steam) == baseline


def test_hostile_receipt_paths_never_touch_external_targets() -> None:
    cases = ("generation", "backup-outside", "backup-symlink",
             "pac-traversal", "game-root", "prefix")
    for case in cases:
        fixture = Fixture("hostile-" + case)
        fixture.run(OperationKind.SETUP)
        external = fixture.root / f"external-{case}"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"must remain exact")

        def change(data, selected=case):
            if selected == "generation":
                data["active_generation_identity"]["root"] = str(external)
            elif selected == "backup-outside":
                record = data["owned_game_targets"][0]
                record.update(prior_state="owned exact",
                              prior_hash=hashlib.sha256(sentinel.read_bytes()).hexdigest(),
                              backup_path=str(sentinel))
            elif selected == "backup-symlink":
                link = fixture.inputs.backup_root / "linked-backup"
                link.symlink_to(sentinel)
                record = data["owned_game_targets"][0]
                record.update(prior_state="owned exact",
                              prior_hash=hashlib.sha256(sentinel.read_bytes()).hexdigest(),
                              backup_path=str(link))
            elif selected == "pac-traversal":
                data["generated_pac_observations"] = [{
                    "relative_path": "../external.pac", "sha256": "0" * 64,
                    "generation_id": data["active_generation_identity"]["generation_id"],
                    "profile_fingerprint": "profile", "launch_id": "launch",
                    "transaction_id": "transaction", "before_state": "absent",
                    "before_sha256": None,
                }]
            elif selected == "game-root":
                data["game_root_identity"]["path"] = str(external)
            else:
                data["prefix_identity"]["path"] = str(external)

        path = fixture.inputs.receipts_root / "fftic-receipt.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        # Traversal is intentionally rejected by the receipt schema itself.
        if case == "pac-traversal":
            path.write_text(json.dumps(data), encoding="utf-8")
        else:
            path.write_bytes(serialize_receipt(data))
        try:
            fixture.run(OperationKind.REMOVE)
        except Exception:
            pass
        else:
            raise AssertionError(f"Hostile {case} receipt was accepted")
        assert sentinel.read_bytes() == b"must remain exact"


def _add_pac(fixture: Fixture, *, present: bool, correlated: bool,
             drift: bool = False) -> Path:
    receipt = read_receipt(fixture.inputs.receipts_root)
    generation = receipt.data["active_generation_identity"]["generation_id"]
    fingerprint = profile_fingerprint(receipt.data["user_packages"])
    evidence = PacLaunchEvidence(generation, fingerprint, "launch", "pac-transaction")
    target = fixture.game / "data/classic/modded.pac"
    owned = b"owned generated pac"
    if present:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"drift" if drift else owned)
    _rewrite_receipt(fixture, lambda data: data.update(
        generated_pac_observations=[{
            "relative_path": "data/classic/modded.pac",
            "sha256": hashlib.sha256(owned).hexdigest(),
            "generation_id": generation, "profile_fingerprint": fingerprint,
            "launch_id": "launch", "transaction_id": "pac-transaction",
            "before_state": "absent", "before_sha256": None,
        }]))
    fixture.recompose(pac_launch_evidence=(evidence,) if correlated else ())
    return target


def test_pac_removal_dispositions() -> None:
    exact = Fixture("pac-exact")
    exact.run(OperationKind.SETUP)
    target = _add_pac(exact, present=True, correlated=True)
    exact.run(OperationKind.REMOVE)
    assert not target.exists() and read_receipt(exact.inputs.receipts_root) is None

    absent = Fixture("pac-absent")
    absent.run(OperationKind.SETUP)
    _add_pac(absent, present=False, correlated=False)
    absent.run(OperationKind.REMOVE)
    assert read_receipt(absent.inputs.receipts_root) is None

    for name, correlated, drift in (("uncorrelated", False, False),
                                    ("drift", True, True)):
        fixture = Fixture("pac-" + name)
        fixture.run(OperationKind.SETUP)
        target = _add_pac(fixture, present=True, correlated=correlated, drift=drift)
        receipt_before = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
        payload = target.read_bytes()
        try:
            fixture.run(OperationKind.REMOVE)
        except RecoveryRequiredError:
            pass
        else:
            raise AssertionError(f"{name} PAC removal did not require recovery")
        assert target.read_bytes() == payload
        assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_before


def test_preexisting_backup_survives_failed_removal() -> None:
    def fail(name, kind):
        if kind == OperationKind.REMOVE and name == "remove:version.dll":
            raise RuntimeError("after first restored target")
    fixture = Fixture("preexisting-backup", failure_injector=fail)
    fixture.run(OperationKind.SETUP)
    prior = b"preexisting version bytes"
    backup = fixture.inputs.backup_root / "preexisting/version.dll"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(prior)
    _rewrite_receipt(fixture, lambda data: data["owned_game_targets"][0].update(
        prior_state="owned exact", prior_hash=hashlib.sha256(prior).hexdigest(),
        backup_path=str(backup)))
    fixture.recompose(failure_injector=fail)
    baseline = _owned_state(fixture)
    try:
        fixture.run(OperationKind.REMOVE)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Injected failed removal reported success")
    assert _owned_state(fixture) == baseline
    assert backup.read_bytes() == prior


def test_cleanup_and_cross_operation_failure_boundaries() -> None:
    successful = Fixture("cleanup-success")
    successful.run(OperationKind.SETUP)
    snapshots = successful.inputs.backup_root / "prefix-snapshots"
    assert not snapshots.exists()
    (successful.profile / "modlist.txt").write_text("-High\n+Low\n-Disabled\n", encoding="utf-8")
    successful.run(OperationKind.SYNCHRONIZE)
    transaction_backups = successful.inputs.backup_root / "transaction-backups"
    assert not transaction_backups.exists() or not any(transaction_backups.iterdir())

    def fail_setup(name, kind):
        if kind == OperationKind.SETUP and name == "generation":
            raise RuntimeError("owned generation rollback")
    failed_setup = Fixture("cleanup-failed-setup", failure_injector=fail_setup)
    try:
        failed_setup.run(OperationKind.SETUP)
    except RuntimeError:
        pass
    assert not (failed_setup.inputs.backup_root / "prefix-snapshots").exists()
    assert read_receipt(failed_setup.inputs.receipts_root) is None

    def fail_cleanup(name, _kind):
        if name == "cleanup":
            raise RuntimeError("cleanup failed")
    cleanup = Fixture("cleanup-failure", failure_injector=fail_cleanup)
    try:
        cleanup.run(OperationKind.SETUP)
    except RecoveryRequiredError:
        pass
    else:
        raise AssertionError("Cleanup failure was reported as success")
    assert read_receipt(cleanup.inputs.receipts_root) is None

    repair = Fixture("repair-failure")
    repair.run(OperationKind.SETUP)
    (repair.game / "version.dll").unlink()
    baseline = _owned_state(repair)
    def fail_repair(name, kind):
        if kind == OperationKind.REPAIR and name == "bootstrap:version.dll":
            raise RuntimeError("repair boundary")
    repair.recompose(failure_injector=fail_repair)
    try:
        repair.run(OperationKind.REPAIR)
    except RuntimeError:
        pass
    assert _owned_state(repair) == baseline

    for point in ("generation", "activation", "receipt", "final-verifier"):
        sync = Fixture("sync-failure-" + point)
        sync.run(OperationKind.SETUP)
        (sync.profile / "modlist.txt").write_text("-High\n+Low\n-Disabled\n", encoding="utf-8")
        baseline = _owned_state(sync)
        def fail_sync(name, kind, selected=point):
            if kind == OperationKind.SYNCHRONIZE and name == selected:
                raise RuntimeError("synchronize boundary " + selected)
        sync.recompose(failure_injector=fail_sync)
        try:
            sync.run(OperationKind.SYNCHRONIZE)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Synchronize {point} failure reported success")
        after = _owned_state(sync)
        assert after == baseline, (
            point, {key: (baseline[key], after[key]) for key in baseline
                    if baseline[key] != after[key]})

    rollback = Fixture("rollback-verifier-failure")
    def fail_rollback(name, kind):
        if kind == OperationKind.SETUP and name in {"generation", "rollback-verifier"}:
            raise RuntimeError(name)
    rollback.recompose(failure_injector=fail_rollback)
    try:
        rollback.run(OperationKind.SETUP)
    except RecoveryRequiredError:
        pass
    else:
        raise AssertionError("Rollback verifier failure did not require recovery")


def test_removal_failure_boundaries_restore_exact_owned_state() -> None:
    points = (
        "remove:version.dll",
        "remove:Reloaded.Mod.Loader.Bootstrapper.asi",
        "remove:prefix-configuration",
        "remove:pac:data/classic/modded.pac",
        "remove:generation",
        "remove:active-state",
        "remove:before-receipt",
        "final-verifier",
    )
    for point in points:
        fixture = Fixture("remove-failure-" + point.replace("/", "-").replace(":", "-"))
        fixture.run(OperationKind.SETUP)
        if point.startswith("remove:pac:"):
            _add_pac(fixture, present=True, correlated=True)
        def fail(name, kind, selected=point):
            if kind == OperationKind.REMOVE and name == selected:
                raise RuntimeError("remove boundary " + selected)
        fixture.recompose(failure_injector=fail)
        baseline = _owned_state(fixture)
        try:
            fixture.run(OperationKind.REMOVE)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Removal {point} failure reported success")
        after = _owned_state(fixture)
        assert after == baseline, (
            point, {key: (baseline[key], after[key]) for key in baseline
                    if baseline[key] != after[key]})


def test_production_handler_uses_guarded_composition() -> None:
    source = Path(__file__).with_name("final_fantasy_tactics.py").read_text(encoding="utf-8")
    assert "executor_factory=create_production_executor" in source
    assert "ManagedLifecycleExecutor" not in source
    assert "FfticLifecycleComposition" not in source


def main() -> None:
    tests = (
        test_complete_setup_repair_synchronize_update_and_remove,
        test_collisions_drift_duplicates_and_missing_inputs_fail_closed,
        test_cancellation_failure_rollback_and_restart_evidence,
        test_prerequisite_failure_requires_repair_without_prefix_rollback_claim,
        test_prepare_is_read_only_and_executable_inputs_are_regular,
        test_current_evidence_mutation_fails_closed,
        test_hostile_receipt_paths_never_touch_external_targets,
        test_pac_removal_dispositions,
        test_preexisting_backup_survives_failed_removal,
        test_cleanup_and_cross_operation_failure_boundaries,
        test_removal_failure_boundaries_restore_exact_owned_state,
        test_production_handler_uses_guarded_composition,
    )
    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__}")
        finally:
            for root in FIXTURE_ROOTS:
                shutil.rmtree(root, ignore_errors=True)
            FIXTURE_ROOTS.clear()
    print("All FFTIC Phase C3C isolated lifecycle checks passed.")


if __name__ == "__main__":
    main()
