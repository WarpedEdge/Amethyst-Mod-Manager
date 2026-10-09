"""Hermetic checks for FFTIC production composition and action wiring."""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fftic_artifacts import ARTIFACTS
from fftic_detection import VERIFIED_STEAM_BUILD
from fftic_managed_executor import ManagedOperationError
from fftic_orchestration import (
    FFTIC_GAME_ID, FfticOrchestrator, FfticStatusViewModel, InspectionContext,
    InspectionResult, OperationKind, StatusRow, StatusSeverity,
    _PREREQUISITE_RUNNER_BLOCKER, _action_availability,
    _journal_recovery_status,
)
from fftic_production import create_production_executor
from fftic_prerequisites import (
    DOTNET_COMPONENT, classify_prerequisite, plan_installer,
)
from fftic_readiness import ReadinessAspect, SUPPORTED_PROTON_RUNNER
from fftic_steam_requirements import COPY_READY_OPTIONS


class Fixture:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="amethyst-fftic-c3d-")).resolve()
        self.library = self.root / "library"
        self.game_root = self.library / "steamapps/common/FFTIC"
        self.prefix = self.root / "prefix"
        self.profile = self.root / "profiles/default"
        self.staging = self.root / "staging"
        self.download_root = self.root / "download-cache"
        for path in (
                self.game_root, self.prefix / "drive_c", self.prefix / "dosdevices",
                self.profile, self.staging):
            path.mkdir(parents=True, exist_ok=True)
        for name in ("FFT_classic.exe", "FFT_enhanced.exe"):
            (self.game_root / name).write_bytes(b"isolated-c3d-executable")
        self.manifest = self.library / "steamapps/appmanifest_1004640.acf"
        self.manifest.write_text(
            '"AppState"\n{\n"appid" "1004640"\n"installdir" "FFTIC"\n'
            f'"buildid" "{VERIFIED_STEAM_BUILD}"\n}}\n', encoding="utf-8")
        (self.prefix / "dosdevices/s:").symlink_to(
            self.library, target_is_directory=True)
        (self.profile / "modlist.txt").write_text("", encoding="utf-8")
        self.game = SimpleNamespace(
            game_id=FFTIC_GAME_ID,
            name="FFTIC fixture",
            steam_id="1004640",
            get_game_path=lambda: self.game_root,
            get_prefix_path=lambda: self.prefix,
        )
        self.cache = self.download_root / self.game.name / "fftic-reviewed"
        self.context = InspectionContext(
            self.game, "default", self.profile, self.staging)


def _row(key: str, state: str = "Ready") -> StatusRow:
    return StatusRow(key, key, state, StatusSeverity.READY, state)


def _inventory(*roots: Path) -> tuple[tuple[str, str, bytes | str], ...]:
    records = []
    for root in roots:
        if not os.path.lexists(root):
            records.append((str(root), "absent", ""))
            continue
        for path in (root, *sorted(root.rglob("*"), key=str)):
            if path.is_symlink():
                records.append((str(path), "symlink", os.readlink(path)))
            elif path.is_file():
                records.append((str(path), "file", path.read_bytes()))
            elif path.is_dir():
                records.append((str(path), "directory", ""))
            else:
                records.append((str(path), "special", ""))
    return tuple(records)


def test_composition_derives_owned_paths_and_delays_acquisition() -> None:
    fixture = Fixture()
    calls = []
    xdg = fixture.root / "xdg"
    config = xdg / "AmethystModManager"
    config.mkdir(parents=True)
    (config / "amethyst.ini").write_text(
        "[paths]\n"
        f"download_cache_path = {fixture.download_root}\n", encoding="utf-8")

    def acquire(pin, cache, **kwargs):
        calls.append((pin, Path(cache), kwargs))
        path = Path(cache) / pin.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fake downloader output")
        return SimpleNamespace(path=path)

    managed_parent = fixture.prefix / "drive_c/Amethyst"
    before = _inventory(fixture.download_root, fixture.prefix / "drive_c")
    previous_xdg = os.environ.get("XDG_CONFIG_HOME")
    os.environ["XDG_CONFIG_HOME"] = str(xdg)
    try:
        executor, reason = create_production_executor(
            fixture.context, lambda _plan: True, artifact_acquire=acquire)
    finally:
        if previous_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = previous_xdg
    assert executor is not None, reason
    assert calls == []
    assert _inventory(fixture.download_root, fixture.prefix / "drive_c") == before
    assert not fixture.cache.exists()
    assert not managed_parent.exists()
    inputs = executor._operations.inputs
    managed = fixture.prefix / "drive_c/Amethyst/FFTIC"
    assert inputs.generations_root == managed / "generations"
    assert inputs.backup_root == managed / "backups"
    assert inputs.quarantine_root == managed / "quarantine"
    assert inputs.receipts_root == managed / "receipts"
    assert inputs.journal_file == managed / "journal/lifecycle.json"
    assert inputs.log_root == managed / "logs"
    assert inputs.process_runner is not None
    assert inputs.process_request_factory is not None
    assert inputs.setup_candidates is None
    runner = fixture.root / "steam/steamapps/common/Proton - Experimental/proton"
    runner.parent.mkdir(parents=True)
    runner.write_text("fixture", encoding="utf-8")
    (runner.parent / "version").write_text(
        f"1 {SUPPORTED_PROTON_RUNNER}\n", encoding="utf-8")
    (fixture.root / "steam/steamapps/appmanifest_1493710.acf").write_text(
        '"AppState"\n{\n"appid" "1493710"\n'
        '"installdir" "Proton - Experimental"\n}\n',
        encoding="utf-8")
    selected = SimpleNamespace(proton_script=runner,
        tool_identity=SUPPORTED_PROTON_RUNNER, prefix_runtime="11.0-100")
    with patch("fftic_production.resolve_proton_selection",
               return_value=selected) as resolver:
        assert inputs.runner_reader() == SUPPORTED_PROTON_RUNNER
    resolver.assert_called_once_with(fixture.game.steam_id, fixture.prefix)
    stable = fixture.root / "steam/steamapps/common/Proton 9.0/proton"
    stable.parent.mkdir(parents=True)
    stable.write_text("fixture", encoding="utf-8")
    (stable.parent / "version").write_text("1 proton-9.0-4f\n", encoding="utf-8")
    (fixture.root / "steam/steamapps/appmanifest_2805730.acf").write_text(
        '"AppState" { "appid" "2805730" "installdir" "Proton 9.0" }',
        encoding="utf-8")
    alternate = SimpleNamespace(proton_script=stable, tool_identity="proton-9.0-4f",
                                prefix_runtime="9.0-200")
    with patch("fftic_production.resolve_proton_selection", return_value=alternate):
        assert inputs.runner_reader() == "proton-9.0-4f"
    health = SimpleNamespace(
        dotnet_desktop=SimpleNamespace(state=SimpleNamespace(value="sufficient")),
        vc_runtime=SimpleNamespace(state=SimpleNamespace(value="sufficient")))
    with patch("fftic_production.inspect_prefix_prerequisites", return_value=health):
        candidates = inputs.artifact_acquirer(None)
    runtime_pins = {
        artifact_id: pin for artifact_id, pin in ARTIFACTS.items()
        if pin.disposition.value == "extract"
    }
    assert set(candidates.paths()) == set(runtime_pins)
    assert [call[0] for call in calls] == list(runtime_pins.values())
    assert all(call[1] == fixture.cache for call in calls)
    assert all(call[2]["quarantine_root"] == inputs.artifact_cache / "quarantine"
               for call in calls)


def test_invalid_composition_keeps_read_only_status() -> None:
    fixture = Fixture()
    fixture.game.get_prefix_path = lambda: None

    class Inspector:
        def inspect(self, _context, cancel=None, progress=None):
            return InspectionResult(
                (_row("recovery"),), (), (), COPY_READY_OPTIONS, (), False, False,
                available_actions=(OperationKind.SETUP.value,))

    controller = FfticOrchestrator(
        Inspector(), executor_factory=create_production_executor)
    model = controller.refresh(fixture.context)
    assert not controller.mutation_available
    assert "Select a FFTIC Proton prefix" in model.mutation_unavailable_reason
    assert model.rows[0].key == "recovery"


def test_prerequisite_acquisition_matrix_and_host_capability() -> None:
    fixture = Fixture()
    calls = []

    def acquire(pin, cache, **_kwargs):
        calls.append(pin.artifact_id)
        path = Path(cache) / pin.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic")
        return SimpleNamespace(path=path)

    executor, reason = create_production_executor(
        fixture.context, lambda _plan: True, artifact_acquire=acquire,
        cache_root=fixture.cache)
    assert executor is not None, reason
    acquire_candidates = executor._operations.inputs.artifact_acquirer
    extract_ids = {artifact_id for artifact_id, pin in ARTIFACTS.items()
                   if pin.disposition.value == "extract"}

    def health(dotnet, vc):
        def item(component, value):
            return SimpleNamespace(
                component=component, state=SimpleNamespace(value=value))
        return SimpleNamespace(
            dotnet_desktop=item(".NET Desktop Runtime", dotnet),
            vc_runtime=item("VC++ Runtime", vc))

    cases = (
        (("missing", "missing"), {"dotnet-desktop-runtime", "vc-runtime"}),
        (("missing", "sufficient"), {"dotnet-desktop-runtime"}),
        (("sufficient", "missing"), {"vc-runtime"}),
        (("sufficient", "sufficient"), set()),
        (("insufficient", "sufficient"), {"dotnet-desktop-runtime"}),
    )
    for states, installers in cases:
        calls.clear()
        with patch("fftic_production.inspect_prefix_prerequisites",
                   return_value=health(*states)):
            candidates = acquire_candidates(None)
        assert set(candidates.paths()) == extract_ids | installers
        assert set(calls) == extract_ids | installers

    for unsafe in ("unknown", "unhealthy"):
        with patch("fftic_production.inspect_prefix_prerequisites",
                   return_value=health(unsafe, "sufficient")):
            try:
                acquire_candidates(None)
            except ValueError as exc:
                assert unsafe in str(exc)
            else:
                raise AssertionError(f"{unsafe} prerequisite health was acquired")

    calls.clear()
    with patch("fftic_production.inspect_prefix_prerequisites",
               return_value=health("missing", "sufficient")), \
            patch("fftic_production.prerequisite_host_capability",
                  return_value=(False, "host portal denied")) as capability:
        try:
            acquire_candidates(None)
        except ValueError as exc:
            assert "host portal denied" in str(exc)
        else:
            raise AssertionError("Installer-dependent acquisition ignored host capability")
    capability.assert_called_once_with(probe=True)
    assert calls == []

    with patch("fftic_prerequisites.prerequisite_host_capability",
               side_effect=AssertionError("status-only capability check leaked into factory")):
        still_available, unavailable_reason = create_production_executor(
            fixture.context, lambda _plan: True, cache_root=fixture.cache)
    assert still_available is not None and not unavailable_reason


def test_production_request_binds_exact_proton_prefix_and_steam_context() -> None:
    fixture = Fixture()
    fixture.cache.mkdir(parents=True)
    installer = fixture.cache / ARTIFACTS["dotnet-desktop-runtime"].filename
    installer.write_bytes(b"synthetic request candidate")
    runner = fixture.root / "steam/steamapps/common/Proton - Experimental/proton"
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/usr/bin/python3\n", encoding="utf-8")
    (runner.parent / "version").write_text(
        f"1 {SUPPORTED_PROTON_RUNNER}\n", encoding="utf-8")
    (fixture.root / "steam/steamapps/appmanifest_1493710.acf").write_text(
        '"AppState"\n{\n"appid" "1493710"\n'
        '"installdir" "Proton - Experimental"\n}\n',
        encoding="utf-8")
    steam_client = fixture.root / "steam"
    steam_alias = fixture.root / "alias/root"
    steam_alias.parent.mkdir()
    steam_alias.symlink_to(steam_client, target_is_directory=True)
    selection = SimpleNamespace(
        proton_script=runner, tool_identity=SUPPORTED_PROTON_RUNNER,
        prefix_runtime="11.0-100")
    with patch("fftic_production.resolve_proton_selection",
               return_value=selection), \
            patch("Utils.launchers.steam.find_steam_root_for_proton_script",
                  return_value=steam_alias):
        executor, reason = create_production_executor(
            fixture.context, lambda _plan: True, cache_root=fixture.cache)
        assert executor is not None, reason
        health = classify_prerequisite(
            component=DOTNET_COMPONENT, required_version="9.0.20",
            observed_version=None, healthy=True, present=False)
        plan = plan_installer(
            artifact_id="dotnet-desktop-runtime", installer_path=installer,
            prefix=fixture.prefix, runner_identity=SUPPORTED_PROTON_RUNNER,
            health=health)
        request = executor._operations.inputs.process_request_factory(plan)
    environment = dict(request.environment)
    assert request.executable == installer
    assert request.executable_pin == ARTIFACTS["dotnet-desktop-runtime"]
    assert request.runner == runner and request.prefix == fixture.prefix
    assert request.arguments == ("/install", "/quiet", "/norestart")
    assert request.accepted_exit_codes == (0,)
    assert request.restart_exit_codes == (3010, 194)
    assert environment["STEAM_COMPAT_DATA_PATH"] == str(fixture.prefix.parent)
    assert environment["STEAM_COMPAT_CLIENT_INSTALL_PATH"] == str(steam_client)
    assert all(environment[key] == "1004640" for key in (
        "SteamAppId", "SteamGameId", "SteamOverlayGameId",
        "STEAM_COMPAT_APP_ID"))
    assert request.log_path.parent == fixture.prefix / "drive_c/Amethyst/FFTIC/logs"
    with patch("fftic_managed_executor.validate_file", return_value=True):
        replace(request, allow_flatpak_host_spawn=False).validate()

    unsafe_environment = tuple(
        (key, str(steam_alias) if key == "STEAM_COMPAT_CLIENT_INSTALL_PATH" else value)
        for key, value in request.environment)
    with patch("fftic_managed_executor.validate_file", return_value=True):
        try:
            replace(
                request, environment=unsafe_environment,
                allow_flatpak_host_spawn=False).validate()
        except ManagedOperationError as exc:
            assert "Steam client root crosses a symbolic link" in str(exc)
        else:
            raise AssertionError("ProcessRequest accepted an unresolved Steam alias")

    missing_alias = fixture.root / "alias/missing-root"
    missing_alias.symlink_to(fixture.root / "missing-steam", target_is_directory=True)
    with patch("fftic_production.resolve_proton_selection",
               return_value=selection), \
            patch("Utils.launchers.steam.find_steam_root_for_proton_script",
               return_value=missing_alias):
        try:
            executor._operations.inputs.process_request_factory(plan)
        except ValueError as exc:
            assert "Steam client root" in str(exc) and "unavailable" in str(exc)
        else:
            raise AssertionError("Missing Steam client target was accepted")

    unrelated_compatdata = fixture.root / "other-compatdata"
    unrelated_compatdata.mkdir()
    with patch("fftic_production.resolve_proton_selection",
               return_value=selection), \
            patch("Utils.launchers.steam.find_steam_root_for_proton_script",
               return_value=steam_alias), \
            patch("Utils.wine.prefix.resolve_compat_data",
                  return_value=unrelated_compatdata):
        try:
            executor._operations.inputs.process_request_factory(plan)
        except ValueError as exc:
            assert "does not belong" in str(exc)
        else:
            raise AssertionError("Unrelated compatdata root was accepted")

    wrong = SimpleNamespace(
        proton_script=runner, tool_identity="wrong-proton", prefix_runtime="11.0-100")
    with patch("fftic_production.resolve_proton_selection", return_value=wrong):
        try:
            executor._operations.inputs.process_request_factory(plan)
        except ValueError as exc:
            assert "identity changed" in str(exc)
        else:
            raise AssertionError("Wrong selected Proton identity was accepted")


def test_action_gating_and_prerequisite_blocker() -> None:
    setup_rows = tuple(_row(key, "Configured" if key == "steam_options" else "Ready")
                       for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                                   "steam_options", "recovery")) + (
        *tuple(_row(key, "Not installed") for key in (
            "runtime", "nenkai", "sigscan", "hooks")),
        _row("bootstrap", "Not installed"),
        _row("prefix_config", "Not installed"),
    )
    actions, reasons = _action_availability(
        setup_rows, receipt_present=False, verification=None, unsupported=())
    assert actions == (OperationKind.SETUP.value,)
    unverified_runner = tuple(
        _row(row.key, "Unverified") if row.key == "runner" else row
        for row in setup_rows)
    actions, _reasons = _action_availability(
        unverified_runner, receipt_present=False, verification=None, unsupported=())
    assert OperationKind.SETUP.value in actions
    assert OperationKind.UPDATE.value not in actions
    assert "No newer reviewed loader asset" in dict(reasons)["update"]

    missing = tuple(
        _row(row.key, "Not installed") if row.key == "dotnet" else row
        for row in setup_rows)
    actions, reasons = _action_availability(
        missing, receipt_present=False, verification=None, unsupported=())
    assert OperationKind.SETUP.value in actions

    actions, reasons = _action_availability(
        missing, receipt_present=False, verification=None, unsupported=(),
        prerequisite_host_available=False,
        prerequisite_host_reason="flatpak-spawn unavailable")
    assert OperationKind.SETUP.value not in actions
    assert dict(reasons)["setup"] == "flatpak-spawn unavailable"

    actions, _reasons = _action_availability(
        setup_rows, receipt_present=False, verification=None, unsupported=(),
        prerequisite_host_available=False,
        prerequisite_host_reason="flatpak-spawn unavailable")
    assert OperationKind.SETUP.value in actions

    unknown = tuple(
        _row(row.key, "Unverified") if row.key == "dotnet" else row
        for row in setup_rows)
    actions, reasons = _action_availability(
        unknown, receipt_present=False, verification=None, unsupported=())
    assert OperationKind.SETUP.value not in actions
    assert dict(reasons)["setup"] == _PREREQUISITE_RUNNER_BLOCKER


def test_host_unavailable_does_not_block_noninstaller_actions() -> None:
    foundation = tuple(
        _row(key, "Configured" if key == "steam_options" else "Ready")
        for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                    "steam_options", "recovery", "profile"))
    managed_keys = (
        "runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config")
    repair_rows = foundation + tuple(
        _row(key, "Not installed" if key == "bootstrap" else "Ready")
        for key in managed_keys)
    actions, _reasons = _action_availability(
        repair_rows, receipt_present=True, verification=None, unsupported=(),
        prerequisite_host_available=False,
        prerequisite_host_reason="flatpak-spawn unavailable")
    assert OperationKind.REPAIR.value in actions

    protected = dict(
        game=ReadinessAspect.READY, artifacts=ReadinessAspect.READY,
        generation=ReadinessAspect.READY, prefix=ReadinessAspect.READY,
        prerequisites=ReadinessAspect.READY, bootstrap=ReadinessAspect.READY,
        steam_options=ReadinessAspect.READY, recovery=ReadinessAspect.READY,
        attested=True)
    synchronized = SimpleNamespace(
        **protected, profile=ReadinessAspect.READY, ready=True)
    actions, _reasons = _action_availability(
        foundation + tuple(_row(key) for key in managed_keys),
        receipt_present=True, verification=synchronized, unsupported=(),
        prerequisite_host_available=False,
        prerequisite_host_reason="flatpak-spawn unavailable")
    assert OperationKind.REMOVE.value in actions

    stale_profile = SimpleNamespace(
        **protected, profile=ReadinessAspect.INVALID, ready=False)
    actions, _reasons = _action_availability(
        foundation + tuple(_row(key) for key in managed_keys),
        receipt_present=True, verification=stale_profile, unsupported=(),
        prerequisite_host_available=False,
        prerequisite_host_reason="flatpak-spawn unavailable")
    assert OperationKind.SYNCHRONIZE.value in actions


def test_retryable_and_genuine_recovery_journal_status() -> None:
    fixture = Fixture()
    managed = fixture.prefix / "drive_c/Amethyst/FFTIC"
    from fftic_transaction_executor import FileTransactionJournal
    journal = FileTransactionJournal(managed / "journal/lifecycle.json")
    journal.record(
        plan_fingerprint="retry", attempt_id="retry", operation="setup",
        step=0, phase="prerequisite", state="prerequisite-retryable",
        original_error="Retry Setup and review /tmp/prerequisite.log")
    required, retry, error = _journal_recovery_status(managed)
    assert not required and "Retry Setup" in retry and not error

    journal.record(
        plan_fingerprint="managed", attempt_id="managed", operation="setup",
        step=0, phase="bootstrap", state="mutation-attempted")
    required, retry, error = _journal_recovery_status(managed)
    assert required and not retry and not error


def test_repair_gating_covers_every_managed_component() -> None:
    foundation = tuple(
        _row(key, "Configured" if key == "steam_options" else "Ready")
        for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                    "steam_options", "recovery", "profile"))
    managed_keys = (
        "runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config")
    for missing_key in managed_keys:
        managed = tuple(_row(
            key, "Not installed" if key == missing_key else "Ready")
            for key in managed_keys)
        actions, _reasons = _action_availability(
            foundation + managed, receipt_present=True,
            verification=None, unsupported=())
        assert OperationKind.REPAIR.value in actions, missing_key


def test_reconciliation_is_narrowly_gated_from_genuine_recovery() -> None:
    foundation = tuple(
        _row(key, "Configured" if key == "steam_options" else
             "Runtime output confirmation required" if key == "recovery" else "Ready")
        for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                    "steam_options", "recovery", "profile"))
    legacy_components = tuple(
        _row(key, "Runtime reconciliation required")
        for key in ("runtime", "nenkai", "sigscan", "hooks"))
    protected = tuple(_row(key) for key in ("bootstrap", "prefix_config"))
    pending = foundation + legacy_components + protected + (
        _row("reconciliation", "Runtime rebuild required"),)
    actions, _reasons = _action_availability(
        pending, receipt_present=True, verification=None, unsupported=())
    assert actions == (OperationKind.RECONCILE_RUNTIME_OUTPUT.value,)

    output_pending = foundation + tuple(
        _row(key) for key in (
            "runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config")) + (
        _row("reconciliation", "Runtime output confirmation required"),)
    actions, _reasons = _action_availability(
        output_pending, receipt_present=True, verification=None, unsupported=())
    assert actions == (OperationKind.RECONCILE_RUNTIME_OUTPUT.value,)

    conflict = tuple(_row(
        row.key, "Recovery required" if row.key == "recovery" else
        "Conflict" if row.key == "bootstrap" else row.state)
        for row in pending)
    actions, _reasons = _action_availability(
        conflict, receipt_present=True, verification=None, unsupported=())
    assert OperationKind.RECONCILE_RUNTIME_OUTPUT.value not in actions
    assert OperationKind.SETUP.value not in actions


def test_panel_enables_only_current_actions() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui_qt.fftic_status import FfticStatusPanel

    app = QApplication.instance() or QApplication([])
    panel = FfticStatusPanel()
    reasons = tuple((kind.value, f"blocked {kind.value}") for kind in OperationKind)
    panel.set_status(FfticStatusViewModel(
        FFTIC_GAME_ID, "FFTIC", (_row("recovery"),), (), (),
        COPY_READY_OPTIONS, (), False, False, True, "", "Launch from Steam",
        available_actions=("setup",), action_unavailable_reasons=reasons))
    assert panel._action_buttons["setup"].isEnabled()
    assert not panel._action_buttons["repair"].isEnabled()
    assert not panel._action_buttons["synchronize"].isEnabled()
    assert not panel._action_buttons["update"].isEnabled()
    assert not panel._action_buttons["remove"].isEnabled()
    assert not panel._action_buttons["reconcile_runtime_output"].isEnabled()
    assert "blocked update" in panel._action_buttons["update"].toolTip()
    panel.set_operation(True)
    assert not any(button.isEnabled() for button in panel._action_buttons.values())
    panel.set_operation(False)
    assert panel._action_buttons["setup"].isEnabled()

    panel.set_status(FfticStatusViewModel(
        FFTIC_GAME_ID, "FFTIC", (
            _row("reconciliation", "Runtime rebuild required"),
            _row("recovery", "Runtime output confirmation required"),
        ), (), (), COPY_READY_OPTIONS, (), False, False, True, "",
        "Confirm the recoverable runtime rebuild",
        available_actions=(OperationKind.RECONCILE_RUNTIME_OUTPUT.value,),
        action_unavailable_reasons=reasons))
    panel.resize(900, panel.sizeHint().height())
    panel.show()
    app.processEvents()
    reconcile = panel._action_buttons["reconcile_runtime_output"]
    assert reconcile.isVisible() and panel._copy.isVisible()
    assert not reconcile.geometry().intersects(panel._copy.geometry())
    assert reconcile.isEnabled()
    assert panel._copy.isEnabled()
    panel._copy.click()
    assert app.clipboard().text() == COPY_READY_OPTIONS
    panel.close()
    app.processEvents()


def test_setup_confirmation_keeps_steam_manual_and_shared_runtimes() -> None:
    from gui_qt.app import _FFTIC_SETUP_CONFIRMATION
    assert "downloads the exact pinned" in _FFTIC_SETUP_CONFIRMATION
    assert ".NET Desktop Runtime and VC++ Runtime" in _FFTIC_SETUP_CONFIRMATION
    assert "remain" in _FFTIC_SETUP_CONFIRMATION
    assert "Steam Launch Options remain manual" in _FFTIC_SETUP_CONFIRMATION
    assert "never edit Steam configuration" in _FFTIC_SETUP_CONFIRMATION


def test_post_launch_focus_is_distinct_from_read_only_recheck() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from gui_qt.app import MainWindow
    from gui_qt.fftic_status import FfticStatusPanel

    app = QApplication.instance() or QApplication([])
    calls = []
    host = SimpleNamespace(_fftic_initial_status_ready=True,
                           _refresh_fftic_status=lambda **kw: calls.append(kw))
    MainWindow._on_fftic_application_state_changed(host, Qt.ApplicationInactive)
    assert calls == []
    MainWindow._on_fftic_application_state_changed(host, Qt.ApplicationActive)
    assert calls == [{"auto_reconcile": True}]

    panel = FfticStatusPanel()
    panel.recheck_requested.connect(lambda: calls.append({"read_only": True}))
    panel._recheck.click()
    assert calls[-1] == {"read_only": True}
    assert "without changing managed game files" in panel._recheck.toolTip()
    assert "notice may be saved" in panel._recheck.toolTip()
    panel.close()
    app.processEvents()


def test_automatic_status_ready_attempts_once_after_failure() -> None:
    from gui_qt.app import MainWindow

    planned = []
    started = []
    shown = []
    notices = []
    refreshed = []
    plan = object()
    controller = SimpleNamespace(plan=lambda kind: (planned.append(kind), plan)[1])
    panel = SimpleNamespace(set_status=lambda model: shown.append(model))
    host = SimpleNamespace(
        _fftic_status_gen=7, _fftic_status=panel,
        _fftic_status_cancel=object(), _fftic_status_controller=controller,
        _fftic_operation_active=False, _fftic_operation_cancel=None,
        _fftic_refresh_pending=False, _fftic_auto_operation=False,
        _fftic_auto_attempted=set(),
        _execute_fftic_plan=lambda selected, selected_plan:
            started.append((selected, selected_plan)),
        _notify=lambda message, level: notices.append((message, level)),
        _append_log=lambda message: None,
        _refresh_fftic_status=lambda **kw: refreshed.append(kw or True),
        tr=lambda message: message,
    )
    model = SimpleNamespace(error=None)

    MainWindow._on_fftic_status_ready(host, 7, (model, "completed-log-hash"))
    assert planned == [OperationKind.RECONCILE_RUNTIME_OUTPUT]
    assert started == [(controller, plan)]
    assert host._fftic_auto_attempted == {"completed-log-hash"}
    assert host._fftic_auto_operation

    MainWindow._on_fftic_operation_ready(host, 7, None, RuntimeError("synthetic failure"))
    assert not host._fftic_auto_operation
    assert notices == [(
        "Could not save FFTIC state: synthetic failure. Close FFTIC and review FFTIC status details.", "error")]
    assert refreshed == [True]

    MainWindow._on_fftic_status_ready(host, 7, (model, "completed-log-hash"))
    assert planned == [OperationKind.RECONCILE_RUNTIME_OUTPUT]
    assert started == [(controller, plan)]
    assert shown == [model, model]
    # Mod-state saving selects a different operation and then allows a fresh
    # independent PAC probe; the same state evidence cannot loop after failure.
    state_key = ('save_mod_state', 'state-hash')
    MainWindow._on_fftic_status_ready(host, 7, (model, state_key))
    assert planned[-1] == OperationKind.SAVE_MOD_STATE
    result = SimpleNamespace(plan=SimpleNamespace(kind=OperationKind.SAVE_MOD_STATE))
    MainWindow._on_fftic_operation_ready(host, 7, result, None)
    assert notices[-1] == ('FFTIC mod state saved.', 'info')
    assert refreshed[-1] == {'auto_reconcile': True}
    before = len(planned)
    MainWindow._on_fftic_status_ready(host, 7, (model, state_key))
    assert len(planned) == before


def test_release_notice_once_across_rechecks_and_restart() -> None:
    from gui_qt.app import MainWindow
    from fftic_loader_releases import LoaderRelease
    from Utils import config_paths

    release = LoaderRelease("1.7.5", 399774110, 600208145, "", 0, "",
                            "https://github.com/Nenkai/fftivc.utility.modloader/releases", True)
    notices = []
    host = SimpleNamespace(
        _fftic_status_gen=3, _fftic_status=SimpleNamespace(set_status=lambda _model: None),
        _fftic_status_cancel=None, _fftic_operation_active=False,
        _fftic_auto_attempted=set(), _notify=lambda message, kind: notices.append((message, kind)),
        _append_log=lambda _message: None, tr=lambda message: message)
    with tempfile.TemporaryDirectory(prefix="fftic-notice-ui-") as temporary, patch.object(
            config_paths, "get_config_dir", return_value=Path(temporary)):
        model = SimpleNamespace(error=None, release=release)
        MainWindow._on_fftic_status_ready(host, 3, model)
        MainWindow._on_fftic_status_ready(host, 3, model)
        assert len(notices) == 1 and notices[0][1] == "info"
        restarted = SimpleNamespace(**host.__dict__)
        MainWindow._on_fftic_status_ready(restarted, 3, model)
        assert len(notices) == 1


def main() -> None:
    tests = (
        test_composition_derives_owned_paths_and_delays_acquisition,
        test_invalid_composition_keeps_read_only_status,
        test_prerequisite_acquisition_matrix_and_host_capability,
        test_production_request_binds_exact_proton_prefix_and_steam_context,
        test_action_gating_and_prerequisite_blocker,
        test_host_unavailable_does_not_block_noninstaller_actions,
        test_retryable_and_genuine_recovery_journal_status,
        test_repair_gating_covers_every_managed_component,
        test_reconciliation_is_narrowly_gated_from_genuine_recovery,
        test_panel_enables_only_current_actions,
        test_setup_confirmation_keeps_steam_manual_and_shared_runtimes,
        test_post_launch_focus_is_distinct_from_read_only_recheck,
        test_automatic_status_ready_attempts_once_after_failure,
        test_release_notice_once_across_rechecks_and_restart,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC Phase C3D production-composition checks passed.")


if __name__ == "__main__":
    main()
