"""Isolated checks for the FFTIC status presenter, controller, and Qt panel."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from types import SimpleNamespace
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from fftic_orchestration import (  # noqa: E402
    EXECUTION_UNAVAILABLE, FFTIC_GAME_ID, FfticOrchestrator,
    InspectionCancelled, InspectionContext, InspectionResult, OperationKind, ProgressUpdate,
    StatusRow, StatusSeverity, UnsupportedPackage, _profile_packages,
    is_fftic_game,
)
from fftic_steam_requirements import COPY_READY_OPTIONS  # noqa: E402


ROOT = Path(tempfile.mkdtemp(prefix="amethyst-fftic-c3a-"))


class _Game:
    game_id = FFTIC_GAME_ID

    def __init__(self, root: Path):
        self._root = root

    def get_game_path(self):
        return self._root / "game"

    def get_prefix_path(self):
        return self._root / "prefix"


def _rows(*, ready=False, steam="Configured", unsupported=False,
          profile="Ready", recovery="Ready"):
    specifications = (
        ("game", "Game installation and build", "Ready" if ready else "Unverified game build"),
        ("steam_prefix", "Steam library and prefix", "Ready" if ready else "Setup required"),
        ("runner", "Proton runner", "Ready" if ready else "Unsupported"),
        ("runtime", "Reloaded-II runtime generation", "Ready" if ready else "Not installed"),
        ("nenkai", "FFT: The Ivalice Chronicles Mod Loader",
         "Ready" if ready else "Not installed"),
        ("sigscan", "SigScan", "Ready" if ready else "Update required"),
        ("hooks", "Shared Hooks", "Ready" if ready else "Different"),
        ("dotnet", ".NET Desktop Runtime", "Ready" if ready else "Not installed"),
        ("vc", "VC++ runtime", "Ready" if ready else "Update required"),
        ("bootstrap", "Game-root ASI bootstrap ownership", "Ready" if ready else "Conflict"),
        ("prefix_config", "Prefix bootstrap configuration", "Ready" if ready else "Setup required"),
        ("profile", "Active Amethyst profile synchronization", profile),
        ("steam_options", "Steam Launch Options", steam),
        ("recovery", "Incomplete operation or recovery", recovery),
        ("launch", "Launch readiness", "Ready" if ready else "Setup required"),
        ("unsupported_mods", "Unsupported or unsafe packages",
         "Unsupported" if unsupported else "Ready"),
    )
    result = []
    for key, label, state in specifications:
        severity = (StatusSeverity.READY if state == "Ready" else
                    StatusSeverity.WARNING if state in {
                        "Different", "Not installed", "Update required",
                        "Profile needs synchronization"} else StatusSeverity.ERROR)
        result.append(StatusRow(key, label, state, severity,
                                f"{label}: {state}", (f"diagnostic for {key}",)))
    return tuple(result)


class _Inspector:
    def __init__(self, *, ready=False, steam="Configured", unsupported=False,
                 profile="Ready", recovery="Ready", error=None,
                 copy_text=COPY_READY_OPTIONS, preserved=("MANGOHUD=1",)):
        self.ready = ready
        self.steam = steam
        self.unsupported = unsupported
        self.profile = profile
        self.recovery = recovery
        self.error = error
        self.copy_text = copy_text
        self.preserved = preserved
        self.calls = 0
        self.cancel_seen = None
        self.progress_seen = None

    def inspect(self, context, cancel, progress):
        self.calls += 1
        self.cancel_seen = cancel
        self.progress_seen = progress
        if self.error:
            raise RuntimeError(self.error)
        if progress:
            progress(ProgressUpdate(1, 1, "fake inspection"))
        packages = ((UnsupportedPackage(
            "Runtime Mod", str(context.staging_root / "runtime-mod"),
            "compiled DLL", True),) if self.unsupported else ())
        return InspectionResult(
            _rows(ready=self.ready, steam=self.steam,
                  unsupported=self.unsupported, profile=self.profile,
                  recovery=self.recovery),
            ("supported tuple", "generation identity", "log location"),
            packages, self.copy_text, self.preserved,
            self.ready and not self.unsupported and self.steam == "Configured",
            self.ready)


class _Executor:
    authorized = True

    def __init__(self):
        self.received = None

    def execute(self, plan, cancel, progress):
        self.received = (plan, cancel, progress)
        if progress:
            progress(ProgressUpdate(1, 1, "executed"))
        return "ok"


def _context() -> InspectionContext:
    profile = ROOT / "profile"
    staging = ROOT / "staging"
    profile.mkdir(exist_ok=True)
    staging.mkdir(exist_ok=True)
    return InspectionContext(_Game(ROOT), "default", profile, staging)


def test_selection_and_required_rows() -> None:
    assert is_fftic_game(_Game(ROOT))
    assert not is_fftic_game(type("Other", (), {"game_id": "cyberpunk_2077"})())
    assert not is_fftic_game(None)
    model = FfticOrchestrator(_Inspector()).refresh(_context())
    expected = {
        "game", "steam_prefix", "runner", "runtime", "nenkai", "sigscan",
        "hooks", "dotnet", "vc", "bootstrap", "prefix_config", "profile",
        "steam_options", "recovery", "launch", "unsupported_mods",
    }
    assert {row.key for row in model.rows} == expected
    assert model.row("game").state == "Unverified game build"
    assert model.row("runner").state == "Unsupported"
    assert model.row("bootstrap").state == "Conflict"
    assert not model.mutation_available
    assert model.mutation_unavailable_reason == EXECUTION_UNAVAILABLE


def test_state_vocabulary_and_steam_variants() -> None:
    observed = set()
    for steam in ("Missing", "Different", "Configured", "Conflict"):
        model = FfticOrchestrator(_Inspector(steam=steam)).refresh(_context())
        assert model.row("steam_options").state == steam
        assert model.steam_copy_text == COPY_READY_OPTIONS
        assert model.steam_preserved_options == ("MANGOHUD=1",)
        observed.update(row.state for row in model.rows)
    assert {"Ready", "Not installed", "Setup required", "Update required",
            "Different", "Conflict", "Unsupported", "Unverified game build"} <= observed
    model = FfticOrchestrator(_Inspector()).refresh(_context())
    expected_severity = {
        "game": StatusSeverity.ERROR,
        "runtime": StatusSeverity.WARNING,
        "sigscan": StatusSeverity.WARNING,
        "bootstrap": StatusSeverity.ERROR,
        "unsupported_mods": StatusSeverity.READY,
    }
    for key, severity in expected_severity.items():
        assert model.row(key).severity == severity


def test_ready_profile_recovery_and_errors() -> None:
    ready = FfticOrchestrator(_Inspector(ready=True)).refresh(_context())
    assert ready.ready and ready.verifier_attested
    assert ready.row("launch").state == "Ready"

    changed = FfticOrchestrator(_Inspector(
        profile="Profile needs synchronization")).refresh(_context())
    assert changed.row("profile").state == "Profile needs synchronization"
    recovery = FfticOrchestrator(_Inspector(
        recovery="Recovery required")).refresh(_context())
    assert recovery.row("recovery").severity == StatusSeverity.ERROR

    failed = FfticOrchestrator(_Inspector(error="visible inspector failure")).refresh(
        _context())
    assert not failed.ready and "visible inspector failure" in failed.error
    assert failed.row("inspection").state == "Recovery required"


def test_unsupported_package_detection_and_plan_block() -> None:
    context = _context()
    (context.profile_dir / "modlist.txt").write_text(
        "+runtime-mod\n-disabled-runtime-mod\n-section_separator\n",
        encoding="utf-8")
    for folder, name, mod_id in (
        ("runtime-mod", "Runtime Mod", "example.runtime"),
        ("disabled-runtime-mod", "Disabled Runtime Mod", "example.disabled"),
    ):
        package = context.staging_root / folder
        package.mkdir(exist_ok=True)
        (package / "ModConfig.json").write_text(json.dumps({
            "ModId": mod_id, "ModName": name, "ModAuthor": "Test",
            "ModVersion": "1.0", "ModDependencies": [], "OptionalDependencies": [],
            "SupportedAppId": ["fft_enhanced.exe"], "ModDll": "Runtime.dll",
            "ModNativeDll64": "Native.dll",
        }), encoding="utf-8")
        (package / "Runtime.dll").write_bytes(b"fixture")
        (package / "FFTIVC" / "data").mkdir(parents=True, exist_ok=True)
        (package / "FFTIVC" / "data" / "fixture.bin").write_bytes(b"fixture")
    packages = _profile_packages(context)
    assert len(packages) == 2
    assert packages[0].name == "Runtime Mod (example.runtime)"
    assert packages[0].path == str(context.staging_root / "runtime-mod")
    assert "unsupported native/external executable" in packages[0].reason
    assert packages[0].enabled and packages[0].state == "enabled"
    assert packages[1].name == "Disabled Runtime Mod (example.disabled)"
    assert not packages[1].enabled and packages[1].state == "disabled"

    controller = FfticOrchestrator(_Inspector(unsupported=True))
    model = controller.refresh(context)
    assert model.row("unsupported_mods").state == "Unsupported"
    try:
        controller.plan(OperationKind.SYNCHRONIZE)
    except RuntimeError as exc:
        assert "Unsupported or unsafe packages" in str(exc)
    else:
        raise AssertionError("unsupported code package did not block synchronization")


def test_plan_execution_cancellation_and_progress() -> None:
    cancel = threading.Event()
    progress = []
    inspector = _Inspector()
    unavailable = FfticOrchestrator(inspector)
    unavailable.refresh(_context(), cancel=cancel, progress=progress.append)
    plan = unavailable.plan(OperationKind.REPAIR)
    try:
        unavailable.execute(plan, cancel, progress.append)
    except PermissionError as exc:
        assert str(exc) == EXECUTION_UNAVAILABLE
    else:
        raise AssertionError("production controller accepted mutation")
    assert inspector.cancel_seen is cancel
    assert inspector.progress_seen == progress.append

    executor = _Executor()
    controller = FfticOrchestrator(_Inspector(), executor)
    controller.refresh(_context())
    plans = {kind: controller.plan(kind) for kind in OperationKind
             if kind != OperationKind.UPDATE}
    assert any(step.component == "managed runtime"
               for step in plans[OperationKind.SETUP].steps)
    assert plans[OperationKind.REMOVE].steps[0].action.startswith("restore receipt-owned")
    assert OperationKind.UPDATE.value not in controller.last_status.available_actions
    selected = plans[OperationKind.REPAIR]
    assert controller.execute(selected, cancel, progress.append) == "ok"
    assert executor.received == (selected, cancel, progress.append)
    assert progress[-1].phase == "executed"


def test_launch_gating() -> None:
    missing = FfticOrchestrator(_Inspector(steam="Missing"))
    missing.refresh(_context())
    assert "Steam Launch Options are Missing" in missing.launch_block_reason()
    unattested = FfticOrchestrator(_Inspector())
    unattested.refresh(_context())
    assert "not verifier-attested" in unattested.launch_block_reason()
    ready = FfticOrchestrator(_Inspector(ready=True))
    ready.refresh(_context())
    assert "Start it normally from Steam" in ready.launch_block_reason()
    ready.invalidate(_context())
    assert "Recheck FFTIC support" in ready.launch_block_reason()


def test_latest_worker_coalesces_and_cancels() -> None:
    from gui_qt.worker import LatestWorker

    worker = LatestWorker("fftic-c3a-test")
    lock = threading.Lock()
    started: list[str] = []
    accepted: list[tuple[str, str]] = []
    cancellations: list[str] = []
    failures: list[str] = []
    active = 0
    maximum_active = 0
    generation = 0
    current_cancel = None
    first_started = threading.Event()
    newest_done = threading.Event()

    def submit(label: str) -> None:
        nonlocal generation, current_cancel
        generation += 1
        own_generation = generation
        if current_cancel is not None:
            current_cancel.set()
        cancel = threading.Event()
        current_cancel = cancel

        def accept(kind: str) -> None:
            if own_generation == generation and not cancel.is_set():
                accepted.append((label, kind))

        def job() -> None:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                started.append(label)
            try:
                if label == "first":
                    first_started.set()
                    while not cancel.wait(0.005):
                        pass
                    accept("stale-progress")
                    raise InspectionCancelled("superseded")
                accept("progress")
                accept("result")
            except InspectionCancelled:
                cancellations.append(label)
            except Exception as exc:
                failures.append(str(exc))
            finally:
                with lock:
                    active -= 1
                if label == "newest":
                    newest_done.set()

        worker.submit(job)

    submit("first")
    assert first_started.wait(1)
    submit("obsolete-pending")
    submit("newest")
    assert newest_done.wait(2)
    assert started == ["first", "newest"]
    assert maximum_active == 1
    assert cancellations == ["first"] and not failures
    assert accepted == [("newest", "progress"), ("newest", "result")]

    panel_state = {"ready": True, "visible": True}
    generation += 1
    current_cancel.set()
    worker.discard_pending()
    panel_state.update(ready=False, visible=False)
    assert panel_state == {"ready": False, "visible": False}

    class CancelledInspector:
        def inspect(self, context, cancel, progress):
            raise InspectionCancelled("superseded")

    controller = FfticOrchestrator(CancelledInspector())
    try:
        controller.refresh(_context())
    except InspectionCancelled:
        pass
    else:
        raise AssertionError("cancellation was presented as a status failure")
    assert controller.last_status is None


def test_qt_panel_copy_and_visibility() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        from gui_qt.fftic_status import FfticStatusPanel
    except ImportError:
        print("Qt widget construction skipped: PySide6 is unavailable")
        return
    app = QApplication.instance() or QApplication([])
    panel = FfticStatusPanel()
    assert panel.isHidden()
    composed = "MANGOHUD=1 " + COPY_READY_OPTIONS + " -windowed"
    model = FfticOrchestrator(_Inspector(
        copy_text=composed, preserved=("MANGOHUD=1", "-windowed"))).refresh(_context())
    panel.set_status(model)
    assert not panel.isHidden()
    assert len(panel._rows) == len(model.rows)
    assert [widget.accessibleName() for widget in panel._rows] == [
        f"{row.label}: {row.state}" for row in model.rows]
    assert all(widget.toolTip() for widget in panel._rows)
    assert all(not button.isEnabled() for button in panel._action_buttons.values())
    assert all(button.toolTip() == EXECUTION_UNAVAILABLE
               for button in panel._action_buttons.values())
    assert model.steam_copy_text in panel._detail_text.toPlainText()
    rechecks = []
    panel.recheck_requested.connect(lambda: rechecks.append(True))
    panel._recheck.click()
    assert rechecks == [True]
    panel._copy_steam_options()
    assert app.clipboard().text() == model.steam_copy_text
    settled_rows = tuple(panel._rows)
    settled_details = panel._detail_text.toPlainText()
    panel.set_loading(preserve_status=True)
    assert panel.model is model and tuple(panel._rows) == settled_rows
    assert panel._detail_text.toPlainText() == settled_details
    assert not panel._recheck.isEnabled()
    panel.set_status(model)
    panel.set_loading()
    assert panel.model is None and not panel._rows
    assert not panel._copy.isEnabled()
    panel.set_status(model)
    panel._details_button.setChecked(True)
    assert not panel._details.isHidden()
    panel.clear()
    assert panel.isHidden()


def test_app_route_boundaries() -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from gui_qt.app import MainWindow
        from gui_qt.confirm_overlay import ConfirmOverlay
    except ImportError:
        print("Qt application routing skipped: PySide6 is unavailable")
        return

    controller = FfticOrchestrator(_Inspector())
    fftic = SimpleNamespace(
        game_id=FFTIC_GAME_ID, name="FFTIC",
        is_configured=lambda: True,
        get_managed_support_controller=lambda: controller,
    )
    shown = []
    original_show_message = ConfirmOverlay.__dict__["show_message"]
    ConfirmOverlay.show_message = classmethod(
        lambda cls, host, title, body, **kwargs: shown.append((title, body)))
    try:
        play = SimpleNamespace(
            _gs=SimpleNamespace(game=fftic),
            _append_log=lambda message: None,
            tr=lambda text: text,
        )
        MainWindow._do_play(play)
    finally:
        ConfirmOverlay.show_message = original_show_message
    assert shown and shown[0][0] == "Start FFTIC from Steam"
    assert "normally from Steam" in shown[0][1]

    actions = []
    route = SimpleNamespace(
        _gs=SimpleNamespace(game=fftic, profile="default"),
        _auto_deploy_in_progress=False,
        _present_fftic_action=actions.append,
        _append_log=lambda message: None,
        _refresh_fftic_status=lambda: None,
    )
    MainWindow._on_deploy(route)
    MainWindow._on_restore(route)
    assert actions == ["synchronize", "remove"]

    other = SimpleNamespace(
        game_id="other", name="Other Game", is_configured=lambda: True,
        deploy=lambda: None,
    )
    deploy_calls = []
    normal_deploy = SimpleNamespace(
        _gs=SimpleNamespace(game=other, profile="normal"),
        _auto_deploy_in_progress=False,
        _start_deploy=lambda game, profile, **kwargs:
            deploy_calls.append((game, profile)),
    )
    MainWindow._on_deploy(normal_deploy)
    assert deploy_calls == [(other, "normal")]

    notices = []
    normal_restore = SimpleNamespace(
        _gs=SimpleNamespace(game=other), _deploy_running=True,
        tr=lambda text: text,
        _notify=lambda message, severity: notices.append((message, severity)),
    )
    MainWindow._on_restore(normal_restore)
    assert notices and notices[-1][1] == "warning"

    normal_play = SimpleNamespace(
        _gs=SimpleNamespace(game=other), _tool_busy=True,
        tr=lambda text: text,
        _tool_busy_label=lambda: "Tool",
        _notify=lambda message, severity: notices.append((message, severity)),
    )
    MainWindow._do_play(normal_play)
    assert "switch games" not in notices[-1][0]
    assert "launch again" in notices[-1][0]

    framework_updates = []
    framework = SimpleNamespace(
        _framework_banner=SimpleNamespace(
            set_statuses=lambda statuses: framework_updates.append(statuses)),
        _framework_gen=0, _conflict_data=None,
        _gs=SimpleNamespace(profile_dir=lambda: None),
        _cache_framework_states=lambda statuses: None,
    )
    MainWindow._refresh_framework_banner(framework)
    assert framework_updates == [[]]


def main() -> None:
    tests = (
        test_selection_and_required_rows,
        test_state_vocabulary_and_steam_variants,
        test_ready_profile_recovery_and_errors,
        test_unsupported_package_detection_and_plan_block,
        test_plan_execution_cancellation_and_progress,
        test_launch_gating,
        test_latest_worker_coalesces_and_cancels,
        test_qt_panel_copy_and_visibility,
        test_app_route_boundaries,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC Phase C3A checks passed.")


if __name__ == "__main__":
    main()
