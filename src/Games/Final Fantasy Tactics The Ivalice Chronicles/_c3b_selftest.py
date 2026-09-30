"""Hermetic checks for the corrected C3B control plane."""

from __future__ import annotations

import hashlib
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from fftic_artifacts import ArtifactDisposition, ArtifactPin
from fftic_managed_executor import (
    LifecycleStep, ManagedLifecycleExecutor, ManagedOperationCancelled,
    ManagedOperationError, MutationCoordinator, OperationBusyError,
    OperationState, ProcessRequest, ProcessResult, RecoveryRequiredError,
    StagedLifecycleOperations,
)
from fftic_orchestration import (
    DefaultStatusInspector, FFTIC_GAME_ID, FfticOrchestrator,
    InspectionCancelled, InspectionContext, InspectionResult, OperationKind, StatusRow,
    StatusSeverity,
)
from fftic_prerequisites import InstallerPlan

ROOT = Path(tempfile.mkdtemp(prefix="amethyst-fftic-c3b-"))


class _Game:
    game_id = FFTIC_GAME_ID
    name = "FFTIC fixture"

    def get_game_path(self): return ROOT / "game"
    def get_prefix_path(self): return ROOT / "prefix"


class _Inspector:
    def inspect(self, context, cancel, progress):
        row = StatusRow("recovery", "Recovery", "Ready", StatusSeverity.READY, "ready")
        return InspectionResult((row,), (), (), "copy", (), False, False)


class _Journal:
    durable = True

    def __init__(self): self.events = []
    def record(self, **values): self.events.append(values)


def _context():
    profile, staging = ROOT / "profile", ROOT / "staging"
    game, prefix = ROOT / "game", ROOT / "prefix"
    for path in (profile, staging, game, prefix): path.mkdir(exist_ok=True)
    for name in ("FFT_classic.exe", "FFT_enhanced.exe"):
        (game / name).write_bytes(b"fixture executable")
    (profile / "modlist.txt").write_text("", encoding="utf-8")
    return InspectionContext(_Game(), "default", profile, staging)


def _workflow(state):
    def prepare(_plan): return {"before": state["value"]}

    def verify_applied(token):
        if state["value"] != token["before"] + 1:
            raise AssertionError("apply not visible")

    def verify_rollback(token):
        if state["value"] != token["before"]:
            raise AssertionError("rollback not restored")

    action = LifecycleStep(
        "fixture action", prepare, lambda token: f"restore {token['before']}",
        lambda token, _cancel: state.update(value=token["before"] + 1),
        verify_applied, lambda token: state.update(value=token["before"]),
        verify_rollback)
    verifier = LifecycleStep(
        "final correlated verifier", lambda _plan: {"value": state["value"]},
        lambda _token: "read-only final verification", lambda _token, _cancel: None,
        lambda token: None if state["value"] == token["value"] else
        (_ for _ in ()).throw(AssertionError("final verification failed")),
        lambda _token: None, lambda _token: None,
        mutates=False, final_verifier=True)
    return action, verifier


def _workflows():
    states = {kind: {"value": 0} for kind in OperationKind}
    return {kind: _workflow(states[kind]) for kind in OperationKind}, states


def _controller(workflows=None, journal=None, coordinator=None):
    holder = {}
    workflows, states = (workflows, {}) if workflows is not None else _workflows()
    operations = StagedLifecycleOperations(
        validator=lambda plan: holder["controller"].revalidate_plan(plan),
        workflows=workflows, journal=journal or _Journal())
    executor = ManagedLifecycleExecutor(
        operations, coordinator=coordinator or MutationCoordinator())
    controller = FfticOrchestrator(_Inspector(), executor)
    holder["controller"] = controller
    controller.refresh(_context())
    return controller, states


def _capture_error(callback, errors):
    try: callback()
    except BaseException as exc: errors.append(exc)


def _fixture_inspection(details=()):
    row = StatusRow("recovery", "Recovery", "Ready", StatusSeverity.READY, "ready")
    return InspectionResult((row,), tuple(details), (), "copy", (), False, False)


def test_status_snapshot_retries_instead_of_accepting_mixed_evidence():
    context = _context()
    modlist = context.profile_dir / "modlist.txt"
    modlist.write_text("+old\n", encoding="utf-8")

    class ChangingInspector(DefaultStatusInspector):
        def __init__(self): self.evidence = []
        def _inspect_unlocked(self, context, cancel=None, progress=None):
            observed = modlist.read_text(encoding="utf-8")
            self.evidence.append(observed)
            if len(self.evidence) == 1:
                modlist.write_text("+new\n", encoding="utf-8")
            return _fixture_inspection((observed,))

    inspector = ChangingInspector()
    result = inspector.inspect(context)
    assert inspector.evidence == ["+old\n", "+new\n"]
    assert result.details == ("+new\n",)
    assert result.observation_sha256 == inspector._observation_identity(context)

    class NeverStableInspector(DefaultStatusInspector):
        def __init__(self): self.calls = 0
        def _inspect_unlocked(self, context, cancel=None, progress=None):
            self.calls += 1
            modlist.write_text(f"+change-{self.calls}\n", encoding="utf-8")
            return _fixture_inspection()
    never_stable = NeverStableInspector()
    model = FfticOrchestrator(never_stable).refresh(context)
    assert never_stable.calls == 2
    assert "changed during status inspection" in model.error

    cancel = threading.Event()
    class CancellingInspector(DefaultStatusInspector):
        def _inspect_unlocked(self, context, cancel=None, progress=None):
            modlist.write_text("+cancelled\n", encoding="utf-8")
            cancel.set()
            return _fixture_inspection()
    try: CancellingInspector().inspect(context, cancel)
    except InspectionCancelled: pass
    else: raise AssertionError("snapshot retry ignored cancellation")


def test_stable_snapshot_identity_is_bound_to_plan():
    context = _context()
    class StableInspector(DefaultStatusInspector):
        def _inspect_unlocked(self, context, cancel=None, progress=None):
            return _fixture_inspection()
    inspector = StableInspector()
    controller = FfticOrchestrator(inspector)
    model = controller.refresh(context)
    plan = controller.plan(OperationKind.REPAIR)
    assert model.observation_sha256 == inspector._observation_identity(context)
    assert plan.binding.observation_sha256 == model.observation_sha256


def test_binding_staleness_and_off_thread_revalidation():
    controller, _states = _controller()
    plan = controller.plan(OperationKind.REPAIR)
    assert plan.binding.game_id == FFTIC_GAME_ID
    original = DefaultStatusInspector._observation_identity
    calls, ui_thread = [], threading.get_ident()

    def observed(context):
        calls.append(threading.get_ident())
        return original(context)

    DefaultStatusInspector._observation_identity = staticmethod(observed)
    try:
        controller.plan(OperationKind.REPAIR)
        assert not calls
        result = []
        worker = threading.Thread(target=lambda: result.append(controller.execute(plan)))
        worker.start(); worker.join(2)
        assert not worker.is_alive() and result[0].state == OperationState.SUCCEEDED
        assert calls and all(thread != ui_thread for thread in calls)
    finally:
        DefaultStatusInspector._observation_identity = staticmethod(original)
    controller.refresh(_context())
    changed = controller.plan(OperationKind.REPAIR)
    (ROOT / "profile" / "modlist.txt").write_text("+new-mod\n", encoding="utf-8")
    assert controller.plan_is_current(changed)
    errors = []
    worker = threading.Thread(
        target=lambda: _capture_error(lambda: controller.execute(changed), errors))
    worker.start(); worker.join(2)
    assert errors and "stale" in str(errors[0])


def test_empty_or_incomplete_workflow_rejected():
    for workflow in ((), _workflow({"value": 0})[:1]):
        workflows, _states = _workflows(); workflows[OperationKind.SETUP] = workflow
        try:
            StagedLifecycleOperations(
                validator=lambda _plan: True, workflows=workflows, journal=_Journal())
        except ValueError as exc:
            assert "final verifier" in str(exc)
        else: raise AssertionError("incomplete workflow was authorized")


def test_partial_apply_failure_rolls_back_and_retries():
    state = {"value": 0, "fail": True}
    def prepare(_plan): return {"before": state["value"]}
    def apply(token, _cancel):
        state["value"] = token["before"] + 1
        if state["fail"]: raise RuntimeError("failure after mutation")
    action = LifecycleStep(
        "partial mutation", prepare, lambda token: f"restore {token['before']}",
        apply, lambda _token: None, lambda token: state.update(value=token["before"]),
        lambda token: None if state["value"] == token["before"] else
        (_ for _ in ()).throw(AssertionError("not restored")))
    verifier = LifecycleStep(
        "final correlated verifier", lambda _plan: object(),
        lambda _token: "verify fixture", lambda _token, _cancel: None,
        lambda _token: None, lambda _token: None, lambda _token: None,
        mutates=False, final_verifier=True)
    workflows, _states = _workflows(); workflows[OperationKind.SETUP] = (action, verifier)
    journal = _Journal(); controller, _states = _controller(workflows, journal)
    plan = controller.plan(OperationKind.SETUP)
    try: controller.execute(plan)
    except RuntimeError as exc: assert "failure after mutation" in str(exc)
    else: raise AssertionError("partial mutation failure passed")
    assert state["value"] == 0
    assert any(event["state"] == "rollback-verified" for event in journal.events)
    state["fail"] = False
    assert controller.execute(plan).state == OperationState.SUCCEEDED


def test_rollback_raise_and_unverified_rollback_require_recovery():
    for mode in ("raise", "unchanged"):
        state = {"value": 0}
        def prepare(_plan): return {"before": state["value"]}
        def apply(token, _cancel):
            state["value"] = token["before"] + 1
            raise RuntimeError("induced")
        def rollback(token):
            if mode == "raise": raise RuntimeError("rollback broke")
        action = LifecycleStep(
            "broken rollback", prepare, lambda token: f"restore {token['before']}",
            apply, lambda _token: None, rollback,
            lambda token: None if state["value"] == token["before"] else
            (_ for _ in ()).throw(RuntimeError("rollback not restored")))
        verifier = LifecycleStep(
            "final correlated verifier", lambda _plan: object(),
            lambda _token: "verify fixture", lambda _token, _cancel: None,
            lambda _token: None, lambda _token: None, lambda _token: None,
            mutates=False, final_verifier=True)
        workflows, _states = _workflows(); workflows[OperationKind.UPDATE] = (action, verifier)
        journal = _Journal(); controller, _states = _controller(workflows, journal)
        try: controller.execute(controller.plan(OperationKind.UPDATE))
        except RecoveryRequiredError as exc:
            assert journal.events[-1]["attempt_id"] in str(exc)
            assert journal.events[-1]["plan_fingerprint"] in str(exc)
        else: raise AssertionError("unverified rollback was reported as restored")
        assert journal.events[-1]["state"] == "recovery-required"


def test_cancellation_between_steps_and_safe_retry():
    state, cancel, arm = {"value": 0}, threading.Event(), [True]
    action, verifier = _workflow(state); original_apply = action.apply
    def apply(token, current_cancel):
        original_apply(token, current_cancel)
        if arm[0]: cancel.set()
    action = LifecycleStep(
        action.name, action.prepare, action.recovery_information, apply,
        action.verify, action.rollback, action.verify_rollback)
    workflows, _states = _workflows(); workflows[OperationKind.SYNCHRONIZE] = (action, verifier)
    controller, _states = _controller(workflows); plan = controller.plan(OperationKind.SYNCHRONIZE)
    try: controller.execute(plan, cancel=cancel)
    except ManagedOperationCancelled: pass
    else: raise AssertionError("cancellation between steps was ignored")
    assert state["value"] == 0
    cancel.clear(); arm[0] = False
    assert controller.execute(plan, cancel=cancel).state == OperationState.SUCCEEDED


def test_duplicate_suppression_and_attempt_identity():
    coordinator, entered, release = MutationCoordinator(), threading.Event(), threading.Event()
    workflows, states = _workflows(); action, verifier = workflows[OperationKind.REPAIR]
    def blocking_apply(token, cancel):
        entered.set(); release.wait(2); action.apply(token, cancel)
    workflows[OperationKind.REPAIR] = (
        LifecycleStep(action.name, action.prepare, action.recovery_information,
                      blocking_apply, action.verify, action.rollback, action.verify_rollback),
        verifier)
    journal = _Journal(); controller, _states = _controller(workflows, journal, coordinator)
    plan = controller.plan(OperationKind.REPAIR)
    thread = threading.Thread(target=lambda: controller.execute(plan)); thread.start()
    assert entered.wait(1)
    try: controller.execute(plan)
    except OperationBusyError: pass
    else: raise AssertionError("duplicate operation was not rejected")
    release.set(); thread.join(2); assert not thread.is_alive()
    controller.execute(plan)
    assert len({event["attempt_id"] for event in journal.events}) == 2
    assert len({event["plan_fingerprint"] for event in journal.events}) == 1
    assert states[OperationKind.REPAIR]["value"] == 2


def test_prerequisite_request_is_injectable_and_flatpak_closed():
    from fftic_readiness import SUPPORTED_PROTON_RUNNER
    payload = b"reviewed installer fixture"
    executable = ROOT / "installer.exe"; executable.write_bytes(payload)
    runner = ROOT / "proton"; runner.write_text("fixture", encoding="utf-8")
    prefix = ROOT / "process-prefix"; prefix.mkdir(exist_ok=True)
    working = ROOT / "process-working"; working.mkdir(exist_ok=True)
    logs = ROOT / "process-logs"; logs.mkdir(exist_ok=True)
    pin = ArtifactPin(
        "fixture", "Fixture Runtime", "1.0", "https://example.invalid/f.exe",
        "installer.exe", len(payload), hashlib.sha256(payload).hexdigest(), "x64",
        "test", "test-only", ArtifactDisposition.EXECUTE, True)
    installer = InstallerPlan(
        pin.component, pin, executable, prefix, SUPPORTED_PROTON_RUNNER,
        ("/install", "/quiet", "/norestart"), (0,), (3010,), True, True, True, True)
    environment = (("PATH", "/usr/bin"),
                   ("STEAM_COMPAT_DATA_PATH", str(prefix.parent)),
                   ("STEAM_COMPAT_CLIENT_INSTALL_PATH", str(ROOT / "steam")))
    request = ProcessRequest(
        installer, executable, pin, runner, SUPPORTED_PROTON_RUNNER, prefix,
        installer.arguments, environment, logs / "installer.log", working,
        (0,), (3010,), 120, False, lambda plan, target: plan is installer and target == prefix)
    request.validate()

    class FakeRunner:
        def __init__(self, code): self.code, self.received = code, None
        def run(self, candidate, cancel=None, progress=None):
            candidate.validate(); self.received = candidate
            if cancel is not None and cancel.is_set():
                raise ManagedOperationCancelled("fixture cancellation")
            if self.code not in {*candidate.accepted_exit_codes, *candidate.restart_exit_codes}:
                raise ManagedOperationError("fixture exit code rejected")
            if not candidate.post_install_health_check(candidate.plan, candidate.prefix):
                raise ManagedOperationError("fixture health check failed")
            return ProcessResult(self.code, self.code in candidate.restart_exit_codes,
                                 candidate.log_path)

    normal, restart = FakeRunner(0), FakeRunner(3010)
    assert not normal.run(request).restart_required and normal.received is request
    assert restart.run(request).restart_required
    assert dict(request.environment)["PATH"] == "/usr/bin"
    assert request.working_directory == working and request.timeout_seconds == 120
    stopped = threading.Event(); stopped.set()
    try: normal.run(request, cancel=stopped)
    except ManagedOperationCancelled: pass
    else: raise AssertionError("fake boundary ignored cancellation")
    unhealthy = ProcessRequest(
        installer, executable, pin, runner, SUPPORTED_PROTON_RUNNER, prefix,
        installer.arguments, environment, logs / "installer.log", working,
        (0,), (3010,), 120, False, lambda _plan, _target: False)
    try: normal.run(unhealthy)
    except ManagedOperationError as exc: assert "health" in str(exc)
    else: raise AssertionError("health-check failure was accepted")
    blocked = ProcessRequest(
        installer, executable, pin, runner, SUPPORTED_PROTON_RUNNER, prefix,
        installer.arguments, environment, logs / "installer.log", working,
        (0,), (3010,), 120, True, lambda _plan, _target: True)
    try: blocked.validate()
    except Exception as exc: assert "Flatpak" in str(exc)
    else: raise AssertionError("Flatpak host process boundary was enabled")


def test_refresh_explicit_cancel_and_close_cancel_are_distinct():
    from gui_qt.app import MainWindow
    cancel = threading.Event()
    panel_messages = []
    fixture = SimpleNamespace(
        _fftic_status=SimpleNamespace(
            set_operation=lambda active, text: panel_messages.append((active, text))),
        _fftic_status_closing=False, _fftic_operation_active=True,
        _fftic_operation_cancel=cancel, _fftic_refresh_pending=False,
        tr=lambda text: text)
    MainWindow._refresh_fftic_status(fixture)
    assert fixture._fftic_refresh_pending and not cancel.is_set()
    MainWindow._cancel_fftic_operation(fixture)
    assert cancel.is_set() and panel_messages
    MainWindow._cancel_fftic_operation(fixture)  # idempotent

    close_cancel = threading.Event(); notices = []; ignored = []
    closing = SimpleNamespace(
        _fftic_operation_active=True, _fftic_operation_cancel=close_cancel,
        tr=lambda text: text,
        _notify=lambda message, level: notices.append((message, level)))
    event = SimpleNamespace(ignore=lambda: ignored.append(True))
    MainWindow.closeEvent(closing, event)
    assert close_cancel.is_set() and ignored == [True] and notices

    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui_qt.fftic_status import FfticStatusPanel
    app = QApplication.instance() or QApplication([])
    panel = FfticStatusPanel(); requested = []
    panel.cancel_requested.connect(lambda: requested.append(True))
    panel.set_operation(True, "fixture")
    assert panel._recheck.isEnabled()
    panel._recheck.click()
    assert requested == [True]


TESTS = (
    test_status_snapshot_retries_instead_of_accepting_mixed_evidence,
    test_stable_snapshot_identity_is_bound_to_plan,
    test_binding_staleness_and_off_thread_revalidation,
    test_empty_or_incomplete_workflow_rejected,
    test_partial_apply_failure_rolls_back_and_retries,
    test_rollback_raise_and_unverified_rollback_require_recovery,
    test_cancellation_between_steps_and_safe_retry,
    test_duplicate_suppression_and_attempt_identity,
    test_prerequisite_request_is_injectable_and_flatpak_closed,
    test_refresh_explicit_cancel_and_close_cancel_are_distinct,
)

if __name__ == "__main__":
    for test in TESTS:
        test(); print("✓", test.__name__)
    print("All corrected FFTIC Phase C3B isolated checks passed.")
