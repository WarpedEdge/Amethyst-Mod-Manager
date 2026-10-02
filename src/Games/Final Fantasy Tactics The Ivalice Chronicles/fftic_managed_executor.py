"""Serialized C3B operation execution and prerequisite process boundary.

The executor owns control flow only.  Filesystem algorithms remain in the C2
services supplied through :class:`LifecycleOperations`.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol

try:
    from .fftic_artifacts import ArtifactPin, validate_file
    from .fftic_orchestration import (
        OperationBinding, OperationKind, OperationPlan, ProgressCallback,
        ProgressUpdate,
    )
    from .fftic_prerequisites import InstallerPlan
    from .fftic_readiness import SUPPORTED_PROTON_RUNNER
except ImportError:
    from fftic_artifacts import ArtifactPin, validate_file
    from fftic_orchestration import (
        OperationBinding, OperationKind, OperationPlan, ProgressCallback,
        ProgressUpdate,
    )
    from fftic_prerequisites import InstallerPlan
    from fftic_readiness import SUPPORTED_PROTON_RUNNER


class OperationState(str, Enum):
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery-required"


class RecoveryState(str, Enum):
    """Durable state reconstructed from one lifecycle attempt."""

    NOT_STARTED = "no operation started"
    STARTED = "operation started but not prepared"
    PREPARED = "prepared but not mutated"
    MUTATION_ATTEMPTED = "mutation attempted"
    FORWARD_VERIFIED = "forward state verified"
    ROLLBACK_STARTED = "rollback started"
    ROLLBACK_VERIFIED = "rollback verified"
    RECOVERY_REQUIRED = "recovery required"
    PREREQUISITE_RETRYABLE = "prerequisite retryable"
    COMPLETED = "operation completed"


class ManagedOperationError(RuntimeError):
    """A lifecycle operation failed before a recovery-only condition."""


class ManagedOperationCancelled(ManagedOperationError):
    """Cancellation observed at a declared safe boundary."""


class RecoveryRequiredError(ManagedOperationError):
    """Rollback was incomplete; durable evidence must be preserved."""


class PrerequisiteRetryableError(ManagedOperationError):
    """A shared prerequisite stopped before managed state remained live."""


class OperationBusyError(ManagedOperationError):
    """A duplicate or conflicting FFTIC operation is already active."""


class StaleOperationPlan(ManagedOperationError):
    """The selected game/profile observation no longer matches the plan."""


@dataclass(frozen=True)
class OperationResult:
    plan: OperationPlan
    state: OperationState
    completed_steps: int
    message: str
    recovery_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcessRequest:
    """Typed data accepted by an injected prerequisite process runner."""

    plan: InstallerPlan
    executable: Path
    executable_pin: ArtifactPin
    runner: Path
    runner_identity: str
    prefix: Path
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    log_path: Path
    working_directory: Path
    accepted_exit_codes: tuple[int, ...]
    restart_exit_codes: tuple[int, ...]
    timeout_seconds: int
    allow_flatpak_host_spawn: bool
    post_install_health_check: Callable[[InstallerPlan, Path], bool]

    @staticmethod
    def _regular_unlinked(path: Path, label: str) -> Path:
        path = Path(path)
        if not path.is_absolute():
            raise ManagedOperationError(f"{label} must be absolute")
        current = path
        while current != current.parent:
            if current.is_symlink():
                raise ManagedOperationError(f"{label} crosses a symbolic link")
            current = current.parent
        if path.is_symlink() or not path.is_file():
            raise ManagedOperationError(f"{label} is not a regular file")
        return path.resolve(strict=True)

    @staticmethod
    def _directory_unlinked(path: Path, label: str) -> Path:
        path = Path(path)
        if not path.is_absolute():
            raise ManagedOperationError(f"{label} must be absolute")
        current = path
        while current != current.parent:
            if current.is_symlink():
                raise ManagedOperationError(f"{label} crosses a symbolic link")
            current = current.parent
        if path.is_symlink() or not path.is_dir():
            raise ManagedOperationError(f"{label} is not a directory")
        return path.resolve(strict=True)

    def validate(self) -> None:
        if self.plan.artifact != self.executable_pin:
            raise ManagedOperationError("Installer request does not match its pinned plan")
        executable = self._regular_unlinked(self.executable, "Installer")
        if (executable != Path(self.executable)
                or executable != Path(self.plan.installer_path)
                or executable != Path(self.plan.installer_path).resolve(strict=True)):
            raise ManagedOperationError("Installer path differs from its prerequisite plan")
        prefix = self._directory_unlinked(self.prefix, "Prefix")
        if (prefix != Path(self.prefix) or prefix != Path(self.plan.prefix)
                or prefix != Path(self.plan.prefix).resolve(strict=True)):
            raise ManagedOperationError("Installer prefix differs from its prerequisite plan")
        if (self.runner_identity != self.plan.runner_identity
                or self.runner_identity != SUPPORTED_PROTON_RUNNER):
            raise ManagedOperationError("Installer runner identity differs from its prerequisite plan")
        if self.arguments != self.plan.arguments:
            raise ManagedOperationError("Installer arguments differ from the reviewed plan")
        if self.accepted_exit_codes != self.plan.success_exit_codes:
            raise ManagedOperationError("Installer success codes differ from the reviewed plan")
        if self.restart_exit_codes != self.plan.restart_exit_codes:
            raise ManagedOperationError("Installer restart codes differ from the reviewed plan")
        if not validate_file(self.executable_pin, self.executable):
            raise ManagedOperationError("Installer bytes do not match the reviewed artifact")
        runner = self._regular_unlinked(self.runner, "Runner")
        if runner != Path(self.runner):
            raise ManagedOperationError("Runner path is not its exact resolved path")
        working_directory = self._directory_unlinked(
            self.working_directory, "Working directory")
        if working_directory != Path(self.working_directory):
            raise ManagedOperationError(
                "Working directory path is not its exact resolved path")
        log_path = Path(self.log_path)
        if not log_path.is_absolute() or log_path.is_symlink():
            raise ManagedOperationError("Installer log path is unsafe")
        log_parent = self._directory_unlinked(log_path.parent, "Log directory")
        if log_parent != log_path.parent or (
                log_path.exists() and not log_path.is_file()):
            raise ManagedOperationError("Installer log path is unsafe")
        if (not self.environment or len(dict(self.environment)) != len(self.environment)
                or any(not key or "\x00" in key or "\x00" in value
                       for key, value in self.environment)):
            raise ManagedOperationError("Installer environment is invalid")
        required = {"STEAM_COMPAT_DATA_PATH", "STEAM_COMPAT_CLIENT_INSTALL_PATH"}
        environment = dict(self.environment)
        if not required.issubset(environment):
            raise ManagedOperationError("Installer environment lacks the Steam app context")
        if any(environment.get(key) != "1004640" for key in (
                "SteamAppId", "SteamGameId", "SteamOverlayGameId",
                "STEAM_COMPAT_APP_ID")):
            raise ManagedOperationError("Installer environment has the wrong Steam app identity")
        compatdata = self._directory_unlinked(
            Path(environment["STEAM_COMPAT_DATA_PATH"]), "Compatdata root")
        if prefix != compatdata and prefix.parent != compatdata:
            raise ManagedOperationError("Installer prefix is outside its compatdata root")
        self._directory_unlinked(
            Path(environment["STEAM_COMPAT_CLIENT_INSTALL_PATH"]),
            "Steam client root")
        if not callable(self.post_install_health_check):
            raise ManagedOperationError("Installer request lacks a post-install health check")
        if self.timeout_seconds <= 0:
            raise ManagedOperationError("Installer timeout must be positive")
        if self.allow_flatpak_host_spawn:
            import shutil
            if not Path("/.flatpak-info").is_file():
                raise ManagedOperationError(
                    "Flatpak host execution was requested outside a Flatpak sandbox")
            if shutil.which("flatpak-spawn") is None:
                raise ManagedOperationError(
                    "Flatpak host execution is unavailable because flatpak-spawn is missing")


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    restart_required: bool
    log_path: Path


class PrerequisiteProcessRunner(Protocol):
    def run(self, request: ProcessRequest, cancel: threading.Event | None = None,
            progress: ProgressCallback | None = None) -> ProcessResult: ...


class LifecycleOperations(Protocol):
    """C2-backed operation facade used by the control-flow executor."""

    def revalidate(self, plan: OperationPlan) -> None: ...
    def setup(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...
    def repair(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...
    def synchronize(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...
    def update(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...
    def remove(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...
    def reconcile_runtime_output(self, plan: OperationPlan, cancel, progress) -> OperationResult: ...


@dataclass(frozen=True)
class LifecycleStep:
    """Prepared C2 action with explicit forward and reverse verification."""

    name: str
    prepare: Callable[[OperationPlan], object]
    recovery_information: Callable[[object], str]
    apply: Callable[[object, object], None]
    verify: Callable[[object], None]
    rollback: Callable[[object], None]
    verify_rollback: Callable[[object], None]
    mutates: bool = True
    final_verifier: bool = False


class DurableOperationJournal(Protocol):
    durable: bool
    def record(self, **values) -> None: ...


class StagedLifecycleOperations:
    """Drive prepared C2 actions with durable, verified reverse rollback."""

    def __init__(self, *, validator: Callable[[OperationPlan], None],
                 workflows: dict[OperationKind, tuple[LifecycleStep, ...]],
                 journal: DurableOperationJournal) -> None:
        if getattr(journal, "durable", False) is not True:
            raise ValueError("A durable lifecycle journal is required")
        if set(workflows) != set(OperationKind):
            raise ValueError("Every typed FFTIC operation requires a workflow")
        for kind, steps in workflows.items():
            if (not steps or not any(step.mutates for step in steps)
                    or not steps[-1].final_verifier or steps[-1].mutates
                    or sum(step.final_verifier for step in steps) != 1):
                raise ValueError(
                    f"{kind.value} requires a mutating action and one final verifier")
        self._validator = validator
        self._workflows = dict(workflows)
        self._journal = journal

    def revalidate(self, plan: OperationPlan) -> None:
        if self._validator(plan) is False:
            raise StaleOperationPlan("FFTIC operation context changed")

    def _run(self, plan, cancel, progress) -> OperationResult:
        steps = self._workflows[plan.kind]
        attempted: list[tuple[LifecycleStep, object, int]] = []
        plan_fingerprint = hashlib.sha256(json.dumps(
            asdict(plan), sort_keys=True, separators=(",", ":"),
            default=str).encode("utf-8")).hexdigest()
        attempt_id = uuid.uuid4().hex

        def record(**values):
            self._journal.record(
                plan_fingerprint=plan_fingerprint, attempt_id=attempt_id,
                operation=plan.kind.value, **values)

        try:
            record(step=-1, phase="operation", state="operation-started")
            for index, step in enumerate(steps):
                if cancel is not None and cancel.is_set():
                    raise ManagedOperationCancelled(
                        f"FFTIC {plan.kind.value} cancelled before {step.name}")
                if self._validator(plan) is False:
                    raise StaleOperationPlan("FFTIC operation context changed between steps")
                token = step.prepare(plan)
                if token is None:
                    raise ManagedOperationError(
                        f"{step.name} did not prepare rollback evidence")
                recovery = step.recovery_information(token)
                if not isinstance(recovery, str) or not recovery:
                    raise ManagedOperationError(
                        f"{step.name} did not describe its recovery action")
                record(step=index, phase=step.name, state="write-ahead",
                       recovery_information=recovery)
                if step.mutates:
                    attempted.append((step, token, index))
                    record(step=index, phase=step.name, state="mutation-attempted")
                step.apply(token, cancel)
                step.verify(token)
                record(step=index, phase=step.name, state="forward-verified")
                if progress is not None:
                    progress(ProgressUpdate(index + 1, len(steps), step.name))
            record(step=len(steps), phase="operation", state="operation-completed")
            return OperationResult(plan, OperationState.SUCCEEDED, len(steps),
                                   f"FFTIC {plan.kind.value} completed and verified")
        except BaseException as original:
            failures = []
            for step, token, index in reversed(attempted):
                try:
                    record(step=index, phase=step.name, state="rollback-started")
                    step.rollback(token)
                    step.verify_rollback(token)
                    record(step=index, phase=step.name, state="rollback-verified")
                except BaseException as rollback_error:
                    failures.append(f"{step.name}: {rollback_error}")
                    record(step=index, phase=step.name, state="rollback-failed",
                           error=str(rollback_error))
            if failures:
                record(step=len(attempted), phase="rollback",
                       state="recovery-required", failed_actions=failures,
                       original_error=str(original))
                raise RecoveryRequiredError(
                    f"Rollback was incomplete for attempt {attempt_id}, plan "
                    f"{plan_fingerprint}: " + "; ".join(failures)) from original
            if isinstance(original, PrerequisiteRetryableError):
                record(step=len(attempted), phase="prerequisite",
                       state="prerequisite-retryable", original_error=str(original))
                raise original
            if isinstance(original, RecoveryRequiredError):
                record(step=len(attempted), phase="rollback",
                       state="recovery-required", original_error=str(original))
                raise original
            record(step=len(attempted), phase="rollback", state="rollback-verified",
                   original_error=str(original))
            raise

    @staticmethod
    def recovery_state(events: list[dict] | tuple[dict, ...],
                       attempt_id: str | None = None) -> RecoveryState:
        """Classify durable evidence without guessing whether a mutation occurred."""
        matching = [event for event in events if (
            attempt_id is None or event.get("attempt_id") == attempt_id)]
        if not matching:
            return RecoveryState.NOT_STARTED
        if attempt_id is None:
            attempt_id = matching[-1].get("attempt_id")
            matching = [event for event in matching
                        if event.get("attempt_id") == attempt_id]
        states = [event.get("state") for event in matching]
        if "operation-completed" in states:
            return RecoveryState.COMPLETED
        if "prerequisite-retryable" in states:
            return RecoveryState.PREREQUISITE_RETRYABLE
        if "recovery-required" in states or "rollback-failed" in states:
            return RecoveryState.RECOVERY_REQUIRED
        if "rollback-started" in states and "rollback-verified" not in states:
            return RecoveryState.ROLLBACK_STARTED
        if "rollback-verified" in states:
            return RecoveryState.ROLLBACK_VERIFIED
        if "forward-verified" in states:
            return RecoveryState.FORWARD_VERIFIED
        if "mutation-attempted" in states:
            return RecoveryState.MUTATION_ATTEMPTED
        if "write-ahead" in states:
            return RecoveryState.PREPARED
        if "operation-started" in states:
            return RecoveryState.STARTED
        return RecoveryState.NOT_STARTED

    def setup(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)

    def repair(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)

    def synchronize(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)

    def update(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)

    def remove(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)

    def reconcile_runtime_output(self, plan, cancel, progress):
        return self._run(plan, cancel, progress)


class MutationCoordinator:
    """One writer or any number of readers, shared by status and mutations."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False

    @contextmanager
    def inspection(self):
        with self._condition:
            while self._writer:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                self._condition.notify_all()

    @contextmanager
    def mutation(self):
        with self._condition:
            if self._writer:
                raise OperationBusyError("An FFTIC operation is already active")
            self._writer = True
            while self._readers:
                self._condition.wait()
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


MUTATION_COORDINATOR = MutationCoordinator()


class ManagedLifecycleExecutor:
    """Concrete authorized executor for typed, context-bound C3B plans."""

    authorized = True

    def automatic_reconciliation_ready(self) -> str | None:
        return self._operations.automatic_reconciliation_ready()

    def __init__(self, operations: LifecycleOperations,
                 *, coordinator: MutationCoordinator = MUTATION_COORDINATOR) -> None:
        self._operations = operations
        self._coordinator = coordinator

    @staticmethod
    def _cancelled(cancel) -> None:
        if cancel is not None and cancel.is_set():
            raise ManagedOperationCancelled("FFTIC operation cancelled before mutation")

    def execute(self, plan: OperationPlan, cancel=None,
                progress: ProgressCallback | None = None) -> OperationResult:
        if not isinstance(plan, OperationPlan) or not isinstance(plan.binding, OperationBinding):
            raise StaleOperationPlan("Only a typed, context-bound FFTIC plan can execute")
        self._cancelled(cancel)
        with self._coordinator.mutation():
            self._cancelled(cancel)
            self._operations.revalidate(plan)
            callback = {
                OperationKind.SETUP: self._operations.setup,
                OperationKind.REPAIR: self._operations.repair,
                OperationKind.SYNCHRONIZE: self._operations.synchronize,
                OperationKind.UPDATE: self._operations.update,
                OperationKind.REMOVE: self._operations.remove,
                OperationKind.RECONCILE_RUNTIME_OUTPUT:
                    self._operations.reconcile_runtime_output,
            }[plan.kind]
            if progress is not None:
                progress(ProgressUpdate(0, max(1, len(plan.steps)),
                                        f"Starting FFTIC {plan.kind.value}"))
            result = callback(plan, cancel, progress)
            if not isinstance(result, OperationResult):
                raise ManagedOperationError("Lifecycle service returned an invalid result")
            if result.plan != plan or result.state != OperationState.SUCCEEDED:
                raise ManagedOperationError("Lifecycle service did not report verified success")
            return result
