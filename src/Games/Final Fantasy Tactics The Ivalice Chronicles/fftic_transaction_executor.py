"""Allowed-root, exact-ownership transaction execution for FFTIC."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

try:
    from .fftic_transactions import OperationKind, PlannedOperation, TransactionPlan
except ImportError:
    from fftic_transactions import OperationKind, PlannedOperation, TransactionPlan


class TransactionError(RuntimeError):
    pass


class TransactionCancelled(TransactionError):
    pass


class TransactionDrift(TransactionError):
    pass


class RollbackError(TransactionError):
    def __init__(self, failed_actions: tuple[str, ...]) -> None:
        self.failed_actions = failed_actions
        super().__init__("; ".join(failed_actions))


@dataclass(frozen=True)
class TransactionResult:
    transaction_id: str
    completed_steps: int
    rolled_back: bool


class TransactionJournal(Protocol):
    durable: bool
    def record(self, **values) -> None: ...


class FileTransactionJournal:
    """Small fsync-backed journal used before and after every owned mutation."""
    durable = True

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def record(self, **values) -> None:
        if os.path.lexists(self.path) and (self.path.is_symlink() or not self.path.is_file()):
            raise TransactionError(f"Transaction journal is not a regular file: {self.path}")
        events = []
        if self.path.exists():
            try:
                events = json.loads(self.path.read_text(encoding="utf-8"))["events"]
            except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise TransactionError(f"Transaction journal is corrupt: {exc}") from exc
            if not isinstance(events, list):
                raise TransactionError("Transaction journal event list is corrupt")
        events.append(values)
        payload = (json.dumps({"schema_version": 1, "events": events},
                              sort_keys=True, indent=2) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.tmp-{uuid.uuid4().hex}")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            FfticTransactionExecutor._fsync_directory(self.path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FfticTransactionExecutor:
    def __init__(self, *, allowed_roots: tuple[Path, ...] | list[Path], lock_path: Path,
                 process_running=None, journal: TransactionJournal | None = None, progress=None,
                 failure_injector=None) -> None:
        raw_roots = tuple(Path(root) for root in allowed_roots)
        for root in raw_roots:
            current = root.absolute()
            while current != current.parent:
                if current.is_symlink():
                    raise ValueError("Allowed roots cannot contain symbolic-link ancestors")
                current = current.parent
        self.allowed_roots = tuple(root.resolve() for root in raw_roots)
        if not self.allowed_roots:
            raise ValueError("At least one explicit allowed root is required")
        if (journal is None or not callable(getattr(journal, "record", None))
                or getattr(journal, "durable", False) is not True):
            raise ValueError("A durable receipt/journal facility is required")
        self.lock_path = Path(lock_path)
        self.process_running = process_running or (lambda: False)
        self.journal = journal
        self.progress = progress or (lambda *_values: None)
        self.failure_injector = failure_injector or (lambda *_values: None)

    def _contained(self, path: Path) -> Path:
        path = Path(path)
        absolute = path if path.is_absolute() else path.absolute()
        # Resolve the nearest existing ancestor without following a target link.
        ancestor = absolute
        tail: list[str] = []
        while not os.path.lexists(ancestor) and ancestor != ancestor.parent:
            tail.append(ancestor.name)
            ancestor = ancestor.parent
        if ancestor.is_symlink():
            raise TransactionError(f"Operation target is or crosses a symlink: {path}")
        resolved = ancestor.resolve()
        for component in reversed(tail):
            resolved /= component
        if not any(resolved == root or resolved.is_relative_to(root) for root in self.allowed_roots):
            raise TransactionError(f"Operation target is outside explicit allowed roots: {path}")
        current = resolved
        while current != current.parent:
            if os.path.lexists(current) and current.is_symlink():
                raise TransactionError(f"Operation target crosses a symlink: {current}")
            if any(current == root for root in self.allowed_roots):
                break
            current = current.parent
        return resolved

    @contextmanager
    def _lock(self):
        self._contained(self.lock_path)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise TransactionError(f"Another FFTIC transaction is active: {self.lock_path}") from exc
        token = f"{os.getpid()}:{uuid.uuid4().hex}".encode("ascii")
        identity = None
        try:
            os.write(fd, token)
            os.fsync(fd)
            identity = os.fstat(fd)
            os.close(fd)
            fd = -1
            yield
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                current = self.lock_path.lstat()
                if (identity is not None
                        and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
                        and self.lock_path.read_bytes() == token):
                    self.lock_path.unlink()
                    self._fsync_directory(self.lock_path.parent)
            except FileNotFoundError:
                pass

    @staticmethod
    def _require_regular(path: Path, expected_hash: str | None = None) -> None:
        if path.is_symlink() or not path.is_file():
            raise TransactionDrift(f"Expected a regular file: {path}")
        if expected_hash is not None and file_sha256(path) != expected_hash.casefold():
            raise TransactionDrift(f"File identity changed: {path}")

    def execute(self, plan: TransactionPlan, *, cancel=None) -> TransactionResult:
        if not plan.can_execute:
            raise TransactionError("Transaction plan contains a collision or drift stop")
        undo: list[tuple[str, Path, Path | None, str | None]] = []
        completed = 0
        with self._lock():
            if self.process_running():
                raise TransactionError("FFTIC or Reloaded is running")
            try:
                for index, operation in enumerate(plan.operations):
                    if cancel is not None and cancel.is_set():
                        raise TransactionCancelled("FFTIC transaction cancelled between durable steps")
                    self.failure_injector("before", index, operation)
                    if self._is_mutating(operation):
                        self.journal.record(
                            transaction_id=plan.transaction_id, step=index,
                            operation=operation.kind.value, state="write-ahead")
                        if self.process_running():
                            raise TransactionError("FFTIC or Reloaded started before a mutating step")
                    self._execute_step(operation, undo)
                    completed += 1
                    self.journal.record(
                        transaction_id=plan.transaction_id, step=index,
                        operation=operation.kind.value, state="durable")
                    self.progress(completed, len(plan.operations), operation.reason)
                    self.failure_injector("after", index, operation)
                return TransactionResult(plan.transaction_id, completed, False)
            except BaseException as original:
                try:
                    self._rollback(undo)
                except BaseException as rollback_error:
                    failed_actions = getattr(
                        rollback_error, "failed_actions", (str(rollback_error),))
                    self.journal.record(
                        transaction_id=plan.transaction_id, step=completed,
                        operation="rollback", state="recovery-required",
                        failed_actions=failed_actions, original_error=str(original))
                    raise TransactionError(
                        f"Transaction failed and rollback requires recovery: {rollback_error}") from original
                self.journal.record(
                    transaction_id=plan.transaction_id, step=completed,
                    operation="rollback", state="rolled-back")
                raise

    @staticmethod
    def _is_mutating(operation: PlannedOperation) -> bool:
        return operation.kind in {
            OperationKind.BACK_UP_TARGET, OperationKind.COPY_OWNED_FILE,
            OperationKind.WRITE_CONFIGURATION,
        }

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_file(path: Path) -> None:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())

    def _execute_step(self, operation: PlannedOperation,
                      undo: list[tuple[str, Path, Path | None, str | None]]) -> None:
        source = self._contained(operation.source) if operation.source else None
        destination = self._contained(operation.destination) if operation.destination else None
        backup = self._contained(operation.backup_path) if operation.backup_path else None
        if operation.kind == OperationKind.VERIFY_ABSENCE:
            if destination is None or os.path.lexists(destination):
                raise TransactionDrift(f"Expected target absence: {destination}")
        elif operation.kind == OperationKind.VERIFY_PRIOR_HASH:
            self._require_regular(destination, operation.expected_target_hash)
        elif operation.kind == OperationKind.BACK_UP_TARGET:
            self._require_regular(destination, operation.expected_target_hash)
            if backup is None or os.path.lexists(backup):
                raise TransactionDrift(f"Backup target is not safely absent: {backup}")
            backup.parent.mkdir(parents=True, exist_ok=True)
            os.replace(destination, backup)
            self._fsync_file(backup)
            self._fsync_directory(destination.parent)
            if backup.parent != destination.parent:
                self._fsync_directory(backup.parent)
            undo.append(("restore", destination, backup, operation.expected_target_hash))
        elif operation.kind in {OperationKind.COPY_OWNED_FILE, OperationKind.WRITE_CONFIGURATION}:
            self._require_regular(source, operation.expected_source_hash)
            if destination is None or os.path.lexists(destination):
                raise TransactionDrift(f"Publication target is not absent: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp-{uuid.uuid4().hex}")
            try:
                with source.open("rb") as incoming, temporary.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                if file_sha256(temporary) != operation.expected_source_hash.casefold():
                    raise TransactionError(f"Published bytes do not match source identity: {source}")
                os.replace(temporary, destination)
                self._fsync_directory(destination.parent)
            finally:
                temporary.unlink(missing_ok=True)
            undo.append(("remove", destination, None, operation.expected_source_hash))
        elif operation.kind == OperationKind.RETAIN_SHARED_PREREQUISITE:
            return
        else:
            raise TransactionError(f"Executor does not authorize operation {operation.kind.value}")

    def _rollback(self, undo: list[tuple[str, Path, Path | None, str | None]]) -> None:
        errors: list[str] = []
        for action, destination, backup, expected in reversed(undo):
            try:
                if action == "remove":
                    self._require_regular(destination, expected)
                    destination.unlink()
                    self._fsync_directory(destination.parent)
                elif action == "restore":
                    if os.path.lexists(destination):
                        raise TransactionDrift(f"Rollback destination is occupied: {destination}")
                    self._require_regular(backup, expected)
                    os.replace(backup, destination)
                    self._fsync_directory(destination.parent)
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RollbackError(tuple(errors))

    def remove_exact_owned(self, *, target: Path, expected_hash: str,
                           quarantine_root: Path, transaction_id: str) -> Path:
        """Move one exact-owned file to quarantine; never recursively delete."""
        with self._lock():
            if self.process_running():
                raise TransactionError("FFTIC or Reloaded is running")
            target = self._contained(target)
            quarantine_root = self._contained(quarantine_root)
            self._require_regular(target, expected_hash)
            quarantine_parent = quarantine_root if quarantine_root.exists() else quarantine_root.parent
            if target.stat().st_dev != quarantine_parent.stat().st_dev:
                raise TransactionError("Quarantine must be on the same filesystem as its source")
            self.journal.record(transaction_id=transaction_id, step=0,
                                operation="quarantine exact-owned file", state="write-ahead")
            if self.process_running():
                raise TransactionError("FFTIC or Reloaded started before quarantine mutation")
            quarantine_root.mkdir(parents=True, exist_ok=True)
            quarantine = quarantine_root / f"{target.name}.{transaction_id}.{uuid.uuid4().hex}"
            if os.path.lexists(quarantine):
                raise TransactionError(f"Quarantine target already exists: {quarantine}")
            os.replace(target, quarantine)
            try:
                self._fsync_file(quarantine)
                self._fsync_directory(target.parent)
                self._fsync_directory(quarantine_root)
                self.journal.record(transaction_id=transaction_id, step=0,
                                    operation="quarantine exact-owned file", state="durable",
                                    source=str(target), destination=str(quarantine))
            except BaseException as exc:
                self._surface_recovery_required(
                    transaction_id, "quarantine exact-owned file", target, quarantine, exc)
            return quarantine

    def quarantine_owned_generation(self, *, generation_root: Path,
                                    generation_id: str, quarantine_root: Path,
                                    transaction_id: str) -> Path:
        """Move one fully verified generation to quarantine without deleting it."""
        try:
            from .fftic_generation import verify_private_generation
        except ImportError:
            from fftic_generation import verify_private_generation
        with self._lock():
            if self.process_running():
                raise TransactionError("FFTIC or Reloaded is running")
            generation_root = self._contained(generation_root)
            quarantine_root = self._contained(quarantine_root)
            verify_private_generation(generation_root, generation_id)
            quarantine_parent = quarantine_root if quarantine_root.exists() else quarantine_root.parent
            if generation_root.stat().st_dev != quarantine_parent.stat().st_dev:
                raise TransactionError("Generation quarantine must be on the same filesystem")
            self.journal.record(transaction_id=transaction_id, step=0,
                                operation="quarantine verified generation", state="write-ahead")
            if self.process_running():
                raise TransactionError("FFTIC or Reloaded started before quarantine mutation")
            quarantine_root.mkdir(parents=True, exist_ok=True)
            target = quarantine_root / f"{generation_id}.{transaction_id}.{uuid.uuid4().hex}"
            if os.path.lexists(target):
                raise TransactionError(f"Generation quarantine target exists: {target}")
            os.replace(generation_root, target)
            try:
                self._fsync_directory(generation_root.parent)
                self._fsync_directory(quarantine_root)
                self.journal.record(transaction_id=transaction_id, step=0,
                                    operation="quarantine verified generation", state="durable",
                                    source=str(generation_root), destination=str(target))
            except BaseException as exc:
                self._surface_recovery_required(
                    transaction_id, "quarantine verified generation", generation_root, target, exc)
            return target

    def _surface_recovery_required(self, transaction_id: str, operation: str,
                                   source: Path, destination: Path,
                                   original: BaseException) -> None:
        details = {
            "transaction_id": transaction_id, "step": 0, "operation": operation,
            "state": "recovery-required", "source": str(source),
            "destination": str(destination), "error": str(original),
        }
        try:
            self.journal.record(**details)
        except BaseException as journal_error:
            raise TransactionError(
                f"Mutation completed; recovery required at {destination}; "
                f"recovery journal also failed: {journal_error}") from original
        raise TransactionError(
            f"Mutation completed; recovery required at {destination}: {original}") from original


def activate_generation(state_file: Path, generation_id: str, generation_root: Path,
                        *, journal: TransactionJournal, transaction_id: str,
                        previous_generation: str | None = None) -> None:
    """Atomically select a complete generation without a symlink/current tree."""
    generation_root = Path(generation_root)
    try:
        from .fftic_generation import verify_private_generation
    except ImportError:
        from fftic_generation import verify_private_generation
    try:
        manifest_sha256 = verify_private_generation(generation_root, generation_id)
    except Exception as exc:
        raise TransactionError(f"Cannot activate an unverified generation: {exc}") from exc
    if (not callable(getattr(journal, "record", None))
            or getattr(journal, "durable", False) is not True):
        raise ValueError("A durable activation journal is required")
    payload = {
        "schema_version": 1,
        "active_generation": generation_id,
        "generation_root": str(generation_root.resolve()),
        "previous_generation": previous_generation,
        "manifest_sha256": manifest_sha256,
    }
    state_file = Path(state_file)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_file.with_name(f".{state_file.name}.tmp-{uuid.uuid4().hex}")
    journal.record(transaction_id=transaction_id, step=0, operation="activate generation",
                   state="write-ahead", state_file=str(state_file),
                   generation_root=str(generation_root.resolve()), generation_id=generation_id)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state_file)
        try:
            FfticTransactionExecutor._fsync_directory(state_file.parent)
            journal.record(transaction_id=transaction_id, step=0,
                           operation="activate generation", state="durable",
                           state_file=str(state_file), generation_root=str(generation_root.resolve()),
                           generation_id=generation_id, manifest_sha256=manifest_sha256)
        except BaseException as exc:
            try:
                journal.record(transaction_id=transaction_id, step=0,
                               operation="activate generation", state="recovery-required",
                               state_file=str(state_file),
                               generation_root=str(generation_root.resolve()),
                               generation_id=generation_id, manifest_sha256=manifest_sha256,
                               error=str(exc))
            except BaseException as journal_error:
                raise TransactionError(
                    f"Generation activation selected {generation_id} in {state_file}; "
                    f"recovery journal also failed: {journal_error}") from exc
            raise TransactionError(
                f"Generation activation selected {generation_id} in {state_file}; "
                f"recovery required: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
