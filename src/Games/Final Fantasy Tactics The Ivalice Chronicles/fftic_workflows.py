"""Isolated C2 lifecycle composition for the C3B operation boundary.

This module deliberately has no production constructor.  Callers must supply
every root, current observation, reviewed cache, prerequisite boundary, and
readiness reader explicitly.  The FFTIC game handler therefore remains
non-mutating until a later phase installs an authorized composition.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

try:
    from .fftic_artifacts import ARTIFACTS, INTERNAL_FILES, validate_file
    from .fftic_detection import InstallStatus, InstallationDetection, VERIFIED_HASHES
    from .fftic_extraction import (
        ExtractedArchive, ExtractionLimits, VerifiedArtifactTree,
        extract_archive, extract_verified_artifact,
    )
    from .fftic_generation import (
        MANAGED_ARTIFACTS, GenerationResult, build_private_generation,
        read_profile_mods,
        verify_private_generation,
    )
    from .fftic_managed_executor import (
        LifecycleStep, ManagedOperationCancelled, ManagedOperationError, OperationResult,
        PrerequisiteProcessRunner, ProcessRequest, RecoveryRequiredError,
        RecoveryState, StagedLifecycleOperations,
    )
    from .fftic_orchestration import OperationKind, OperationPlan
    from .fftic_pac import PacLaunchEvidence, PacObservation, PacOwnershipState, pac_ownership
    from .fftic_prerequisites import (
        PrefixPrerequisites,
        PrerequisiteState, plan_installer,
    )
    from .fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, SUPPORTED_PROTON_RUNNER,
        verify_launch_readiness,
    )
    from .fftic_receipts import (
        PREFIX_CONFIGURATION_PATH, Receipt, read_receipt, validate_receipt,
        write_receipt,
    )
    from .fftic_reloaded_config import MANAGED_ORDER, generate_bootstrap_configuration
    from .fftic_steam_path import resolve_prefix_generation_path, resolve_steam_s_path
    from .fftic_steam_requirements import REQUIRED_OPTIONS_SHA256, SteamOptionsAnalysis
    from .fftic_transaction_executor import (
        FileTransactionJournal, FfticTransactionExecutor, file_sha256,
        activate_generation,
    )
    from .fftic_transactions import TargetObservation, plan_owned_file_install
except ImportError:
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES, validate_file
    from fftic_detection import InstallStatus, InstallationDetection, VERIFIED_HASHES
    from fftic_extraction import (
        ExtractedArchive, ExtractionLimits, VerifiedArtifactTree,
        extract_archive, extract_verified_artifact,
    )
    from fftic_generation import (
        MANAGED_ARTIFACTS, GenerationResult, build_private_generation,
        read_profile_mods,
        verify_private_generation,
    )
    from fftic_managed_executor import (
        LifecycleStep, ManagedOperationCancelled, ManagedOperationError, OperationResult,
        PrerequisiteProcessRunner, ProcessRequest, RecoveryRequiredError,
        RecoveryState, StagedLifecycleOperations,
    )
    from fftic_orchestration import OperationKind, OperationPlan
    from fftic_pac import PacLaunchEvidence, PacObservation, PacOwnershipState, pac_ownership
    from fftic_prerequisites import (
        PrefixPrerequisites,
        PrerequisiteState, plan_installer,
    )
    from fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, SUPPORTED_PROTON_RUNNER,
        verify_launch_readiness,
    )
    from fftic_receipts import (
        PREFIX_CONFIGURATION_PATH, Receipt, read_receipt, validate_receipt,
        write_receipt,
    )
    from fftic_reloaded_config import MANAGED_ORDER, generate_bootstrap_configuration
    from fftic_steam_path import resolve_prefix_generation_path, resolve_steam_s_path
    from fftic_steam_requirements import REQUIRED_OPTIONS_SHA256, SteamOptionsAnalysis
    from fftic_transaction_executor import (
        FileTransactionJournal, FfticTransactionExecutor, file_sha256,
        activate_generation,
    )
    from fftic_transactions import TargetObservation, plan_owned_file_install


class WorkflowError(ManagedOperationError):
    pass


@dataclass(frozen=True)
class ReviewedCandidateSet:
    """Explicit archive set; no URL resolution or acquisition is performed."""

    archives: tuple[tuple[str, Path], ...]

    def paths(self) -> dict[str, Path]:
        result = dict(self.archives)
        if len(result) != len(self.archives):
            raise WorkflowError("Reviewed candidate set contains duplicate component IDs")
        return result


@dataclass(frozen=True)
class CurrentInstallationEvidence:
    """One current compatibility observation and its explicit authority."""

    detection: InstallationDetection
    authority: str


@dataclass(frozen=True)
class WorkflowInputs:
    isolation_root: Path
    game_root: Path
    steam_library: Path
    app_manifest: Path
    prefix: Path
    profile_dir: Path
    staging_root: Path
    artifact_cache: Path
    extraction_root: Path
    generations_root: Path
    backup_root: Path
    quarantine_root: Path
    receipts_root: Path
    active_state_file: Path
    journal_file: Path
    log_root: Path
    installation_reader: Callable[[], CurrentInstallationEvidence]
    steam_options_reader: Callable[[], SteamOptionsAnalysis]
    runner_reader: Callable[[], str]
    prerequisite_reader: Callable[[Path], PrefixPrerequisites]
    process_request_factory: Callable[[object], ProcessRequest] | None = None
    process_runner: PrerequisiteProcessRunner | None = None
    setup_candidates: ReviewedCandidateSet | None = None
    pac_launch_evidence: tuple[PacLaunchEvidence, ...] = ()
    failure_injector: Callable[[str, OperationKind], None] | None = None


@dataclass
class _Baseline:
    kind: OperationKind
    receipt: bytes | None
    active_state: bytes | None
    game_files: dict[str, bytes | None]
    pac_files: dict[str, bytes | None]
    prefix_config: bytes | None
    generation_names: set[str]
    receipt_record: Receipt | None = None
    backup_files: dict[Path, bytes] | None = None
    generated_sources: tuple[Path, ...] = ()
    quarantine_moves: list[tuple[Path, Path]] | None = None
    cleanup_moves: list[tuple[Path, Path]] | None = None
    transaction_backups: list[tuple[Path, str]] | None = None
    mutated_files: set[Path] | None = None


class FfticLifecycleComposition:
    """Complete isolated setup/repair/sync/update/remove composition."""

    def __init__(self, inputs: WorkflowInputs,
                 *, plan_validator: Callable[[OperationPlan], bool]) -> None:
        self.inputs = inputs
        self._plan_validator = plan_validator
        self._operation_token: _Baseline | None = None
        self.journal = FileTransactionJournal(inputs.journal_file)
        self._validate_roots()
        events = self.journal.read_events()
        state = StagedLifecycleOperations.recovery_state(events)
        if state in {
                RecoveryState.MUTATION_ATTEMPTED, RecoveryState.FORWARD_VERIFIED,
                RecoveryState.ROLLBACK_STARTED, RecoveryState.RECOVERY_REQUIRED
        }:
            raise RecoveryRequiredError(
                f"Incomplete FFTIC lifecycle evidence requires recovery: {state.value}")
        workflows = {
            kind: self._workflow(kind) for kind in OperationKind
        }
        self._staged = StagedLifecycleOperations(
            validator=self._revalidate, workflows=workflows, journal=self.journal)

    def _validate_roots(self) -> None:
        root = Path(self.inputs.isolation_root)
        if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root.absolute():
            raise ValueError("The isolated lifecycle root must be canonical and unlinked")
        root = root.resolve()
        path_fields = (
            "game_root", "steam_library", "app_manifest", "prefix", "profile_dir",
            "staging_root", "artifact_cache", "extraction_root", "generations_root",
            "backup_root", "quarantine_root", "receipts_root", "active_state_file",
            "journal_file", "log_root",
        )
        for field in path_fields:
            path = Path(getattr(self.inputs, field)).absolute()
            if not path.is_relative_to(root):
                raise ValueError(f"{field} escapes the isolated lifecycle root: {path}")
            current = path
            while current != root and current != current.parent:
                if os.path.lexists(current) and current.is_symlink():
                    # The verified Steam S: mapping is below prefix/dosdevices and is
                    # never itself one of the supplied roots.
                    raise ValueError(f"{field} crosses a symbolic link: {current}")
                current = current.parent
        for name in ("installation_reader", "steam_options_reader", "runner_reader"):
            if not callable(getattr(self.inputs, name)):
                raise ValueError(f"{name} must be an injected current-evidence provider")

    @staticmethod
    def _sha256(path: Path) -> str:
        return file_sha256(path)

    def _current_installation(self) -> CurrentInstallationEvidence:
        evidence = self.inputs.installation_reader()
        if not isinstance(evidence, CurrentInstallationEvidence):
            raise WorkflowError("Installation provider returned invalid evidence")
        detection = evidence.detection
        if (detection.game_root is None
                or Path(detection.game_root).resolve() != self.inputs.game_root):
            raise WorkflowError("Current installation evidence belongs to another game root")
        observed = {}
        for identity, filename in (("classic", "FFT_classic.exe"),
                                   ("enhanced", "FFT_enhanced.exe")):
            executable = self.inputs.game_root / filename
            if (executable.is_symlink() or not executable.is_file()
                    or executable.parent.resolve(strict=True) != self.inputs.game_root
                    or executable.resolve(strict=True) != executable.absolute()):
                raise WorkflowError(
                    f"Current FFTIC executable is missing, linked, or outside the game root: {filename}")
            observed[identity] = self._sha256(executable)
        if dict(detection.executable_hashes) != observed:
            raise WorkflowError("Current executable bytes differ from installation evidence")
        if evidence.authority == "reviewed-production":
            if (detection.status != InstallStatus.EXACT_VERIFIED
                    or observed != VERIFIED_HASHES):
                raise WorkflowError("The selected FFTIC executable identities are unsupported")
        elif not (evidence.authority.startswith("isolated-fixture:")
                  and detection.status == InstallStatus.UNVERIFIED):
            raise WorkflowError("Installation evidence authority is not recognized")
        return evidence

    def _current_runner(self) -> str:
        runner = self.inputs.runner_reader()
        if runner != SUPPORTED_PROTON_RUNNER:
            raise WorkflowError("Current runner identity is outside the reviewed tuple")
        return runner

    def _current_steam_options(self) -> SteamOptionsAnalysis:
        value = self.inputs.steam_options_reader()
        if not isinstance(value, SteamOptionsAnalysis):
            raise WorkflowError("Steam Launch Options provider returned invalid evidence")
        return value

    def _revalidate(self, plan: OperationPlan) -> None:
        if self._plan_validator(plan) is False:
            raise WorkflowError("FFTIC operation plan is stale")
        binding = plan.binding
        if binding is None or any((
                Path(binding.game_root) != self.inputs.game_root,
                Path(binding.prefix) != self.inputs.prefix,
                Path(binding.profile_dir) != self.inputs.profile_dir,
                Path(binding.staging_root) != self.inputs.staging_root,
                binding.profile != plan.profile,
        )):
            raise WorkflowError("Operation binding differs from the composed lifecycle roots")
        self._current_installation()
        self._current_runner()
        self._current_steam_options()
        resolve_steam_s_path(
            steam_library=self.inputs.steam_library,
            app_manifest=self.inputs.app_manifest,
            game_root=self.inputs.game_root,
            prefix=self.inputs.prefix)
        read_profile_mods(self.inputs.profile_dir, self.inputs.staging_root)

    def _workflow(self, kind: OperationKind) -> tuple[LifecycleStep, ...]:
        action = LifecycleStep(
            f"compose {kind.value} C2 services",
            lambda plan, selected=kind: self._prepare(plan, selected),
            lambda token: self._recovery_information(token),
            lambda token, cancel: self._apply(token, cancel),
            lambda token: self._verify_forward(token),
            lambda token: self._rollback(token),
            lambda token: self._verify_rollback(token),
        )
        cleanup = LifecycleStep(
            f"clean verified {kind.value} recovery data",
            lambda _plan: self._prepared_token(kind),
            lambda token: self._recovery_information(token),
            lambda token, _cancel: self._cleanup(token),
            lambda token: self._verify_cleanup(token),
            lambda token: self._rollback_cleanup(token),
            lambda token: self._verify_cleanup_rollback(token),
        )
        final = LifecycleStep(
            f"final correlated {kind.value} verification",
            lambda _plan: self._prepared_token(kind),
            lambda token: f"repeat final {token.kind.value} verification",
            lambda _token, _cancel: None,
            lambda token: self._final_verify(token),
            lambda _token: None,
            lambda _token: None,
            mutates=False, final_verifier=True,
        )
        return action, cleanup, final

    def _prepared_token(self, kind: OperationKind) -> _Baseline:
        if self._operation_token is None or self._operation_token.kind != kind:
            raise WorkflowError("Lifecycle operation lost its prepared recovery evidence")
        return self._operation_token

    @staticmethod
    def _read_optional(path: Path) -> bytes | None:
        if not os.path.lexists(path):
            return None
        if path.is_symlink() or not path.is_file():
            raise WorkflowError(f"Owned state is not a regular file: {path}")
        return path.read_bytes()

    @staticmethod
    def _bounded_path(value: str | Path, root: Path, label: str,
                      *, kind: str | None = None) -> Path:
        """Validate an existing or safely unresolved receipt-controlled path."""
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise RecoveryRequiredError(f"{label} root is not a regular directory")
        root = root.resolve(strict=True)
        path = Path(value)
        if not path.is_absolute():
            raise RecoveryRequiredError(f"{label} is not absolute")
        absolute = path.absolute()
        if absolute == root or not absolute.is_relative_to(root):
            raise RecoveryRequiredError(f"{label} escapes its owned root")
        current = root
        for component in absolute.relative_to(root).parts:
            current /= component
            if not os.path.lexists(current):
                continue
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise RecoveryRequiredError(f"{label} crosses a symbolic link")
            if current != absolute and not stat.S_ISDIR(mode):
                raise RecoveryRequiredError(f"{label} crosses a non-directory")
            if current == absolute:
                if kind == "file" and not stat.S_ISREG(mode):
                    raise RecoveryRequiredError(f"{label} is not a regular file")
                if kind == "directory" and not stat.S_ISDIR(mode):
                    raise RecoveryRequiredError(f"{label} is not a directory")
                if current.resolve(strict=True) != absolute:
                    raise RecoveryRequiredError(f"{label} is not canonical")
        return absolute

    def _receipt_pac_path(self, relative: str) -> Path:
        pure = PurePosixPath(relative)
        if (pure.is_absolute() or str(pure) != relative or not pure.parts
                or any(part in {"", ".", ".."} for part in pure.parts)
                or "\\" in relative):
            raise RecoveryRequiredError("Receipt PAC path is not a canonical relative path")
        target = (self.inputs.game_root / Path(*pure.parts)).absolute()
        return self._bounded_path(target, self.inputs.game_root, "Receipt PAC path")

    def _validate_receipt_context(self, receipt: Receipt) -> None:
        evidence = self._current_installation()
        runner = self._current_runner()
        self._current_steam_options()
        steam = resolve_steam_s_path(
            steam_library=self.inputs.steam_library, app_manifest=self.inputs.app_manifest,
            game_root=self.inputs.game_root, prefix=self.inputs.prefix)
        data = receipt.data
        game = data["game_root_identity"]
        prefix = data["prefix_identity"]
        if any((Path(game["path"]) != steam.game_root,
                Path(game["steam_library"]) != steam.steam_library,
                game["installed_directory"] != steam.installed_directory,
                Path(prefix["path"]) != steam.prefix,
                prefix["runner_identity"] != runner,
                data["compatibility_tuple"]["proton_runner"] != runner,
                data["evidence_authority"] != evidence.authority,
                data["executable_hashes"] != dict(evidence.detection.executable_hashes))):
            raise RecoveryRequiredError(
                "Receipt installation, prefix, runner, or executable identity is stale")
        generation = data["active_generation_identity"]
        self._bounded_path(generation["root"], self.inputs.generations_root,
                           "Receipt generation root", kind="directory")
        for record in (*data["owned_game_targets"],
                       *data["prefix_owned_configuration"]):
            if record["backup_path"] is not None:
                self._bounded_path(record["backup_path"], self.inputs.backup_root,
                                   "Receipt backup path", kind="file")
        for item in data["generated_pac_observations"]:
            self._receipt_pac_path(item["relative_path"])

    def _prepare(self, plan: OperationPlan, kind: OperationKind) -> _Baseline:
        if plan.kind != kind:
            raise WorkflowError("Lifecycle workflow kind differs from its typed plan")
        self._revalidate(plan)
        receipt_path = self.inputs.receipts_root / "fftic-receipt.json"
        config_path = self.inputs.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
        baseline = _Baseline(
            kind=kind,
            receipt=self._read_optional(receipt_path),
            active_state=self._read_optional(self.inputs.active_state_file),
            game_files={name: self._read_optional(self.inputs.game_root / name) for name in (
                "version.dll", "Reloaded.Mod.Loader.Bootstrapper.asi")},
            pac_files={},
            prefix_config=self._read_optional(config_path),
            generation_names={item.name for item in self.inputs.generations_root.iterdir()
                              if item.is_dir() and not item.is_symlink()}
            if self.inputs.generations_root.exists() else set(),
        )
        baseline.transaction_backups = []
        baseline.backup_files = {}
        baseline.quarantine_moves = []
        baseline.cleanup_moves = []
        baseline.mutated_files = set()
        current_receipt = read_receipt(self.inputs.receipts_root)
        if current_receipt is not None:
            self._validate_receipt_context(current_receipt)
            baseline.receipt_record = current_receipt
            baseline.pac_files = {
                item["relative_path"]: self._read_optional(
                    self._receipt_pac_path(item["relative_path"]))
                for item in current_receipt.data["generated_pac_observations"]
            }
            for record in (*current_receipt.data["owned_game_targets"],
                           *current_receipt.data["prefix_owned_configuration"]):
                if record["backup_path"] is not None:
                    backup = self._bounded_path(
                        record["backup_path"], self.inputs.backup_root,
                        "Receipt backup path", kind="file")
                    baseline.backup_files[backup] = self._read_optional(backup)
        self._operation_token = baseline
        return baseline

    def _recovery_information(self, token: _Baseline) -> str:
        return (
            f"restore exact pre-{token.kind.value} receipt, activation, bootstrap, "
            "prefix configuration, PACs, generations, and explicit replaced-file backups")

    def _inject(self, name: str, kind: OperationKind) -> None:
        if self.inputs.failure_injector is not None:
            self.inputs.failure_injector(name, kind)

    @staticmethod
    def _cancelled(cancel) -> None:
        if cancel is not None and cancel.is_set():
            raise ManagedOperationCancelled(
                "FFTIC lifecycle operation cancelled at a durable boundary")

    def _apply(self, token: _Baseline, cancel) -> None:
        if token.kind == OperationKind.SETUP:
            self._setup(token, cancel)
        elif token.kind == OperationKind.REPAIR:
            self._repair(token, cancel)
        elif token.kind == OperationKind.SYNCHRONIZE:
            self._publish_profile(token, cancel, self.inputs.setup_candidates, "synchronize")
        elif token.kind == OperationKind.UPDATE:
            raise WorkflowError(
                "Managed-runtime update is unavailable because the reviewed ArtifactPin "
                "contract cannot express a different candidate identity; use synchronize "
                "for profile-only changes")
        elif token.kind == OperationKind.REMOVE:
            self._remove(token, cancel)
        else:
            raise WorkflowError(f"Unsupported lifecycle operation {token.kind.value}")

    def _candidate_paths(self, candidates: ReviewedCandidateSet | None,
                         *, require_all: bool = True) -> dict[str, Path]:
        if candidates is None:
            paths = {artifact_id: self.inputs.artifact_cache / pin.filename
                     for artifact_id, pin in ARTIFACTS.items()}
        else:
            paths = candidates.paths()
        expected = set(ARTIFACTS)
        if require_all and set(paths) != expected:
            raise WorkflowError("All and only the reviewed component candidates are required")
        for artifact_id, path in paths.items():
            path = Path(path)
            pin = ARTIFACTS.get(artifact_id)
            if (pin is None or path.is_symlink() or path.parent.resolve() !=
                    self.inputs.artifact_cache.resolve()
                    or path.name != pin.filename or not validate_file(pin, path)):
                raise WorkflowError(f"Candidate {artifact_id} is absent or differs from its reviewed pin")
        return paths

    def _verified_trees(self, paths: dict[str, Path], cancel) -> dict[str, VerifiedArtifactTree]:
        result = {}
        attempt = self.inputs.extraction_root / uuid.uuid4().hex
        attempt.mkdir(parents=True, exist_ok=False)
        for artifact_id in sorted({*MANAGED_ARTIFACTS.values(), "reloaded-ii"}):
            result[artifact_id] = extract_verified_artifact(
                ARTIFACTS[artifact_id], paths[artifact_id], attempt / artifact_id,
                cancel=cancel)
        return result

    def _current_generation_id(self) -> str | None:
        try:
            data = json.loads(self.inputs.active_state_file.read_text(encoding="utf-8"))
            return data["active_generation"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
            return None

    def _build(self, token: _Baseline, cancel,
               candidates: ReviewedCandidateSet | None) -> tuple[GenerationResult, dict[str, Path]]:
        paths = self._candidate_paths(candidates)
        trees = self._verified_trees(paths, cancel)
        steam = resolve_steam_s_path(
            steam_library=self.inputs.steam_library, app_manifest=self.inputs.app_manifest,
            game_root=self.inputs.game_root, prefix=self.inputs.prefix)
        extraction_attempts = {evidence.root.parent for evidence in trees.values()}
        try:
            generation = build_private_generation(
                generations_root=self.inputs.generations_root,
                verified_inputs=trees,
                user_mods=read_profile_mods(self.inputs.profile_dir, self.inputs.staging_root),
                windows_game_path=steam.windows_game_path,
                cancel=cancel, previous_generation=self._current_generation_id())
        finally:
            for attempt in extraction_attempts:
                if attempt.is_dir() and attempt.is_relative_to(self.inputs.extraction_root):
                    shutil.rmtree(attempt)
        return generation, paths

    def _run_prerequisites(self, token: _Baseline, paths: dict[str, Path], cancel) -> None:
        current = self.inputs.prerequisite_reader(self.inputs.prefix)
        attempted_logs: list[Path] = []
        health_by_id = {
            "dotnet-desktop-runtime": current.dotnet_desktop,
            "vc-runtime": current.vc_runtime,
        }
        for artifact_id, health in health_by_id.items():
            if health.state == PrerequisiteState.SUFFICIENT:
                continue
            if self.inputs.process_runner is None or self.inputs.process_request_factory is None:
                raise WorkflowError(
                    f"{health.component} is missing and no authorized prerequisite runner was injected")
            plan = plan_installer(
                artifact_id=artifact_id, installer_path=paths[artifact_id],
                prefix=self.inputs.prefix, runner_identity=self._current_runner(),
                health=health)
            if plan is None:
                continue
            request = self.inputs.process_request_factory(plan)
            request.validate()
            if request.plan != plan:
                raise WorkflowError("Prerequisite request differs from the reviewed installer plan")
            attempted_logs.append(request.log_path)
            try:
                result = self.inputs.process_runner.run(request, cancel)
                if result.returncode not in (*plan.success_exit_codes, *plan.restart_exit_codes):
                    raise RuntimeError(
                        f"installer returned {result.returncode} for {plan.component}")
                if not request.post_install_health_check(plan, self.inputs.prefix):
                    raise RuntimeError(f"installer left {plan.component} unhealthy")
                self._inject(f"prerequisite:{artifact_id}", token.kind)
                if cancel is not None and cancel.is_set():
                    raise RuntimeError("operation was interrupted after prerequisite installation")
            except BaseException as exc:
                raise RecoveryRequiredError(
                    f"Prerequisite setup may have changed the shared Proton prefix; "
                    f"run FFTIC setup or repair and review {request.log_path}: {exc}") from exc
        after = self.inputs.prerequisite_reader(self.inputs.prefix)
        if any(item.state != PrerequisiteState.SUFFICIENT
               for item in (after.dotnet_desktop, after.vc_runtime)):
            logs = ", ".join(str(path) for path in attempted_logs)
            raise RecoveryRequiredError(
                "Prerequisite setup did not establish sufficient evidence; run FFTIC "
                f"setup or repair and review: {logs}")

    def _transaction(self) -> FfticTransactionExecutor:
        roots = (
            self.inputs.game_root, self.inputs.prefix, self.inputs.backup_root,
            self.inputs.quarantine_root, self.inputs.receipts_root,
            self.inputs.generations_root, self.inputs.extraction_root,
        )
        return FfticTransactionExecutor(
            allowed_roots=roots,
            lock_path=self.inputs.backup_root / "fftic-transaction.lock",
            journal=self.journal)

    def _bootstrap_sources(self, generation: GenerationResult) -> tuple[Path, Path]:
        nested_root = self.inputs.extraction_root / f"asi-{uuid.uuid4().hex}"
        extracted: ExtractedArchive = extract_archive(
            generation.root / "Loader/Asi/UltimateAsiLoader.7z", nested_root,
            required_members=("ASILoader64.dll",),
            limits=ExtractionLimits(2, 9_029_424, 5_413_776))
        version = extracted.root / "ASILoader64.dll"
        bootstrap = generation.root / "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll"
        if (not validate_file(INTERNAL_FILES["version-dll"], version)
                or not validate_file(INTERNAL_FILES["reloaded-bootstrapper-asi"], bootstrap)):
            raise WorkflowError("Generation does not contain the reviewed bootstrap identities")
        return version, bootstrap

    def _install_file(self, token: _Baseline, source: Path, destination: Path,
                      ownership: str, prior_hash: str | None = None,
                      backup: Path | None = None) -> None:
        exists = os.path.lexists(destination)
        observed_hash = (file_sha256(destination) if exists and destination.is_file()
                         and not destination.is_symlink() else None)
        source_hash = file_sha256(source)
        if exists and observed_hash == source_hash:
            return
        if exists and prior_hash is not None and backup is None:
            backup = (self.inputs.backup_root / "transaction-backups" /
                      f"{destination.name}-{uuid.uuid4().hex}")
        observation = TargetObservation(
            exists, observed_hash, ownership if prior_hash is not None else None, backup)
        plan = plan_owned_file_install(
            transaction_id=f"workflow-{uuid.uuid4().hex}", source=source,
            destination=destination, expected_source_hash=source_hash,
            ownership_identity=ownership, observed=observation,
            prior_owned_hash=prior_hash)
        if not plan.can_execute:
            raise WorkflowError(f"Unowned collision or drift at {destination}")
        self._transaction().execute(plan)
        token.mutated_files.add(destination)
        if backup is not None and backup.is_file():
            token.transaction_backups.append((backup, file_sha256(backup)))

    def _install_bootstrap(self, token: _Baseline, generation: GenerationResult) -> None:
        receipt = token.receipt_record
        prior_targets = ({item["relative_path"]: item for item in receipt.data["owned_game_targets"]}
                         if receipt is not None else {})
        version, bootstrap = self._bootstrap_sources(generation)
        token.generated_sources = (version.parent,)
        for relative, source in (
                ("version.dll", version),
                ("Reloaded.Mod.Loader.Bootstrapper.asi", bootstrap)):
            prior = prior_targets.get(relative)
            self._install_file(
                token, source, self.inputs.game_root / relative, f"fftic:{relative}",
                prior_hash=prior["expected_hash"] if prior else None,
                backup=Path(prior["backup_path"]) if prior and prior["backup_path"] else None)
            self._inject(f"bootstrap:{relative}", token.kind)
        windows_root = resolve_prefix_generation_path(
            prefix=self.inputs.prefix, host_generation_root=generation.root)
        payload = generate_bootstrap_configuration(windows_root)
        generated = self.inputs.extraction_root / f"bootstrap-{uuid.uuid4().hex}.json"
        generated.write_bytes(payload)
        token.generated_sources += (generated,)
        config_path = self.inputs.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
        prior_config = (receipt.data["prefix_owned_configuration"][0]
                        if receipt is not None else None)
        self._install_file(
            token, generated, config_path, "fftic:prefix-config",
            prior_hash=prior_config["expected_hash"] if prior_config else None,
            backup=Path(prior_config["backup_path"])
            if prior_config and prior_config["backup_path"] else None)
        self._inject("prefix-configuration", token.kind)
        shutil.rmtree(version.parent)
        generated.unlink()

    def _activate(self, token: _Baseline, generation: GenerationResult) -> None:
        activate_generation(
            self.inputs.active_state_file, generation.generation_id, generation.root,
            journal=self.journal, transaction_id=f"activate-{uuid.uuid4().hex}",
            previous_generation=generation.previous_generation)
        token.mutated_files.add(self.inputs.active_state_file)
        self._inject("activation", token.kind)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _receipt_data(self, generation: GenerationResult, operation: str,
                      prior: Receipt | None = None) -> dict:
        manifest = json.loads((generation.root / "amethyst-generation.json").read_text(encoding="utf-8"))
        steam = resolve_steam_s_path(
            steam_library=self.inputs.steam_library, app_manifest=self.inputs.app_manifest,
            game_root=self.inputs.game_root, prefix=self.inputs.prefix)
        prereqs = self.inputs.prerequisite_reader(self.inputs.prefix)
        installation = self._current_installation()
        runner = self._current_runner()
        steam_options = self._current_steam_options()
        if any(item.state != PrerequisiteState.SUFFICIENT
               for item in (prereqs.dotnet_desktop, prereqs.vc_runtime)):
            raise WorkflowError("Receipt cannot record insufficient prerequisite evidence")
        artifact_inputs = {item["artifact_id"]: item for item in manifest["artifact_inputs"]}
        now = self._now()
        old = prior.data if prior is not None else None

        def ownership(relative: str, expected: str, prefix_config: bool = False) -> dict:
            prior_records = (old["prefix_owned_configuration"] if prefix_config else
                             old["owned_game_targets"]) if old else ()
            match = next((item for item in prior_records if item["relative_path"] == relative), None)
            if match is not None:
                return dict(match, expected_hash=expected)
            before = (self.inputs.prefix / "drive_c" / relative if prefix_config
                      else self.inputs.game_root / relative)
            baseline = None
            # The current file is the just-published owned result.  Preexisting
            # bytes, if any, were moved by the C2 transaction to this backup.
            backup = self.inputs.backup_root / "preexisting" / relative.replace("/", "_")
            if backup.is_file() and not backup.is_symlink():
                baseline = file_sha256(backup)
            return {
                "relative_path": relative, "expected_hash": expected,
                "prior_state": "owned exact" if baseline else "absent",
                "prior_hash": baseline, "backup_path": str(backup) if baseline else None,
            }

        bootstrap_bytes = generate_bootstrap_configuration(resolve_prefix_generation_path(
            prefix=self.inputs.prefix, host_generation_root=generation.root))
        bootstrap_hash = hashlib.sha256(bootstrap_bytes).hexdigest()
        app_hashes = manifest["configuration"]["hashes"]
        data = {
            "schema_version": 1,
            "transaction_id": f"fftic-{uuid.uuid4().hex}",
            "created_at": old["created_at"] if old else now,
            "updated_at": now,
            "steam_app_id": "1004640",
            "game_root_identity": {
                "path": str(steam.game_root), "steam_library": str(steam.steam_library),
                "installed_directory": steam.installed_directory,
            },
            "prefix_identity": {"path": str(steam.prefix),
                                "runner_identity": runner},
            "executable_hashes": dict(installation.detection.executable_hashes),
            "evidence_authority": installation.authority,
            "compatibility_tuple": {
                "steam_build": "24304444", "ui_version": "v1.5.2",
                "proton_runner": runner,
                "reloaded": "1.31.0", "sigscan": "1.2.14",
                "shared_hooks": "1.16.3", "nenkai": "1.7.3",
            },
            "active_generation_identity": {
                "generation_id": generation.generation_id,
                "root": str(generation.root.resolve()),
                "manifest_sha256": verify_private_generation(
                    generation.root, generation.generation_id),
            },
            "artifacts": [{
                "artifact_id": pin.artifact_id, "version": pin.version,
                "url": pin.url, "size": pin.size, "sha256": pin.sha256,
            } for pin in ARTIFACTS.values()],
            "managed_packages": [{
                "mod_id": mod_id,
                "version": {MANAGED_ORDER[0]: "1.2.14", MANAGED_ORDER[1]: "1.16.3",
                            MANAGED_ORDER[2]: "1.7.3"}[mod_id],
                "content_identity": artifact_inputs[MANAGED_ARTIFACTS[mod_id]]["content_identity"],
            } for mod_id in MANAGED_ORDER],
            "configuration_hashes": {
                "bootstrap": bootstrap_hash,
                "classic_app": app_hashes["Apps/fft_classic.exe/AppConfig.json"],
                "enhanced_app": app_hashes["Apps/fft_enhanced.exe/AppConfig.json"],
            },
            "user_packages": [{
                "mod_id": item["mod_id"], "enabled": item["enabled"],
                "priority": item["priority"], "classification": item["classification"],
                "content_identity": item["content_manifest_sha256"],
            } for item in manifest["user_packages"]],
            "owned_game_targets": [
                ownership("version.dll", INTERNAL_FILES["version-dll"].sha256),
                ownership("Reloaded.Mod.Loader.Bootstrapper.asi",
                          INTERNAL_FILES["reloaded-bootstrapper-asi"].sha256),
            ],
            "prefix_owned_configuration": [ownership(
                PREFIX_CONFIGURATION_PATH, bootstrap_hash, True)],
            "shared_prerequisites": [{
                "component": item.component, "state": item.state.value,
                "observed_version": item.observed_version,
                "required_version": item.required_version,
            } for item in (prereqs.dotnet_desktop, prereqs.vc_runtime)],
            "steam_launch_options": {
                "status": steam_options.status.value,
                "required_sha256": REQUIRED_OPTIONS_SHA256,
                "observed_sha256": hashlib.sha256(
                    steam_options.original.encode("utf-8")).hexdigest(),
            },
            "generated_pac_observations": old["generated_pac_observations"] if old else [],
            "last_successful_operation": operation,
            "incomplete_operation": None,
            "recovery_instructions": [
                f"Review durable lifecycle evidence at {self.inputs.journal_file}."],
        }
        return validate_receipt(data)

    def _write_receipt(self, token: _Baseline, generation: GenerationResult,
                       operation: str) -> None:
        old = read_receipt(self.inputs.receipts_root)
        write_receipt(self.inputs.receipts_root,
                      self._receipt_data(generation, operation, old))
        token.mutated_files.add(self.inputs.receipts_root / "fftic-receipt.json")
        self._inject("receipt", token.kind)

    def _setup(self, token: _Baseline, cancel) -> None:
        if read_receipt(self.inputs.receipts_root) is not None:
            raise WorkflowError("Setup refuses an existing managed receipt; use repair or synchronize")
        paths = self._candidate_paths(self.inputs.setup_candidates)
        self._run_prerequisites(token, paths, cancel)
        self._cancelled(cancel)
        generation, _paths = self._build(token, cancel, self.inputs.setup_candidates)
        self._inject("generation", token.kind)
        self._cancelled(cancel)
        self._install_bootstrap(token, generation)
        self._cancelled(cancel)
        self._activate(token, generation)
        self._cancelled(cancel)
        self._write_receipt(token, generation, "setup")

    def _repair(self, token: _Baseline, cancel) -> None:
        receipt = token.receipt_record
        if receipt is None:
            raise WorkflowError("Repair requires an ownership receipt")
        generation_record = receipt.data["active_generation_identity"]
        generation = GenerationResult(
            generation_record["generation_id"], Path(generation_record["root"]),
            generation_record["manifest_sha256"], None)
        verify_private_generation(generation.root, generation.generation_id)
        # Drift is never overwritten. Missing receipt-owned bootstrap state is
        # reconstructed from the exact retained generation.
        missing_owned = False
        for record in receipt.data["owned_game_targets"]:
            target = self.inputs.game_root / record["relative_path"]
            if not os.path.lexists(target):
                missing_owned = True
            elif (
                    target.is_symlink() or not target.is_file()
                    or file_sha256(target) != record["expected_hash"]):
                raise WorkflowError(f"Owned file drift is preserved for recovery: {target}")
        config_record = receipt.data["prefix_owned_configuration"][0]
        config_path = self.inputs.prefix / "drive_c" / config_record["relative_path"]
        if not os.path.lexists(config_path):
            missing_owned = True
        elif (
                config_path.is_symlink() or not config_path.is_file()
                or file_sha256(config_path) != config_record["expected_hash"]):
            raise WorkflowError(f"Owned configuration drift is preserved for recovery: {config_path}")
        expected_state = {
            "schema_version": 1,
            "active_generation": generation.generation_id,
            "generation_root": str(generation.root.resolve()),
            "previous_generation": None,
            "manifest_sha256": generation.manifest_sha256,
        }
        if not os.path.lexists(self.inputs.active_state_file):
            missing_owned = True
        else:
            try:
                observed_state = json.loads(
                    self.inputs.active_state_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise WorkflowError(
                    "Owned activation state drift is preserved for recovery") from exc
            comparable = dict(observed_state)
            comparable["previous_generation"] = None
            if comparable != expected_state:
                raise WorkflowError(
                    "Owned activation state drift is preserved for recovery")
        if not missing_owned:
            raise WorkflowError("Repair found no missing receipt-owned state")
        self._install_bootstrap(token, generation)
        self._cancelled(cancel)
        self._activate(token, generation)
        self._cancelled(cancel)
        self._write_receipt(token, generation, "repair")

    def _publish_profile(self, token: _Baseline, cancel,
                         candidates: ReviewedCandidateSet | None, operation: str) -> None:
        receipt = token.receipt_record
        if receipt is None:
            raise WorkflowError(f"{operation.title()} requires an ownership receipt")
        self._assert_readiness(
            f"{operation.title()} refuses drift outside the current profile",
            allow_profile_drift=True)
        generation, _paths = self._build(token, cancel, candidates)
        if generation.generation_id == self._current_generation_id():
            raise WorkflowError(
                f"{operation.title()} has no changed reviewed input to publish")
        self._inject("generation", token.kind)
        self._cancelled(cancel)
        self._install_bootstrap(token, generation)
        self._cancelled(cancel)
        self._activate(token, generation)
        self._cancelled(cancel)
        self._write_receipt(token, generation, operation)

    def _quarantine_file(self, token: _Baseline, target: Path, digest: str,
                         *, cleanup: bool = False) -> None:
        quarantined = self._transaction().remove_exact_owned(
            target=target, expected_hash=digest,
            quarantine_root=self.inputs.quarantine_root,
            transaction_id=f"{'cleanup' if cleanup else 'remove'}-{uuid.uuid4().hex}")
        token.mutated_files.add(target)
        (token.cleanup_moves if cleanup else token.quarantine_moves).append(
            (target, quarantined))

    @staticmethod
    def _atomic_copy(source: Path, destination: Path, expected_hash: str) -> None:
        if source.is_symlink() or not source.is_file() or file_sha256(source) != expected_hash:
            raise RecoveryRequiredError(f"Verified backup is unavailable: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.restore-{uuid.uuid4().hex}")
        try:
            shutil.copyfile(source, temporary)
            if file_sha256(temporary) != expected_hash:
                raise RecoveryRequiredError("Atomic restore copy changed bytes")
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    def _remove_owned_file(self, token: _Baseline, target: Path, record: dict) -> None:
        if os.path.lexists(target):
            if (target.is_symlink() or not target.is_file()
                    or file_sha256(target) != record["expected_hash"]):
                raise RecoveryRequiredError(
                    f"Owned file drift is preserved for recovery: {target}")
            self._quarantine_file(token, target, record["expected_hash"])
        if record["prior_state"] == "owned exact":
            backup = self._bounded_path(
                record["backup_path"], self.inputs.backup_root,
                "Receipt backup path", kind="file")
            self._atomic_copy(backup, target, record["prior_hash"])

    def _remove(self, token: _Baseline, cancel) -> None:
        receipt = token.receipt_record
        if receipt is None:
            raise WorkflowError("Removal requires an ownership receipt")
        try:
            self._assert_readiness(
                "Removal refuses unverified owned state", allow_pac_disposition=True)
        except WorkflowError as exc:
            raise RecoveryRequiredError(str(exc)) from exc
        for record in receipt.data["owned_game_targets"]:
            self._remove_owned_file(
                token, self.inputs.game_root / record["relative_path"], record)
            self._inject(f"remove:{record['relative_path']}", token.kind)
            self._cancelled(cancel)
        config = receipt.data["prefix_owned_configuration"][0]
        self._remove_owned_file(
            token, self.inputs.prefix / "drive_c" / config["relative_path"], config)
        self._inject("remove:prefix-configuration", token.kind)
        self._cancelled(cancel)
        launch_evidence = {
            (item.generation_id, item.profile_fingerprint, item.launch_id,
             item.transaction_id) for item in self.inputs.pac_launch_evidence
        }
        for item in receipt.data["generated_pac_observations"]:
            target = self._receipt_pac_path(item["relative_path"])
            observation = PacObservation(**item)
            correlated = (
                item["generation_id"], item["profile_fingerprint"],
                item["launch_id"], item["transaction_id"]) in launch_evidence
            state = pac_ownership(
                self.inputs.game_root, item["relative_path"], observation)
            if correlated and state == PacOwnershipState.OWNED_EXACT:
                self._quarantine_file(token, target, item["sha256"])
            elif state == PacOwnershipState.OWNED_EXACT:
                raise RecoveryRequiredError(
                    f"Generated PAC lacks exact launch correlation: {item['relative_path']}")
            elif state in {PacOwnershipState.DRIFT, PacOwnershipState.UNKNOWN}:
                raise RecoveryRequiredError(
                    f"Generated PAC drift is preserved for recovery: {item['relative_path']}")
            self._inject(f"remove:pac:{item['relative_path']}", token.kind)
            self._cancelled(cancel)
        generation = receipt.data["active_generation_identity"]
        generation_root = self._bounded_path(
            generation["root"], self.inputs.generations_root,
            "Receipt generation root", kind="directory")
        quarantined = self._transaction().quarantine_owned_generation(
            generation_root=generation_root, generation_id=generation["generation_id"],
            quarantine_root=self.inputs.quarantine_root,
            transaction_id=f"remove-generation-{uuid.uuid4().hex}")
        token.quarantine_moves.append((generation_root, quarantined))
        self._inject("remove:generation", token.kind)
        self._cancelled(cancel)
        if not self.inputs.active_state_file.is_file() or self.inputs.active_state_file.is_symlink():
            raise RecoveryRequiredError("Active generation state is not exact-owned")
        self._quarantine_file(
            token, self.inputs.active_state_file, file_sha256(self.inputs.active_state_file))
        self._inject("remove:active-state", token.kind)
        self._verify_removed(token, receipt_present=True, backups_present=True)
        for backup, payload in (token.backup_files or {}).items():
            self._quarantine_file(token, backup, hashlib.sha256(payload).hexdigest())
        self._inject("remove:backups", token.kind)
        self._verify_removed(token, receipt_present=True, backups_present=False)
        self._inject("remove:before-receipt", token.kind)
        receipt_path = self.inputs.receipts_root / "fftic-receipt.json"
        self._quarantine_file(token, receipt_path, file_sha256(receipt_path))
        self._inject("remove:receipt", token.kind)

    def _readiness(self):
        receipt = read_receipt(self.inputs.receipts_root)
        if receipt is None:
            raise WorkflowError("A complete ownership receipt is missing")
        self._validate_receipt_context(receipt)
        installation = self._current_installation()
        steam = resolve_steam_s_path(
            steam_library=self.inputs.steam_library, app_manifest=self.inputs.app_manifest,
            game_root=self.inputs.game_root, prefix=self.inputs.prefix)
        return installation, verify_launch_readiness(ReadinessEvidence(
            receipt, installation.detection, steam, self.inputs.app_manifest,
            self._current_runner(), self.inputs.active_state_file,
            self.inputs.profile_dir, self.inputs.staging_root,
            self.inputs.prerequisite_reader(self.inputs.prefix),
            self._current_steam_options(), self.inputs.pac_launch_evidence))

    def _assert_readiness(self, prefix: str, *, allow_profile_drift: bool = False,
                          allow_pac_disposition: bool = False) -> None:
        installation, verified = self._readiness()
        states = (verified.artifacts, verified.generation, verified.prefix,
                  verified.prerequisites, verified.bootstrap, verified.steam_options,
                  verified.recovery)
        pac_only = (allow_pac_disposition
                    and all(issue.startswith("PAC observation")
                            for issue in verified.issues
                            if not issue.startswith("Current installation evidence")))
        profile_ok = (allow_profile_drift or pac_only
                      or verified.profile == ReadinessAspect.READY)
        fixture_ok = (installation.authority.startswith("isolated-fixture:")
                      and verified.attested and verified.game == ReadinessAspect.INVALID
                      and profile_ok
                      and all(state == ReadinessAspect.READY for state in states))
        production_ok = (installation.authority == "reviewed-production"
                         and verified.attested and verified.game == ReadinessAspect.READY
                         and profile_ok
                         and all(state == ReadinessAspect.READY for state in states))
        if not (fixture_ok or production_ok):
            raise WorkflowError(prefix + ": " + "; ".join(verified.issues))

    def _verify_forward(self, token: _Baseline) -> None:
        if token.kind == OperationKind.REMOVE:
            self._verify_removed(token, receipt_present=False, backups_present=False)
        else:
            self._assert_readiness("Final correlated readiness failed")

    def _final_verify(self, token: _Baseline) -> None:
        self._inject("final-verifier", token.kind)
        if token.kind == OperationKind.REMOVE:
            self._verify_removed(token, receipt_present=False, backups_present=False)
        else:
            self._assert_readiness("Final correlated C2 verifier did not attest readiness")

    def _verify_removed(self, token: _Baseline, *, receipt_present: bool,
                        backups_present: bool) -> None:
        prior = token.receipt_record
        if prior is None:
            raise WorkflowError("Removal verifier lacks the original receipt")
        if (read_receipt(self.inputs.receipts_root) is not None) != receipt_present:
            raise WorkflowError("Ownership receipt disposition is incorrect")
        if os.path.lexists(self.inputs.active_state_file):
            raise WorkflowError("Active generation remains after removal")
        records = [
            (self.inputs.game_root / item["relative_path"], item)
            for item in prior.data["owned_game_targets"]]
        config = prior.data["prefix_owned_configuration"][0]
        records.append((self.inputs.prefix / "drive_c" / config["relative_path"], config))
        for target, record in records:
            expected = None if record["prior_state"] == "absent" else record["prior_hash"]
            if expected is None:
                if os.path.lexists(target):
                    raise WorkflowError(f"Absent-baseline target remains: {target}")
            elif (target.is_symlink() or not target.is_file()
                  or file_sha256(target) != expected):
                raise WorkflowError(f"Preexisting target was not restored exactly: {target}")
        for item in prior.data["generated_pac_observations"]:
            if os.path.lexists(self._receipt_pac_path(item["relative_path"])):
                raise WorkflowError(f"Receipt-owned PAC remains: {item['relative_path']}")
        generation = self._bounded_path(
            prior.data["active_generation_identity"]["root"],
            self.inputs.generations_root, "Receipt generation root")
        if os.path.lexists(generation):
            raise WorkflowError("Receipt-owned generation remains live")
        for backup in (token.backup_files or {}):
            if os.path.lexists(backup) != backups_present:
                raise WorkflowError("Long-term backup disposition is incorrect")
        prerequisites = self.inputs.prerequisite_reader(self.inputs.prefix)
        if any(item.state != PrerequisiteState.SUFFICIENT
               for item in (prerequisites.dotnet_desktop, prerequisites.vc_runtime)):
            raise WorkflowError("Shared prerequisites were not retained")

    def _cleanup(self, token: _Baseline) -> None:
        if token.kind != OperationKind.REMOVE and token.receipt_record is not None:
            old = token.receipt_record.data["active_generation_identity"]
            current = read_receipt(self.inputs.receipts_root)
            if current is None:
                raise RecoveryRequiredError("Cleanup lost the active receipt")
            if old["generation_id"] != current.data["active_generation_identity"]["generation_id"]:
                root = self._bounded_path(
                    old["root"], self.inputs.generations_root,
                    "Superseded generation root", kind="directory")
                destination = self._transaction().quarantine_owned_generation(
                    generation_root=root, generation_id=old["generation_id"],
                    quarantine_root=self.inputs.quarantine_root,
                    transaction_id=f"cleanup-generation-{uuid.uuid4().hex}")
                token.cleanup_moves.append((root, destination))
        for backup, digest in token.transaction_backups or ():
            if os.path.lexists(backup):
                self._quarantine_file(token, backup, digest, cleanup=True)
        try:
            self._inject("cleanup", token.kind)
        except BaseException as exc:
            raise RecoveryRequiredError(
                "Verified operation cleanup failed; recovery evidence must be retained") from exc

    def _verify_cleanup(self, token: _Baseline) -> None:
        for source, destination in token.cleanup_moves or ():
            if os.path.lexists(source) or not os.path.lexists(destination):
                raise RecoveryRequiredError("Temporary recovery cleanup was not durable")

    def _rollback_cleanup(self, token: _Baseline) -> None:
        for source, destination in reversed(token.cleanup_moves or ()):
            if os.path.lexists(destination) and not os.path.lexists(source):
                source.parent.mkdir(parents=True, exist_ok=True)
                os.replace(destination, source)

    def _verify_cleanup_rollback(self, token: _Baseline) -> None:
        for source, _destination in token.cleanup_moves or ():
            if not os.path.lexists(source):
                raise WorkflowError("Cleanup rollback did not restore recovery evidence")

    @staticmethod
    def _atomic_restore(path: Path, payload: bytes | None) -> None:
        if payload is None:
            if os.path.lexists(path):
                if path.is_symlink() or not path.is_file():
                    raise WorkflowError(f"Rollback target is unsafe: {path}")
                path.unlink()
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.rollback-{uuid.uuid4().hex}")
        temporary.write_bytes(payload)
        os.replace(temporary, path)

    def _rollback(self, token: _Baseline) -> None:
        # Restore only exact files owned or explicitly replaced by this FFTIC
        # integration. Shared prerequisite installer changes are never reversed.
        for original, quarantined in reversed(token.quarantine_moves or ()):
            if os.path.lexists(quarantined):
                if os.path.lexists(original):
                    displaced = self.inputs.quarantine_root / (
                        f"rollback-displaced-{original.name}-{uuid.uuid4().hex}")
                    os.replace(original, displaced)
                original.parent.mkdir(parents=True, exist_ok=True)
                os.replace(quarantined, original)
        for relative, payload in token.game_files.items():
            target = self.inputs.game_root / relative
            if target in token.mutated_files:
                self._atomic_restore(target, payload)
        for relative, payload in token.pac_files.items():
            target = self.inputs.game_root / relative
            if target in token.mutated_files:
                self._atomic_restore(target, payload)
        config = self.inputs.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
        if config in token.mutated_files:
            self._atomic_restore(config, token.prefix_config)
        if self.inputs.active_state_file in token.mutated_files:
            self._atomic_restore(self.inputs.active_state_file, token.active_state)
        receipt_path = self.inputs.receipts_root / "fftic-receipt.json"
        if receipt_path in token.mutated_files:
            self._atomic_restore(receipt_path, token.receipt)
        for backup, payload in (token.backup_files or {}).items():
            if backup in token.mutated_files:
                self._atomic_restore(backup, payload)
        for backup, _digest in token.transaction_backups or ():
            if backup not in (token.backup_files or {}) and os.path.lexists(backup):
                self._atomic_restore(backup, None)
        for scratch in token.generated_sources:
            if scratch.exists() and scratch.is_relative_to(self.inputs.extraction_root):
                if scratch.is_dir():
                    shutil.rmtree(scratch)
                elif scratch.is_file() and not scratch.is_symlink():
                    scratch.unlink()
        if self.inputs.generations_root.exists():
            for item in self.inputs.generations_root.iterdir():
                if item.is_dir() and not item.is_symlink() and item.name not in token.generation_names:
                    try:
                        generation_id = json.loads(
                            (item / "amethyst-generation.json").read_text(encoding="utf-8"))["generation_id"]
                        self._transaction().quarantine_owned_generation(
                            generation_root=item, generation_id=generation_id,
                            quarantine_root=self.inputs.quarantine_root,
                            transaction_id=f"rollback-generation-{uuid.uuid4().hex}")
                    except Exception as exc:
                        raise WorkflowError(f"Could not roll back published generation {item}: {exc}") from exc

    def _verify_rollback(self, token: _Baseline) -> None:
        self._inject("rollback-verifier", token.kind)
        receipt_path = self.inputs.receipts_root / "fftic-receipt.json"
        active = self.inputs.active_state_file
        config = self.inputs.prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
        if self._read_optional(receipt_path) != token.receipt:
            raise WorkflowError("Receipt rollback did not restore the exact baseline")
        if self._read_optional(active) != token.active_state:
            raise WorkflowError("Activation rollback did not restore the exact baseline")
        if self._read_optional(config) != token.prefix_config:
            raise WorkflowError("Prefix configuration rollback did not restore the exact baseline")
        for relative, payload in token.game_files.items():
            if self._read_optional(self.inputs.game_root / relative) != payload:
                raise WorkflowError(f"Game-root rollback did not restore {relative}")
        for relative, payload in token.pac_files.items():
            if self._read_optional(self.inputs.game_root / relative) != payload:
                raise WorkflowError(f"PAC rollback did not restore {relative}")
        for backup, payload in (token.backup_files or {}).items():
            if self._read_optional(backup) != payload:
                raise WorkflowError(f"Backup rollback did not restore {backup}")
        current = ({item.name for item in self.inputs.generations_root.iterdir()
                    if item.is_dir() and not item.is_symlink()}
                   if self.inputs.generations_root.exists() else set())
        if current != token.generation_names:
            raise WorkflowError("Generation rollback did not restore the exact baseline")

    def revalidate(self, plan: OperationPlan) -> None:
        self._staged.revalidate(plan)

    def _run(self, method: str, plan, cancel, progress) -> OperationResult:
        return getattr(self._staged, method)(plan, cancel, progress)

    def setup(self, plan, cancel, progress): return self._run("setup", plan, cancel, progress)
    def repair(self, plan, cancel, progress): return self._run("repair", plan, cancel, progress)
    def synchronize(self, plan, cancel, progress): return self._run("synchronize", plan, cancel, progress)
    def update(self, plan, cancel, progress): return self._run("update", plan, cancel, progress)
    def remove(self, plan, cancel, progress): return self._run("remove", plan, cancel, progress)
