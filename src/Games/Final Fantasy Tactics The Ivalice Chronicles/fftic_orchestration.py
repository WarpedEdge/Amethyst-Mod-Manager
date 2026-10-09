"""Read-only FFTIC UI orchestration and an explicit mutation boundary."""

from __future__ import annotations

import json
import hashlib
import os
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol

try:
    from .fftic_artifacts import ARTIFACTS, INTERNAL_FILES, validate_file
    from .fftic_loader_releases import CHECKER, LoaderRelease, reviewed_release_identity
    from .fftic_detection import (
        InstallStatus, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
    )
    from .fftic_generation import (
        verify_legacy_reloaded_normalization, verify_private_generation,
    )
    from .fftic_packages import PackageClassification, inspect_package
    from .fftic_pac import baseline_set_from_receipt, inspect_matching_launch_log
    from .fftic_prerequisites import (
        PrerequisiteState, inspect_prefix_prerequisites,
        prerequisite_host_capability,
    )
    from .fftic_proton import ProtonSelection, managed_runner_label, resolve_proton_selection, supported_runner
    from .fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, absent_pac_reversion_ready,
        verify_launch_readiness,
    )
    from .fftic_receipts import PREFIX_CONFIGURATION_PATH, read_receipt
    from .fftic_steam_path import resolve_steam_s_path
    from .fftic_steam_requirements import (
        COPY_READY_OPTIONS, SteamOptionsStatus, analyze_steam_launch_options,
    )
except ImportError:
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES, validate_file
    from fftic_loader_releases import CHECKER, LoaderRelease, reviewed_release_identity
    from fftic_detection import (
        InstallStatus, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
    )
    from fftic_generation import (
        verify_legacy_reloaded_normalization, verify_private_generation,
    )
    from fftic_packages import PackageClassification, inspect_package
    from fftic_pac import baseline_set_from_receipt, inspect_matching_launch_log
    from fftic_prerequisites import (
        PrerequisiteState, inspect_prefix_prerequisites,
        prerequisite_host_capability,
    )
    from fftic_proton import ProtonSelection, managed_runner_label, resolve_proton_selection, supported_runner
    from fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, absent_pac_reversion_ready,
        verify_launch_readiness,
    )
    from fftic_receipts import PREFIX_CONFIGURATION_PATH, read_receipt
    from fftic_steam_path import resolve_steam_s_path
    from fftic_steam_requirements import (
        COPY_READY_OPTIONS, SteamOptionsStatus, analyze_steam_launch_options,
    )

FFTIC_GAME_ID = "final_fantasy_tactics_the_ivalice_chronicles"


def force_loader_release_recheck() -> None:
    CHECKER.invalidate()


EXECUTION_UNAVAILABLE = (
    "Live FFTIC changes are not available in this build. This action only "
    "becomes available when an authorized managed-lifecycle executor is installed."
)


class StatusSeverity(str, Enum):
    READY = "ready"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class OperationKind(str, Enum):
    SETUP = "setup"
    REPAIR = "repair"
    SYNCHRONIZE = "synchronize"
    UPDATE = "update"
    REVERT_LOADER = "revert_loader"
    REMOVE = "remove"
    RECONCILE_RUNTIME_OUTPUT = "reconcile_runtime_output"
    SAVE_MOD_STATE = "save_mod_state"


@dataclass(frozen=True)
class StatusRow:
    key: str
    label: str
    state: str
    severity: StatusSeverity
    summary: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class UnsupportedPackage:
    name: str
    path: str
    reason: str
    enabled: bool

    @property
    def state(self) -> str:
        return "enabled" if self.enabled else "disabled"


@dataclass(frozen=True)
class OperationStep:
    component: str
    action: str
    target: str


@dataclass(frozen=True)
class OperationPlan:
    kind: OperationKind
    profile: str
    steps: tuple[OperationStep, ...]
    requires_confirmation: bool = True
    mutating: bool = True
    binding: "OperationBinding | None" = None
    release: "LoaderRelease | None" = None


@dataclass(frozen=True)
class OperationBinding:
    """Exact controller observation to which a mutation plan is authorized."""

    game_id: str
    profile: str
    game_root: str
    prefix: str
    profile_dir: str
    staging_root: str
    status_generation: int
    status_sha256: str
    observation_sha256: str
    runner_identity: str = ""
    runner_script: str = ""


@dataclass(frozen=True)
class ProgressUpdate:
    completed: int
    total: int
    phase: str


@dataclass(frozen=True)
class FfticStatusViewModel:
    game_id: str
    title: str
    rows: tuple[StatusRow, ...]
    details: tuple[str, ...]
    unsupported_packages: tuple[UnsupportedPackage, ...]
    steam_copy_text: str
    steam_preserved_options: tuple[str, ...]
    ready: bool
    verifier_attested: bool
    mutation_available: bool
    mutation_unavailable_reason: str
    launch_instruction: str
    error: str = ""
    observation_sha256: str = ""
    available_actions: tuple[str, ...] = ()
    action_unavailable_reasons: tuple[tuple[str, str], ...] = ()
    release: "LoaderRelease | None" = None

    def row(self, key: str) -> StatusRow:
        return next(item for item in self.rows if item.key == key)


@dataclass(frozen=True)
class InspectionContext:
    game: object
    profile_name: str
    profile_dir: Path
    staging_root: Path


@dataclass(frozen=True)
class InspectionResult:
    rows: tuple[StatusRow, ...]
    details: tuple[str, ...]
    unsupported_packages: tuple[UnsupportedPackage, ...]
    steam_copy_text: str
    steam_preserved_options: tuple[str, ...]
    ready: bool
    verifier_attested: bool
    observation_sha256: str = ""
    available_actions: tuple[str, ...] = ()
    action_unavailable_reasons: tuple[tuple[str, str], ...] = ()
    release: "LoaderRelease | None" = None


ProgressCallback = Callable[[ProgressUpdate], None]


class InspectionCancelled(RuntimeError):
    """A superseded read-only inspection stopped cooperatively."""


class InspectionStateChanged(RuntimeError):
    """Relevant files changed while one status snapshot was being gathered."""


def is_fftic_game(game: object | None) -> bool:
    """Keep selection gating testable without importing the Qt application."""
    return getattr(game, "game_id", "") == FFTIC_GAME_ID


class StatusInspector(Protocol):
    def inspect(self, context: InspectionContext, cancel: threading.Event | None,
                progress: ProgressCallback | None) -> InspectionResult: ...


class AuthorizedExecutor(Protocol):
    authorized: bool

    def execute(self, plan: OperationPlan, cancel: threading.Event | None,
                progress: ProgressCallback | None): ...


ExecutorFactory = Callable[
    [InspectionContext, Callable[[OperationPlan], bool]],
    tuple[AuthorizedExecutor | None, str],
]


_PREREQUISITE_RUNNER_BLOCKER = (
    "Automatic prerequisite installation is unavailable in this environment. "
    "Review the managed-action status, restore Flatpak host access if shown, then recheck."
)


def _action_availability(
    rows: tuple[StatusRow, ...], *, receipt_present: bool,
    verification, unsupported: tuple[UnsupportedPackage, ...],
    prerequisite_host_available: bool = True,
    prerequisite_host_reason: str = "",
    release: LoaderRelease | None = None,
    installed_loader: str = "",
    revert_absent_pac: bool = False,
    color_state_present: bool = False,
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Return only lifecycle actions supported by the current exact evidence."""
    by_key = {row.key: row for row in rows}
    reasons = {
        kind.value: "Current FFTIC evidence does not authorize this action. Recheck the status details."
        for kind in OperationKind
    }
    reasons[OperationKind.UPDATE.value] = (
        "No newer reviewed loader asset is ready to install. Recheck release details.")
    reasons[OperationKind.REVERT_LOADER.value] = (
        "Return to 1.7.3 requires an exact receipt-owned 1.7.5 installation. "
        "Missing generated PAC output is allowed only with exact retained backups "
        "and no matching completed launch log; resolve any other drift first.")
    required = ("game", "steam_prefix", "runner", "steam_options", "recovery")
    foundation_ready = all(
        by_key.get(key) is not None
        and by_key[key].state in {"Ready", "Configured", "Retry available", "Unverified", "Verified"}
        for key in required)
    prerequisites_setup_safe = all(
        by_key.get(key) is not None
        and by_key[key].state in {"Ready", "Not installed", "Update required"}
        for key in ("dotnet", "vc"))
    prerequisites_ready = all(
        by_key.get(key) is not None and by_key[key].state == "Ready"
        for key in ("dotnet", "vc"))
    prerequisite_install_required = any(
        by_key.get(key) is not None
        and by_key[key].state in {"Not installed", "Update required"}
        for key in ("dotnet", "vc"))
    no_unsupported = not unsupported
    actions: list[str] = []
    reversion_ready = bool(
        installed_loader == "1.7.5" and receipt_present and no_unsupported
        and verification is not None and verification.attested
        and (verification.ready or revert_absent_pac)
        and verification.runner == ReadinessAspect.READY
        and all(getattr(verification, key) == ReadinessAspect.READY for key in (
            "game", "artifacts", "generation", "prefix", "prerequisites",
            "bootstrap", "steam_options", "recovery"))
        and by_key.get("runner") is not None
        and by_key["runner"].state in {"Ready", "Unverified", "Verified"})

    reconciliation = by_key.get("reconciliation")
    reconciliation_state = reconciliation.state if reconciliation is not None else ""
    expected_component_state = (
        "Runtime reconciliation required"
        if reconciliation_state == "Runtime rebuild required" else
        "Ready" if reconciliation_state == "Runtime output confirmation required" else "")
    protected_reconciliation_state = bool(
        receipt_present and no_unsupported and expected_component_state
        and all(by_key.get(key) is not None and by_key[key].state == state
                for key, state in (
                    ("game", "Ready"), ("steam_prefix", "Ready"),
                    ("dotnet", "Ready"), ("vc", "Ready"),
                    ("steam_options", "Configured"), ("bootstrap", "Ready"),
                    ("prefix_config", "Ready"), ("profile", "Ready"),
                    ("recovery", "Runtime output confirmation required")))
        and by_key.get("runner") is not None
        and by_key["runner"].state in {"Ready", "Unverified", "Verified"}
        and all(by_key.get(key) is not None
                and by_key[key].state == expected_component_state
                for key in ("runtime", "nenkai", "sigscan", "hooks")))
    if (color_state_present and receipt_present and no_unsupported and verification is not None and verification.attested
            and all(getattr(verification, key) == ReadinessAspect.READY for key in (
                'game', 'artifacts', 'generation', 'prefix', 'prerequisites', 'bootstrap',
                'steam_options', 'runner', 'recovery'))):
        actions.append(OperationKind.SAVE_MOD_STATE.value)
        reasons[OperationKind.SAVE_MOD_STATE.value] = ''
    if protected_reconciliation_state:
        actions.append(OperationKind.RECONCILE_RUNTIME_OUTPUT.value)
        reasons[OperationKind.RECONCILE_RUNTIME_OUTPUT.value] = ""
        if reversion_ready:
            actions.append(OperationKind.REVERT_LOADER.value)
            reasons[OperationKind.REVERT_LOADER.value] = ""
        return tuple(actions), tuple((kind.value, reasons[kind.value]) for kind in OperationKind)

    if not prerequisites_setup_safe:
        reasons[OperationKind.SETUP.value] = _PREREQUISITE_RUNNER_BLOCKER
        reasons[OperationKind.REPAIR.value] = _PREREQUISITE_RUNNER_BLOCKER
    elif prerequisite_install_required and not prerequisite_host_available:
        blocker = prerequisite_host_reason or _PREREQUISITE_RUNNER_BLOCKER
        reasons[OperationKind.SETUP.value] = blocker
        reasons[OperationKind.REPAIR.value] = blocker

    if (not receipt_present and foundation_ready and prerequisites_setup_safe
            and (not prerequisite_install_required or prerequisite_host_available)
            and no_unsupported
            and all(by_key.get(key) is not None
                    and by_key[key].state == "Not installed"
                    for key in ("runtime", "nenkai", "sigscan", "hooks"))
            and by_key.get("bootstrap") is not None
            and by_key["bootstrap"].state == "Not installed"
            and by_key.get("prefix_config") is not None
            and by_key["prefix_config"].state == "Not installed"):
        actions.append(OperationKind.SETUP.value)

    managed = tuple(by_key.get(key) for key in (
        "runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config"))
    if (receipt_present and foundation_ready and prerequisites_ready
            and no_unsupported and all(row is not None for row in managed)
            and by_key.get("profile") is not None
            and by_key["profile"].state == "Ready"
            and any(row.state == "Not installed" for row in managed)
            and not any(row.state in {"Conflict", "Different"} for row in managed)):
        actions.append(OperationKind.REPAIR.value)

    if verification is not None and verification.attested:
        protected = (
            verification.game, verification.artifacts, verification.generation,
            verification.prefix, verification.prerequisites, verification.bootstrap,
            verification.steam_options, verification.recovery,
        )
        runner_state = getattr(verification, "runner", ReadinessAspect.READY)
        runner_transition = (runner_state == ReadinessAspect.INVALID
                             and any(issue.startswith("Selected Proton runner changed since")
                                     for issue in verification.issues))
        profile_reconcilable = not any(issue.startswith((
            "PAC ", "Unknown preexisting PAC"))
            for issue in getattr(verification, "issues", ()))
        if (receipt_present and no_unsupported and profile_reconcilable
                and by_key.get("runner") is not None
                and by_key["runner"].state in {"Ready", "Unverified", "Verified", "Different"}
                and all(value == ReadinessAspect.READY for value in protected)
                and (verification.profile != ReadinessAspect.READY or runner_transition)):
            actions.append(OperationKind.SYNCHRONIZE.value)
        if (receipt_present and no_unsupported
                and by_key.get("runner") is not None
                and by_key["runner"].state in {"Ready", "Unverified", "Verified", "Different"}
                and all(value == ReadinessAspect.READY for value in protected)
                and (runner_state == ReadinessAspect.READY or runner_transition)
                and verification.profile == ReadinessAspect.READY):
            actions.append(OperationKind.REMOVE.value)

        if (reviewed_release_identity(release) and receipt_present
                and no_unsupported and verification.ready and
                runner_state == ReadinessAspect.READY and
                all(value == ReadinessAspect.READY for value in protected)):
            actions.append(OperationKind.UPDATE.value)
            reasons[OperationKind.UPDATE.value] = ""
        if reversion_ready:
            actions.append(OperationKind.REVERT_LOADER.value)
            reasons[OperationKind.REVERT_LOADER.value] = ""

    return tuple(actions), tuple((kind.value, reasons[kind.value]) for kind in OperationKind)


def _row(key: str, label: str, state: str, severity: StatusSeverity,
         summary: str, *details: str) -> StatusRow:
    return StatusRow(key, label, state, severity, summary,
                     tuple(value for value in details if value))


def _manifest_value(path: Path, key: str) -> str | None:
    try:
        import re
        text = path.read_text(encoding="utf-8", errors="strict")
        match = re.search(rf'"{re.escape(key)}"\s+"([^"]+)"', text,
                          re.IGNORECASE)
        return match.group(1) if match else None
    except (OSError, UnicodeError):
        return None


def _pe_version(game_root: Path | None) -> str | None:
    if game_root is None:
        return None
    try:
        from Utils.executables.icon import extract_exe_version
        value = extract_exe_version(game_root / "FFT_enhanced.exe")
    except Exception:
        return None
    parts = value.split(".") if value else []
    return "v" + ".".join(parts[:3]) if len(parts) >= 3 else None


def _managed_root(prefix: Path | None) -> Path | None:
    if prefix is None:
        return None
    return Path(prefix) / "drive_c" / "Amethyst" / "FFTIC"


def _journal_recovery_status(root: Path | None) -> tuple[bool, str, str]:
    """Return managed-recovery required, retry diagnostic, and journal error."""
    if root is None:
        return False, "", ""
    try:
        try:
            from .fftic_managed_executor import RecoveryState, StagedLifecycleOperations
            from .fftic_transaction_executor import FileTransactionJournal
        except ImportError:
            from fftic_managed_executor import RecoveryState, StagedLifecycleOperations
            from fftic_transaction_executor import FileTransactionJournal
        events = FileTransactionJournal(root / "journal" / "lifecycle.json").read_events()
        state = StagedLifecycleOperations.recovery_state(events)
        required = state in {
            RecoveryState.MUTATION_ATTEMPTED,
            RecoveryState.FORWARD_VERIFIED,
            RecoveryState.ROLLBACK_STARTED,
            RecoveryState.RECOVERY_REQUIRED,
        }
        retry = ""
        if state == RecoveryState.PREREQUISITE_RETRYABLE:
            event = next((item for item in reversed(events)
                          if item.get("state") == "prerequisite-retryable"), {})
            retry = str(event.get("original_error") or
                        "The prerequisite attempt can be retried safely.")
        return required, retry, ""
    except Exception as exc:
        return True, "", f"Lifecycle journal could not be verified: {exc}"


def _profile_packages(
    context: InspectionContext, cancel: threading.Event | None = None,
) -> tuple[UnsupportedPackage, ...]:
    from Utils.mods.modlist import read_modlist
    entries = read_modlist(context.profile_dir / "modlist.txt")
    unsupported: list[UnsupportedPackage] = []
    for entry in entries:
        if cancel is not None and cancel.is_set():
            raise InspectionCancelled("FFTIC status inspection cancelled")
        if getattr(entry, "is_separator", False):
            continue
        source = context.staging_root / entry.name
        result = inspect_package(source)
        if not result.is_user_content:
            manifest = result.manifest
            unsupported.append(UnsupportedPackage(
                f"{manifest.name} ({manifest.mod_id})" if manifest is not None else entry.name,
                str(source),
                result.diagnostics[0] if result.diagnostics else result.classification.value,
                entry.enabled))
    return tuple(unsupported)


class DefaultStatusInspector:
    """Gather current evidence with C2 readers; never create or change state."""

    def _progress(self, callback, done: int, total: int, phase: str) -> None:
        if callback is not None:
            callback(ProgressUpdate(done, total, phase))

    @staticmethod
    def _cancelled(cancel: threading.Event | None) -> None:
        if cancel is not None and cancel.is_set():
            raise InspectionCancelled("FFTIC status inspection cancelled")

    def inspect(self, context: InspectionContext, cancel=None,
                progress=None) -> InspectionResult:
        # Status must never observe a transaction between publication steps.
        try:
            from .fftic_managed_executor import MUTATION_COORDINATOR
        except ImportError:
            from fftic_managed_executor import MUTATION_COORDINATOR
        with MUTATION_COORDINATOR.inspection():
            for attempt in range(2):
                self._cancelled(cancel)
                before = self._observation_identity(context)
                self._cancelled(cancel)
                result = self._inspect_unlocked(context, cancel, progress)
                self._cancelled(cancel)
                after = self._observation_identity(context)
                self._cancelled(cancel)
                if before == after:
                    self._progress(progress, 5, 5, "FFTIC status ready")
                    return InspectionResult(
                        result.rows, result.details, result.unsupported_packages,
                        result.steam_copy_text, result.steam_preserved_options,
                        result.ready, result.verifier_attested, after,
                        result.available_actions,
                        result.action_unavailable_reasons, result.release)
                if attempt == 0:
                    self._progress(
                        progress, 0, 5,
                        "FFTIC files changed during inspection; retrying")
            raise InspectionStateChanged(
                "FFTIC profile or game files changed during status inspection. "
                "Wait for file changes to finish, then recheck.")

    def _inspect_unlocked(self, context: InspectionContext, cancel=None,
                          progress=None) -> InspectionResult:
        self._cancelled(cancel)
        game = context.game
        game_root = game.get_game_path()
        prefix = game.get_prefix_path()
        steamapps = None
        try:
            from Utils.launchers.steam import owning_steamapps_dir
            steamapps = owning_steamapps_dir(game.steam_id, game_root)
        except Exception:
            pass
        manifest = (steamapps / f"appmanifest_{game.steam_id}.acf"
                    if steamapps is not None else None)
        build = _manifest_value(manifest, "buildid") if manifest is not None else None
        installation = game.compatibility(
            steam_build=build, pe_version=_pe_version(game_root))
        self._cancelled(cancel)
        self._progress(progress, 1, 5, "Inspecting the game and Steam library")

        if installation.status == InstallStatus.EXACT_VERIFIED:
            game_row = _row("game", "Game installation and build", "Ready",
                            StatusSeverity.READY, "The exact supported game build is installed.")
        elif installation.status == InstallStatus.NOT_FOUND:
            game_row = _row("game", "Game installation and build", "Not installed",
                            StatusSeverity.ERROR, installation.diagnostics[0])
        elif installation.status == InstallStatus.INCOMPLETE:
            game_row = _row("game", "Game installation and build", "Setup required",
                            StatusSeverity.ERROR, "The FFTIC installation is incomplete.",
                            *installation.diagnostics)
        else:
            game_row = _row("game", "Game installation and build", "Unverified game build",
                            StatusSeverity.ERROR, "This game build is outside the tested tuple.",
                            *installation.diagnostics)

        steam_path = None
        steam_error = ""
        if steamapps is not None and manifest is not None and game_root and prefix:
            try:
                steam_path = resolve_steam_s_path(
                    steam_library=steamapps.parent, app_manifest=manifest,
                    game_root=game_root, prefix=prefix)
            except Exception as exc:
                steam_error = str(exc)
        if steam_path is not None:
            location_row = _row(
                "steam_prefix", "Steam library and prefix", "Ready",
                StatusSeverity.READY, "The owning Steam library, prefix, and S: mapping agree.",
                f"Steam library: {steam_path.steam_library}",
                f"Prefix: {steam_path.prefix}",
                f"Windows game path: {steam_path.windows_game_path.value}")
        else:
            location_row = _row(
                "steam_prefix", "Steam library and prefix", "Setup required",
                StatusSeverity.ERROR, "The required Steam-created path identity is not verified.",
                steam_error or "Select the owning Steam library and initialized FFTIC prefix.")

        try:
            proton = resolve_proton_selection(game.steam_id, prefix)
        except Exception:
            proton = ProtonSelection(None, "", "")
        runner = proton.tool_identity
        runner_supported = (proton.proton_script is not None
                            and supported_runner(runner, proton.proton_script))
        if not proton.steam_mapping:
            runner_problem = (
                "Steam has no readable per-game compatibility mapping. Select this game's "
                "Proton tool in Steam Compatibility; the prefix's last-used runner "
                "does not prove the current selection.")
        elif (proton.steam_mapping == "proton_hotfix"
              or proton.steam_mapping.endswith("_beta")):
            runner_problem = (
                "Steam Hotfix and Beta mappings have not been audited for their "
                "exact tool layout and version format.")
        elif not (proton.steam_mapping == "proton_experimental"
                  or proton.steam_mapping.startswith("proton_")
                  and proton.steam_mapping[7:].isdigit()):
            runner_problem = (
                "This custom compatibility mapping selects a user-provided executable "
                "whose origin and prerequisite behavior have not been reviewed.")
        else:
            runner_problem = (
                "The selected Steam-managed Proton script, version, or matching "
                "appmanifest is missing, malformed, linked, or ambiguous.")
        runner_label = managed_runner_label(runner, runner_supported)
        runner_row = _row(
            "runner", "Proton runner",
            runner_label,
            (StatusSeverity.READY if runner_label == "Verified" else
             StatusSeverity.WARNING if runner_supported else StatusSeverity.ERROR),
            ("The selected Steam Proton tool is safe to test; this game and mod "
             "combination has not been verified in-game." if
             runner_supported else
             runner_problem),
            f"Selected runner: {runner or '<unresolved>'}",
            f"Selected script: {proton.proton_script or '<unresolved>'}",
            f"Steam compatibility mapping: {proton.steam_mapping or '<unresolved>'}",
            f"Prefix runtime: {proton.prefix_runtime or '<unresolved>'}",
            "Steam-managed official Proton releases and Experimental can be tested; Hotfix and unreviewed custom executables remain blocked.",
            "Verified describes the exact canonical Steam-selected managed runner under runner policy, not proof that every build, mod, or game mode works in-game.")

        self._cancelled(cancel)
        prerequisites = (inspect_prefix_prerequisites(prefix) if prefix is not None
                         else None)
        self._cancelled(cancel)
        prerequisite_rows = []
        for key, label, health in (
            ("dotnet", ".NET Desktop Runtime",
             prerequisites.dotnet_desktop if prerequisites else None),
            ("vc", "VC++ runtime", prerequisites.vc_runtime if prerequisites else None),
        ):
            ready = health is not None and health.state == PrerequisiteState.SUFFICIENT
            state = ("Ready" if ready else "Not installed" if health is None or
                     health.state == PrerequisiteState.MISSING else "Update required" if
                     health.state == PrerequisiteState.INSUFFICIENT else "Unverified")
            prerequisite_rows.append(_row(
                key, label, state,
                StatusSeverity.READY if ready else StatusSeverity.ERROR,
                (health.diagnostics[0] if health is not None
                 else f"{label} could not be inspected without a selected prefix."),
                (f"Detected version: {health.observed_version or '<none>'}; "
                 f"required: {health.required_version}" if health is not None else "")))
        self._progress(progress, 2, 5, "Inspecting prefix prerequisites")

        from Utils.launchers.steam import steam_launch_options
        steam_options = analyze_steam_launch_options(steam_launch_options(game.steam_id))
        steam_severity = (StatusSeverity.READY if
                          steam_options.status == SteamOptionsStatus.CONFIGURED
                          else StatusSeverity.ERROR if
                          steam_options.status == SteamOptionsStatus.CONFLICT
                          else StatusSeverity.WARNING)
        steam_row = _row(
            "steam_options", "Steam Launch Options", steam_options.status.value,
            steam_severity,
            ("Steam has the exact required launch assignments." if
             steam_options.status == SteamOptionsStatus.CONFIGURED else
             "Open FFTIC's Steam Properties → General, update Launch Options, then recheck."),
            *steam_options.diagnostics,
            *(f"Preserved unrelated option: {value}"
              for value in steam_options.preserved_unrelated))

        unsupported = _profile_packages(context, cancel)
        unsupported_row = _row(
            "unsupported_mods", "Unsupported or unsafe packages",
            "Unsupported" if unsupported else "Ready",
            StatusSeverity.ERROR if unsupported else StatusSeverity.READY,
            ("Unsafe or unsupported packages block synchronization. "
             "Amethyst runs user-selected managed code through Reloaded-II." if unsupported else
             "Content and valid managed Reloaded code/API packages are supported; "
             "Amethyst runs user-selected managed code through Reloaded-II."),
            *(f"{item.name} ({item.state}): {item.path} — {item.reason}"
              for item in unsupported))
        self._progress(progress, 3, 5, "Inspecting the active profile")

        root = _managed_root(prefix)
        receipt = None
        receipt_error = ""
        if root is not None:
            try:
                self._cancelled(cancel)
                receipt = read_receipt(root / "receipts")
                self._cancelled(cancel)
            except InspectionCancelled:
                raise
            except Exception as exc:
                receipt_error = str(exc)

        component_rows: dict[str, StatusRow] = {}
        installed_loader = next((item["version"] for item in receipt.data["artifacts"]
                                 if item["artifact_id"] == "nenkai-loader"),
                                ARTIFACTS["nenkai-loader"].version) if receipt else ARTIFACTS["nenkai-loader"].version
        versions = {
            "runtime": ARTIFACTS["reloaded-ii"].version,
            "nenkai": installed_loader,
            "sigscan": ARTIFACTS["sigscan"].version,
            "hooks": ARTIFACTS["shared-hooks"].version,
        }
        for key, label in (("runtime", "Reloaded-II runtime generation"),
                           ("nenkai", "FFT: The Ivalice Chronicles Mod Loader"),
                           ("sigscan", "SigScan"),
                           ("hooks", "Shared Hooks")):
            component_rows[key] = _row(
                key, label, "Not installed", StatusSeverity.ERROR,
                f"Managed {label} {versions[key]} has no verified ownership receipt.")

        active_state = root / "active-generation.json" if root is not None else None
        generation_id = ""
        generation_root = None
        generation_error = ""
        normalization_pending = False
        if active_state is not None and os.path.lexists(active_state):
            try:
                self._cancelled(cancel)
                data = json.loads(active_state.read_text(encoding="utf-8"))
                generation_id = data["active_generation"]
                generation_root = Path(data["generation_root"])
                digest = verify_private_generation(generation_root, generation_id)
                self._cancelled(cancel)
                if digest != data["manifest_sha256"]:
                    raise ValueError("active generation manifest identity differs")
                for key, label in (("runtime", "Reloaded-II runtime generation"),
                                   ("nenkai", "FFT: The Ivalice Chronicles Mod Loader"),
                                   ("sigscan", "SigScan"),
                                   ("hooks", "Shared Hooks")):
                    component_rows[key] = _row(
                        key, label, "Ready" if receipt else "Conflict",
                        StatusSeverity.READY if receipt else StatusSeverity.ERROR,
                        (f"Version {versions[key]} is present in generation {generation_id}."
                         + ((" A matching normal Steam launch was recorded; visible mod behavior remains unverified."
                             if receipt and receipt.data["last_successful_operation"] == "confirm-runtime-output"
                             else " This loader version is in-game untested until a normal Steam launch validates it.")
                            if key == "nenkai" and versions[key] != "1.7.3" else "")
                         if receipt else "Reviewed bytes exist without an ownership receipt."))
            except InspectionCancelled:
                raise
            except Exception as exc:
                try:
                    digest = verify_legacy_reloaded_normalization(
                        generation_root, generation_id)
                    if digest != data["manifest_sha256"]:
                        raise ValueError("active generation manifest identity differs")
                    normalization_pending = True
                    for key, label in (("runtime", "Reloaded-II runtime generation"),
                                       ("nenkai", "FFT: The Ivalice Chronicles Mod Loader"),
                                       ("sigscan", "SigScan"),
                                       ("hooks", "Shared Hooks")):
                        component_rows[key] = _row(
                            key, label, "Runtime reconciliation required",
                            StatusSeverity.WARNING,
                            "Reloaded performed the exact known three-file metadata normalization.")
                except Exception:
                    generation_error = str(exc)
                    component_rows["runtime"] = _row(
                        "runtime", "Reloaded-II runtime generation", "Conflict",
                        StatusSeverity.ERROR, "The active generation is incomplete or changed.",
                        generation_error)

        def owned_file_row(key, label, path, pin_id):
            self._cancelled(cancel)
            if path is None or not os.path.lexists(path):
                return _row(key, label, "Not installed", StatusSeverity.ERROR,
                            f"{label} is absent.")
            valid = validate_file(INTERNAL_FILES[pin_id], path)
            self._cancelled(cancel)
            if valid:
                state = "Ready" if receipt else "Conflict"
                return _row(
                    key, label, state,
                    StatusSeverity.READY if receipt else StatusSeverity.ERROR,
                    ("The reviewed file is receipt-owned." if receipt else
                     "Reviewed bytes exist but Amethyst has no ownership receipt."),
                    str(path))
            return _row(key, label, "Conflict", StatusSeverity.ERROR,
                        "The path is occupied by different or drifted content.", str(path))

        bootstrap_paths = [] if game_root is None else [
            game_root / "version.dll",
            game_root / "Reloaded.Mod.Loader.Bootstrapper.asi",
        ]
        bootstrap_parts = (
            owned_file_row("bootstrap-version", "version.dll", bootstrap_paths[0], "version-dll"),
            owned_file_row("bootstrap-asi", "bootstrap ASI", bootstrap_paths[1],
                           "reloaded-bootstrapper-asi"),
        ) if bootstrap_paths else ()
        if bootstrap_parts and all(item.state == "Ready" for item in bootstrap_parts):
            bootstrap_row = _row("bootstrap", "Game-root ASI bootstrap ownership",
                                 "Ready", StatusSeverity.READY,
                                 "Both reviewed bootstrap files are receipt-owned.")
        elif bootstrap_parts and any(item.state == "Conflict" for item in bootstrap_parts):
            bootstrap_row = _row("bootstrap", "Game-root ASI bootstrap ownership",
                                 "Conflict", StatusSeverity.ERROR,
                                 "A bootstrap target is unowned or differs.",
                                 *(detail for item in bootstrap_parts for detail in
                                   (item.summary, *item.details)))
        else:
            bootstrap_row = _row("bootstrap", "Game-root ASI bootstrap ownership",
                                 "Not installed", StatusSeverity.ERROR,
                                 "The managed ASI bootstrap is absent.")

        config_path = (prefix / "drive_c" / PREFIX_CONFIGURATION_PATH
                       if prefix is not None else None)
        if config_path is not None and os.path.lexists(config_path):
            config_state = "Ready" if receipt else "Conflict"
            prefix_config_row = _row(
                "prefix_config", "Prefix bootstrap configuration", config_state,
                StatusSeverity.READY if receipt else StatusSeverity.ERROR,
                ("The receipt-owned bootstrap configuration is present." if receipt else
                 "A Reloaded configuration exists without Amethyst ownership."),
                str(config_path))
        else:
            prefix_config_row = _row(
                "prefix_config", "Prefix bootstrap configuration", "Not installed",
                StatusSeverity.ERROR, "The managed prefix configuration is absent.")

        verification = None
        pac_evidence = ()
        if (receipt is not None and steam_path is not None and prerequisites is not None
                and active_state is not None):
            try:
                self._cancelled(cancel)
                pac_evidence = ()
                if receipt.data["schema_version"] >= 2:
                    baseline = baseline_set_from_receipt(
                        receipt.data["generated_pac_baseline"])
                    log_root = (prefix / "drive_c/users/steamuser/AppData/Roaming/"
                                "Reloaded-Mod-Loader-II/Logs")
                    required_ids = tuple(
                        item["mod_id"] for item in receipt.data["managed_packages"])
                    required_ids += tuple(
                        item["mod_id"] for item in receipt.data["user_packages"]
                        if item["enabled"])
                    launch = inspect_matching_launch_log(
                        log_root, baseline=baseline, required_mod_ids=required_ids)
                    pac_evidence = (launch,) if launch is not None else ()
                verification = verify_launch_readiness(ReadinessEvidence(
                    receipt, installation, steam_path, manifest, runner,
                    active_state, context.profile_dir, context.staging_root,
                    prerequisites, steam_options, pac_evidence,
                    str(proton.proton_script) if proton.proton_script else None))
                self._cancelled(cancel)
            except InspectionCancelled:
                raise
            except Exception as exc:
                receipt_error = f"Readiness verification failed: {exc}"
        self._progress(progress, 4, 5, "Correlating ownership and readiness")

        # Individual readers make the rows useful before setup exists, while
        # the attested verifier remains authoritative once a receipt can be
        # correlated.  Never leave a component looking ready when that final
        # correlation rejected it.
        if verification is not None:
            issues = verification.issues

            def rejected(row: StatusRow, summary: str) -> StatusRow:
                if row.severity != StatusSeverity.READY and not (row.key == "runner" and row.state in {"Unverified", "Verified"}):
                    return row
                return _row(row.key, row.label, "Different",
                            StatusSeverity.ERROR, summary, *issues)

            if verification.game != ReadinessAspect.READY:
                game_row = rejected(
                    game_row, "The current game no longer matches the managed receipt.")
            if verification.prefix != ReadinessAspect.READY:
                location_row = rejected(
                    location_row,
                    "The Steam library or prefix differs from the managed receipt.")
            if verification.runner != ReadinessAspect.READY:
                runner_row = rejected(
                    runner_row, "The runner identity differs from the managed receipt.")
            if verification.generation != ReadinessAspect.READY:
                component_rows["runtime"] = rejected(
                    component_rows["runtime"],
                    "The active Reloaded-II generation is not verifier-attested.")
            if verification.artifacts != ReadinessAspect.READY:
                for key in ("nenkai", "sigscan", "hooks"):
                    component_rows[key] = rejected(
                        component_rows[key],
                        "The managed artifact identity differs from the reviewed generation.")
            if verification.prerequisites != ReadinessAspect.READY:
                prerequisite_rows = [
                    rejected(row, "The prerequisite evidence differs from the receipt.")
                    for row in prerequisite_rows
                ]
            if verification.bootstrap != ReadinessAspect.READY:
                bootstrap_row = rejected(
                    bootstrap_row,
                    "The ASI bootstrap is missing, changed, or no longer receipt-owned.")
                prefix_config_row = rejected(
                    prefix_config_row,
                    "The prefix bootstrap configuration is not verifier-attested.")
        pac_confirmation_pending = bool(
            verification and verification.issues
            and all(issue.startswith("PAC runtime output confirmation required")
                    for issue in verification.issues))
        profile_ready = bool(
            verification and verification.attested and not unsupported
            and (verification.profile == ReadinessAspect.READY
                 or pac_confirmation_pending))
        profile_row = _row(
            "profile", "Active Amethyst profile synchronization",
            "Ready" if profile_ready else "Unsupported" if unsupported else
            "Profile needs synchronization",
            StatusSeverity.READY if profile_ready else StatusSeverity.ERROR,
            ("The active profile and staged content match the managed generation."
             if profile_ready else "The current profile is not verifier-attested as synchronized."),
            *((verification.issues if verification else ())))

        reconciliation_state = (
            "Runtime rebuild required" if normalization_pending else
            "Runtime output confirmation required" if pac_confirmation_pending else "Ready")
        reconciliation_row = _row(
            "reconciliation", "Post-launch runtime reconciliation", reconciliation_state,
            StatusSeverity.WARNING if reconciliation_state != "Ready" else StatusSeverity.READY,
            ("Confirm the recoverable managed-runtime reconciliation plan."
             if normalization_pending else
             "Amethyst saves completed launch results when it regains focus and can "
             "verify them. If this remains pending, use Confirm runtime output."
             if pac_confirmation_pending else
             "No pending managed runtime output requires confirmation."))

        journal_requires_recovery, journal_retry, journal_error = (
            _journal_recovery_status(root))

        recovery_required = bool(
            receipt_error or generation_error or
            (receipt and receipt.data.get("incomplete_operation")) or
            (verification and verification.recovery != ReadinessAspect.READY) or
            journal_requires_recovery)
        recovery_state = ("Recovery required" if recovery_required else
                          "Runtime output confirmation required"
                          if normalization_pending or pac_confirmation_pending else
                          "Retry available" if journal_retry else "Ready")
        recovery_severity = (StatusSeverity.ERROR if recovery_required else
                             StatusSeverity.WARNING
                             if normalization_pending or pac_confirmation_pending else
                             StatusSeverity.WARNING if journal_retry else
                             StatusSeverity.READY)
        recovery_row = _row(
            "recovery", "Incomplete operation or recovery",
            recovery_state, recovery_severity,
            ("Preserve the managed files and review the diagnostics before retrying."
             if recovery_required else
             "Launch results are waiting to be saved. Return to Amethyst after "
             "closing the game, or use Confirm runtime output."
             if normalization_pending or pac_confirmation_pending else
             "A prerequisite-only attempt left no managed FFTIC state; Setup can be retried."
             if journal_retry else "No incomplete managed operation is recorded."),
            receipt_error, generation_error, journal_error, journal_retry,
            *((receipt.data.get("recovery_instructions", ()) if receipt else ())))

        ready = bool(verification and verification.ready and not unsupported
                     and runner_row.state in {"Ready", "Unverified", "Verified"})
        release = None
        release_error = ""
        if receipt is not None and not receipt_error:
            release, release_error = CHECKER.check(installed_loader)
        release_row = _row(
            "loader_release", "FFTIC Mod Loader release",
            "Not installed" if receipt is None else
            "Update available" if release and release.installable else
            "Review required" if release else
            "Check unavailable" if release_error else "Current",
            StatusSeverity.WARNING if release or release_error else StatusSeverity.INFO,
            ("Set up managed FFTIC support before checking loader updates."
             if receipt is None else
             f"Installed {installed_loader}; available {release.version}. "
             + ("Choose Update to install the reviewed loader only." if release.installable
                else release.reason) if release else
             release_error or f"Installed {installed_loader}; no newer stable release was found."),
            release.notes_url if release else "")
        launch_pending = normalization_pending or pac_confirmation_pending
        launch_row = _row(
            "launch", "Launch readiness", "Ready to test" if ready else
            "Runtime output confirmation required" if launch_pending else
            "Managed support needs attention" if receipt is not None else "Setup required",
            StatusSeverity.WARNING if ready else
            StatusSeverity.WARNING if launch_pending else StatusSeverity.ERROR,
            ("Managed state is ready. Start FFTIC normally from Steam and check the exact in-game result."
             if ready else
             "The managed installation exists; confirm the exact pending runtime transition."
             if launch_pending else
             "Managed launch is blocked until every required state is verified."),
            *((verification.issues if verification else
               ("No complete correlated ownership receipt is available.",))))

        rows = (
            game_row, location_row, runner_row,
            component_rows["runtime"], component_rows["nenkai"],
            component_rows["sigscan"], component_rows["hooks"],
            *prerequisite_rows, bootstrap_row, prefix_config_row, profile_row,
            steam_row, reconciliation_row, recovery_row, launch_row, release_row,
            unsupported_row,
        )
        host_available, host_reason = prerequisite_host_capability(probe=False)
        revert_absent_pac = bool(
            receipt is not None and verification is not None and root is not None
            and game_root is not None and absent_pac_reversion_ready(
                verification, receipt, game_root, root / "backups", pac_evidence))
        available_actions, action_reasons = _action_availability(
            rows, receipt_present=receipt is not None,
            verification=verification, unsupported=unsupported,
            prerequisite_host_available=host_available,
            prerequisite_host_reason=host_reason, release=release,
            installed_loader=installed_loader, revert_absent_pac=revert_absent_pac,
            color_state_present=bool(receipt and receipt.data.get("color_state")))
        if receipt is None or not receipt.data.get('color_state'):
            available_actions = tuple(a for a in available_actions if a != OperationKind.SAVE_MOD_STATE.value)
        hashes = dict(installation.executable_hashes)
        details = (
            f"Detected Steam build: {build or '<unknown>'}",
            f"PE executable version: {installation.pe_version or '<unknown>'}",
            (f"Runtime-proven in-game UI metadata: "
             f"{installation.runtime_proof_ui_version or '<unavailable for this tuple>'}"),
            "The in-game UI version is recorded proof metadata, not detected before launch.",
            f"Classic executable SHA-256: {hashes.get('classic', '<unavailable>')}",
            f"Enhanced executable SHA-256: {hashes.get('enhanced', '<unavailable>')}",
            (f"Supported tuple: Steam {VERIFIED_STEAM_BUILD}; runtime-proven UI metadata "
             f"{VERIFIED_UI_VERSION}; "
            "runner policy: canonical Steam-managed Proton; Verified labels managed selection readiness only"),
            "Exact observed in-game compatibility results are separate from this runner label.",
            f"Current generation: {generation_id or '<none>'}",
            f"Reloaded-II: {versions['runtime']}; Nenkai: {versions['nenkai']}; "
            f"SigScan: {versions['sigscan']}; Shared Hooks: {versions['hooks']}",
            f"Managed root: {root or '<unresolved>'}",
            f"Detected Steam Launch Options: {steam_options.original or '<empty>'}",
            f"Recommended Steam Launch Options: {steam_options.required_copy_text}",
            "The recommendation is separate from the unchanged current Steam value.",
            "Reloaded log location: " + str(
                prefix / "drive_c/users/steamuser/AppData/Roaming/"
                "Reloaded-Mod-Loader-II/Logs" if prefix else "<unresolved>"),
        )
        return InspectionResult(
            rows, details, unsupported, steam_options.required_copy_text,
            steam_options.preserved_unrelated, ready,
            bool(verification and verification.attested),
            available_actions=available_actions,
            action_unavailable_reasons=action_reasons, release=release)

    @staticmethod
    def _observation_identity(context: InspectionContext) -> str:
        records = FfticOrchestrator._live_file_identity(context)
        try:
            selection = resolve_proton_selection(
                context.game.steam_id, context.game.get_prefix_path())
            runner = (str(selection.proton_script or ""), selection.tool_identity,
                      selection.prefix_runtime)
        except Exception:
            runner = ("", "", "")
        return hashlib.sha256(json.dumps(
            (records, runner), sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()


class FfticOrchestrator:
    """UI-facing controller. Inspection is always separate from execution."""

    def __init__(self, inspector: StatusInspector | None = None,
                 executor: AuthorizedExecutor | None = None,
                 executor_factory: ExecutorFactory | None = None):
        self._inspector = inspector or DefaultStatusInspector()
        self._executor = executor
        self._executor_factory = executor_factory
        self._executor_unavailable_reason = EXECUTION_UNAVAILABLE
        self._last_context: InspectionContext | None = None
        self._last_status: FfticStatusViewModel | None = None
        self._state_lock = threading.Lock()
        self._epoch = 0

    @property
    def mutation_available(self) -> bool:
        return bool(self._executor is not None and
                    getattr(self._executor, "authorized", False) is True)

    def automatic_reconciliation_ready(self) -> str | None:
        status = self.last_status
        probe = getattr(self._executor, "automatic_reconciliation_ready", None)
        if (status and status.mutation_available
                and OperationKind.RECONCILE_RUNTIME_OUTPUT.value in status.available_actions
                and callable(probe)):
            return probe()
        return None

    def automatic_mod_state_ready(self) -> str | None:
        status = self.last_status
        probe = getattr(self._executor, 'mod_state_pending', None)
        if (status and status.mutation_available and OperationKind.SAVE_MOD_STATE.value in status.available_actions
                and callable(probe)):
            try:
                return probe()
            except Exception:
                return None
        return None

    @property
    def last_status(self) -> FfticStatusViewModel | None:
        with self._state_lock:
            return self._last_status

    def invalidate(self, context: InspectionContext) -> None:
        """Block plans and readiness while newer profile evidence is loading."""
        with self._state_lock:
            self._epoch += 1
            self._last_context = context
            self._last_status = None

    def refresh(self, context: InspectionContext, cancel: threading.Event | None = None,
                progress: ProgressCallback | None = None) -> FfticStatusViewModel:
        with self._state_lock:
            self._last_context = context
            epoch = self._epoch
        try:
            result = self._inspector.inspect(context, cancel, progress)
            observation = (result.observation_sha256
                           or DefaultStatusInspector._observation_identity(context))
            if self._executor_factory is not None:
                executor, reason = self._executor_factory(context, self.revalidate_plan)
                self._executor = executor
                self._executor_unavailable_reason = reason or EXECUTION_UNAVAILABLE
            mutation_available = self.mutation_available
            available_actions = result.available_actions
            if not available_actions and not result.action_unavailable_reasons:
                available_actions = tuple(kind.value for kind in OperationKind
                                          if kind != OperationKind.UPDATE)
            unbound_update = (OperationKind.UPDATE.value in available_actions
                              and not reviewed_release_identity(result.release))
            if not reviewed_release_identity(result.release):
                available_actions = tuple(action for action in available_actions
                                          if action != OperationKind.UPDATE.value)
            action_reasons = dict(result.action_unavailable_reasons)
            if unbound_update:
                action_reasons[OperationKind.UPDATE.value] = (
                    "The FFTIC loader update has no exact reviewed release and asset identity. "
                    "Recheck status before choosing Update.")
            elif OperationKind.UPDATE.value not in available_actions:
                action_reasons.setdefault(
                    OperationKind.UPDATE.value,
                    "No newer reviewed loader asset is ready to install. Recheck release details.")
            model = FfticStatusViewModel(
                FFTIC_GAME_ID, "FFTIC Mod Support", result.rows, result.details,
                result.unsupported_packages, result.steam_copy_text,
                result.steam_preserved_options, result.ready,
                result.verifier_attested, mutation_available,
                "" if mutation_available else self._executor_unavailable_reason,
                "Start FFTIC normally from Steam. Amethyst's direct Proton route is not supported.",
                observation_sha256=observation,
                available_actions=available_actions,
                action_unavailable_reasons=tuple(action_reasons.items()),
                release=result.release)
        except InspectionCancelled:
            raise
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            model = FfticStatusViewModel(
                FFTIC_GAME_ID, "FFTIC Mod Support",
                (_row("inspection", "Status inspection", "Recovery required",
                      StatusSeverity.ERROR,
                      "FFTIC status could not be inspected safely.", error),),
                (error,), (), COPY_READY_OPTIONS, (), False, False,
                self.mutation_available,
                "" if self.mutation_available else self._executor_unavailable_reason,
                "Start FFTIC normally from Steam only after readiness is verified.",
                error=error)
        with self._state_lock:
            if epoch == self._epoch:
                self._last_status = model
        return model

    def plan(self, kind: OperationKind) -> OperationPlan:
        with self._state_lock:
            context, status, epoch = self._last_context, self._last_status, self._epoch
        if context is None or status is None:
            raise RuntimeError(
                "Recheck FFTIC status before constructing an operation plan")
        if kind.value not in status.available_actions:
            reason = dict(status.action_unavailable_reasons).get(
                kind.value, "Current FFTIC evidence does not authorize this action.")
            raise RuntimeError(reason)
        if kind == OperationKind.UPDATE and not reviewed_release_identity(status.release):
            raise RuntimeError(
                "The FFTIC loader update plan is stale: exact reviewed release and asset "
                "identity is missing or changed. Recheck status before choosing Update.")
        targets = {
            OperationKind.SETUP: (
                OperationStep(
                    "prefix", "download, install, and verify missing reviewed prerequisites",
                    str(context.game.get_prefix_path())),
                OperationStep(
                    "managed runtime", "acquire and publish the reviewed generation",
                    "private FFTIC root"),
                OperationStep(
                    "bootstrap", "deploy receipt-owned ASI files and configuration",
                    str(context.game.get_game_path())),
                OperationStep(
                    "profile", "synchronize the active content profile",
                    context.profile_name),
            ),
            OperationKind.REPAIR: (
                OperationStep(
                    "ownership", "repair only missing or corrupt receipt-owned state",
                    "verified managed paths"),),
            OperationKind.SYNCHRONIZE: (
                OperationStep(
                    "profile", "publish an immutable synchronized generation",
                    context.profile_name),),
            OperationKind.UPDATE: (
                OperationStep(
                    "FFTIC Mod Loader",
                    f"acquire exact release {status.release.version if status.release else '<unavailable>'} asset "
                    f"{status.release.asset_id if status.release else '<unavailable>'} "
                    f"SHA-256 {status.release.asset_sha256 if status.release else '<unavailable>'}; "
                    "publish and activate a side-by-side generation",
                    "private FFTIC root"),),
            OperationKind.REVERT_LOADER: (
                OperationStep(
                    "FFTIC Mod Loader",
                    "rebuild reviewed 1.7.3 and publish a new owned generation; "
                    "replace the 1.7.5 receipt and reset the PAC/log baseline",
                    "private FFTIC root"),),
            OperationKind.REMOVE: (
                OperationStep(
                    "managed support", "restore receipt-owned files and retain shared runtimes",
                    "FFTIC game and prefix"),),
            OperationKind.SAVE_MOD_STATE: (
                OperationStep('mod state', 'snapshot stopped-game profile settings, themes and output',
                              'receipt-owned working copy; PACs remain separate'),),
            OperationKind.RECONCILE_RUNTIME_OUTPUT: (
                OperationStep(
                    "post-launch runtime output",
                    "verify exact normalization/log/PAC evidence and reconcile recoverably",
                    "active FFTIC generation and known generated PAC paths"),),
        }
        if status.unsupported_packages and kind in {
                OperationKind.SETUP, OperationKind.SYNCHRONIZE}:
            names = ", ".join(item.name for item in status.unsupported_packages)
            raise RuntimeError(f"Unsupported or unsafe packages block this plan: {names}")
        binding = self._binding(context, status, epoch)
        return OperationPlan(kind, context.profile_name, targets[kind], binding=binding,
                             release=status.release if kind == OperationKind.UPDATE else None)

    @staticmethod
    def _binding(context: InspectionContext, status: FfticStatusViewModel,
                 epoch: int) -> OperationBinding:
        game_root = context.game.get_game_path()
        prefix = context.game.get_prefix_path()
        material = {
            "game_id": getattr(context.game, "game_id", ""),
            "profile": context.profile_name,
            "game_root": str(Path(game_root).resolve(strict=False)) if game_root else "",
            "prefix": str(Path(prefix).resolve(strict=False)) if prefix else "",
            "profile_dir": str(context.profile_dir.resolve(strict=False)),
            "staging_root": str(context.staging_root.resolve(strict=False)),
            "rows": [(row.key, row.state, row.summary, row.details) for row in status.rows],
            "unsupported": [
                (item.name, item.path, item.reason, item.enabled)
                for item in status.unsupported_packages
            ],
            "ready": status.ready,
            "attested": status.verifier_attested,
            "release": (getattr(status, "release", None).__dict__
                        if getattr(status, "release", None) else None),
        }
        digest = hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        try:
            selection = resolve_proton_selection(context.game.steam_id, prefix)
        except Exception:
            selection = ProtonSelection(None, "", "")
        return OperationBinding(
            material["game_id"], context.profile_name, material["game_root"],
            material["prefix"], material["profile_dir"], material["staging_root"],
            epoch, digest, status.observation_sha256, selection.tool_identity,
            str(selection.proton_script or ""))

    @staticmethod
    def _live_file_identity(context: InspectionContext) -> tuple[tuple, ...]:
        """Rebind plans to current executables, modlist and referenced staging bytes."""
        paths: list[tuple[str, Path]] = []
        game_root = context.game.get_game_path()
        if game_root is not None:
            paths.extend((f"game/{name}", Path(game_root) / name) for name in (
                "FFT_classic.exe", "FFT_enhanced.exe"))
        modlist = context.profile_dir / "modlist.txt"
        paths.append(("profile/modlist.txt", modlist))
        try:
            from Utils.mods.modlist import read_modlist
            entries = read_modlist(modlist)
        except Exception:
            entries = ()
        for entry in entries:
            if getattr(entry, "is_separator", False):
                continue
            root = context.staging_root / entry.name
            paths.append((f"staging/{entry.name}", root))
            if root.is_dir() and not root.is_symlink():
                paths.extend((
                    f"staging/{entry.name}/{child.relative_to(root).as_posix()}", child)
                    for child in sorted(root.rglob("*"), key=lambda item: str(item).casefold())
                )
        identities = []
        for label, path in paths:
            try:
                info = path.lstat()
                if path.is_symlink():
                    identities.append((label, "symlink", os.readlink(path)))
                elif path.is_dir():
                    identities.append((label, "directory", info.st_mode))
                elif path.is_file():
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                    identities.append((label, "file", info.st_size, digest.hexdigest()))
                else:
                    identities.append((label, "special", info.st_mode))
            except OSError as exc:
                identities.append((label, "missing", exc.__class__.__name__))
        return tuple(identities)

    def plan_is_current(self, plan: OperationPlan) -> bool:
        with self._state_lock:
            context, status, epoch = self._last_context, self._last_status, self._epoch
        if plan.binding is None or context is None or status is None:
            return False
        return (plan.binding == self._binding(context, status, epoch)
                and (plan.kind != OperationKind.UPDATE or (
                    OperationKind.UPDATE.value in status.available_actions
                    and reviewed_release_identity(plan.release)
                    and reviewed_release_identity(status.release)
                    and plan.release == status.release)))

    def revalidate_plan(self, plan: OperationPlan) -> bool:
        """Recompute the background observation before an executor may mutate."""
        if not isinstance(plan, OperationPlan) or not self.plan_is_current(plan):
            return False
        with self._state_lock:
            context = self._last_context
        return bool(
            context is not None and plan.binding is not None
            and plan.binding.observation_sha256
            and DefaultStatusInspector._observation_identity(context)
            == plan.binding.observation_sha256)

    def execute(self, plan: OperationPlan, cancel: threading.Event | None = None,
                progress: ProgressCallback | None = None):
        if not self.mutation_available:
            raise PermissionError(self._executor_unavailable_reason)
        if not isinstance(plan, OperationPlan) or not self.plan_is_current(plan):
            raise RuntimeError(
                "This FFTIC operation plan is stale. Recheck status and confirm the action again.")
        if not self.revalidate_plan(plan):
            raise RuntimeError(
                "This FFTIC operation plan is stale. Profile or staged content changed.")
        return self._executor.execute(plan, cancel, progress)

    def launch_block_reason(self) -> str:
        status = self.last_status
        if status is None:
            return "Recheck FFTIC support before launch. Start the game normally from Steam."
        steam = next((row for row in status.rows if row.key == "steam_options"), None)
        if steam is not None and steam.state != "Configured":
            return (f"Steam Launch Options are {steam.state}. Copy the required value, "
                    "save it in FFTIC's Steam Properties, and recheck.")
        if not status.verifier_attested or not status.ready:
            return ("FFTIC managed support is not verifier-attested as ready. "
                    "Review the status details and recheck.")
        return ("FFTIC is ready. Start it normally from Steam; this Amethyst "
                "build does not start FFTIC directly.")
