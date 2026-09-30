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
    from .fftic_detection import (
        InstallStatus, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
    )
    from .fftic_generation import verify_private_generation
    from .fftic_packages import PackageClassification, inspect_package
    from .fftic_pac import PacLaunchEvidence
    from .fftic_prerequisites import PrerequisiteState, inspect_prefix_prerequisites
    from .fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, SUPPORTED_PROTON_RUNNER,
        verify_launch_readiness,
    )
    from .fftic_receipts import PREFIX_CONFIGURATION_PATH, read_receipt
    from .fftic_steam_path import resolve_steam_s_path
    from .fftic_steam_requirements import (
        COPY_READY_OPTIONS, SteamOptionsStatus, analyze_steam_launch_options,
    )
except ImportError:
    from fftic_artifacts import ARTIFACTS, INTERNAL_FILES, validate_file
    from fftic_detection import (
        InstallStatus, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
    )
    from fftic_generation import verify_private_generation
    from fftic_packages import PackageClassification, inspect_package
    from fftic_pac import PacLaunchEvidence
    from fftic_prerequisites import PrerequisiteState, inspect_prefix_prerequisites
    from fftic_readiness import (
        ReadinessAspect, ReadinessEvidence, SUPPORTED_PROTON_RUNNER,
        verify_launch_readiness,
    )
    from fftic_receipts import PREFIX_CONFIGURATION_PATH, read_receipt
    from fftic_steam_path import resolve_steam_s_path
    from fftic_steam_requirements import (
        COPY_READY_OPTIONS, SteamOptionsStatus, analyze_steam_launch_options,
    )

FFTIC_GAME_ID = "final_fantasy_tactics_the_ivalice_chronicles"
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
    REMOVE = "remove"


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


def _ui_version(game_root: Path | None) -> str | None:
    if game_root is None:
        return None
    try:
        from Utils.executables.icon import extract_exe_version
        value = extract_exe_version(game_root / "FFT_enhanced.exe")
    except Exception:
        return None
    parts = value.split(".") if value else []
    return "v" + ".".join(parts[:3]) if len(parts) >= 3 else None


def _runner_identity(prefix: Path | None) -> str:
    if prefix is None:
        return ""
    try:
        from Utils.wine.prefix import read_prefix_runner, resolve_compat_data
        lines = (resolve_compat_data(prefix) / "config_info").read_text(
            encoding="utf-8", errors="replace").splitlines()
        candidates = [read_prefix_runner(resolve_compat_data(prefix)), *lines]
    except OSError:
        candidates = []
    for value in candidates:
        if SUPPORTED_PROTON_RUNNER in value:
            return SUPPORTED_PROTON_RUNNER
    return next((value.strip() for value in candidates if value.strip()), "")


def _managed_root(prefix: Path | None) -> Path | None:
    if prefix is None:
        return None
    return Path(prefix) / "drive_c" / "Amethyst" / "FFTIC"


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
        if result.classification == PackageClassification.UNSUPPORTED_CODE:
            manifest = result.manifest
            unsupported.append(UnsupportedPackage(
                manifest.name if manifest is not None else entry.name,
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
                        result.ready, result.verifier_attested, after)
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
            steam_build=build, ui_version=_ui_version(game_root))
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

        runner = _runner_identity(prefix)
        runner_row = _row(
            "runner", "Proton runner",
            "Ready" if runner == SUPPORTED_PROTON_RUNNER else "Unsupported",
            StatusSeverity.READY if runner == SUPPORTED_PROTON_RUNNER else StatusSeverity.ERROR,
            ("The selected Proton runner matches the tested tuple." if
             runner == SUPPORTED_PROTON_RUNNER
             else "The selected runner is not the tested FFTIC runner."),
            f"Selected runner: {runner or '<unresolved>'}",
            f"Supported runner: {SUPPORTED_PROTON_RUNNER}")

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
            "unsupported_mods", "Unsupported compiled/API mods",
            "Unsupported" if unsupported else "Ready",
            StatusSeverity.ERROR if unsupported else StatusSeverity.READY,
            ("Current support covers content mods through the managed Nenkai stack; "
             "compiled/runtime packages block synchronization." if unsupported else
             "No unsupported compiled/runtime package was detected in the active profile."),
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
        versions = {
            "runtime": ARTIFACTS["reloaded-ii"].version,
            "nenkai": ARTIFACTS["nenkai-loader"].version,
            "sigscan": ARTIFACTS["sigscan"].version,
            "hooks": ARTIFACTS["shared-hooks"].version,
        }
        for key, label in (("runtime", "Reloaded-II runtime generation"),
                           ("nenkai", "Nenkai loader"),
                           ("sigscan", "SigScan"),
                           ("hooks", "Shared Hooks")):
            component_rows[key] = _row(
                key, label, "Not installed", StatusSeverity.ERROR,
                f"Managed {label} {versions[key]} has no verified ownership receipt.")

        active_state = root / "active-generation.json" if root is not None else None
        generation_id = ""
        generation_root = None
        generation_error = ""
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
                                   ("nenkai", "Nenkai loader"),
                                   ("sigscan", "SigScan"),
                                   ("hooks", "Shared Hooks")):
                    component_rows[key] = _row(
                        key, label, "Ready" if receipt else "Conflict",
                        StatusSeverity.READY if receipt else StatusSeverity.ERROR,
                        (f"Version {versions[key]} is present in generation {generation_id}."
                         if receipt else "Reviewed bytes exist without an ownership receipt."))
            except InspectionCancelled:
                raise
            except Exception as exc:
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
        if (receipt is not None and steam_path is not None and prerequisites is not None
                and active_state is not None):
            try:
                self._cancelled(cancel)
                pac_evidence = tuple(PacLaunchEvidence(
                    item["generation_id"], item["profile_fingerprint"],
                    item["launch_id"], item["transaction_id"])
                    for item in receipt.data["generated_pac_observations"])
                verification = verify_launch_readiness(ReadinessEvidence(
                    receipt, installation, steam_path, manifest, runner,
                    active_state, context.profile_dir, context.staging_root,
                    prerequisites, steam_options, pac_evidence))
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
                if row.severity != StatusSeverity.READY:
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
        profile_ready = bool(verification and verification.attested and
                             verification.profile == ReadinessAspect.READY and not unsupported)
        profile_row = _row(
            "profile", "Active Amethyst profile synchronization",
            "Ready" if profile_ready else "Unsupported" if unsupported else
            "Profile needs synchronization",
            StatusSeverity.READY if profile_ready else StatusSeverity.ERROR,
            ("The active profile and staged content match the managed generation."
             if profile_ready else "The current profile is not verifier-attested as synchronized."),
            *((verification.issues if verification else ())))

        recovery_required = bool(
            receipt_error or generation_error or
            (receipt and receipt.data.get("incomplete_operation")) or
            (verification and verification.recovery != ReadinessAspect.READY))
        recovery_row = _row(
            "recovery", "Incomplete operation or recovery",
            "Recovery required" if recovery_required else "Ready",
            StatusSeverity.ERROR if recovery_required else StatusSeverity.READY,
            ("Preserve the managed files and review the diagnostics before retrying."
             if recovery_required else "No incomplete managed operation is recorded."),
            receipt_error, generation_error,
            *((receipt.data.get("recovery_instructions", ()) if receipt else ())))

        ready = bool(verification and verification.ready and not unsupported)
        launch_row = _row(
            "launch", "Launch readiness", "Ready" if ready else "Setup required",
            StatusSeverity.READY if ready else StatusSeverity.ERROR,
            ("Verifier-attested readiness passed. Start FFTIC normally from Steam."
             if ready else "Managed launch is blocked until every required state is verified."),
            *((verification.issues if verification else
               ("No complete correlated ownership receipt is available.",))))

        rows = (
            game_row, location_row, runner_row,
            component_rows["runtime"], component_rows["nenkai"],
            component_rows["sigscan"], component_rows["hooks"],
            *prerequisite_rows, bootstrap_row, prefix_config_row, profile_row,
            steam_row, recovery_row, launch_row, unsupported_row,
        )
        hashes = dict(installation.executable_hashes)
        details = (
            f"Detected Steam build: {build or '<unknown>'}",
            f"Detected game version: {installation.ui_version or '<unknown>'}",
            f"Classic executable SHA-256: {hashes.get('classic', '<unavailable>')}",
            f"Enhanced executable SHA-256: {hashes.get('enhanced', '<unavailable>')}",
            f"Supported tuple: Steam {VERIFIED_STEAM_BUILD}; UI {VERIFIED_UI_VERSION}; "
            f"runner {SUPPORTED_PROTON_RUNNER}",
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
            bool(verification and verification.attested))

    @staticmethod
    def _observation_identity(context: InspectionContext) -> str:
        records = FfticOrchestrator._live_file_identity(context)
        return hashlib.sha256(json.dumps(
            records, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class FfticOrchestrator:
    """UI-facing controller. Inspection is always separate from execution."""

    def __init__(self, inspector: StatusInspector | None = None,
                 executor: AuthorizedExecutor | None = None):
        self._inspector = inspector or DefaultStatusInspector()
        self._executor = executor
        self._last_context: InspectionContext | None = None
        self._last_status: FfticStatusViewModel | None = None
        self._state_lock = threading.Lock()
        self._epoch = 0

    @property
    def mutation_available(self) -> bool:
        return bool(self._executor is not None and
                    getattr(self._executor, "authorized", False) is True)

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
            model = FfticStatusViewModel(
                FFTIC_GAME_ID, "FFTIC Mod Support", result.rows, result.details,
                result.unsupported_packages, result.steam_copy_text,
                result.steam_preserved_options, result.ready,
                result.verifier_attested, self.mutation_available,
                "" if self.mutation_available else EXECUTION_UNAVAILABLE,
                "Start FFTIC normally from Steam. Amethyst's direct Proton route is not supported.",
                observation_sha256=observation)
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
                "" if self.mutation_available else EXECUTION_UNAVAILABLE,
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
        targets = {
            OperationKind.SETUP: (
                OperationStep(
                    "managed runtime", "acquire and publish the reviewed generation",
                    "private FFTIC root"),
                OperationStep(
                    "prefix", "install missing reviewed prerequisites",
                    str(context.game.get_prefix_path())),
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
                    "managed runtime",
                    "publish and activate a reviewed side-by-side generation",
                    "private FFTIC root"),),
            OperationKind.REMOVE: (
                OperationStep(
                    "managed support", "restore receipt-owned files and retain shared runtimes",
                    "FFTIC game and prefix"),),
        }
        if status.unsupported_packages and kind in {
                OperationKind.SETUP, OperationKind.SYNCHRONIZE}:
            names = ", ".join(item.name for item in status.unsupported_packages)
            raise RuntimeError(f"Unsupported compiled/API mods block this plan: {names}")
        binding = self._binding(context, status, epoch)
        return OperationPlan(kind, context.profile_name, targets[kind], binding=binding)

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
        }
        digest = hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return OperationBinding(
            material["game_id"], context.profile_name, material["game_root"],
            material["prefix"], material["profile_dir"], material["staging_root"],
            epoch, digest, status.observation_sha256)

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
        return plan.binding == self._binding(context, status, epoch)

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
            raise PermissionError(EXECUTION_UNAVAILABLE)
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
