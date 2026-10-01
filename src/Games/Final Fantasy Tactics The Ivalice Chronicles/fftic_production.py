"""Production path and evidence composition for FFTIC managed support."""

from __future__ import annotations

from pathlib import Path

try:
    from .fftic_artifact_service import acquire_artifact
    from .fftic_artifacts import ARTIFACTS
    from .fftic_managed_executor import ManagedLifecycleExecutor
    from .fftic_orchestration import (
        FFTIC_GAME_ID, InspectionContext, _manifest_value, _runner_identity,
        _ui_version,
    )
    from .fftic_prerequisites import inspect_prefix_prerequisites
    from .fftic_steam_path import resolve_steam_s_path
    from .fftic_steam_requirements import analyze_steam_launch_options
    from .fftic_workflows import (
        CurrentInstallationEvidence, FfticLifecycleComposition,
        ReviewedCandidateSet, WorkflowInputs,
    )
except ImportError:
    from fftic_artifact_service import acquire_artifact
    from fftic_artifacts import ARTIFACTS
    from fftic_managed_executor import ManagedLifecycleExecutor
    from fftic_orchestration import (
        FFTIC_GAME_ID, InspectionContext, _manifest_value, _runner_identity,
        _ui_version,
    )
    from fftic_prerequisites import inspect_prefix_prerequisites
    from fftic_steam_path import resolve_steam_s_path
    from fftic_steam_requirements import analyze_steam_launch_options
    from fftic_workflows import (
        CurrentInstallationEvidence, FfticLifecycleComposition,
        ReviewedCandidateSet, WorkflowInputs,
    )


def _canonical_directory(value, label: str) -> Path:
    if value is None:
        raise ValueError(f"Select a {label} before using FFTIC managed actions")
    path = Path(value).absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"The selected {label} is not a regular directory")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ValueError(f"The selected {label} crosses a symbolic link")
    return resolved


def create_production_executor(
    context: InspectionContext,
    plan_validator,
    *,
    artifact_acquire=acquire_artifact,
    cache_root: Path | None = None,
):
    """Compose one executor from the currently selected FFTIC installation."""
    try:
        game = context.game
        if getattr(game, "game_id", "") != FFTIC_GAME_ID:
            raise ValueError("The selected game is not FFTIC")
        game_root = _canonical_directory(game.get_game_path(), "FFTIC game path")
        prefix = _canonical_directory(game.get_prefix_path(), "FFTIC Proton prefix")
        profile_dir = _canonical_directory(context.profile_dir, "active profile")
        staging_root = _canonical_directory(context.staging_root, "mod staging root")

        from Utils.launchers.steam import owning_steamapps_dir, steam_launch_options
        steamapps = owning_steamapps_dir(game.steam_id, game_root)
        if steamapps is None:
            raise ValueError("The owning Steam library could not be resolved")
        steamapps = _canonical_directory(steamapps, "Steam steamapps directory")
        steam_library = steamapps.parent
        app_manifest = steamapps / f"appmanifest_{game.steam_id}.acf"
        if (app_manifest.is_symlink() or not app_manifest.is_file()
                or app_manifest.resolve(strict=True) != app_manifest.absolute()):
            raise ValueError("The FFTIC Steam app manifest is missing or linked")
        resolve_steam_s_path(
            steam_library=steam_library, app_manifest=app_manifest,
            game_root=game_root, prefix=prefix)

        managed = prefix / "drive_c" / "Amethyst" / "FFTIC"
        if cache_root is None:
            from Utils.config_paths import get_download_cache_dir_for_game
            artifact_cache = (
                get_download_cache_dir_for_game(game.name, create=False)
                / "fftic-reviewed")
        else:
            artifact_cache = Path(cache_root).absolute()

        def production_installation():
            current_steamapps = owning_steamapps_dir(game.steam_id, game_root)
            if current_steamapps is None or Path(current_steamapps).resolve() != steamapps:
                raise ValueError("The owning Steam library changed")
            current_manifest = steamapps / f"appmanifest_{game.steam_id}.acf"
            build = _manifest_value(current_manifest, "buildid")
            return CurrentInstallationEvidence(
                game.compatibility(
                    steam_build=build, ui_version=_ui_version(game_root)),
                "reviewed-production")

        def acquire_reviewed(cancel):
            acquired = []
            for artifact_id, pin in ARTIFACTS.items():
                if pin.disposition.value != "extract":
                    continue
                result = artifact_acquire(
                    pin, artifact_cache, cancel=cancel,
                    quarantine_root=artifact_cache / "quarantine")
                acquired.append((artifact_id, Path(result.path)))
            return ReviewedCandidateSet(tuple(acquired))

        inputs = WorkflowInputs(
            isolation_root=None,
            game_root=game_root,
            steam_library=steam_library,
            app_manifest=app_manifest,
            prefix=prefix,
            profile_dir=profile_dir,
            staging_root=staging_root,
            artifact_cache=artifact_cache,
            extraction_root=managed / "work" / "extraction",
            generations_root=managed / "generations",
            backup_root=managed / "backups",
            quarantine_root=managed / "quarantine",
            receipts_root=managed / "receipts",
            active_state_file=managed / "active-generation.json",
            journal_file=managed / "journal" / "lifecycle.json",
            log_root=managed / "logs",
            installation_reader=production_installation,
            steam_options_reader=lambda: analyze_steam_launch_options(
                steam_launch_options(game.steam_id)),
            runner_reader=lambda: _runner_identity(prefix),
            prerequisite_reader=inspect_prefix_prerequisites,
            process_request_factory=None,
            process_runner=None,
            setup_candidates=None,
            artifact_acquirer=acquire_reviewed,
        )
        lifecycle = FfticLifecycleComposition(
            inputs, plan_validator=plan_validator)
        return ManagedLifecycleExecutor(lifecycle), ""
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return None, f"FFTIC managed actions are unavailable: {detail}"
