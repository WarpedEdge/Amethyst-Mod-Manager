"""Production path and evidence composition for FFTIC managed support."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from .fftic_artifact_service import acquire_artifact
    from .fftic_artifacts import ARTIFACTS
    from .fftic_managed_executor import ManagedLifecycleExecutor
    from .fftic_managed_executor import ProcessRequest
    from .fftic_orchestration import (
        FFTIC_GAME_ID, InspectionContext, _manifest_value, _pe_version,
    )
    from .fftic_proton import resolve_proton_selection
    from .fftic_prerequisites import (
        inspect_prefix_prerequisites, prerequisite_host_capability,
    )
    from .fftic_prerequisite_runner import FfticPrerequisiteRunner
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
    from fftic_managed_executor import ProcessRequest
    from fftic_orchestration import (
        FFTIC_GAME_ID, InspectionContext, _manifest_value, _pe_version,
    )
    from fftic_proton import resolve_proton_selection
    from fftic_prerequisites import (
        inspect_prefix_prerequisites, prerequisite_host_capability,
    )
    from fftic_prerequisite_runner import FfticPrerequisiteRunner
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


def _canonical_steam_client_root(value) -> Path:
    """Resolve Steam's standard client alias, then validate its real target."""
    if value is None:
        raise ValueError(
            "The Steam client root for selected Proton is unavailable")
    try:
        resolved = Path(value).absolute().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(
            "The Steam client root for selected Proton is unavailable") from exc
    return _canonical_directory(resolved, "Steam client root")


def _prerequisite_is_sufficient(plan, prefix: Path) -> bool:
    current = inspect_prefix_prerequisites(prefix)
    return any(
        item.component == plan.component and item.state.value == "sufficient"
        for item in (current.dotnet_desktop, current.vc_runtime))


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
                    steam_build=build, pe_version=_pe_version(game_root)),
                "reviewed-production")

        def managed_processes_running():
            from Utils.processes.game import matching_pids, prefix_markers
            markers = prefix_markers(prefix)
            markers.extend((
                "SteamAppId=1004640", "SteamGameId=1004640",
                "STEAM_COMPAT_APP_ID=1004640",
            ))
            matches = matching_pids(markers)
            if matches is None:
                raise ValueError(
                    "Could not verify that FFTIC, Proton, Wine, and Reloaded are stopped")
            return bool(matches)

        def acquire_reviewed(cancel):
            prerequisites = inspect_prefix_prerequisites(prefix)
            prerequisite_health = {
                "dotnet-desktop-runtime": prerequisites.dotnet_desktop,
                "vc-runtime": prerequisites.vc_runtime,
            }
            for health in prerequisite_health.values():
                if health.state.value not in {
                        "missing", "insufficient", "sufficient"}:
                    raise ValueError(
                        f"Cannot acquire setup artifacts while {health.component} "
                        f"health is {health.state.value}")
            if any(health.state.value in {"missing", "insufficient"}
                   for health in prerequisite_health.values()):
                available, reason = prerequisite_host_capability(probe=True)
                if not available:
                    raise ValueError(reason)
            archives = []
            installers = []
            for artifact_id, pin in ARTIFACTS.items():
                health = prerequisite_health.get(artifact_id)
                if (pin.disposition.value == "execute"
                        and (health is None or health.state.value == "sufficient")):
                    continue
                result = artifact_acquire(
                    pin, artifact_cache, cancel=cancel,
                    quarantine_root=artifact_cache / "quarantine")
                destination = (installers if pin.disposition.value == "execute"
                               else archives)
                destination.append((artifact_id, Path(result.path)))
            return ReviewedCandidateSet(tuple(archives), tuple(installers))

        def process_request(plan):
            selection = resolve_proton_selection(game.steam_id, prefix)
            runner = selection.proton_script
            if selection.tool_identity != plan.runner_identity:
                raise ValueError("The selected Proton identity changed before installation")
            if runner is None:
                raise ValueError("The selected Proton installation could not be resolved")
            runner = Path(runner).absolute()
            if (runner.is_symlink() or not runner.is_file()
                    or runner.resolve(strict=True) != runner):
                raise ValueError("The selected Proton script is not canonical")
            from Utils.launchers.steam import find_steam_root_for_proton_script
            steam_root = find_steam_root_for_proton_script(runner)
            steam_root = _canonical_steam_client_root(steam_root)
            from Utils.wine.prefix import resolve_compat_data
            compatdata = Path(resolve_compat_data(prefix)).absolute()
            if compatdata.is_symlink() or not compatdata.is_dir():
                raise ValueError("The selected FFTIC compatdata root is unavailable")
            compatdata = compatdata.resolve(strict=True)
            if not (prefix == compatdata or prefix.parent == compatdata):
                raise ValueError("The selected prefix does not belong to its compatdata root")
            from Utils.wine.protontricks import strip_appimage_env
            environment = strip_appimage_env(os.environ.copy())
            environment.update({
                "STEAM_COMPAT_DATA_PATH": str(compatdata),
                "STEAM_COMPAT_CLIENT_INSTALL_PATH": str(steam_root),
                "STEAM_COMPAT_INSTALL_PATH": str(game_root),
                "SteamAppId": "1004640",
                "SteamGameId": "1004640",
                "SteamOverlayGameId": "1004640",
                "STEAM_COMPAT_APP_ID": "1004640",
            })
            log_root = managed / "logs"
            log_root.mkdir(parents=True, exist_ok=True)
            return ProcessRequest(
                plan=plan, executable=Path(plan.installer_path),
                executable_pin=plan.artifact, runner=runner,
                runner_identity=selection.tool_identity, prefix=prefix,
                arguments=plan.arguments,
                environment=tuple(sorted(environment.items())),
                log_path=log_root / f"{plan.artifact.artifact_id}.log",
                working_directory=artifact_cache,
                accepted_exit_codes=plan.success_exit_codes,
                restart_exit_codes=plan.restart_exit_codes,
                timeout_seconds=600,
                allow_flatpak_host_spawn=Path("/.flatpak-info").is_file(),
                post_install_health_check=lambda selected_plan, selected_prefix:
                    _prerequisite_is_sufficient(selected_plan, selected_prefix),
            )

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
            runner_reader=lambda: resolve_proton_selection(
                game.steam_id, prefix).tool_identity,
            prerequisite_reader=inspect_prefix_prerequisites,
            process_request_factory=process_request,
            process_runner=FfticPrerequisiteRunner(),
            setup_candidates=None,
            artifact_acquirer=acquire_reviewed,
            process_running=managed_processes_running,
        )
        lifecycle = FfticLifecycleComposition(
            inputs, plan_validator=plan_validator)
        return ManagedLifecycleExecutor(lifecycle), ""
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return None, f"FFTIC managed actions are unavailable: {detail}"
