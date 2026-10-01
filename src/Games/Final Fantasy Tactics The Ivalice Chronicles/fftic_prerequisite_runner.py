"""Narrow production runner for FFTIC's two reviewed prerequisite installers."""

from __future__ import annotations

import threading
from pathlib import Path

try:
    from .fftic_artifacts import ARTIFACTS
    from .fftic_managed_executor import (
        ManagedOperationCancelled, ManagedOperationError, ProcessRequest,
        ProcessResult,
    )
    from .fftic_orchestration import ProgressUpdate
    from .fftic_prerequisites import prerequisite_host_capability
except ImportError:
    from fftic_artifacts import ARTIFACTS
    from fftic_managed_executor import (
        ManagedOperationCancelled, ManagedOperationError, ProcessRequest,
        ProcessResult,
    )
    from fftic_orchestration import ProgressUpdate
    from fftic_prerequisites import prerequisite_host_capability


_AUTHORIZED_INSTALLERS = {
    ARTIFACTS["dotnet-desktop-runtime"], ARTIFACTS["vc-runtime"]}


def host_execution_capability() -> tuple[bool, str]:
    """Probe only the fixed Flatpak host boundary; never start Proton or Wine."""
    return prerequisite_host_capability(probe=True)


def _append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(message.rstrip() + "\n")


def _prefix_processes_active(request: ProcessRequest) -> bool:
    """Fail closed when the exact app/prefix process identity cannot be checked."""
    from Utils.processes.game import matching_pids, prefix_markers
    markers = prefix_markers(request.prefix)
    markers.extend((
        "SteamAppId=1004640", "SteamGameId=1004640",
        "STEAM_COMPAT_APP_ID=1004640",
    ))
    matches = matching_pids(markers)
    if matches is None:
        raise ManagedOperationError(
            "Could not verify that FFTIC, Proton, Wine, and installer processes are stopped")
    return bool(matches)


class FfticPrerequisiteRunner:
    """Execute only a validated FFTIC installer plan through selected Proton."""

    def run(self, request: ProcessRequest, cancel: threading.Event | None = None,
            progress=None) -> ProcessResult:
        request.validate()
        if request.executable_pin not in _AUTHORIZED_INSTALLERS:
            raise ManagedOperationError("Installer is outside the FFTIC prerequisite allowlist")
        try:
            from .fftic_proton import _selected_tool_identity
        except ImportError:
            from fftic_proton import _selected_tool_identity
        if _selected_tool_identity(request.runner) != request.runner_identity:
            raise ManagedOperationError(
                "The selected Proton installation identity changed before execution")
        if request.allow_flatpak_host_spawn:
            available, reason = host_execution_capability()
            if not available:
                raise ManagedOperationError(reason)
        if cancel is not None and cancel.is_set():
            raise ManagedOperationCancelled(
                "FFTIC setup cancelled before prerequisite execution")
        if _prefix_processes_active(request):
            raise ManagedOperationError(
                "Close FFTIC and other Proton/Wine tools using its prefix, then retry setup")

        # Revalidate immediately before the external process is created.
        request.validate()
        from Utils.flatpak.i386 import preflight_i386_error
        error = preflight_i386_error(request.runner)
        if error:
            raise ManagedOperationError(error)
        from Utils.launchers.steam import proton_run_command
        from Utils.wine.protontricks import run_prefix_installer

        environment = dict(request.environment)
        command = proton_run_command(
            request.runner, "runinprefix", str(request.executable),
            *request.arguments, env=environment,
            host_cwd=request.working_directory)
        if any(value in {"sh", "bash", "-c"} for value in command):
            raise ManagedOperationError("Installer command unexpectedly requires a shell")
        _append_log(request.log_path, f"Starting reviewed {request.plan.component} installer")
        if progress is not None:
            progress(ProgressUpdate(0, 1, f"Installing {request.plan.component}"))
        rc, output = run_prefix_installer(
            command, environment, request.working_directory,
            label=request.plan.component,
            log_fn=lambda message: _append_log(request.log_path, message),
            timeout=request.timeout_seconds, proton_script=request.runner,
            compat_data=environment["STEAM_COMPAT_DATA_PATH"])
        if output:
            _append_log(request.log_path, output)
        if rc is None:
            raise ManagedOperationError(
                f"{request.plan.component} installer timed out; shared prefix changes were retained")
        allowed = {*request.accepted_exit_codes, *request.restart_exit_codes}
        if rc not in allowed:
            raise ManagedOperationError(
                f"{request.plan.component} installer returned unaccepted exit code {rc}")
        if cancel is not None and cancel.is_set():
            raise ManagedOperationCancelled(
                f"Cancellation waited for {request.plan.component} to finish; "
                "the shared prefix change was retained and setup requires repair verification")
        if progress is not None:
            progress(ProgressUpdate(
                1, 1, f"Installed {request.plan.component}; verifying"))
        return ProcessResult(
            rc, rc in request.restart_exit_codes, request.log_path)
