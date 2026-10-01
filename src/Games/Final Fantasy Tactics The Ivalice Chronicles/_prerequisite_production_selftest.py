"""Hermetic checks for the narrowly authorized FFTIC prerequisite runner."""

from __future__ import annotations

import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fftic_artifacts import ARTIFACTS
from fftic_managed_executor import (
    ManagedOperationCancelled, ManagedOperationError, ProcessRequest,
)
from fftic_prerequisite_runner import (
    FfticPrerequisiteRunner, host_execution_capability,
)
from fftic_prerequisites import (
    DOTNET_COMPONENT, classify_prerequisite, plan_installer,
    prerequisite_host_capability,
)
from fftic_readiness import SUPPORTED_PROTON_RUNNER


def _request() -> ProcessRequest:
    root = Path(tempfile.mkdtemp(prefix="amethyst-fftic-prerequisite-")).resolve()
    compatdata = root / "steamapps/compatdata/1004640"
    prefix = compatdata / "pfx"
    cache = root / "cache"
    client = root / "steam-client"
    logs = root / "logs"
    for directory in (prefix / "drive_c", cache, client, logs):
        directory.mkdir(parents=True, exist_ok=True)
    installer = cache / ARTIFACTS["dotnet-desktop-runtime"].filename
    installer.write_bytes(b"synthetic installer; hash validation is selectively patched")
    runner = root / "Proton Experimental/proton"
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/usr/bin/python3\n", encoding="utf-8")
    (runner.parent / "version").write_text(
        f"1 {SUPPORTED_PROTON_RUNNER}\n", encoding="utf-8")
    health = classify_prerequisite(
        component=DOTNET_COMPONENT, required_version="9.0.20",
        observed_version=None, healthy=True, present=False)
    plan = plan_installer(
        artifact_id="dotnet-desktop-runtime", installer_path=installer,
        prefix=prefix, runner_identity=SUPPORTED_PROTON_RUNNER, health=health)
    assert plan is not None
    environment = (
        ("STEAM_COMPAT_DATA_PATH", str(compatdata)),
        ("STEAM_COMPAT_CLIENT_INSTALL_PATH", str(client)),
        ("STEAM_COMPAT_INSTALL_PATH", str(root / "game")),
        ("SteamAppId", "1004640"), ("SteamGameId", "1004640"),
        ("SteamOverlayGameId", "1004640"),
        ("STEAM_COMPAT_APP_ID", "1004640"),
    )
    return ProcessRequest(
        plan, installer, plan.artifact, runner, SUPPORTED_PROTON_RUNNER,
        prefix, plan.arguments, environment, logs / "dotnet.log", cache,
        plan.success_exit_codes, plan.restart_exit_codes, 60, False,
        lambda _plan, _prefix: True)


def _run_with_code(request: ProcessRequest, code, cancel=None):
    command = []

    def build(_runner, *arguments, **_kwargs):
        command.extend(arguments)
        return [str(request.runner), *map(str, arguments)]

    with patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("fftic_prerequisite_runner._prefix_processes_active", return_value=False), \
            patch("Utils.flatpak.i386.preflight_i386_error", return_value=None), \
            patch("Utils.launchers.steam.proton_run_command", side_effect=build), \
            patch("Utils.wine.protontricks.run_prefix_installer",
                  return_value=(code, "synthetic output")) as execute:
        result = FfticPrerequisiteRunner().run(request, cancel)
    return result, tuple(command), execute


def test_exact_command_success_and_restart_codes() -> None:
    request = _request()
    result, command, execute = _run_with_code(request, 0)
    assert result.returncode == 0 and not result.restart_required
    assert command == ("runinprefix", str(request.executable), *request.arguments)
    assert request.arguments == ("/install", "/quiet", "/norestart")
    assert dict(request.environment)["STEAM_COMPAT_APP_ID"] == "1004640"
    assert execute.call_count == 1
    for code in (3010, 194):
        restarted, _command, _execute = _run_with_code(_request(), code)
        assert restarted.restart_required


def test_wrong_hash_and_proton_identity_stop_before_execution() -> None:
    request = _request()
    with patch("Utils.wine.protontricks.run_prefix_installer") as execute:
        try:
            FfticPrerequisiteRunner().run(request)
        except ManagedOperationError as exc:
            assert "bytes" in str(exc)
        else:
            raise AssertionError("Wrong installer hash reached execution")
        assert not execute.called

    active = _request()
    with patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("fftic_prerequisite_runner._prefix_processes_active", return_value=True), \
            patch("Utils.wine.protontricks.run_prefix_installer") as execute:
        try:
            FfticPrerequisiteRunner().run(active)
        except ManagedOperationError as exc:
            assert "Close FFTIC" in str(exc)
        else:
            raise AssertionError("Active prefix processes did not block installation")
        assert not execute.called

    changed = _request()
    (changed.runner.parent / "version").write_text(
        "1 wrong-proton-identity\n", encoding="utf-8")
    with patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("Utils.wine.protontricks.run_prefix_installer") as execute:
        try:
            FfticPrerequisiteRunner().run(changed)
        except ManagedOperationError as exc:
            assert "Proton" in str(exc)
        else:
            raise AssertionError("Wrong Proton identity reached execution")
        assert not execute.called


def test_failure_timeout_and_cancellation_boundaries() -> None:
    for code in (5, 1, 1638):
        try:
            _run_with_code(_request(), code)
        except ManagedOperationError as exc:
            assert "unaccepted exit code" in str(exc)
        else:
            raise AssertionError(f"Unrelated exit code {code} was accepted")
    try:
        _run_with_code(_request(), None)
    except ManagedOperationError as exc:
        assert "timed out" in str(exc)
    else:
        raise AssertionError("Timeout was accepted")

    before = threading.Event(); before.set()
    request = _request()
    with patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("Utils.wine.protontricks.run_prefix_installer") as execute:
        try:
            FfticPrerequisiteRunner().run(request, before)
        except ManagedOperationCancelled as exc:
            assert "before" in str(exc)
        else:
            raise AssertionError("Pre-execution cancellation was ignored")
        assert not execute.called

    during = threading.Event()
    request = _request()

    def finish_then_cancel(*_args, **_kwargs):
        during.set()
        return 0, "completed safely"

    with patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("fftic_prerequisite_runner._prefix_processes_active", return_value=False), \
            patch("Utils.flatpak.i386.preflight_i386_error", return_value=None), \
            patch("Utils.launchers.steam.proton_run_command",
                  return_value=[str(request.runner), "runinprefix"]), \
            patch("Utils.wine.protontricks.run_prefix_installer",
                  side_effect=finish_then_cancel):
        try:
            FfticPrerequisiteRunner().run(request, during)
        except ManagedOperationCancelled as exc:
            assert "waited" in str(exc) and "requires repair" in str(exc)
        else:
            raise AssertionError("In-flight cancellation was not reported")


def test_unavailable_flatpak_host_capability_is_actionable() -> None:
    original = Path.is_file

    def flatpak_only(path):
        if str(path) == "/.flatpak-info":
            return True
        return original(path)

    with patch.object(Path, "is_file", flatpak_only), \
            patch("fftic_prerequisites.shutil.which", return_value=None):
        available, reason = host_execution_capability()
    assert not available
    assert "flatpak-spawn" in reason and "org.freedesktop.Flatpak" in reason


def test_status_check_does_not_probe_and_runner_rechecks_host() -> None:
    original = Path.is_file

    def flatpak_only(path):
        if str(path) == "/.flatpak-info":
            return True
        return original(path)

    with patch.object(Path, "is_file", flatpak_only), \
            patch("fftic_prerequisites.shutil.which",
                  return_value="/usr/bin/flatpak-spawn"), \
            patch("subprocess.run") as probe:
        available, reason = prerequisite_host_capability(probe=False)
    assert available and not reason and not probe.called

    request = replace(_request(), allow_flatpak_host_spawn=True)
    with patch.object(Path, "is_file", flatpak_only), \
            patch("shutil.which", return_value="/usr/bin/flatpak-spawn"), \
            patch("fftic_managed_executor.validate_file", return_value=True), \
            patch("fftic_prerequisite_runner.host_execution_capability",
                  return_value=(False, "host portal denied")) as capability, \
            patch("Utils.wine.protontricks.run_prefix_installer") as execute:
        try:
            FfticPrerequisiteRunner().run(request)
        except ManagedOperationError as exc:
            assert "host portal denied" in str(exc)
        else:
            raise AssertionError("Runner skipped its immediate host capability check")
    capability.assert_called_once_with()
    assert not execute.called


def main() -> None:
    tests = (
        test_exact_command_success_and_restart_codes,
        test_wrong_hash_and_proton_identity_stop_before_execution,
        test_failure_timeout_and_cancellation_boundaries,
        test_unavailable_flatpak_host_capability_is_actionable,
        test_status_check_does_not_probe_and_runner_rechecks_host,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC production prerequisite checks passed.")


if __name__ == "__main__":
    main()
