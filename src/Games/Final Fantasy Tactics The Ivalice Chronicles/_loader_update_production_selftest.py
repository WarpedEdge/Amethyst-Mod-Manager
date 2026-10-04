"""Isolated regression for the real FFTIC status-to-production-update path."""

from __future__ import annotations

import os
import shutil
from contextlib import ExitStack
from dataclasses import replace
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from _c3c_selftest import Fixture
from _loader_update_selftest import metadata
from fftic_artifacts import REVIEWED_LOADER_UPDATE
from fftic_detection import InstallStatus, VERIFIED_HASHES
from fftic_loader_releases import CHECKER, parse_release
from fftic_orchestration import (DefaultStatusInspector, FFTIC_GAME_ID,
                                  FfticOrchestrator, InspectionContext,
                                  OperationKind)
from fftic_production import create_production_executor
from fftic_proton import ProtonSelection, supported_runner
from fftic_readiness import SUPPORTED_PROTON_RUNNER
from fftic_receipts import read_receipt
from fftic_steam_requirements import COPY_READY_OPTIONS
from fftic_transaction_executor import file_sha256 as real_file_sha256
from fftic_workflows import CurrentInstallationEvidence


def test_default_status_to_production_update(asset: Path) -> None:
    fixture = Fixture("production-update-plan")
    try:
        runner = fixture.root / "steam/steamapps/common/Proton - Experimental/proton"
        runner.parent.mkdir(parents=True)
        runner.write_text("isolated runner", encoding="utf-8")
        (runner.parent / "version").write_text(
            f"1 {SUPPORTED_PROTON_RUNNER}\n", encoding="utf-8")
        (runner.parent.parent.parent / "appmanifest_1493710.acf").write_text(
            '"AppState" { "appid" "1493710" '
            '"installdir" "Proton - Experimental" }', encoding="utf-8")
        assert supported_runner(SUPPORTED_PROTON_RUNNER, runner)
        selected = ProtonSelection(runner, SUPPORTED_PROTON_RUNNER, "fixture",
                                   "proton_experimental")
        detection = replace(
            fixture.installation_evidence().detection,
            status=InstallStatus.EXACT_VERIFIED,
            executable_hashes=tuple(VERIFIED_HASHES.items()),
            runtime_proof_ui_version="v1.5.2")
        executable_hashes = {
            fixture.game / "FFT_classic.exe": VERIFIED_HASHES["classic"],
            fixture.game / "FFT_enhanced.exe": VERIFIED_HASHES["enhanced"],
        }
        def synthetic_file_hash(path):
            if Path(path) in executable_hashes:
                return executable_hashes[Path(path)]
            return real_file_sha256(path)
        managed = fixture.prefix / "drive_c/Amethyst/FFTIC"
        fixture.recompose(
            extraction_root=managed / "work/extraction",
            generations_root=managed / "generations",
            backup_root=managed / "backups",
            quarantine_root=managed / "quarantine",
            receipts_root=managed / "receipts",
            active_state_file=managed / "active-generation.json",
            journal_file=managed / "journal/lifecycle.json",
            log_root=managed / "logs",
            installation_reader=lambda: CurrentInstallationEvidence(
                detection, "reviewed-production"),
            runner_script_reader=lambda: runner)
        with patch("fftic_workflows.file_sha256", side_effect=synthetic_file_hash):
            fixture.run(OperationKind.SETUP)
        shutil.copyfile(asset, fixture.cache / REVIEWED_LOADER_UPDATE.filename)
        release = parse_release(metadata(), "1.7.3")
        game = SimpleNamespace(
            game_id=FFTIC_GAME_ID, name="FFTIC fixture", steam_id="1004640",
            get_game_path=lambda: fixture.game,
            get_prefix_path=lambda: fixture.prefix,
            compatibility=lambda **_kwargs: detection)
        context = InspectionContext(game, "default", fixture.profile, fixture.staging)
        steamapps = fixture.library / "steamapps"
        def acquire(pin, cache, **_kwargs):
            assert Path(cache) == fixture.cache
            selected_path = fixture.cache / pin.filename
            assert selected_path.is_file()
            return SimpleNamespace(path=selected_path)
        controller = FfticOrchestrator(executor_factory=partial(
            create_production_executor, artifact_acquire=acquire,
            cache_root=fixture.cache))
        inner_results = []
        original_inspect = DefaultStatusInspector._inspect_unlocked
        def trace_inspect(inspector, *args):
            result = original_inspect(inspector, *args)
            inner_results.append(result)
            return result
        with ExitStack() as stack:
            stack.enter_context(patch("Utils.launchers.steam.owning_steamapps_dir",
                                      return_value=steamapps))
            stack.enter_context(patch("Utils.launchers.steam.steam_launch_options",
                                      return_value=COPY_READY_OPTIONS))
            stack.enter_context(patch("fftic_orchestration.resolve_proton_selection",
                                      return_value=selected))
            stack.enter_context(patch("fftic_production.resolve_proton_selection",
                                      return_value=selected))
            stack.enter_context(patch("fftic_orchestration.inspect_prefix_prerequisites",
                                      side_effect=fixture.prerequisites))
            stack.enter_context(patch("fftic_production.inspect_prefix_prerequisites",
                                      side_effect=fixture.prerequisites))
            stack.enter_context(patch("fftic_workflows.file_sha256",
                                      side_effect=synthetic_file_hash))
            stack.enter_context(patch("Utils.processes.game.matching_pids",
                                      return_value=[]))
            stack.enter_context(patch("Utils.processes.game.prefix_markers",
                                      return_value=[]))
            stack.enter_context(patch.object(CHECKER, "check", return_value=(release, "")))
            stack.enter_context(patch.object(DefaultStatusInspector, "_inspect_unlocked",
                                             trace_inspect))
            status = controller.refresh(context)
            assert inner_results
            assert next(row.state for row in inner_results[-1].rows
                        if row.key == "loader_release") == "Update available"
            assert OperationKind.UPDATE.value in inner_results[-1].available_actions
            assert inner_results[-1].release == release
            assert status.row("loader_release").state == "Update available"
            assert OperationKind.UPDATE.value in status.available_actions
            assert status.release == release
            assert status.action_unavailable_reasons == (
                inner_results[-1].action_unavailable_reasons)
            assert controller.mutation_available

            plan = controller.plan(OperationKind.UPDATE)
            assert plan.release is release
            operations = controller._executor._operations
            prepared = []
            updated = []
            original_prepare = operations._prepare
            original_update = operations._update
            def trace_prepare(selected_plan, kind):
                assert selected_plan is plan and kind == OperationKind.UPDATE
                prepared.append(selected_plan)
                return original_prepare(selected_plan, kind)
            def trace_update(token, cancel):
                assert token.plan is plan and token.plan.release is release
                updated.append(token.plan)
                return original_update(token, cancel)
            with patch.object(operations, "_prepare", side_effect=trace_prepare), \
                    patch.object(operations, "_update", side_effect=trace_update):
                # The UI confirmation closure passes this same plan to execute.
                confirmed = lambda accepted: controller.execute(plan) if accepted else None
                assert confirmed(False) is None
                assert not prepared and not updated
                confirmed(True)
            assert prepared == [plan] and updated == [plan]
            receipt = read_receipt(fixture.inputs.receipts_root)
            assert next(item["version"] for item in receipt.data["artifacts"]
                        if item["artifact_id"] == "nenkai-loader") == "1.7.5"
    finally:
        shutil.rmtree(fixture.root)


if __name__ == "__main__":
    asset_path = os.environ.get("FFTIC_REVIEWED_LOADER_ASSET")
    if not asset_path:
        raise SystemExit("Set FFTIC_REVIEWED_LOADER_ASSET to the isolated reviewed archive")
    test_default_status_to_production_update(Path(asset_path))
    print("FFTIC production Update plan identity passed")
