"""Isolated release checks; set FFTIC_REVIEWED_LOADER_ASSET for full transition."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from _c3c_selftest import Fixture, _write_matching_log
from fftic_artifacts import ARTIFACTS, REVIEWED_LOADER_UPDATE
from fftic_extraction import ExtractionError, validate_loader_update_tree
from fftic_loader_releases import CHECKER, LoaderReleaseChecker, ReleaseNoticeLedger, parse_release
from fftic_managed_executor import RecoveryRequiredError
from fftic_pac import (PacOwnershipState, baseline_set_from_receipt,
                       exact_absent_reversion_output)
from fftic_orchestration import (FFTIC_GAME_ID, FfticOrchestrator,
                                  OperationBinding, OperationKind, OperationPlan,
                                  StatusRow, StatusSeverity, _action_availability)
from fftic_proton import managed_runner_label
from fftic_readiness import ReadinessAspect, absent_pac_reversion_ready
from fftic_receipts import read_receipt, validate_receipt
from fftic_workflows import ReviewedCandidateSet, WorkflowError


def metadata():
    pin = REVIEWED_LOADER_UPDATE
    return {"id": 399774110, "tag_name": pin.version, "draft": False,
            "prerelease": False,
            "html_url": f"https://github.com/Nenkai/fftivc.utility.modloader/releases/tag/{pin.version}",
            "assets": [{"id": 600208145, "name": pin.filename, "size": pin.size,
                        "digest": f"sha256:{pin.sha256}",
                        "browser_download_url": pin.url}]}


def test_metadata():
    source = metadata()
    assert parse_release(source, "1.7.3").installable
    assert parse_release(source, "1.7.5") is None
    for change in ({"tag_name": "1.7.5-rc1"}, {"prerelease": True},
                   {"draft": True}, {"tag_name": "bad"}):
        try:
            parse_release(dict(source, **change), "1.7.3")
        except ValueError:
            pass
        else:
            raise AssertionError(f"Invalid metadata accepted: {change}")
    for assets in ([], [dict(source["assets"][0], digest="")],
                   [dict(source["assets"][0], size=8_000_001)]):
        assert not parse_release(dict(source, assets=assets), "1.7.3").installable
    future = dict(source, id=5, tag_name="1.7.6",
                  html_url="https://github.com/Nenkai/fftivc.utility.modloader/releases/tag/1.7.6")
    future["assets"] = [dict(source["assets"][0],
                             name="fftivc.utility.modloader1.7.6.7z",
                             browser_download_url="https://github.com/Nenkai/fftivc.utility.modloader/releases/download/1.7.6/fftivc.utility.modloader1.7.6.7z")]
    assert not parse_release(future, "1.7.3").installable


def test_check_cache():
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, _limit): return json.dumps(metadata()).encode()
    def open_fixture(*_args, **_kwargs):
        calls.append(True)
        return Response()
    checker = LoaderReleaseChecker(opener=open_fixture, clock=lambda: 10)
    assert checker.check("1.7.3")[0].installable
    assert checker.check("1.7.3")[0].installable and len(calls) == 1
    checker.invalidate()
    assert checker.check("1.7.3")[0].installable and len(calls) == 2
    def failed(error):
        def raise_error(*_args, **_kwargs):
            raise error
        return LoaderReleaseChecker(opener=raise_error).check("1.7.3")
    assert "limit" in failed(urllib.error.HTTPError("url", 403, "limit", {}, None))[1]
    assert "limit" in failed(urllib.error.HTTPError("url", 429, "limit", {}, None))[1]
    assert "offline" in failed(urllib.error.URLError("offline"))[1]


def test_notice_once_per_release():
    with tempfile.TemporaryDirectory(prefix="fftic-release-notice-") as temporary:
        path = Path(temporary) / "notices.json"
        first = parse_release(metadata(), "1.7.3")
        assert ReleaseNoticeLedger(path).mark_if_new(first)
        assert not ReleaseNoticeLedger(path).mark_if_new(first)
        later = replace(first, release_id=first.release_id + 1, version="1.7.6")
        assert ReleaseNoticeLedger(path).mark_if_new(later)
        assert not ReleaseNoticeLedger(path).mark_if_new(first)


def test_proton_labels_and_setup_actions():
    def row(key, state):
        return StatusRow(key, key, state, StatusSeverity.READY, state)
    base = [row("game", "Ready"), row("steam_prefix", "Ready"),
            row("steam_options", "Configured"), row("recovery", "Ready"),
            row("dotnet", "Ready"), row("vc", "Ready"),
            *(row(key, "Not installed") for key in
              ("runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config"))]
    for major in (8, 9, 10, 11, 12):
        for family in ("proton", "experimental"):
            identity = f"{family}-{major}.0-fixture"
            label = managed_runner_label(identity, True)
            assert label == ("Verified" if major in (9, 10, 11) else "Unverified")
            assert managed_runner_label(identity, False) == "Unverified"
            actions, _ = _action_availability(
                tuple(base + [row("runner", label)]), receipt_present=False,
                verification=None, unsupported=())
            assert OperationKind.SETUP.value in actions
    assert managed_runner_label("unsafe", True) == "Unsupported"
    actions, _ = _action_availability(
        tuple(base + [row("runner", "Unsupported")]), receipt_present=False,
        verification=None, unsupported=())
    assert OperationKind.SETUP.value not in actions

    managed_rows = tuple(row(key, "Ready") for key in (
        "game", "steam_prefix", "dotnet", "vc", "runner", "steam_options",
        "recovery", "bootstrap", "prefix_config", "profile", "runtime",
        "nenkai", "sigscan", "hooks"))
    verification = SimpleNamespace(**{
        key: ReadinessAspect.READY for key in (
            "game", "artifacts", "generation", "prefix", "prerequisites",
            "bootstrap", "steam_options", "recovery", "runner", "profile")},
        ready=True, attested=True, issues=())
    actions, _ = _action_availability(
        managed_rows, receipt_present=True, verification=verification,
        unsupported=(), installed_loader="1.7.5")
    assert OperationKind.REVERT_LOADER.value in actions
    for version in ("1.7.3", "1.7.4"):
        actions, _ = _action_availability(
            managed_rows, receipt_present=True, verification=verification,
            unsupported=(), installed_loader=version)
        assert OperationKind.REVERT_LOADER.value not in actions
    actions, _ = _action_availability(
        managed_rows, receipt_present=True,
        verification=SimpleNamespace(**dict(verification.__dict__, ready=False)),
        unsupported=(), installed_loader="1.7.5")
    assert OperationKind.REVERT_LOADER.value not in actions
    pending = SimpleNamespace(**dict(
        verification.__dict__, ready=False, profile=ReadinessAspect.INVALID,
        issues=("PAC runtime output confirmation required: data/enhanced/modded.pac",)))
    pending_rows = tuple(
        row(item.key, "Configured" if item.key == "steam_options" else
            "Runtime output confirmation required" if item.key == "recovery" else
            "Ready" if item.key == "profile" else item.state)
        for item in managed_rows) + (row("reconciliation", "Runtime output confirmation required"),)
    actions, _ = _action_availability(
        pending_rows, receipt_present=True, verification=pending,
        unsupported=(), installed_loader="1.7.5", revert_absent_pac=True)
    assert OperationKind.REVERT_LOADER.value in actions
    actions, _ = _action_availability(
        pending_rows, receipt_present=True, verification=pending,
        unsupported=(), installed_loader="1.7.5", revert_absent_pac=False)
    assert OperationKind.REVERT_LOADER.value not in actions


def test_release_bound_plan_staleness():
    release = parse_release(metadata(), "1.7.3")
    context = SimpleNamespace(
        game=SimpleNamespace(game_id=FFTIC_GAME_ID, steam_id="1004640",
                             get_game_path=lambda: None,
                             get_prefix_path=lambda: None),
        profile_name="fixture", profile_dir=Path("/tmp/fftic-plan-profile"),
        staging_root=Path("/tmp/fftic-plan-staging"))
    status = SimpleNamespace(rows=(), unsupported_packages=(), ready=True,
                             verifier_attested=True, observation_sha256="fixture",
                             release=release)
    controller = FfticOrchestrator()
    controller._last_context = context
    controller._last_status = status
    binding = controller._binding(context, status, 0)
    plan = OperationPlan(OperationKind.UPDATE, "fixture", (), binding=binding,
                         release=release)
    assert controller.plan_is_current(plan)
    controller._last_status = SimpleNamespace(**dict(status.__dict__, release=None))
    assert not controller.plan_is_current(plan)


def test_transition(asset: Path):
    assert asset.stat().st_size == REVIEWED_LOADER_UPDATE.size
    assert hashlib.sha256(asset.read_bytes()).hexdigest() == REVIEWED_LOADER_UPDATE.sha256
    with tempfile.TemporaryDirectory(prefix="fftic-update-shape-") as temporary:
        root = Path(temporary)
        subprocess.run(["7z", "x", "-y", f"-o{root}", str(asset)],
                       check=True, stdout=subprocess.DEVNULL)
        validate_loader_update_tree(root)
        config = root / "ModConfig.json"
        original = config.read_bytes()
        malformed = json.loads(original)
        malformed["ModDependencies"] = []
        config.write_text(json.dumps(malformed))
        try:
            validate_loader_update_tree(root)
        except ExtractionError:
            pass
        else:
            raise AssertionError("Missing loader dependency accepted")
        config.write_bytes(original)
    fixture = Fixture("reviewed-loader-update")
    fixture.run(OperationKind.SETUP)
    before = read_receipt(fixture.inputs.receipts_root)
    validate_receipt(before.data)
    prior_generation = before.data["active_generation_identity"]["generation_id"]
    shutil.copyfile(asset, fixture.cache / REVIEWED_LOADER_UPDATE.filename)
    def acquire(_release, _cancel):
        return ReviewedCandidateSet(tuple(
            (key, fixture.cache / (REVIEWED_LOADER_UPDATE if key == "nenkai-loader"
                                   else ARTIFACTS[key]).filename)
            for key in ("reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks")))
    fixture.recompose(update_acquirer=acquire, setup_candidates=None)
    release = parse_release(metadata(), "1.7.3")
    plan = replace(fixture.plan(OperationKind.UPDATE), release=release)
    with patch.object(CHECKER, "check", return_value=(None, "offline")):
        try:
            fixture.executor.execute(plan)
        except WorkflowError:
            pass
        else:
            raise AssertionError("Unavailable release accepted")
    assert read_receipt(fixture.inputs.receipts_root).data == before.data
    with patch.object(CHECKER, "check", return_value=(release, "")):
        fixture.executor.execute(plan)
    after = read_receipt(fixture.inputs.receipts_root)
    validate_receipt(after.data)
    assert after.data["active_generation_identity"]["generation_id"] != prior_generation
    assert next(item["version"] for item in after.data["artifacts"]
                if item["artifact_id"] == "nenkai-loader") == "1.7.5"
    assert {item["artifact_id"]: item["sha256"] for item in after.data["artifacts"]
            if item["artifact_id"] != "nenkai-loader"} == {
                item["artifact_id"]: item["sha256"] for item in before.data["artifacts"]
                if item["artifact_id"] != "nenkai-loader"}
    assert after.data["generated_pac_baseline"]["transaction_id"] != before.data["generated_pac_baseline"]["transaction_id"]
    updated_receipt = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    updated_state = fixture.inputs.active_state_file.read_bytes()
    owned_bootstrap = fixture.game / "version.dll"
    original_bootstrap = owned_bootstrap.read_bytes()
    owned_bootstrap.write_bytes(b"drifted owned bootstrap")
    fixture.recompose(revert_acquirer=lambda _cancel: ReviewedCandidateSet(tuple(
        (key, fixture.cache / ARTIFACTS[key].filename)
        for key in ("reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks"))),
        process_running=lambda: False)
    try:
        fixture.run(OperationKind.REVERT_LOADER)
    except Exception as exc:
        assert "drift" in str(exc).lower() or "bootstrap" in str(exc).lower()
    else:
        raise AssertionError("Drifted owned state allowed loader reversion")
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == updated_receipt
    assert fixture.inputs.active_state_file.read_bytes() == updated_state
    assert owned_bootstrap.read_bytes() == b"drifted owned bootstrap"
    owned_bootstrap.write_bytes(original_bootstrap)
    fixture.run(OperationKind.REVERT_LOADER)
    reverted = read_receipt(fixture.inputs.receipts_root)
    validate_receipt(reverted.data)
    assert next(item["version"] for item in reverted.data["artifacts"]
                if item["artifact_id"] == "nenkai-loader") == "1.7.3"
    assert reverted.data["active_generation_identity"]["generation_id"] != after.data["active_generation_identity"]["generation_id"]
    assert reverted.data["generated_pac_baseline"]["transaction_id"] != after.data["generated_pac_baseline"]["transaction_id"]
    assert {item["artifact_id"]: item["sha256"] for item in reverted.data["artifacts"]} == {
        item["artifact_id"]: item["sha256"] for item in before.data["artifacts"]}
    receipt_bytes = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    fixture.recompose(failure_injector=lambda event, kind: (_ for _ in ()).throw(
        RuntimeError("injected receipt failure")) if event == "receipt" and
        kind == OperationKind.SYNCHRONIZE else None)
    (fixture.profile / "modlist.txt").write_text("-High\n+Low\n-Disabled\n")
    try:
        fixture.run(OperationKind.SYNCHRONIZE)
    except RuntimeError:
        pass
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_bytes
    shutil.rmtree(fixture.root)

    rollback = Fixture("reviewed-loader-update-rollback")
    rollback.run(OperationKind.SETUP)
    old_receipt = (rollback.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    old_state = rollback.inputs.active_state_file.read_bytes()
    shutil.copyfile(asset, rollback.cache / REVIEWED_LOADER_UPDATE.filename)
    def rollback_acquire(_release, _cancel):
        return ReviewedCandidateSet(tuple(
            (key, rollback.cache / (REVIEWED_LOADER_UPDATE if key == "nenkai-loader"
                                    else ARTIFACTS[key]).filename)
            for key in ("reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks")))
    def fail_receipt(event, kind):
        if event == "receipt" and kind == OperationKind.UPDATE:
            raise RuntimeError("injected update receipt failure")
    rollback.recompose(update_acquirer=rollback_acquire,
                       failure_injector=fail_receipt)
    with patch.object(CHECKER, "check", return_value=(release, "")):
        try:
            rollback.executor.execute(replace(rollback.plan(OperationKind.UPDATE),
                                              release=release))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Injected update failure reported success")
    assert (rollback.inputs.receipts_root / "fftic-receipt.json").read_bytes() == old_receipt
    assert rollback.inputs.active_state_file.read_bytes() == old_state
    shutil.rmtree(rollback.root)


def test_failed_launch_absent_pac_reversion(asset: Path):
    fixture = Fixture("failed-launch-return")
    fixture.run(OperationKind.SETUP)
    fixture.recompose(process_running=lambda: False)
    target = fixture.game / "data/enhanced/modded.pac"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"prior verified generated PAC")
    _write_matching_log(fixture, read_receipt(fixture.inputs.receipts_root), "prior.txt")
    fixture.run(OperationKind.RECONCILE_RUNTIME_OUTPUT)
    (fixture.profile / "modlist.txt").write_text("-High\n+Low\n-Disabled\n")
    fixture.run(OperationKind.SYNCHRONIZE)
    shutil.copyfile(asset, fixture.cache / REVIEWED_LOADER_UPDATE.filename)

    def candidates(pin):
        return ReviewedCandidateSet(tuple(
            (key, fixture.cache / (pin if key == "nenkai-loader" else ARTIFACTS[key]).filename)
            for key in ("reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks")))

    fixture.recompose(
        update_acquirer=lambda _release, _cancel: candidates(REVIEWED_LOADER_UPDATE),
        revert_acquirer=lambda _cancel: candidates(ARTIFACTS["nenkai-loader"]))
    release = parse_release(metadata(), "1.7.3")
    with patch.object(CHECKER, "check", return_value=(release, "")):
        fixture.executor.execute(replace(fixture.plan(OperationKind.UPDATE), release=release))
    updated = read_receipt(fixture.inputs.receipts_root)
    baseline = next(item for item in updated.data["generated_pac_baseline"]["paths"]
                    if item["relative_path"] == "data/enhanced/modded.pac")
    assert baseline["state"] == "owned exact"
    backup = Path(baseline["backup_path"])
    assert backup.read_bytes() == target.read_bytes()
    target.unlink()
    baseline_set = baseline_set_from_receipt(updated.data["generated_pac_baseline"])
    unknown_paths = tuple(
        replace(item, state=PacOwnershipState.UNKNOWN, sha256=None, backup_path=None)
        if item.relative_path == "data/enhanced/modded.pac" else item
        for item in baseline_set.paths)
    assert not exact_absent_reversion_output(
        fixture.game, replace(baseline_set, paths=unknown_paths),
        fixture.inputs.backup_root)
    assert not fixture.composition._dynamic_pac_evidence(updated)
    _, pending = fixture.composition._readiness()
    assert not pending.ready and pending.profile == ReadinessAspect.INVALID
    assert any(issue.startswith("PAC runtime output confirmation required: ")
               for issue in pending.issues)
    def absent_return_ready():
        try:
            _, observed = fixture.composition._readiness()
        except RecoveryRequiredError:
            return False
        return absent_pac_reversion_ready(
            observed, read_receipt(fixture.inputs.receipts_root), fixture.game,
            fixture.inputs.backup_root,
            fixture.composition._dynamic_pac_evidence(
                read_receipt(fixture.inputs.receipts_root)))
    assert absent_return_ready()
    try:
        fixture.composition._assert_readiness("normal launch gate")
    except WorkflowError:
        pass
    else:
        raise AssertionError("Missing PAC unexpectedly passed launch readiness")
    fixture.composition._assert_readiness(
        "narrow return gate", allow_absent_reversion=True)
    receipt_bytes = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    active_bytes = fixture.inputs.active_state_file.read_bytes()

    def blocked():
        try:
            fixture.run(OperationKind.REVERT_LOADER)
        except Exception:
            pass
        else:
            raise AssertionError("Unsafe PAC state allowed reversion")
        assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_bytes
        assert fixture.inputs.active_state_file.read_bytes() == active_bytes

    target.write_bytes(b"unrelated PAC output")
    assert not absent_return_ready()
    blocked()
    target.unlink()
    modlist = fixture.profile / "modlist.txt"
    original_modlist = modlist.read_bytes()
    modlist.write_text("-High\n-Low\n-Disabled\n")
    blocked()
    modlist.write_bytes(original_modlist)
    fixture.recompose(process_running=lambda: True)
    blocked()
    fixture.recompose(process_running=None)
    blocked()
    fixture.recompose(process_running=lambda: False)
    target.symlink_to(fixture.root / "linked-PAC")
    assert not absent_return_ready()
    blocked()
    target.unlink()
    original_backup = backup.read_bytes()
    backup.write_bytes(b"changed retained backup")
    assert not absent_return_ready()
    blocked()
    backup.write_bytes(original_backup)
    backup.unlink()
    backup.symlink_to(fixture.root / "linked-backup")
    blocked()
    backup.unlink()
    backup.write_bytes(original_backup)
    _write_matching_log(fixture, updated, "completed-after-failure.txt")
    assert not absent_return_ready()
    blocked()
    (fixture.prefix / "drive_c/users/steamuser/AppData/Roaming/"
     "Reloaded-Mod-Loader-II/Logs/completed-after-failure.txt").unlink()
    def fail_revert_receipt(event, kind):
        if event == "receipt" and kind == OperationKind.REVERT_LOADER:
            raise RuntimeError("injected reversion receipt failure")
    fixture.recompose(failure_injector=fail_revert_receipt)
    try:
        fixture.run(OperationKind.REVERT_LOADER)
    except RuntimeError as exc:
        assert "reversion receipt failure" in str(exc)
    else:
        raise AssertionError("Injected reversion failure reported success")
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_bytes
    assert fixture.inputs.active_state_file.read_bytes() == active_bytes
    assert backup.read_bytes() == original_backup and not target.exists()
    fixture.recompose(failure_injector=None)
    fixture.run(OperationKind.REVERT_LOADER)
    returned = read_receipt(fixture.inputs.receipts_root)
    assert next(item["version"] for item in returned.data["artifacts"]
                if item["artifact_id"] == "nenkai-loader") == "1.7.3"
    assert returned.data["generated_pac_baseline"]["transaction_id"] != (
        updated.data["generated_pac_baseline"]["transaction_id"])
    assert not target.exists()
    shutil.rmtree(fixture.root)


if __name__ == "__main__":
    test_metadata()
    test_check_cache()
    test_notice_once_per_release()
    test_proton_labels_and_setup_actions()
    test_release_bound_plan_staleness()
    if os.environ.get("FFTIC_REVIEWED_LOADER_ASSET"):
        test_transition(Path(os.environ["FFTIC_REVIEWED_LOADER_ASSET"]))
        test_failed_launch_absent_pac_reversion(Path(os.environ["FFTIC_REVIEWED_LOADER_ASSET"]))
    print("FFTIC loader release checks passed")
