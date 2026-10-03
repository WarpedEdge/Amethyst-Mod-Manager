"""Isolated Steam Proton Experimental transition and receipt boundary checks."""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from _c3c_selftest import Fixture, _owned_state, _write_matching_log
from fftic_orchestration import FfticOrchestrator, InspectionContext, OperationKind
from fftic_proton import _selected_tool_identity, supported_runner
from fftic_readiness import ReadinessAspect
from fftic_receipts import read_receipt, validate_receipt
from fftic_pac import baseline_set_from_receipt, inspect_matching_launch_log
from fftic_managed_executor import ManagedOperationError


SEPTEMBER = "experimental-11.0-20260924-x86_64"
OCTOBER = "experimental-11.0-20261001-x86_64"


def test_selected_tool_policy() -> None:
    with tempfile.TemporaryDirectory(prefix="fftic-tool-policy-") as temporary:
        root = Path(temporary)
        script = root / "steamapps/common/Proton - Experimental/proton"
        script.parent.mkdir(parents=True)
        script.write_text("fixture", encoding="utf-8")
        (root / "steamapps/appmanifest_1493710.acf").write_text(
            '"AppState"\n{\n"appid" "1493710"\n'
            '"installdir" "Proton - Experimental"\n}\n',
            encoding="utf-8")
        version = script.parent / "version"
        for identity in (SEPTEMBER, OCTOBER, "experimental-11.0-20270101-x86_64"):
            version.write_text(f"1 {identity}\n", encoding="utf-8")
            assert _selected_tool_identity(script) == identity
            assert supported_runner(identity, script)
        for identity in ("experimental-11.0-20260923-x86_64",
                         "experimental-12.0-20261001-x86_64",
                         "proton-10.0", "GE-Proton11-1", "", "garbage"):
            version.write_text(f"1 {identity}\n", encoding="utf-8")
            assert not supported_runner(identity, script)
        version.write_text("broken\nsecond line\n", encoding="utf-8")
        assert _selected_tool_identity(script) == ""
        assert not supported_runner(OCTOBER, script)
        version.unlink()
        assert not supported_runner(OCTOBER, script)
        version.write_text(f"1 {OCTOBER}\n", encoding="utf-8")
        manifest = root / "steamapps/appmanifest_1493710.acf"
        manifest.write_text('"AppState"\n{\n"appid" "1493710"\n'
                            '"installdir" "Custom Proton"\n}\n',
                            encoding="utf-8")
        assert not supported_runner(OCTOBER, script)
        manifest.write_text('"AppState"\n{\n"appid" "1493710"\n'
                            '"installdir" "Proton - Experimental"\n',
                            encoding="utf-8")
        assert not supported_runner(OCTOBER, script)
        manifest.unlink()
        assert not supported_runner(OCTOBER, script)
        custom = root / "compatibilitytools.d/Proton - Experimental/proton"
        custom.parent.mkdir(parents=True)
        custom.write_text("fixture", encoding="utf-8")
        (custom.parent / "version").write_text(f"1 {OCTOBER}\n", encoding="utf-8")
        assert not supported_runner(OCTOBER, custom)


def test_september_receipt_transitions_only_by_synchronization() -> None:
    fixture = Fixture("runner-transition")
    selected = [SEPTEMBER]
    fixture.recompose(runner_reader=lambda: selected[0])
    fixture.run(OperationKind.SETUP)
    old_bytes = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    old = read_receipt(fixture.inputs.receipts_root)
    assert old is not None
    selected[0] = OCTOBER
    installation, verification = fixture.composition._readiness(
        allow_runner_transition=True)
    assert verification.prefix == ReadinessAspect.READY
    assert verification.runner == ReadinessAspect.INVALID
    assert any("synchronize" in issue for issue in verification.issues)
    stale_plan = replace(fixture.plan(OperationKind.SYNCHRONIZE), binding=replace(
        fixture.plan(OperationKind.SYNCHRONIZE).binding, runner_identity=SEPTEMBER))
    try:
        fixture.executor.execute(stale_plan)
    except Exception as exc:
        assert "runner changed" in str(exc).lower()
    else:
        raise AssertionError("Stale September operation plan ran under October")
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == old_bytes
    fixture.run(OperationKind.SYNCHRONIZE)
    new = read_receipt(fixture.inputs.receipts_root)
    assert new is not None
    assert new.data["prefix_identity"]["runner_identity"] == OCTOBER
    assert new.data["compatibility_tuple"]["proton_runner"] == OCTOBER
    assert new.data["runner_history"][-1] == {
        "transaction_id": old.transaction_id,
        "from_runner": SEPTEMBER,
        "to_runner": OCTOBER,
        "prior_receipt_sha256": hashlib.sha256(old_bytes).hexdigest(),
    }
    assert new.data["generated_pac_baseline"]["compatibility_fingerprint"] != \
        old.data["generated_pac_baseline"]["compatibility_fingerprint"]
    assert validate_receipt(old.data) and validate_receipt(new.data)
    assert fixture.composition._readiness()[1].runner == ReadinessAspect.READY


def test_prior_owned_pac_log_and_rollback_transition() -> None:
    fixture = Fixture("runner-owned-pac")
    selected = [SEPTEMBER]
    fixture.recompose(runner_reader=lambda: selected[0], process_running=lambda: False)
    fixture.run(OperationKind.SETUP)
    target = fixture.game / "data/enhanced/modded.pac"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"September owned output")
    original = read_receipt(fixture.inputs.receipts_root)
    _write_matching_log(fixture, original, "september.txt")
    fixture.run(OperationKind.RECONCILE_RUNTIME_OUTPUT)
    before = _owned_state(fixture)
    selected[0] = OCTOBER
    fixture.recompose(failure_injector=lambda name, kind: (
        (_ for _ in ()).throw(RuntimeError("injected runner receipt failure"))
        if name == "receipt" and kind == OperationKind.SYNCHRONIZE else None))
    try:
        fixture.run(OperationKind.SYNCHRONIZE)
    except RuntimeError as exc:
        assert "injected runner receipt failure" in str(exc)
    else:
        raise AssertionError("Injected runner transition succeeded")
    assert _owned_state(fixture) == before
    assert target.read_bytes() == b"September owned output"
    fixture.recompose(failure_injector=None)
    fixture.run(OperationKind.SYNCHRONIZE)
    updated = read_receipt(fixture.inputs.receipts_root)
    assert updated is not None
    baseline = baseline_set_from_receipt(updated.data["generated_pac_baseline"])
    owned = next(item for item in baseline.paths
                 if item.relative_path == "data/enhanced/modded.pac")
    assert owned.state.value == "owned exact"
    assert Path(owned.backup_path).read_bytes() == b"September owned output"
    logs = fixture.prefix / "drive_c/users/steamuser/AppData/Roaming/Reloaded-Mod-Loader-II/Logs"
    identities = tuple(item["mod_id"] for item in updated.data["managed_packages"])
    identities += tuple(item["mod_id"] for item in updated.data["user_packages"]
                        if item["enabled"])
    assert inspect_matching_launch_log(logs, baseline=baseline,
                                       required_mod_ids=identities) is None
    fixture.run(OperationKind.REMOVE)
    assert read_receipt(fixture.inputs.receipts_root) is None
    assert not target.exists()


def test_changed_prefix_and_stale_installer_plan() -> None:
    fixture = Fixture("runner-prefix-change")
    fixture.run(OperationKind.SETUP)
    receipt_bytes = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    different = fixture.root / "different-prefix"
    (different / "drive_c").mkdir(parents=True)
    (different / "dosdevices").mkdir()
    (different / "dosdevices/s:").symlink_to(fixture.library, target_is_directory=True)
    fixture.recompose(prefix=different, runner_reader=lambda: OCTOBER)
    try:
        plan = fixture.plan(OperationKind.SYNCHRONIZE)
        fixture.executor.execute(replace(plan, binding=replace(plan.binding,
                                                               prefix=str(different))))
    except Exception as exc:
        assert any(word in str(exc).lower() for word in ("prefix", "receipt", "binding"))
    else:
        raise AssertionError("Changed prefix was mistaken for runner transition")
    assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == receipt_bytes

    from unittest.mock import patch
    from _prerequisite_production_selftest import _request
    request = _request()
    with patch("fftic_managed_executor.validate_file", return_value=True):
        request.validate()
        (request.runner.parent / "version").write_text(f"1 {OCTOBER}\n", encoding="utf-8")
        try:
            request.validate()
        except ManagedOperationError as exc:
            assert "changed" in str(exc).lower() or "policy" in str(exc).lower()
        else:
            raise AssertionError("September installer plan accepted October tool")


def test_operation_binding_keeps_exact_selected_script() -> None:
    fixture = Fixture("runner-binding")
    game = SimpleNamespace(game_id="final_fantasy_tactics_the_ivalice_chronicles",
                           steam_id="1004640", get_game_path=lambda: fixture.game,
                           get_prefix_path=lambda: fixture.prefix)
    context = InspectionContext(game, "default", fixture.profile, fixture.staging)
    status = SimpleNamespace(rows=(), unsupported_packages=(), ready=False,
                             verifier_attested=False, observation_sha256="fixture")
    first = SimpleNamespace(proton_script=fixture.root / "steam-a/proton",
                            tool_identity=OCTOBER, prefix_runtime="11.0-100")
    second = SimpleNamespace(proton_script=fixture.root / "steam-b/proton",
                             tool_identity=OCTOBER, prefix_runtime="11.0-100")
    with patch("fftic_orchestration.resolve_proton_selection", return_value=first):
        original = FfticOrchestrator._binding(context, status, 1)
    with patch("fftic_orchestration.resolve_proton_selection", return_value=second):
        changed = FfticOrchestrator._binding(context, status, 1)
    assert original.runner_identity == changed.runner_identity == OCTOBER
    assert original.runner_script != changed.runner_script
    assert original != changed


def test_runner_change_blocks_repair_and_reconciliation_but_allows_exact_removal() -> None:
    fixture = Fixture("runner-operation-boundaries")
    selected = [SEPTEMBER]
    fixture.recompose(runner_reader=lambda: selected[0], process_running=lambda: False)
    fixture.run(OperationKind.SETUP)
    before = (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes()
    selected[0] = OCTOBER
    for kind in (OperationKind.REPAIR, OperationKind.RECONCILE_RUNTIME_OUTPUT):
        try:
            fixture.run(kind)
        except Exception as exc:
            assert "runner changed" in str(exc).lower()
        else:
            raise AssertionError(f"{kind.value} accepted an old runner receipt")
        assert (fixture.inputs.receipts_root / "fftic-receipt.json").read_bytes() == before
    fixture.run(OperationKind.REMOVE)
    assert read_receipt(fixture.inputs.receipts_root) is None


if __name__ == "__main__":
    test_selected_tool_policy()
    test_september_receipt_transitions_only_by_synchronization()
    test_prior_owned_pac_log_and_rollback_transition()
    test_changed_prefix_and_stale_installer_plan()
    test_operation_binding_keeps_exact_selected_script()
    test_runner_change_blocks_repair_and_reconciliation_but_allows_exact_removal()
    print("All isolated Proton policy checks passed.")
