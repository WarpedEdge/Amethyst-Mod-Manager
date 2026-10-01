"""Hermetic checks for FFTIC production composition and action wiring."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

from fftic_artifacts import ARTIFACTS
from fftic_detection import VERIFIED_STEAM_BUILD
from fftic_orchestration import (
    FFTIC_GAME_ID, FfticOrchestrator, FfticStatusViewModel, InspectionContext,
    InspectionResult, OperationKind, StatusRow, StatusSeverity,
    _PREREQUISITE_RUNNER_BLOCKER, _action_availability,
)
from fftic_production import create_production_executor
from fftic_steam_requirements import COPY_READY_OPTIONS


class Fixture:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="amethyst-fftic-c3d-")).resolve()
        self.library = self.root / "library"
        self.game_root = self.library / "steamapps/common/FFTIC"
        self.prefix = self.root / "prefix"
        self.profile = self.root / "profiles/default"
        self.staging = self.root / "staging"
        self.download_root = self.root / "download-cache"
        for path in (
                self.game_root, self.prefix / "drive_c", self.prefix / "dosdevices",
                self.profile, self.staging):
            path.mkdir(parents=True, exist_ok=True)
        for name in ("FFT_classic.exe", "FFT_enhanced.exe"):
            (self.game_root / name).write_bytes(b"isolated-c3d-executable")
        self.manifest = self.library / "steamapps/appmanifest_1004640.acf"
        self.manifest.write_text(
            '"AppState"\n{\n"appid" "1004640"\n"installdir" "FFTIC"\n'
            f'"buildid" "{VERIFIED_STEAM_BUILD}"\n}}\n', encoding="utf-8")
        (self.prefix / "dosdevices/s:").symlink_to(
            self.library, target_is_directory=True)
        (self.profile / "modlist.txt").write_text("", encoding="utf-8")
        self.game = SimpleNamespace(
            game_id=FFTIC_GAME_ID,
            name="FFTIC fixture",
            steam_id="1004640",
            get_game_path=lambda: self.game_root,
            get_prefix_path=lambda: self.prefix,
        )
        self.cache = self.download_root / self.game.name / "fftic-reviewed"
        self.context = InspectionContext(
            self.game, "default", self.profile, self.staging)


def _row(key: str, state: str = "Ready") -> StatusRow:
    return StatusRow(key, key, state, StatusSeverity.READY, state)


def _inventory(*roots: Path) -> tuple[tuple[str, str, bytes | str], ...]:
    records = []
    for root in roots:
        if not os.path.lexists(root):
            records.append((str(root), "absent", ""))
            continue
        for path in (root, *sorted(root.rglob("*"), key=str)):
            if path.is_symlink():
                records.append((str(path), "symlink", os.readlink(path)))
            elif path.is_file():
                records.append((str(path), "file", path.read_bytes()))
            elif path.is_dir():
                records.append((str(path), "directory", ""))
            else:
                records.append((str(path), "special", ""))
    return tuple(records)


def test_composition_derives_owned_paths_and_delays_acquisition() -> None:
    fixture = Fixture()
    calls = []
    xdg = fixture.root / "xdg"
    config = xdg / "AmethystModManager"
    config.mkdir(parents=True)
    (config / "amethyst.ini").write_text(
        "[paths]\n"
        f"download_cache_path = {fixture.download_root}\n", encoding="utf-8")

    def acquire(pin, cache, **kwargs):
        calls.append((pin, Path(cache), kwargs))
        path = Path(cache) / pin.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fake downloader output")
        return SimpleNamespace(path=path)

    managed_parent = fixture.prefix / "drive_c/Amethyst"
    before = _inventory(fixture.download_root, fixture.prefix / "drive_c")
    previous_xdg = os.environ.get("XDG_CONFIG_HOME")
    os.environ["XDG_CONFIG_HOME"] = str(xdg)
    try:
        executor, reason = create_production_executor(
            fixture.context, lambda _plan: True, artifact_acquire=acquire)
    finally:
        if previous_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = previous_xdg
    assert executor is not None, reason
    assert calls == []
    assert _inventory(fixture.download_root, fixture.prefix / "drive_c") == before
    assert not fixture.cache.exists()
    assert not managed_parent.exists()
    inputs = executor._operations.inputs
    managed = fixture.prefix / "drive_c/Amethyst/FFTIC"
    assert inputs.generations_root == managed / "generations"
    assert inputs.backup_root == managed / "backups"
    assert inputs.quarantine_root == managed / "quarantine"
    assert inputs.receipts_root == managed / "receipts"
    assert inputs.journal_file == managed / "journal/lifecycle.json"
    assert inputs.log_root == managed / "logs"
    assert inputs.process_runner is None
    assert inputs.setup_candidates is None
    candidates = inputs.artifact_acquirer(None)
    runtime_pins = {
        artifact_id: pin for artifact_id, pin in ARTIFACTS.items()
        if pin.disposition.value == "extract"
    }
    assert set(candidates.paths()) == set(runtime_pins)
    assert [call[0] for call in calls] == list(runtime_pins.values())
    assert all(call[1] == fixture.cache for call in calls)
    assert all(call[2]["quarantine_root"] == inputs.artifact_cache / "quarantine"
               for call in calls)


def test_invalid_composition_keeps_read_only_status() -> None:
    fixture = Fixture()
    fixture.game.get_prefix_path = lambda: None

    class Inspector:
        def inspect(self, _context, cancel=None, progress=None):
            return InspectionResult(
                (_row("recovery"),), (), (), COPY_READY_OPTIONS, (), False, False,
                available_actions=(OperationKind.SETUP.value,))

    controller = FfticOrchestrator(
        Inspector(), executor_factory=create_production_executor)
    model = controller.refresh(fixture.context)
    assert not controller.mutation_available
    assert "Select a FFTIC Proton prefix" in model.mutation_unavailable_reason
    assert model.rows[0].key == "recovery"


def test_action_gating_and_prerequisite_blocker() -> None:
    setup_rows = tuple(_row(key, "Configured" if key == "steam_options" else "Ready")
                       for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                                   "steam_options", "recovery")) + (
        *tuple(_row(key, "Not installed") for key in (
            "runtime", "nenkai", "sigscan", "hooks")),
        _row("bootstrap", "Not installed"),
        _row("prefix_config", "Not installed"),
    )
    actions, reasons = _action_availability(
        setup_rows, receipt_present=False, verification=None, unsupported=())
    assert actions == (OperationKind.SETUP.value,)
    assert OperationKind.UPDATE.value not in actions
    assert "distinct reviewed artifact identity" in dict(reasons)["update"]

    missing = tuple(
        _row(row.key, "Not installed") if row.key == "dotnet" else row
        for row in setup_rows)
    actions, reasons = _action_availability(
        missing, receipt_present=False, verification=None, unsupported=())
    assert OperationKind.SETUP.value not in actions
    assert dict(reasons)["setup"] == _PREREQUISITE_RUNNER_BLOCKER


def test_repair_gating_covers_every_managed_component() -> None:
    foundation = tuple(
        _row(key, "Configured" if key == "steam_options" else "Ready")
        for key in ("game", "steam_prefix", "runner", "dotnet", "vc",
                    "steam_options", "recovery", "profile"))
    managed_keys = (
        "runtime", "nenkai", "sigscan", "hooks", "bootstrap", "prefix_config")
    for missing_key in managed_keys:
        managed = tuple(_row(
            key, "Not installed" if key == missing_key else "Ready")
            for key in managed_keys)
        actions, _reasons = _action_availability(
            foundation + managed, receipt_present=True,
            verification=None, unsupported=())
        assert OperationKind.REPAIR.value in actions, missing_key


def test_panel_enables_only_current_actions() -> None:
    from PySide6.QtWidgets import QApplication
    from gui_qt.fftic_status import FfticStatusPanel

    app = QApplication.instance() or QApplication([])
    panel = FfticStatusPanel()
    reasons = tuple((kind.value, f"blocked {kind.value}") for kind in OperationKind)
    panel.set_status(FfticStatusViewModel(
        FFTIC_GAME_ID, "FFTIC", (_row("recovery"),), (), (),
        COPY_READY_OPTIONS, (), False, False, True, "", "Launch from Steam",
        available_actions=("setup",), action_unavailable_reasons=reasons))
    assert panel._action_buttons["setup"].isEnabled()
    assert not panel._action_buttons["repair"].isEnabled()
    assert not panel._action_buttons["synchronize"].isEnabled()
    assert not panel._action_buttons["update"].isEnabled()
    assert not panel._action_buttons["remove"].isEnabled()
    assert "blocked update" in panel._action_buttons["update"].toolTip()
    panel.set_operation(True)
    assert not any(button.isEnabled() for button in panel._action_buttons.values())
    panel.set_operation(False)
    assert panel._action_buttons["setup"].isEnabled()
    panel.close()
    app.processEvents()


def main() -> None:
    tests = (
        test_composition_derives_owned_paths_and_delays_acquisition,
        test_invalid_composition_keeps_read_only_status,
        test_action_gating_and_prerequisite_blocker,
        test_repair_gating_covers_every_managed_component,
        test_panel_enables_only_current_actions,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC Phase C3D production-composition checks passed.")


if __name__ == "__main__":
    main()
