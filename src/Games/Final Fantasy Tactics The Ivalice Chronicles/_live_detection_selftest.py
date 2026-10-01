"""Focused checks for the corrected FFTIC live identities and app title."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_SRC = Path(__file__).resolve().parents[2]
_HERE = Path(__file__).resolve().parent
for _path in (_SRC, _HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from fftic_detection import (  # noqa: E402
    EXECUTABLES, VERIFIED_HASHES, VERIFIED_STEAM_BUILD, VERIFIED_UI_VERSION,
    InstallStatus, detect_installation,
)
from fftic_proton import resolve_proton_selection  # noqa: E402
from fftic_readiness import SUPPORTED_PROTON_RUNNER  # noqa: E402
from fftic_workflows import FfticLifecycleComposition, WorkflowError  # noqa: E402


class Hashes:
    def __init__(self, values=None):
        self.values = dict(VERIFIED_HASHES if values is None else values)

    def sha256(self, path: Path) -> str:
        mode = "classic" if "classic" in path.name.casefold() else "enhanced"
        return self.values[mode]


def test_exact_game_tuple_ignores_pe_placeholder() -> None:
    with tempfile.TemporaryDirectory(prefix="fftic-detection-") as temp:
        game = Path(temp)
        for name in EXECUTABLES.values():
            (game / name).write_bytes(b"fixture")
        exact = detect_installation(
            game, steam_build=VERIFIED_STEAM_BUILD, pe_version="v1.0.0",
            hash_cache=Hashes())
        assert exact.status == InstallStatus.EXACT_VERIFIED
        assert exact.pe_version == "v1.0.0"
        assert exact.runtime_proof_ui_version == VERIFIED_UI_VERSION

        changed_build = detect_installation(
            game, steam_build="24304445", pe_version="v1.0.0",
            hash_cache=Hashes())
        assert changed_build.status == InstallStatus.UNVERIFIED
        for mode in EXECUTABLES:
            changed = dict(VERIFIED_HASHES)
            changed[mode] = "0" * 64
            result = detect_installation(
                game, steam_build=VERIFIED_STEAM_BUILD, pe_version="v1.0.0",
                hash_cache=Hashes(changed))
            assert result.status == InstallStatus.UNVERIFIED, mode
            assert result.runtime_proof_ui_version is None


def _tool(root: Path, identity: str) -> Path:
    root.mkdir(parents=True)
    script = root / "proton"
    script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (root / "version").write_text(f"1234567890 {identity}\n", encoding="utf-8")
    return script


def test_selected_proton_tool_and_prefix_runtime_are_distinct() -> None:
    with tempfile.TemporaryDirectory(prefix="fftic-proton-") as temp:
        root = Path(temp)
        prefix = root / "compatdata/1004640/pfx"
        (prefix / "drive_c").mkdir(parents=True)
        (prefix.parent / "version").write_text("11.0-100\n", encoding="utf-8")
        experimental = _tool(root / "Proton - Experimental", SUPPORTED_PROTON_RUNNER)
        proton_9 = _tool(root / "Proton 9.0 (Beta)", "proton-9.0-4f")

        with patch("Utils.launchers.steam.find_proton_for_game",
                   return_value=experimental):
            selected = resolve_proton_selection("1004640", prefix)
        assert selected.tool_identity == SUPPORTED_PROTON_RUNNER
        assert selected.prefix_runtime == "11.0-100"
        assert selected.prefix_runtime != selected.tool_identity

        with patch("Utils.launchers.steam.find_proton_for_game", return_value=proton_9):
            unsupported = resolve_proton_selection("1004640", prefix)
        assert unsupported.tool_identity == "proton-9.0-4f"
        assert unsupported.tool_identity != SUPPORTED_PROTON_RUNNER

        unknown_tool = _tool(root / "Unknown Proton", "unknown-build")
        with patch("Utils.launchers.steam.find_proton_for_game",
                   return_value=unknown_tool):
            unknown = resolve_proton_selection("1004640", prefix)
        assert unknown.tool_identity == "unknown-build"
        assert unknown.tool_identity != SUPPORTED_PROTON_RUNNER

        with patch("Utils.launchers.steam.find_proton_for_game", return_value=None):
            missing = resolve_proton_selection("1004640", prefix)
        assert missing.tool_identity == ""

        def workflow_runner(identity: str) -> str:
            composition = SimpleNamespace(inputs=SimpleNamespace(
                runner_reader=lambda: identity))
            return FfticLifecycleComposition._current_runner(composition)

        assert workflow_runner(selected.tool_identity) == SUPPORTED_PROTON_RUNNER
        for identity in (unsupported.tool_identity, unknown.tool_identity, ""):
            try:
                workflow_runner(identity)
            except WorkflowError:
                pass
            else:
                raise AssertionError(f"unsupported runner passed: {identity!r}")


def test_status_and_production_share_runner_resolver() -> None:
    import fftic_orchestration
    import fftic_production

    assert (fftic_orchestration.resolve_proton_selection is
            fftic_production.resolve_proton_selection is
            resolve_proton_selection)


def test_stable_and_fftic_titles_use_display_identity() -> None:
    import Utils.app_identity as identity

    with patch.object(identity, "DISPLAY_NAME", "Amethyst Mod Manager"):
        assert identity.main_window_title("2.5.2") == "Amethyst Mod Manager - v2.5.2"
    with patch.object(identity, "DISPLAY_NAME", "Amethyst FFTIC Mod Manager"):
        assert identity.main_window_title("2.5.2") == (
            "Amethyst FFTIC Mod Manager - v2.5.2")


def main() -> None:
    tests = (
        test_exact_game_tuple_ignores_pe_placeholder,
        test_selected_proton_tool_and_prefix_runtime_are_distinct,
        test_status_and_production_share_runner_resolver,
        test_stable_and_fftic_titles_use_display_identity,
    )
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All focused FFTIC live-detection correction checks passed.")


if __name__ == "__main__":
    main()
