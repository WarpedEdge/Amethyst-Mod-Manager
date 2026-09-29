"""Focused Phase C1 checks for the non-mutating FFTIC foundation.

Run from the source tree:

    python3 'src/Games/Final Fantasy Tactics The Ivalice Chronicles/_selftest.py'
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

_SANDBOX = tempfile.TemporaryDirectory(prefix="amethyst-fftic-selftest-")
_ROOT = Path(_SANDBOX.name)
for _name in ("config", "data", "cache", "profiles"):
    (_ROOT / _name).mkdir()
os.environ["XDG_CONFIG_HOME"] = str(_ROOT / "config")
os.environ["XDG_DATA_HOME"] = str(_ROOT / "data")
os.environ["XDG_CACHE_HOME"] = str(_ROOT / "cache")
os.environ["MOD_MANAGER_PROFILES_DIR"] = str(_ROOT / "profiles")

_SRC = Path(__file__).resolve().parents[2]
_HERE = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_HERE) not in sys.path:
    sys.path.append(str(_HERE))

_GENERIC_MODULE_NAMES = ("packages", "detection", "transactions")
_GENERIC_MODULE_PREVIOUS = {
    name: sys.modules.get(name) for name in _GENERIC_MODULE_NAMES
}
_GENERIC_MODULE_SENTINELS = {}
for _name in _GENERIC_MODULE_NAMES:
    _module = ModuleType(_name)
    _module.fftic_collision_sentinel = True
    sys.modules[_name] = _module
    _GENERIC_MODULE_SENTINELS[_name] = _module

from fftic_artifacts import (  # noqa: E402
    ARTIFACTS, INTERNAL_FILES, ArtifactDisposition, InternalFilePin,
    validate_bytes, validate_sha256, validate_size,
)
from fftic_detection import (  # noqa: E402
    EXECUTABLES, VERIFIED_HASHES, VERIFIED_STEAM_BUILD,
    InstallStatus, detect_installation,
)
from final_fantasy_tactics import (  # noqa: E402
    FinalFantasyTacticsTheIvaliceChronicles,
)
from fftic_packages import (  # noqa: E402
    CLASSIC_APP_ID, COMPILED_RUNTIME_EXTENSIONS, ENHANCED_APP_ID,
    PackageClassification, inspect_package,
)
from fftic_reloaded_config import (  # noqa: E402
    MANAGED_ORDER, Mode, UserMod, ValidatedSteamPath,
    generate_reloaded_configuration,
)
from fftic_steam_requirements import (  # noqa: E402
    COPY_READY_OPTIONS, SteamOptionsStatus, analyze_steam_launch_options,
)
from fftic_transactions import (  # noqa: E402
    OperationKind, TargetObservation, plan_owned_file_install,
    plan_shared_prerequisite_retention,
)


def _manifest(*, mod_id="author.mod", apps=None, code=False, deps=None,
              optional=None) -> dict:
    return {
        "ModId": mod_id,
        "ModName": "Synthetic Mod",
        "ModAuthor": "Self Test",
        "ModVersion": "1.0",
        "ModDependencies": deps or ["fftivc.utility.modloader"],
        "OptionalDependencies": optional or [],
        "SupportedAppId": apps or [ENHANCED_APP_ID],
        "ModDll": "Code.dll" if code else "",
        "ModR2RManagedDll32": "",
        "ModR2RManagedDll64": "",
        "ModNativeDll32": "",
        "ModNativeDll64": "",
    }


def _package(root: Path, manifest: dict, payload="FFTIVC/data/enhanced/test.nxd") -> Path:
    root.mkdir(parents=True)
    (root / "ModConfig.json").write_text(json.dumps(manifest), encoding="utf-8")
    if payload:
        target = root / payload
        target.parent.mkdir(parents=True)
        target.write_bytes(b"fixture")
    return root


class _KnownHashCache:
    def sha256(self, path: Path) -> str:
        mode = "classic" if "classic" in path.name.casefold() else "enhanced"
        return VERIFIED_HASHES[mode]


def test_collision_safe_discovery_imports() -> None:
    for name, sentinel in _GENERIC_MODULE_SENTINELS.items():
        assert sys.modules[name] is sentinel
    try:
        from Utils.games.discovery import discover_games, get_load_failures
        games = discover_games()
        assert "Final Fantasy Tactics: The Ivalice Chronicles" in games
        fftic_failures = [
            failure for failure in get_load_failures()
            if "Final Fantasy Tactics The Ivalice Chronicles" in failure[0]
        ]
        assert not fftic_failures, fftic_failures
    finally:
        for name, previous in _GENERIC_MODULE_PREVIOUS.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def test_identity_detection_and_cache_contract() -> None:
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    assert handler.name == "Final Fantasy Tactics: The Ivalice Chronicles"
    assert handler.steam_id == "1004640"
    assert handler.exe_name == "FFT_enhanced.exe"
    assert handler.exe_name_alts == ["FFT_classic.exe"]

    assert detect_installation(None).status == InstallStatus.NOT_FOUND
    game = _ROOT / "fake-game"
    game.mkdir()
    (game / EXECUTABLES["classic"]).write_bytes(b"classic")
    assert detect_installation(game).status == InstallStatus.INCOMPLETE
    (game / EXECUTABLES["enhanced"]).write_bytes(b"enhanced")
    exact = detect_installation(
        game, steam_build=VERIFIED_STEAM_BUILD,
        ui_version="v1.5.2", hash_cache=_KnownHashCache())
    assert exact.status == InstallStatus.EXACT_VERIFIED
    unknown = detect_installation(game, steam_build=VERIFIED_STEAM_BUILD)
    assert unknown.status == InstallStatus.UNVERIFIED

    # Registration uses the repository's Steam-library and owning-prefix
    # mechanisms, including a library outside Steam's default root.
    steamapps = _ROOT / "second-library" / "steamapps"
    installed_root = steamapps / "common" / "FFTIC"
    installed_root.mkdir(parents=True)
    for name in EXECUTABLES.values():
        (installed_root / name).write_bytes(b"exe")
    (steamapps / "appmanifest_1004640.acf").write_text(
        '"AppState"\n{\n\t"appid" "1004640"\n\t"installdir" "FFTIC"\n}\n',
        encoding="utf-8")
    prefix = steamapps / "compatdata" / "1004640" / "pfx"
    (prefix / "drive_c").mkdir(parents=True)
    from Utils.launchers.installed import InstalledIndex
    with patch("Utils.launchers.installed.find_steam_libraries",
               return_value=[steamapps / "common"]):
        assert InstalledIndex().game_installed(handler)
    from Utils.launchers.steam import find_prefix
    assert find_prefix("1004640", installed_root) == prefix


def test_package_recognition() -> None:
    packages = _ROOT / "packages"
    enhanced = inspect_package(_package(packages / "enhanced", _manifest()))
    assert enhanced.classification == PackageClassification.ENHANCED_CONTENT
    assert enhanced.manifest.dependencies == ("fftivc.utility.modloader",)
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    assert handler.validate_mod_package(packages / "enhanced") == []

    classic = inspect_package(_package(
        packages / "classic", _manifest(apps=[CLASSIC_APP_ID]),
        "FFTIVC/tables/classic/Test.xml"))
    assert classic.classification == PackageClassification.CLASSIC_CONTENT
    dual = inspect_package(_package(
        packages / "dual", _manifest(
            apps=[CLASSIC_APP_ID, ENHANCED_APP_ID], optional=["author.optional"]),
        "FFTIVC/data/combined/test.nxd"))
    assert dual.classification == PackageClassification.DUAL_MODE_CONTENT
    assert dual.manifest.optional_dependencies == ("author.optional",)

    unsupported = inspect_package(_package(
        packages / "other", _manifest(apps=["other.exe"])))
    assert unsupported.classification == PackageClassification.UNSUPPORTED_APPLICATION
    compiled = inspect_package(_package(
        packages / "compiled", _manifest(code=True)))
    assert compiled.classification == PackageClassification.UNSUPPORTED_CODE
    assert handler.validate_mod_package(packages / "compiled")
    from Utils.mods.install import _validate_prepared_package
    install_log: list[str] = []
    prepared = SimpleNamespace(
        game=SimpleNamespace(validate_mod_package=Mock(
            return_value=handler.validate_mod_package(packages / "compiled"))),
        src_root=packages / "compiled",
    )
    assert not _validate_prepared_package(prepared, install_log.append)
    assert any("Compiled/runtime code" in line for line in install_log)
    invalid_id = inspect_package(_package(
        packages / "invalid-id", _manifest(mod_id="../escape")))
    assert invalid_id.classification == PackageClassification.MALFORMED
    malformed = packages / "bad-json"
    malformed.mkdir()
    (malformed / "ModConfig.json").write_text("{", encoding="utf-8")
    assert inspect_package(malformed).classification == PackageClassification.MALFORMED
    missing_id_data = _manifest()
    missing_id_data["ModId"] = ""
    assert inspect_package(_package(packages / "missing-id", missing_id_data)).classification \
        == PackageClassification.MALFORMED

    unsafe = _package(packages / "unsafe", _manifest())
    (unsafe / "FFTIVC" / "link").symlink_to(_ROOT / "outside")
    unsafe_result = inspect_package(unsafe)
    assert unsafe_result.classification == PackageClassification.MALFORMED
    assert any("Unsafe package path" in value for value in unsafe_result.diagnostics)

    managed_ids = (
        "FFTIVC.UTILITY.MODLOADER",
        "reLOADED.sharedLIB.HOOKS",
        "RELOADED.MEMORY.SIGSCAN.RELOADEDII",
    )
    for index, managed_id in enumerate(managed_ids):
        managed = inspect_package(_package(
            packages / f"managed-{index}", _manifest(mod_id=managed_id)))
        assert managed.classification == PackageClassification.MANAGED_INTERNAL
        assert managed_id in managed.diagnostics[0]

    for extension in sorted(COMPILED_RUNTIME_EXTENSIONS):
        root = _package(packages / f"runtime-{extension[1:]}", _manifest())
        runtime_file = root / "unrelated" / f"payload{extension.upper()}"
        runtime_file.parent.mkdir()
        runtime_file.write_bytes(b"not executed")
        runtime = inspect_package(root)
        assert runtime.classification == PackageClassification.UNSUPPORTED_CODE
        assert runtime_file.relative_to(root).as_posix() in runtime.diagnostics[0]

    fixture = Path(
        "/var/mnt/game_drive/github/Amethyst-Mod-Manager-Documents/"
        "Heretic Ramza 39 0.9 2026-07-24T14-53Z SuhvGfXLk")
    if fixture.is_dir():
        before = {p.relative_to(fixture).as_posix(): p.stat().st_mtime_ns
                  for p in fixture.rglob("*")}
        result = inspect_package(fixture)
        assert result.classification == PackageClassification.ENHANCED_CONTENT
        assert result.manifest.mod_id == "fftivc.jobs.hereticramza"
        after = {p.relative_to(fixture).as_posix(): p.stat().st_mtime_ns
                 for p in fixture.rglob("*")}
        assert before == after


def test_artifact_manifest() -> None:
    assert set(ARTIFACTS) == {
        "reloaded-ii", "nenkai-loader", "sigscan", "shared-hooks",
        "dotnet-desktop-runtime", "vc-runtime",
    }
    assert all(len(pin.sha256) == 64 and pin.size > 0 and pin.url.startswith("https://")
               for pin in ARTIFACTS.values())
    assert ARTIFACTS["dotnet-desktop-runtime"].disposition == ArtifactDisposition.EXECUTE
    assert ARTIFACTS["dotnet-desktop-runtime"].requires_separate_transaction
    assert INTERNAL_FILES["version-dll"].sha256.startswith("22fda9c7")
    synthetic = InternalFilePin(
        "test", "test", "source", "target", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "test", "test")
    assert validate_size(synthetic, 3)
    assert validate_sha256(synthetic, synthetic.sha256.upper())
    assert validate_bytes(synthetic, b"abc")
    assert not validate_bytes(replace(synthetic, size=4), b"abc")


def test_reloaded_generation() -> None:
    private = (_ROOT / "generation").resolve()
    windows = ValidatedSteamPath.from_resolver(
        r"S:\steamapps\common\FINAL FANTASY TACTICS - The Ivalice Chronicles")
    managed = {mod_id: (_ROOT / "managed" / mod_id).resolve()
               for mod_id in MANAGED_ORDER}
    mods = (
        UserMod("high.enhanced", (_ROOT / "mods/high").resolve(),
                PackageClassification.ENHANCED_CONTENT, True, 0),
        UserMod("low.dual", (_ROOT / "mods/low").resolve(),
                PackageClassification.DUAL_MODE_CONTENT, True, 5),
        UserMod("disabled.enhanced", (_ROOT / "mods/off").resolve(),
                PackageClassification.ENHANCED_CONTENT, False, 2),
        UserMod("classic.only", (_ROOT / "mods/classic").resolve(),
                PackageClassification.CLASSIC_CONTENT, True, 1),
        UserMod("bad.code", (_ROOT / "mods/code").resolve(),
                PackageClassification.UNSUPPORTED_CODE, True, 3),
    )
    first = generate_reloaded_configuration(
        private_generation_root=private, windows_game_path=windows,
        selected_mode=Mode.ENHANCED, managed_package_locations=managed,
        user_mods=mods)
    second = generate_reloaded_configuration(
        private_generation_root=private, windows_game_path=windows,
        selected_mode=Mode.ENHANCED, managed_package_locations=managed,
        user_mods=mods)
    assert dict(first.files) == dict(second.files)
    assert first.file_bytes("portable.txt") == b""
    assert "ReloadedPortable.txt" not in first.files
    enhanced = json.loads(first.file_bytes(
        f"Apps/{ENHANCED_APP_ID}/AppConfig.json"))
    classic = json.loads(first.file_bytes(
        f"Apps/{CLASSIC_APP_ID}/AppConfig.json"))
    assert enhanced["AutoInject"] is False and enhanced["DontInject"] is True
    assert enhanced["EnabledMods"] == [*MANAGED_ORDER, "low.dual", "high.enhanced"]
    assert "disabled.enhanced" not in enhanced["EnabledMods"]
    assert "classic.only" not in enhanced["SortedMods"]
    assert "bad.code" not in enhanced["SortedMods"]
    assert classic["EnabledMods"] == [*MANAGED_ORDER, "low.dual", "classic.only"]
    assert first.directories == ("Apps", "Mods", "User/Mods")
    try:
        ValidatedSteamPath.from_resolver(r"Z:\var\mnt\game")
    except ValueError:
        pass
    else:
        raise AssertionError("unvalidated Z: path was accepted")

    duplicate_case = mods + (
        UserMod("HIGH.ENHANCED", (_ROOT / "mods/duplicate").resolve(),
                PackageClassification.ENHANCED_CONTENT, True, 6),
    )
    try:
        generate_reloaded_configuration(
            private_generation_root=private, windows_game_path=windows,
            selected_mode=Mode.ENHANCED, managed_package_locations=managed,
            user_mods=duplicate_case)
    except ValueError as exc:
        assert "Duplicate user mod ID" in str(exc)
    else:
        raise AssertionError("case-insensitive duplicate user mod ID was accepted")

    managed_user = mods + (
        UserMod("FFTIVC.UTILITY.MODLOADER", (_ROOT / "mods/managed").resolve(),
                PackageClassification.DUAL_MODE_CONTENT, True, 6),
    )
    try:
        generate_reloaded_configuration(
            private_generation_root=private, windows_game_path=windows,
            selected_mode=Mode.ENHANCED, managed_package_locations=managed,
            user_mods=managed_user)
    except ValueError as exc:
        assert "Managed package IDs" in str(exc)
    else:
        raise AssertionError("case-insensitive managed user-mod ID was accepted")


def test_transaction_plans() -> None:
    common = dict(
        transaction_id="tx", source=_ROOT / "source", destination=_ROOT / "target",
        expected_source_hash="a" * 64, ownership_identity="fftic:version.dll")
    fresh = plan_owned_file_install(
        **common, observed=TargetObservation(False))
    assert fresh.can_execute
    assert [op.kind for op in fresh.operations] == [
        OperationKind.VERIFY_ABSENCE, OperationKind.COPY_OWNED_FILE]
    collision = plan_owned_file_install(
        **common, observed=TargetObservation(True, "b" * 64, "foreign"))
    assert not collision.can_execute
    assert collision.operations[0].kind == OperationKind.STOP_UNOWNED_COLLISION
    drift = plan_owned_file_install(
        **common, prior_owned_hash="c" * 64,
        observed=TargetObservation(True, "d" * 64, "fftic:version.dll"))
    assert drift.operations[0].kind == OperationKind.STOP_DRIFT
    update = plan_owned_file_install(
        **common, prior_owned_hash="c" * 64,
        observed=TargetObservation(True, "c" * 64, "fftic:version.dll"))
    assert update.can_execute
    assert all(op.rollback_action and op.reason and op.ownership_identity
               for op in update.operations)
    retained = plan_shared_prerequisite_retention(
        transaction_id="remove", destination=_ROOT / "dotnet",
        ownership_identity="fftic:dotnet")
    assert retained.operations[0].kind == OperationKind.RETAIN_SHARED_PREREQUISITE


def test_steam_options() -> None:
    assert analyze_steam_launch_options("").status == SteamOptionsStatus.MISSING
    assert analyze_steam_launch_options(COPY_READY_OPTIONS).status \
        == SteamOptionsStatus.CONFIGURED
    preserved = analyze_steam_launch_options(
        'MANGOHUD=1 ' + COPY_READY_OPTIONS + ' -windowed')
    assert preserved.status == SteamOptionsStatus.CONFIGURED
    assert preserved.original.startswith("MANGOHUD=1")
    assert "MANGOHUD=1" in preserved.preserved_unrelated
    assert "-windowed" in preserved.preserved_unrelated
    assert analyze_steam_launch_options(
        'DOTNET_ROOT="C:\\Wrong" %command%').status == SteamOptionsStatus.DIFFERENT
    assert analyze_steam_launch_options(
        COPY_READY_OPTIONS.replace("version=n,b", "version=b")
    ).status == SteamOptionsStatus.CONFLICT
    assert analyze_steam_launch_options(
        COPY_READY_OPTIONS + " %command%").status == SteamOptionsStatus.CONFLICT
    assert analyze_steam_launch_options(
        "gamemoderun " + COPY_READY_OPTIONS).status == SteamOptionsStatus.CONFLICT
    assert analyze_steam_launch_options(
        'EXTRA="$(touch forbidden)" ' + COPY_READY_OPTIONS
    ).status == SteamOptionsStatus.CONFLICT
    duplicate = COPY_READY_OPTIONS.replace(
        "%command%", 'DOTNET_ROOT="C:\\Program Files\\dotnet" %command%')
    assert analyze_steam_launch_options(duplicate).status == SteamOptionsStatus.CONFLICT


def test_direct_launch_policy_and_no_live_side_effects() -> None:
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    assert "requires normal Steam launch" in handler.direct_proton_launch_blocked_reason(
        Path("FFT_enhanced.exe"))
    assert handler.direct_proton_launch_blocked_reason(Path("tool.exe")) == ""

    from Utils.executables.launch import launch_exe_via_proton
    messages: list[str] = []
    launch_exe_via_proton(Path("FFT_classic.exe"), handler, messages.append)
    assert any("refusing direct Proton launch" in message for message in messages)

    from Games.base_game import BaseGame

    class RepresentativeGame:
        direct_proton_launch_blocked_reason = BaseGame.direct_proton_launch_blocked_reason

    # The capability is permissive by default, so every existing handler that
    # does not opt in retains its former direct-launch behavior.
    assert RepresentativeGame().direct_proton_launch_blocked_reason(
        Path("OtherGame.exe")) == ""

    # The handler creates only ordinary empty config parents under the isolated
    # XDG root. It must not create managed generations, game files, prefixes,
    # downloads, profiles, or staging content merely by being instantiated.
    assert not (_ROOT / "generation").exists() or not any(
        p.name.endswith((".dll", ".asi", ".exe")) for p in (_ROOT / "generation").rglob("*"))
    assert not any((_ROOT / "profiles").rglob("modded*.pac"))


def main() -> None:
    tests = [
        test_collision_safe_discovery_imports,
        test_identity_detection_and_cache_contract,
        test_package_recognition,
        test_artifact_manifest,
        test_reloaded_generation,
        test_transaction_plans,
        test_steam_options,
        test_direct_launch_policy_and_no_live_side_effects,
    ]
    for test in tests:
        test()
        print(f"✓ {test.__name__}")
    print("All FFTIC Phase C1 checks passed.")


if __name__ == "__main__":
    main()
