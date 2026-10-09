"""Focused Phase C1 checks for the non-mutating FFTIC foundation.

Run from the source tree:

    python3 'src/Games/Final Fantasy Tactics The Ivalice Chronicles/_selftest.py'
"""

from __future__ import annotations

import json
from _managed_fixture import managed_bytes
import os
import sys
import tempfile
import zipfile
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
        from Utils.games import discovery
        loaded_paths = []
        original_loader = discovery.importlib.util.spec_from_file_location

        def record_loader(name, location, *args, **kwargs):
            loaded_paths.append(Path(location).as_posix())
            return original_loader(name, location, *args, **kwargs)

        with patch.object(
                discovery.importlib.util, "spec_from_file_location",
                side_effect=record_loader):
            games = discovery.discover_games()
        fftic_games = [
            game for game in games.values()
            if getattr(game, "game_id", None)
            == "final_fantasy_tactics_the_ivalice_chronicles"
        ]
        assert len(fftic_games) == 1
        for excluded in (
                "fftic_mod_state.py",
                "_managed_fixture.py",
                "_mod_state_selftest.py",
                "fftic_prerequisite_runner.py",
                "fftic_loader_releases.py",
                "_prerequisite_production_selftest.py",
                "_loader_update_selftest.py",
                "_loader_update_production_selftest.py"):
            assert not any(path.endswith("/" + excluded) for path in loaded_paths)
        fftic_failures = [
            failure for failure in discovery.get_load_failures()
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
        pe_version="v1.0.0", hash_cache=_KnownHashCache())
    assert exact.status == InstallStatus.EXACT_VERIFIED
    assert exact.pe_version == "v1.0.0"
    assert exact.runtime_proof_ui_version == "v1.5.2"
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
    assert compiled.classification == PackageClassification.MALFORMED
    assert handler.validate_mod_package(packages / "compiled")
    from Utils.mods.install import _validate_prepared_package
    install_log: list[str] = []
    prepared = SimpleNamespace(
        game=SimpleNamespace(validate_mod_package=Mock(
            return_value=handler.validate_mod_package(packages / "compiled"))),
        src_root=packages / "compiled",
    )
    assert not _validate_prepared_package(prepared, install_log.append)
    assert any("ModDll" in line for line in install_log)
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
        assert runtime_file.relative_to(root).as_posix() in runtime.diagnostics[0] or extension == ".dll"

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


def test_special_file_manifest() -> None:
    from threading import Thread
    package = _ROOT / "special-manifest"
    package.mkdir()
    os.mkfifo(package / "ModConfig.json")
    results = []
    worker = Thread(target=lambda: results.append(inspect_package(package)), daemon=True)
    worker.start()
    worker.join(timeout=1)
    assert not worker.is_alive(), "Reading a FIFO manifest blocked package inspection"
    assert results[0].classification == PackageClassification.MALFORMED
    assert "ModConfig.json must be a regular non-symlink file" in results[0].diagnostics[0]


def test_managed_code_packages() -> None:
    from fftic_generation import content_manifest, manifest_digest, validate_user_dependencies, GenerationError
    from Utils.mods.install import _validate_prepared_package
    root = _ROOT / "managed-code-fixtures"
    data = _manifest(mod_id="ffttic.jobs.genericjobs", deps=list(MANAGED_ORDER))
    data["ModDll"] = "GenericJobs.dll"
    data["ModR2RManagedDll32"] = "x86/GenericJobs.dll"
    data["ModR2RManagedDll64"] = "x64/GenericJobs.dll"
    package = _package(root / "valid", data, "FFTIVC/data/enhanced/job.nxd")
    (package / "GenericJobs.dll").write_bytes(managed_bytes())
    (package / "GenericJobs.deps.json").write_text("{}", encoding="utf-8")
    (package / "Reloaded.Support.dll").write_bytes(managed_bytes(b"dependency"))
    result = inspect_package(package)
    assert result.classification == PackageClassification.ENHANCED_MANAGED_CODE
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    assert handler.validate_mod_package(package) == []
    prepared = SimpleNamespace(game=handler, src_root=package)
    assert _validate_prepared_package(prepared, lambda _line: None)
    before = manifest_digest(content_manifest(package))
    (package / "GenericJobs.dll").write_bytes(managed_bytes(b"changed"))
    assert manifest_digest(content_manifest(package)) != before
    mod = UserMod(data["ModId"], package, result.classification, True, 0)
    validate_user_dependencies((mod,))
    config = generate_reloaded_configuration(
        private_generation_root=(_ROOT / "generation").resolve(),
        windows_game_path=ValidatedSteamPath.from_resolver(r"S:\steamapps\common\FFTIC"),
        managed_package_locations={identity: (_ROOT / "managed" / identity).resolve()
                                   for identity in MANAGED_ORDER}, user_mods=(mod,))
    enhanced = json.loads(config.file_bytes(f"Apps/{ENHANCED_APP_ID}/AppConfig.json"))
    classic = json.loads(config.file_bytes(f"Apps/{CLASSIC_APP_ID}/AppConfig.json"))
    assert enhanced["EnabledMods"] == [*MANAGED_ORDER, data["ModId"]]
    assert data["ModId"] not in classic["EnabledMods"]
    disabled = replace(mod, enabled=False)
    config_off = generate_reloaded_configuration(
        private_generation_root=(_ROOT / "generation").resolve(),
        windows_game_path=ValidatedSteamPath.from_resolver(r"S:\steamapps\common\FFTIC"),
        managed_package_locations={identity: (_ROOT / "managed" / identity).resolve()
                                   for identity in MANAGED_ORDER}, user_mods=(disabled,))
    assert data["ModId"] not in json.loads(config_off.file_bytes(
        f"Apps/{ENHANCED_APP_ID}/AppConfig.json"))["EnabledMods"]
    for bad in ("../GenericJobs.dll", "/tmp/GenericJobs.dll", "missing.dll"):
        altered = dict(data, ModDll=bad)
        candidate = _package(root / f"bad-{len(list(root.iterdir()))}", altered)
        assert inspect_package(candidate).classification == PackageClassification.MALFORMED
    linked = _package(root / "linked", data)
    (linked / "GenericJobs.dll").symlink_to(package / "GenericJobs.dll")
    assert inspect_package(linked).classification == PackageClassification.MALFORMED
    special = _package(root / "special", data)
    os.mkfifo(special / "GenericJobs.dll")
    assert inspect_package(special).classification == PackageClassification.MALFORMED
    collision = _package(root / "collision", data)
    (collision / "GenericJobs.dll").write_bytes(b"synthetic")
    (collision / "genericjobs.dll").write_bytes(b"collision")
    assert inspect_package(collision).classification == PackageClassification.MALFORMED
    native = _package(root / "native", dict(data, ModNativeDll64="Native.dll"))
    (native / "GenericJobs.dll").write_bytes(b"synthetic")
    assert inspect_package(native).classification == PackageClassification.UNSUPPORTED_CODE
    missing = _package(root / "missing-dependency", dict(data, ModDependencies=["unknown.api"]))
    (missing / "GenericJobs.dll").write_bytes(managed_bytes())
    try:
        validate_user_dependencies((replace(mod, package_location=missing),))
    except GenerationError as exc:
        assert "unknown.api" in str(exc)
    else:
        raise AssertionError("missing dependency was accepted")


def test_reviewed_color_customizer_archive() -> None:
    """Optional unchanged release fixture; never loads or executes release code."""
    import hashlib
    import shutil
    from fftic_extraction import ExtractionLimits, extract_archive
    from fftic_packages import (is_reviewed_color_customizer_archive,
                                validate_color_customizer_archive,
                                _COLOR_COMPILED_FILES)
    from fftic_generation import GenerationError, read_profile_mods
    from fftic_orchestration import _profile_packages
    from Utils.mods.install import _finish_install, _single_root_unwrap, _validate_prepared_package

    fixture = os.environ.get("FFTIC_COLOR_330_ARCHIVE")
    if not fixture:
        print("Release fixture checks not run: set FFTIC_COLOR_330_ARCHIVE to the isolated audited ZIP.")
        return
    archive = Path(fixture)
    assert is_reviewed_color_customizer_archive(archive), "Fixture must be the unchanged reviewed ZIP"
    before = hashlib.sha256(archive.read_bytes()).hexdigest()
    profile = _ROOT / "reviewed-color"
    staging = profile / "mods"
    extracted = extract_archive(archive, staging, limits=ExtractionLimits(1323, 108569077, 1691648))
    package = _single_root_unwrap(extracted.root)
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    assert validate_color_customizer_archive(package, archive) == []
    result = inspect_package(package)
    assert result.classification == PackageClassification.DUAL_MODE_MANAGED_CODE
    assert result.is_user_content
    context = SimpleNamespace(profile_dir=profile, staging_root=staging)
    for enabled in (True, False):
        (profile / "modlist.txt").write_text(("+" if enabled else "-") + package.name + "\n")
        assert _profile_packages(context) == ()
        mods = read_profile_mods(profile, staging)
        assert len(mods) == 1 and mods[0].enabled == enabled

    def refused():
        observed = inspect_package(package)
        assert observed.classification in {PackageClassification.UNSUPPORTED_CODE,
                                            PackageClassification.MALFORMED}, observed
        assert not observed.is_user_content

    # Every compiled member is independently bound, including all five Windows
    # SQLite DLLs and the static archive. Same-length edits cannot inherit trust.
    for relative in _COLOR_COMPILED_FILES:
        item = package / relative
        original = item.read_bytes()
        item.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        refused()
        item.write_bytes(original)
    item = package / "Preview.png"
    original = item.read_bytes()
    item.write_bytes(original + b"changed")
    refused()
    item.write_bytes(original)
    item = package / "runtimes/linux-x64/native/libe_sqlite3.so"
    original = item.read_bytes()
    renamed = item.with_name("renamed.so")
    item.rename(renamed)
    refused()
    renamed.rename(item)
    item.unlink()
    refused()
    item.write_bytes(original)
    for relative in ("extra.so", "extra.a", "extra.txt", "unknown.exe"):
        extra = package / relative
        extra.write_bytes(b"unreviewed")
        refused()
        extra.unlink()
    extra_dir = package / "empty-unreviewed-directory"
    extra_dir.mkdir()
    refused()
    extra_dir.rmdir()
    item.unlink()
    item.symlink_to(package / "e_sqlite3.dll")
    refused()
    item.unlink()
    item.write_bytes(original)
    manifest = package / "ModConfig.json"
    manifest_bytes = manifest.read_bytes()
    data = json.loads(manifest_bytes)
    for edits in ({"ModVersion": "3.3.1"}, {"ModId": "unrelated.native"},
                  {"ModId": data["ModId"].upper()}, {"ModDll": "../outside.dll"},
                  {"ModDll": "missing.dll"}, {"ModNativeDll64": "e_sqlite3.dll"}):
        manifest.write_text(json.dumps(dict(data, **edits)))
        refused()
    manifest.write_bytes(manifest_bytes)

    # Repacking identical member contents changes archive identity too. Path,
    # version, member set, trailing bytes and ZIP metadata are not substitutes.
    altered = _ROOT / "changed-color.zip"
    shutil.copyfile(archive, altered)
    with altered.open("r+b") as stream:
        first = stream.read(1)
        stream.seek(0)
        stream.write(bytes([first[0] ^ 1]))
    assert altered.stat().st_size == archive.stat().st_size
    assert not is_reviewed_color_customizer_archive(altered)
    assert validate_color_customizer_archive(package, altered)
    # Verify the original-archive seam independently of the exact release boundary.
    # The patch models a future completed persistence gate; no installation runs.
    with patch.object(handler, "validate_mod_package", return_value=[]):
        assert _validate_prepared_package(
            SimpleNamespace(game=handler, src_root=package, archive=archive), lambda _line: None)
        assert not _validate_prepared_package(
            SimpleNamespace(game=handler, src_root=package, archive=altered), lambda _line: None)
        assert not _validate_prepared_package(
            SimpleNamespace(game=handler, src_root=package), lambda _line: None)
    shutil.copyfile(archive, altered)
    with altered.open("ab") as stream:
        stream.write(b"changed archive bytes")
    assert not is_reviewed_color_customizer_archive(altered)
    assert validate_color_customizer_archive(package, altered)
    shutil.copyfile(archive, altered)
    with zipfile.ZipFile(altered, "a") as output:
        output.comment = b"repacked identity"
    assert not is_reviewed_color_customizer_archive(altered)
    for changed in ("path", "member", "version"):
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(altered, "w", zipfile.ZIP_DEFLATED) as output:
            for info in source.infolist():
                payload = source.read(info)
                name = info.filename
                if name.endswith("/ModConfig.json") and changed == "version":
                    payload = json.dumps(dict(json.loads(payload), ModVersion="3.3.1")).encode()
                if name.endswith("/e_sqlite3.dll") and changed == "path":
                    name += ".renamed"
                if name.endswith("/Preview.png") and changed == "member":
                    continue
                output.writestr(name, payload)
        assert not is_reviewed_color_customizer_archive(altered)
        assert validate_color_customizer_archive(package, altered)
    assert inspect_package(package).is_user_content
    assert validate_color_customizer_archive(package, archive) == []
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == before
    assert len(list(package.rglob("*.so"))) == 11
    assert len(list(package.rglob("*.dylib"))) == 4
    print("Reviewed ZIP accepted by payload policy; all 35 compiled-member edits and lifecycle bypasses refused.")


def test_color_customizer_configuration_boundary() -> None:
    """Source-shaped bytes only: neither a release archive nor executable code."""
    from fftic_generation import GenerationError, content_manifest, read_profile_mods
    from fftic_orchestration import _profile_packages
    from Utils.mods.install import _validate_prepared_package

    profile = _ROOT / "color-customizer"
    staging = profile / "mods"
    data = _manifest(mod_id="paxtrick.fft.colorcustomizer",
                     apps=[ENHANCED_APP_ID, CLASSIC_APP_ID], deps=list(MANAGED_ORDER))
    data.update(ModName="FFT Color Customizer", ModAuthor="prawl", ModVersion="3.3.0",
                ModDll="FFTColorCustomizer.dll",
                ModR2RManagedDll32="x86/FFTColorCustomizer.dll",
                ModR2RManagedDll64="x64/FFTColorCustomizer.dll",
                ModConfig="FFTColorCustomizer.Configuration.Configurator")
    package = _package(staging / "Color Customizer", data,
                       "FFTIVC/data/enhanced/fftpack/unit/battle_knight_m_spr.bin")
    (package / data["ModDll"]).write_bytes(managed_bytes(b"color-shaped"))
    (package / "UserThemes.json").write_text('{"Knight_Male": ["Mine"]}')
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    before = content_manifest(package)
    result = inspect_package(package)
    assert result.classification == PackageClassification.UNSUPPORTED_CONFIGURATION
    assert not result.is_user_content
    assert result.manifest.dependencies == tuple(MANAGED_ORDER)
    assert result.manifest.supported_app_ids == (ENHANCED_APP_ID, CLASSIC_APP_ID)
    assert dict(result.manifest.managed_native_declarations)["ModDll"] == data["ModDll"]
    assert "unchanged reviewed" in handler.validate_mod_package(package)[0]
    messages = []
    assert not _validate_prepared_package(
        SimpleNamespace(game=handler, src_root=package), messages.append)
    assert any("unchanged reviewed" in message for message in messages)

    # Already-staged copies must surface the same reason, including disabled
    # ones: generations snapshot disabled packages too. Never discard edits.
    context = SimpleNamespace(profile_dir=profile, staging_root=staging)
    for enabled in (True, False):
        (profile / "modlist.txt").write_text(
            ("+" if enabled else "-") + "Color Customizer\n")
        unsupported = _profile_packages(context)
        assert len(unsupported) == 1
        assert unsupported[0].enabled == enabled
        assert "unchanged reviewed" in unsupported[0].reason
        try:
            read_profile_mods(profile, staging)
        except GenerationError as exc:
            assert "unchanged reviewed" in str(exc)
        else:
            raise AssertionError("Mutable package entered a generation")
    assert content_manifest(package) == before

    # Case variants do not bypass exact release identity. Structural/executable validation
    # still takes precedence; this name never authorizes a payload exception.
    manifest_path = package / "ModConfig.json"
    data["ModId"] = data["ModId"].upper()
    manifest_path.write_text(json.dumps(data))
    assert inspect_package(package).classification == PackageClassification.UNSUPPORTED_CONFIGURATION
    # Synthetic SQLite .so/.dylib bytes do not match the reviewed release.
    # Each is independently rejected before the exact release boundary, including
    # for disabled staged packages. Never remove payloads to make it install.
    from Utils.mods.install import _finish_install
    for relative in ("unknown.exe",
                     "runtimes/linux-x64/native/libe_sqlite3.so",
                     "runtimes/osx-arm64/native/libe_sqlite3.dylib"):
        extra = package / relative
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_bytes(b"synthetic non-executable fixture")
        snapshot = content_manifest(package)
        result = inspect_package(package)
        assert result.classification == PackageClassification.UNSUPPORTED_CODE
        assert relative in result.diagnostics[0]
        messages = []
        # This minimal prepared record deliberately lacks staging fields: the
        # real finish seam must reject before resolving or replacing staging.
        assert _finish_install(SimpleNamespace(game=handler, src_root=package),
                               None, log_fn=messages.append) is None
        assert any(relative in message for message in messages)
        for enabled in (True, False):
            (profile / "modlist.txt").write_text(
                ("+" if enabled else "-") + "Color Customizer\n")
            assert relative in _profile_packages(context)[0].reason
            try:
                read_profile_mods(profile, staging)
            except GenerationError as exc:
                assert relative in str(exc)
            else:
                raise AssertionError("Unsupported native payload entered a generation")
        assert content_manifest(package) == snapshot
        extra.unlink()
    manifest_path.write_text(json.dumps(dict(data, ModDll="../outside.dll")))
    assert inspect_package(package).classification == PackageClassification.MALFORMED
    manifest_path.write_text(json.dumps(dict(data, ModDll="missing.dll")))
    assert inspect_package(package).classification == PackageClassification.MALFORMED

    # Other managed packages with a configurator retain the existing D1 rule.
    # A configurator declaration by itself proves neither writes nor safety.
    manifest_path.write_text(json.dumps(dict(data, ModId="test.configurable")))
    assert inspect_package(package).classification == PackageClassification.DUAL_MODE_MANAGED_CODE
    (profile / "modlist.txt").write_text("+Color Customizer\n")
    accepted = read_profile_mods(profile, staging)
    manifest_before = manifest_path.read_bytes()
    generated = generate_reloaded_configuration(
        private_generation_root=(profile / "generation").resolve(),
        windows_game_path=ValidatedSteamPath.from_resolver(r"S:\steamapps\common\FFTIC"),
        managed_package_locations={identity: (profile / identity).resolve()
                                   for identity in MANAGED_ORDER}, user_mods=accepted)
    for app in (CLASSIC_APP_ID, ENHANCED_APP_ID):
        assert json.loads(generated.file_bytes(f"Apps/{app}/AppConfig.json"))["EnabledMods"] \
            == [*MANAGED_ORDER, "test.configurable"]
    assert manifest_path.read_bytes() == manifest_before

    # A configurable dual-mode mod must still have every required user
    # dependency enabled in both modes, not merely installed for Enhanced.
    dependent = dict(data, ModId="test.configurable",
                     ModDependencies=[*MANAGED_ORDER, "test.api"])
    manifest_path.write_text(json.dumps(dependent))
    dependency = _package(staging / "API", _manifest(mod_id="test.api"))
    for modlist in ("+Color Customizer\n", "+Color Customizer\n-API\n",
                    "+Color Customizer\n+API\n"):
        (profile / "modlist.txt").write_text(modlist)
        try:
            read_profile_mods(profile, staging)
        except GenerationError as exc:
            assert "test.api" in str(exc) and "classic" in str(exc)
        else:
            raise AssertionError("Missing, disabled, or mode-incompatible dependency accepted")
    (dependency / "ModConfig.json").write_text(json.dumps(
        _manifest(mod_id="test.api", apps=[CLASSIC_APP_ID, ENHANCED_APP_ID])))
    assert len(read_profile_mods(profile, staging)) == 2


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
        managed_package_locations=managed,
        user_mods=mods)
    second = generate_reloaded_configuration(
        private_generation_root=private, windows_game_path=windows,
        managed_package_locations=managed,
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
            managed_package_locations=managed,
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
            managed_package_locations=managed,
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
    empty = analyze_steam_launch_options("")
    assert empty.status == SteamOptionsStatus.MISSING
    assert empty.required_copy_text == COPY_READY_OPTIONS
    configured = analyze_steam_launch_options(COPY_READY_OPTIONS)
    assert configured.status == SteamOptionsStatus.CONFIGURED
    assert configured.required_copy_text == COPY_READY_OPTIONS
    preserved = analyze_steam_launch_options(
        'MANGOHUD=1 ' + COPY_READY_OPTIONS + ' -windowed')
    assert preserved.status == SteamOptionsStatus.CONFIGURED
    assert preserved.original.startswith("MANGOHUD=1")
    assert "MANGOHUD=1" in preserved.preserved_unrelated
    assert "-windowed" in preserved.preserved_unrelated
    assert preserved.required_copy_text.startswith("MANGOHUD=1 WINEDLLOVERRIDES=")
    assert preserved.required_copy_text.endswith("%command% -windowed")
    assert preserved.recommendation_is_composed
    assert preserved.required_copy_text.count("%command%") == 1
    missing = analyze_steam_launch_options("MANGOHUD=1 %command% -windowed")
    assert missing.status == SteamOptionsStatus.MISSING
    assert "MANGOHUD=1" in missing.required_copy_text
    assert missing.required_copy_text.endswith("%command% -windowed")
    different = analyze_steam_launch_options(
        'MANGOHUD=1 DOTNET_ROOT="C:\\Wrong" %command% -windowed')
    assert different.status == SteamOptionsStatus.DIFFERENT
    assert 'DOTNET_ROOT="C:\\Program Files\\dotnet"' in different.required_copy_text
    assert "C:\\Wrong" not in different.required_copy_text
    assert different.required_copy_text.count("%command%") == 1
    conflict = analyze_steam_launch_options(
        COPY_READY_OPTIONS.replace("version=n,b", "version=b")
    )
    assert conflict.status == SteamOptionsStatus.CONFLICT
    assert conflict.required_copy_text == COPY_READY_OPTIONS
    assert not conflict.preserved_unrelated
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
    safely_quoted = analyze_steam_launch_options(
        "LABEL='value with spaces; $HOME' " + COPY_READY_OPTIONS +
        " 'argument with spaces'")
    assert safely_quoted.status == SteamOptionsStatus.CONFIGURED
    assert "LABEL='value with spaces; $HOME'" in safely_quoted.required_copy_text
    assert safely_quoted.required_copy_text.endswith("%command% 'argument with spaces'")
    for unsafe in (
        "env " + COPY_READY_OPTIONS,
        "sh -c " + COPY_READY_OPTIONS,
        COPY_READY_OPTIONS + " ; echo unsafe",
        "EXTRA=$HOME " + COPY_READY_OPTIONS,
    ):
        result = analyze_steam_launch_options(unsafe)
        assert result.status == SteamOptionsStatus.CONFLICT
        assert result.required_copy_text == COPY_READY_OPTIONS


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


def test_nexus_browser_install_contract() -> None:
    """Exercise the shared UI handoff without a network request or live install."""
    from gui_qt.app import MainWindow
    from gui_qt.nexus_browser_view import NexusBrowserView
    from Utils.mods.install import (
        _validate_prepared_package, finish_install, prepare_archive)
    from Nexus.nexus_meta import NexusModMeta

    fftic = FinalFantasyTacticsTheIvaliceChronicles()
    fftic.is_configured = lambda: True
    domain = "finalfantasytacticstheivalicechronicles"
    assert fftic.nexus_game_domain == domain
    assert fftic.nexus_game_domains == (domain,)
    assert fftic.accepts_nexus_domain(domain)

    class Button:
        _hide_key = "nexus"

        def setVisible(self, visible):
            self.visible = visible

    button = Button()
    game_state = SimpleNamespace(game=fftic)
    header = SimpleNamespace(
        _gs=game_state, _nexus_btn=button, _action_buttons=(),
        _game_has_prefix=lambda game: False,
        _wabbajack_available=lambda: False,
        _hidden_header_buttons=lambda: set(),
    )
    MainWindow._sync_thunderstore_button(header)
    assert button.visible

    opened = []
    class Tabs:
        def has_key(self, key):
            return False

        def open_tab(self, view, title, key):
            opened.append((view, title, key))

    class Signal:
        def connect(self, callback):
            self.callback = callback

    class Browser:
        def __init__(self, api, selected_domain, game, **kwargs):
            self.api = api
            self.domain = selected_domain
            self.game = game
            self._game = game
            self.install_fn = kwargs["install_fn"]
            self._install_fn = self.install_fn
            self.destroyed = Signal()

        def set_game(self, game, selected_domain):
            self.game = game
            self._game = game
            self.domain = selected_domain

    archive_installs = []
    app = SimpleNamespace(
        _tabs=Tabs(), _gs=game_state, _nexus_view=None,
        _collections_view=None, _thunderstore_view=None,
        _download_only_active=lambda: False,
        _install_paths=lambda paths, metas=None: archive_installs.append(
            (paths, metas)),
        _ensure_nexus_api=lambda: "existing OAuth API",
        _append_log=lambda message: None,
        _nexus_download_progress=lambda *args: None,
        _notify=lambda *args: None, tr=lambda message: message,
    )
    app._deliver_download = lambda paths, metas=None: MainWindow._deliver_download(
        app, paths, metas)
    with patch("gui_qt.nexus_browser_view.NexusBrowserView", Browser):
        MainWindow._open_nexus_browser_tab(app)
    browser = app._nexus_view
    assert browser.domain == domain and browser.api == "existing OAuth API"
    assert opened[0][2] == "nexus_browser"

    other = SimpleNamespace(
        name="Other game", nexus_game_domain="othergame",
        is_configured=lambda: True,
        accepts_nexus_domain=lambda candidate: candidate == "othergame")
    game_state.game_name = fftic.name
    with patch.dict("Utils.games.registry._GAMES",
                    {fftic.name: fftic, other.name: other}, clear=True):
        assert MainWindow._match_game_for_domain(app, domain) == (fftic.name, fftic)
        assert MainWindow._match_game_for_domain(app, "othergame") == (other.name, other)
        game_state.game = other
        game_state.game_name = other.name
        assert MainWindow._match_game_for_domain(app, domain) == (fftic.name, fftic)
        assert MainWindow._match_game_for_domain(app, "othergame") == (other.name, other)
    game_state.game = fftic
    game_state.game_name = fftic.name

    # The browser's completed-download callback supplies the cached archive
    # and Nexus metadata to the same install function used by other games.
    cached = str(_ROOT / "cache" / "fftic-package.zip")
    metadata = object()
    browser._progress_fn = lambda *args: None
    browser._download_cancels = {"download": None}
    browser._download_games = {"download": fftic.name}
    browser._download_oversize = {"download": None}
    browser._install_all_active = set()
    browser._log = lambda message: None
    browser._download_only = lambda: False
    NexusBrowserView._on_download_done(browser, cached, metadata, "download")
    assert archive_installs == [([cached], {cached: metadata})]

    packages = _ROOT / "nexus-packages"
    supported = _package(packages / "supported", _manifest())
    unsupported = _package(packages / "unsupported",
                           _manifest(apps=["other.exe"]))
    unsafe = _package(packages / "unsafe", _manifest())
    (unsafe / "FFTIVC" / "link").symlink_to(_ROOT / "outside")
    for package, accepted, diagnostic in (
            (supported, True, ""),
            (unsupported, False, "unsupported"),
            (unsafe, False, "Unsafe package path")):
        log = []
        prepared = SimpleNamespace(game=fftic, src_root=package)
        assert _validate_prepared_package(prepared, log.append) is accepted
        if diagnostic:
            assert any(diagnostic in line for line in log), log

    # A synthetic cached archive follows the ordinary extraction and staging
    # path with prebuilt Nexus metadata; no API lookup or live game path is used.
    install_root = _ROOT / "nexus-install"
    install_root.mkdir()
    fftic.get_mod_staging_path = lambda: install_root / "mods"
    archive = install_root / "supported.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("ModConfig.json", json.dumps(_manifest()))
        handle.writestr("FFTIVC/data/enhanced/test.nxd", b"fixture")
    log = []
    prepared = prepare_archive(
        str(archive), fftic, install_root / "profile", log_fn=log.append,
        preferred_name="supported", prebuilt_meta=NexusModMeta(
            game_domain=domain, mod_id=1, file_id=2))
    assert prepared is not None
    assert finish_install(prepared, None, log_fn=log.append,
                          interactive=False) == "supported", log
    assert (install_root / "mods/supported/FFTIVC/data/enhanced/test.nxd").is_file()

    # An in-flight FFTIC download stays in its original cache after a switch.
    game_state.game = other
    browser._download_games = {"switched": fftic.name}
    browser._download_cancels = {"switched": None}
    browser._download_oversize = {"switched": None}
    browser.game = browser._game = other
    NexusBrowserView._on_download_done(browser, cached, metadata, "switched")
    assert len(archive_installs) == 1
    MainWindow._retarget_browsers_for_game(app)
    assert browser.domain == "othergame" and browser.game is other
    MainWindow._sync_thunderstore_button(header)
    assert button.visible
    game_state.game = SimpleNamespace(name="No Nexus", nexus_game_domain="")
    MainWindow._sync_thunderstore_button(header)
    assert not button.visible


def main() -> None:
    tests = [
        test_collision_safe_discovery_imports,
        test_identity_detection_and_cache_contract,
        test_package_recognition,
        test_nexus_browser_install_contract,
        test_special_file_manifest,
        test_managed_code_packages,
        test_color_customizer_configuration_boundary,
        test_reviewed_color_customizer_archive,
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
