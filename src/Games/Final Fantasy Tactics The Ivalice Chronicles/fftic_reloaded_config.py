"""Deterministic, write-free Reloaded configuration generation for FFTIC."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PureWindowsPath
from types import MappingProxyType

try:
    from .fftic_packages import (
        CLASSIC_APP_ID, ENHANCED_APP_ID,
        PackageClassification,
        is_managed_package_id,
    )
except ImportError:  # direct self-test / file-based game discovery
    from fftic_packages import (
        CLASSIC_APP_ID, ENHANCED_APP_ID,
        PackageClassification,
        is_managed_package_id,
    )

SIGSCAN_ID = "Reloaded.Memory.SigScan.ReloadedII"
SHARED_HOOKS_ID = "reloaded.sharedlib.hooks"
NENKAI_ID = "fftivc.utility.modloader"
MANAGED_ORDER = (SIGSCAN_ID, SHARED_HOOKS_ID, NENKAI_ID)
_WINDOWS_PATH_TOKEN = object()


class Mode(str, Enum):
    CLASSIC = "classic"
    ENHANCED = "enhanced"


@dataclass(frozen=True)
class ValidatedSteamPath:
    value: str

    @classmethod
    def from_resolver(cls, value: str) -> "ValidatedSteamPath":
        """Accept only the runtime's resolver-validated Steam ``S:`` identity."""
        if not isinstance(value, str) or not re.match(
                r"^S:\\steamapps\\common\\[^\\]+$", value, re.IGNORECASE):
            raise ValueError(
                "FFTIC requires a resolver-validated S:\\steamapps\\common\\... path")
        return cls(value.rstrip("\\"))


@dataclass(frozen=True)
class ValidatedWindowsGenerationPath:
    value: str
    prefix: Path
    host_root: Path
    _attestation: object

    @classmethod
    def _from_resolved(cls, value: str, prefix: Path,
                       host_root: Path) -> "ValidatedWindowsGenerationPath":
        return cls(value, prefix, host_root, _WINDOWS_PATH_TOKEN)

    def revalidate(self) -> None:
        if self._attestation is not _WINDOWS_PATH_TOKEN:
            raise ValueError("Managed generation path lacks resolver evidence")
        current = self.host_root
        while current != self.prefix and current != current.parent:
            if current.is_symlink():
                raise ValueError(f"Managed generation path crosses a symbolic link: {current}")
            current = current.parent
        if current != self.prefix:
            raise ValueError("Managed generation path no longer belongs to the selected prefix")
        drive_c = (self.prefix / "drive_c").resolve(strict=True)
        root = self.host_root.resolve(strict=True)
        if not root.is_dir() or not root.is_relative_to(drive_c):
            raise ValueError("Managed generation path no longer maps to the selected prefix C: drive")
        expected = "C:\\" + "\\".join(root.relative_to(drive_c).parts)
        if expected != self.value:
            raise ValueError("Managed generation Windows/host mapping changed")


@dataclass(frozen=True)
class UserMod:
    mod_id: str
    package_location: Path
    classification: PackageClassification
    enabled: bool
    amethyst_priority: int


@dataclass(frozen=True)
class GeneratedReloadedConfig:
    private_generation_root: Path
    files: MappingProxyType
    directories: tuple[str, ...]
    managed_package_sources: MappingProxyType
    user_package_sources: MappingProxyType

    def file_bytes(self, relative_path: str) -> bytes:
        return self.files[relative_path]


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def _compatible(classification: PackageClassification, mode: Mode) -> bool:
    return classification == PackageClassification.DUAL_MODE_CONTENT or (
        mode == Mode.CLASSIC and classification == PackageClassification.CLASSIC_CONTENT
    ) or (
        mode == Mode.ENHANCED and classification == PackageClassification.ENHANCED_CONTENT
    )


def _record(game_path: ValidatedSteamPath, mode: Mode,
            mods: tuple[UserMod, ...]) -> dict:
    app_id = CLASSIC_APP_ID if mode == Mode.CLASSIC else ENHANCED_APP_ID
    compatible = [mod for mod in mods if _compatible(mod.classification, mode)]
    if len({mod.mod_id.casefold() for mod in compatible}) != len(compatible):
        raise ValueError(f"Duplicate compatible mod ID for {mode.value}")
    if any(is_managed_package_id(mod.mod_id) for mod in compatible):
        raise ValueError("Managed package IDs cannot be supplied as user mods")
    enabled = sorted(
        (mod for mod in compatible if mod.enabled),
        key=lambda mod: (mod.amethyst_priority, mod.mod_id.casefold()),
        reverse=True,
    )
    all_sorted = sorted(
        compatible,
        key=lambda mod: (mod.amethyst_priority, mod.mod_id.casefold()),
        reverse=True,
    )
    location = str(PureWindowsPath(game_path.value) / (
        "FFT_classic.exe" if mode == Mode.CLASSIC else "FFT_enhanced.exe"))
    return {
        "AppArguments": "",
        "AppIcon": "",
        "AppId": app_id,
        "AppLocation": location,
        "AppName": f"FFTIC — {'Classic' if mode == Mode.CLASSIC else 'Enhanced'}",
        "AutoInject": False,
        "DontInject": True,
        "EnabledMods": [*MANAGED_ORDER, *(mod.mod_id for mod in enabled)],
        "IsMsStore": False,
        "PluginData": {},
        "PreserveDisabledModOrder": True,
        "SortedMods": [*MANAGED_ORDER, *(mod.mod_id for mod in all_sorted)],
        "WorkingDirectory": game_path.value,
    }


def generate_reloaded_configuration(
    *,
    private_generation_root: Path,
    windows_game_path: ValidatedSteamPath,
    managed_package_locations: dict[str, Path],
    user_mods: tuple[UserMod, ...] | list[UserMod],
) -> GeneratedReloadedConfig:
    """Build both application records and portable marker entirely in memory."""
    root = Path(private_generation_root)
    if not root.is_absolute():
        raise ValueError("private_generation_root must be absolute")
    if set(managed_package_locations) != set(MANAGED_ORDER):
        raise ValueError("All and only the pinned managed packages are required")
    if any(not Path(path).is_absolute() for path in managed_package_locations.values()):
        raise ValueError("Managed package locations must be absolute")
    mods = tuple(user_mods)
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", mod.mod_id)
           or ".." in mod.mod_id for mod in mods):
        raise ValueError("User mod IDs must be safe portable identifiers")
    if any(not Path(mod.package_location).is_absolute() for mod in mods):
        raise ValueError("User package locations must be absolute")
    if len({mod.mod_id.casefold() for mod in mods}) != len(mods):
        raise ValueError("Duplicate user mod ID")
    if any(is_managed_package_id(mod.mod_id) for mod in mods):
        raise ValueError("Managed package IDs cannot be supplied as user mods")
    files = {
        "portable.txt": b"",
        f"Apps/{CLASSIC_APP_ID}/AppConfig.json": _json_bytes(
            _record(windows_game_path, Mode.CLASSIC, mods)),
        f"Apps/{ENHANCED_APP_ID}/AppConfig.json": _json_bytes(
            _record(windows_game_path, Mode.ENHANCED, mods)),
    }
    directories = ("Apps", "Mods", "User/Mods")
    return GeneratedReloadedConfig(
        root,
        MappingProxyType(dict(sorted(files.items()))),
        directories,
        MappingProxyType({key: str(managed_package_locations[key])
                          for key in MANAGED_ORDER}),
        MappingProxyType({mod.mod_id: str(mod.package_location)
                          for mod in sorted(mods, key=lambda item: item.mod_id.casefold())}),
    )


def generate_bootstrap_configuration(root: ValidatedWindowsGenerationPath) -> bytes:
    """Generate the bootstrap schema required by the reviewed Reloaded runtime tuple."""
    root.revalidate()
    base = PureWindowsPath(root.value)
    payload = {
        "LoaderPath32": str(base / "Loader" / "X86" / "Reloaded.Mod.Loader.dll"),
        "LoaderPath64": str(base / "Loader" / "X64" / "Reloaded.Mod.Loader.dll"),
        "LauncherPath": str(base / "Reloaded-II.exe"),
        "Bootstrapper32Path": str(base / "Loader" / "X86" / "Bootstrapper" /
                                  "Reloaded.Mod.Loader.Bootstrapper.dll"),
        "Bootstrapper64Path": str(base / "Loader" / "X64" / "Bootstrapper" /
                                  "Reloaded.Mod.Loader.Bootstrapper.dll"),
        "ApplicationConfigDirectory": str(base / "Apps"),
        "ModUserConfigDirectory": str(base / "User" / "Mods"),
        "MiscConfigDirectory": str(base / "User" / "Misc"),
        "PluginConfigDirectory": str(base / "Plugins"),
        "ModConfigDirectory": str(base / "Mods"),
        "EnabledPlugins": [],
        "LanguageFile": "en-GB.xaml",
        "ThemeFile": "Default.xaml",
        "FirstLaunch": False,
        "ShowConsole": True,
        "LogFileCompressTimeHours": 6,
        "LogFileDeleteHours": 336,
        "CrashDumpDeleteHours": 24,
        # No update feeds are delegated to Reloaded; Amethyst moves only
        # between complete reviewed compatibility generations.
        "NuGetFeeds": [],
        "ForceModPrereleases": False,
        "ReloadedProcessListRefreshInterval": 1000,
        "LoaderSetupTimeout": 30000,
        "LoaderSetupSleeptime": 32,
        "ProcessRefreshInterval": 200,
        "SkipWineLaunchWarning": True,
        "DisableDInput": False,
    }
    return _json_bytes(payload)
