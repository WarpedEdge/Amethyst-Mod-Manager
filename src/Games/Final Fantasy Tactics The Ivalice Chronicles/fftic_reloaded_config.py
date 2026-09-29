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


class Mode(str, Enum):
    CLASSIC = "classic"
    ENHANCED = "enhanced"


@dataclass(frozen=True)
class ValidatedSteamPath:
    value: str

    @classmethod
    def from_resolver(cls, value: str) -> "ValidatedSteamPath":
        """Accept only the production Steam-visible identity proved in Phase B2."""
        if not isinstance(value, str) or not re.match(
                r"^S:\\steamapps\\common\\[^\\]+$", value, re.IGNORECASE):
            raise ValueError(
                "FFTIC requires a resolver-validated S:\\steamapps\\common\\... path")
        return cls(value.rstrip("\\"))


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
    selected_mode: Mode
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
    selected_mode: Mode,
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
        selected_mode,
        MappingProxyType(dict(sorted(files.items()))),
        directories,
        MappingProxyType({key: str(managed_package_locations[key])
                          for key in MANAGED_ORDER}),
        MappingProxyType({mod.mod_id: str(mod.package_location)
                          for mod in sorted(mods, key=lambda item: item.mod_id.casefold())}),
    )
