"""Read-only verification of FFTIC's Steam-created Windows ``S:`` identity."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    from .fftic_detection import EXECUTABLES, STEAM_APP_ID
    from .fftic_reloaded_config import ValidatedSteamPath, ValidatedWindowsGenerationPath
except ImportError:
    from fftic_detection import EXECUTABLES, STEAM_APP_ID
    from fftic_reloaded_config import ValidatedSteamPath, ValidatedWindowsGenerationPath


class SteamPathError(RuntimeError):
    pass


@dataclass(frozen=True)
class SteamPathResolution:
    steam_library: Path
    game_root: Path
    prefix: Path
    drive_mapping: Path
    installed_directory: str
    windows_game_path: ValidatedSteamPath


def _manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf'"{re.escape(key)}"\s+"([^"]+)"', text, re.IGNORECASE)
    return match.group(1) if match else None


def resolve_steam_s_path(
    *, steam_library: Path, app_manifest: Path, game_root: Path, prefix: Path,
) -> SteamPathResolution:
    """Verify, never create, the mapping used by the proven Reloaded records."""
    library = Path(steam_library).resolve()
    root = Path(game_root).resolve()
    prefix = Path(prefix).resolve()
    try:
        manifest = Path(app_manifest).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise SteamPathError(f"Cannot read Steam app manifest: {exc}") from exc
    if _manifest_value(manifest, "appid") != STEAM_APP_ID:
        raise SteamPathError(f"Steam manifest is not for app {STEAM_APP_ID}")
    installed = _manifest_value(manifest, "installdir")
    if not installed or any(value in installed for value in ("/", "\\", "..")):
        raise SteamPathError("Steam manifest has an unsafe or missing installdir")
    expected_root = (library / "steamapps" / "common" / installed).resolve()
    if root != expected_root:
        raise SteamPathError(
            f"Selected game root {root} does not match manifest root {expected_root}")
    drive = prefix / "dosdevices" / "s:"
    if not drive.is_symlink():
        raise SteamPathError(f"The owning prefix has no verified S: mapping at {drive}")
    try:
        mapping = drive.resolve(strict=True)
    except OSError as exc:
        raise SteamPathError(f"The S: mapping is broken: {exc}") from exc
    # Steam/Proton maps S: to the selected library root. A mapping to steamapps
    # or the game itself is a different identity and is rejected.
    if mapping != library:
        raise SteamPathError(
            f"S: maps to {mapping}, not the selected Steam library {library}")
    for executable in EXECUTABLES.values():
        target = root / executable
        if target.is_symlink() or not target.is_file():
            raise SteamPathError(f"Required FFTIC executable is missing: {target}")
    windows = ValidatedSteamPath.from_resolver(
        rf"S:\steamapps\common\{installed}")
    return SteamPathResolution(library, root, prefix, mapping, installed, windows)


def resolve_prefix_generation_path(*, prefix: Path,
                                   host_generation_root: Path) -> ValidatedWindowsGenerationPath:
    """Prove that a host generation directory is the same prefix-local ``C:`` path."""
    raw_prefix = Path(prefix)
    raw_root = Path(host_generation_root)
    if raw_prefix.is_symlink() or raw_root.is_symlink():
        raise SteamPathError("Prefix and generation roots cannot be symbolic links")
    prefix = raw_prefix.resolve(strict=True)
    drive_c = (prefix / "drive_c").resolve(strict=True)
    root = raw_root.resolve(strict=True)
    if not drive_c.is_dir() or not root.is_dir() or not root.is_relative_to(drive_c):
        raise SteamPathError("Managed generation must be a directory below the selected prefix C: drive")
    current = raw_root
    while current != raw_prefix and current != current.parent:
        if current.is_symlink():
            raise SteamPathError(f"Managed generation path crosses a symbolic link: {current}")
        current = current.parent
    if current != raw_prefix:
        raise SteamPathError("Managed generation does not belong to the selected prefix")
    relative = root.relative_to(drive_c)
    if not relative.parts:
        raise SteamPathError("Managed generation cannot be the C: drive root")
    windows = "C:\\" + "\\".join(relative.parts)
    return ValidatedWindowsGenerationPath._from_resolved(windows, prefix, root)
