"""Read-only FFTIC installation and compatibility detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

STEAM_APP_ID = "1004640"
VERIFIED_STEAM_BUILD = "24304444"
VERIFIED_UI_VERSION = "v1.5.2"
EXECUTABLES = {
    "classic": "FFT_classic.exe",
    "enhanced": "FFT_enhanced.exe",
}
VERIFIED_HASHES = {
    "classic": "7cfcd294830b315248114c42f14ac7b1a2f35ba835c0cef8314d480601d15a9f",
    "enhanced": "937233f7fe76182a665c487c8802f5cec6662ddd09967e87cd09fb146fc6b5d5",
}


class InstallStatus(str, Enum):
    NOT_FOUND = "game not found"
    INCOMPLETE = "incomplete installation"
    EXACT_VERIFIED = "exact verified tuple"
    UNVERIFIED = "installed but unverified executable tuple"


@dataclass(frozen=True)
class InstallationDetection:
    status: InstallStatus
    game_root: Path | None
    steam_build: str | None
    ui_version: str | None
    executable_hashes: tuple[tuple[str, str], ...]
    missing_executables: tuple[str, ...]
    diagnostics: tuple[str, ...]


class ExecutableHashCache:
    """Session cache invalidated by path, size and nanosecond mtime."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[int, int, str]] = {}

    def sha256(self, path: Path) -> str:
        stat = path.stat()
        key = str(path.resolve())
        cached = self._values.get(key)
        identity = (stat.st_size, stat.st_mtime_ns)
        if cached is not None and cached[:2] == identity:
            return cached[2]
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        value = digest.hexdigest()
        self._values[key] = (identity[0], identity[1], value)
        return value


def detect_installation(
    game_root: Path | None,
    *,
    steam_build: str | None = None,
    ui_version: str | None = None,
    hash_cache: ExecutableHashCache | None = None,
) -> InstallationDetection:
    """Classify an installation.  Hashes are cached for the calling session."""
    if game_root is None or not Path(game_root).is_dir():
        return InstallationDetection(
            InstallStatus.NOT_FOUND, None, steam_build, ui_version, (), (),
            ("FFTIC installation directory was not found.",),
        )
    root = Path(game_root)
    resolved: dict[str, Path] = {}
    try:
        entries = {entry.name.casefold(): entry for entry in root.iterdir()}
    except OSError as exc:
        return InstallationDetection(
            InstallStatus.NOT_FOUND, root, steam_build, ui_version, (), (),
            (f"Cannot inspect FFTIC installation: {exc}",),
        )
    missing: list[str] = []
    for mode, name in EXECUTABLES.items():
        candidate = entries.get(name.casefold())
        if candidate is None or not candidate.is_file():
            missing.append(name)
        else:
            resolved[mode] = candidate
    if missing:
        return InstallationDetection(
            InstallStatus.INCOMPLETE, root, steam_build, ui_version, (),
            tuple(missing),
            ("Both Classic and Enhanced executables are required.",),
        )
    cache = hash_cache or ExecutableHashCache()
    try:
        hashes = tuple((mode, cache.sha256(resolved[mode])) for mode in EXECUTABLES)
    except OSError as exc:
        return InstallationDetection(
            InstallStatus.INCOMPLETE, root, steam_build, ui_version, (), (),
            (f"Cannot read an FFTIC executable: {exc}",),
        )
    exact_hashes = all(dict(hashes)[mode] == VERIFIED_HASHES[mode] for mode in EXECUTABLES)
    exact_build = steam_build == VERIFIED_STEAM_BUILD
    exact_ui = ui_version == VERIFIED_UI_VERSION
    if exact_hashes and exact_build and exact_ui:
        return InstallationDetection(
            InstallStatus.EXACT_VERIFIED, root, steam_build, ui_version,
            hashes, (), ("Executable hashes and Steam build match the tested tuple.",),
        )
    reasons: list[str] = []
    if not exact_hashes:
        reasons.append("One or both executable hashes are not in the supported tuple.")
    if not exact_build:
        reasons.append(
            f"Steam build {steam_build or '<unknown>'} is not verified build {VERIFIED_STEAM_BUILD}.")
    if not exact_ui:
        reasons.append(
            f"UI version {ui_version!r} is not verified version {VERIFIED_UI_VERSION!r}.")
    return InstallationDetection(
        InstallStatus.UNVERIFIED, root, steam_build, ui_version, hashes, (),
        tuple(reasons),
    )
