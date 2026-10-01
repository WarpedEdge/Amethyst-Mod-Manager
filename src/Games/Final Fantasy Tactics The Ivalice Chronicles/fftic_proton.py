"""Read-only resolution of FFTIC's selected Steam compatibility tool."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


_TOOL_VERSION = re.compile(r"^[0-9]+\s+([A-Za-z0-9._+-]+)$")


@dataclass(frozen=True)
class ProtonSelection:
    proton_script: Path | None
    tool_identity: str
    prefix_runtime: str


def _selected_tool_identity(proton_script: Path | None) -> str:
    """Read the selected Proton installation's exact build identity."""
    if proton_script is None:
        return ""
    script = Path(proton_script).absolute()
    version_file = script.parent / "version"
    try:
        if (script.is_symlink() or not script.is_file()
                or script.resolve(strict=True) != script
                or version_file.is_symlink() or not version_file.is_file()
                or version_file.resolve(strict=True) != version_file.absolute()):
            return ""
        lines = version_file.read_text(
            encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return ""
    if len(lines) != 1:
        return ""
    match = _TOOL_VERSION.fullmatch(lines[0].strip())
    return match.group(1) if match else ""


def _prefix_runtime(prefix: Path | None) -> str:
    """Read the prefix schema/runtime version; never use it as tool identity."""
    if prefix is None:
        return ""
    try:
        from Utils.wine.prefix import resolve_compat_data
        version_file = resolve_compat_data(Path(prefix)) / "version"
        if version_file.is_symlink() or not version_file.is_file():
            return ""
        lines = version_file.read_text(
            encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return ""
    return lines[0].strip() if len(lines) == 1 else ""


def resolve_proton_selection(steam_id: str, prefix: Path | None) -> ProtonSelection:
    """Resolve Steam's selected Proton tool and independent prefix runtime."""
    from Utils.launchers.steam import find_proton_for_game

    try:
        proton_script = find_proton_for_game(steam_id)
    except Exception:
        proton_script = None
    return ProtonSelection(
        proton_script=Path(proton_script).absolute() if proton_script else None,
        tool_identity=_selected_tool_identity(proton_script),
        prefix_runtime=_prefix_runtime(prefix),
    )
