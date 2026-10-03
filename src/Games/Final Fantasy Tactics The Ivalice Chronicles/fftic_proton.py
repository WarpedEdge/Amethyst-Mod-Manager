"""Read-only resolution of FFTIC's selected Steam compatibility tool."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


_TOOL_VERSION = re.compile(r"^[0-9]+\s+([A-Za-z0-9._+-]+)$")
_EXPERIMENTAL_11 = re.compile(r"experimental-11\.0-(20[0-9]{6})-x86_64\Z")
_VDF_TOKEN = re.compile(r'\s*(?:"((?:\\.|[^"\\])*)"|([{}]))', re.DOTALL)


def _experimental_manifest_matches(contents: str) -> bool:
    """Read only the two immediate AppState fields needed to identify app 1493710."""
    tokens: list[tuple[str, str]] = []
    offset = 0
    while offset < len(contents):
        match = _VDF_TOKEN.match(contents, offset)
        if match is None:
            if contents[offset:].strip():
                return False
            break
        tokens.append(("value", match.group(1)) if match.group(1) is not None
                      else ("brace", match.group(2)))
        offset = match.end()
    if tokens[:2] != [("value", "AppState"), ("brace", "{")]:
        return False
    fields: dict[str, str] = {}
    depth = 1
    index = 2
    while index < len(tokens):
        kind, value = tokens[index]
        if kind == "brace" and value == "}":
            depth -= 1
            if depth == 0:
                return (index == len(tokens) - 1
                        and fields.get("appid") == "1493710"
                        and fields.get("installdir") == "Proton - Experimental")
            index += 1
            continue
        if kind != "value" or index + 1 >= len(tokens):
            return False
        next_kind, next_value = tokens[index + 1]
        if next_kind == "brace" and next_value == "{":
            depth += 1
        elif next_kind == "value":
            if depth == 1 and value in {"appid", "installdir"}:
                if value in fields:
                    return False
                fields[value] = next_value
        else:
            return False
        index += 2
    return False


def supported_runner(identity: str, script: Path | None = None) -> bool:
    """Accept Steam's canonical Experimental 11.0 series from the reviewed baseline.

    A caller with a selected script must also prove its Steam installation shape;
    compatibilitytools.d and arbitrary executables are never inferred compatible.
    """
    if not isinstance(identity, str):
        return False
    match = _EXPERIMENTAL_11.fullmatch(identity)
    if match is None or match.group(1) < "20260924":
        return False
    try:
        datetime.strptime(match.group(1), "%Y%m%d")
    except ValueError:
        return False
    if script is None:
        return True  # Isolated evidence providers validate identity separately.
    script = Path(script).absolute()
    if not (script.name == "proton" and script.parent.name == "Proton - Experimental"
            and script.parent.parent.name == "common"
            and script.parent.parent.parent.name == "steamapps"
            and _selected_tool_identity(script) == identity):
        return False
    manifest = script.parent.parent.parent / "appmanifest_1493710.acf"
    try:
        if (manifest.is_symlink() or not manifest.is_file()
                or manifest.resolve(strict=True) != manifest.absolute()):
            return False
        contents = manifest.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return False
    return _experimental_manifest_matches(contents)


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
