"""Read-only resolution of FFTIC's selected Steam compatibility tool."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


_TOOL_VERSION = re.compile(r"^[0-9]+\s+([A-Za-z0-9._+-]+)$")
_VDF_TOKEN = re.compile(r'\s*(?:"((?:\\.|[^"\\])*)"|([{}]))', re.DOTALL)
_SAFE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_OFFICIAL_IDENTITY = re.compile(
    r"(?:experimental|proton)-[0-9]+\.[0-9]+-[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
_STABLE_MAPPING = re.compile(r"proton_([0-9]+)\Z")
_OFFICIAL_DIRECTORY = re.compile(r"Proton [0-9]+\.0\Z")


def _vdf_tokens(contents: str) -> list[tuple[str, str]] | None:
    tokens: list[tuple[str, str]] = []
    offset = 0
    while offset < len(contents):
        while offset < len(contents) and contents[offset].isspace():
            offset += 1
        if contents.startswith("//", offset):
            newline = contents.find("\n", offset)
            offset = len(contents) if newline < 0 else newline + 1
            continue
        if offset == len(contents):
            break
        match = _VDF_TOKEN.match(contents, offset)
        if match is None:
            if contents[offset:].strip():
                return None
            break
        tokens.append(("value", match.group(1)) if match.group(1) is not None
                      else ("brace", match.group(2)))
        offset = match.end()
    return tokens


def _vdf_object(tokens: list[tuple[str, str]], start: int = 0,
                nested: bool = False) -> tuple[dict, int]:
    result = {}
    index = start
    while index < len(tokens):
        kind, key = tokens[index]
        if (kind, key) == ("brace", "}"):
            if not nested:
                raise ValueError("Unexpected VDF close brace")
            return result, index + 1
        if kind != "value" or index + 1 >= len(tokens) or key in result:
            raise ValueError("Malformed or duplicate VDF key")
        next_kind, value = tokens[index + 1]
        if (next_kind, value) == ("brace", "{"):
            result[key], index = _vdf_object(tokens, index + 2, True)
        elif next_kind == "value":
            result[key], index = value, index + 2
        else:
            raise ValueError("Malformed VDF value")
    if nested:
        raise ValueError("Unclosed VDF object")
    return result, index


def _parse_vdf(contents: str) -> dict | None:
    tokens = _vdf_tokens(contents)
    if tokens is None:
        return None
    try:
        data, end = _vdf_object(tokens)
    except ValueError:
        return None
    return data if end == len(tokens) else None


def _steam_app_manifest_matches(contents: str, directory: str,
                                filename: str | None = None) -> bool:
    data = _parse_vdf(contents)
    app = data.get("AppState") if isinstance(data, dict) else None
    return (isinstance(app, dict) and len(data) == 1
            and str(app.get("appid", "")).isdigit()
            and int(app["appid"]) > 0
            and app.get("installdir") == directory
            and (filename is None or filename == f"appmanifest_{app['appid']}.acf"))


def _canonical_selected_script(script: Path) -> bool:
    script = Path(script).absolute()
    return (script.name == "proton" and script.is_file()
            and not script.is_symlink() and script.resolve(strict=True) == script)


def _steam_managed_tool(script: Path, identity: str) -> bool:
    script = Path(script).absolute()
    if (not _canonical_selected_script(script)
            or script.parent.parent.name != "common"
            or script.parent.parent.parent.name != "steamapps"
            or (script.parent.name != "Proton - Experimental"
                and not _OFFICIAL_DIRECTORY.fullmatch(script.parent.name))
            or _selected_tool_identity(script) != identity):
        return False
    if script.parent.name == "Proton - Experimental":
        if not identity.startswith("experimental-"):
            return False
    else:
        major = script.parent.name.split()[1].split(".")[0]
        if not identity.startswith(f"proton-{major}.0-"):
            return False
    steamapps = script.parent.parent.parent
    manifests = list(steamapps.glob("appmanifest_*.acf"))
    for manifest in manifests:
        try:
            if (manifest.is_symlink() or not manifest.is_file()
                    or manifest.resolve(strict=True) != manifest.absolute()):
                continue
            contents = manifest.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            continue
        if _steam_app_manifest_matches(contents, script.parent.name, manifest.name):
            return True
    return False


def _mapping_name(contents: str, steam_id: str) -> str:
    data = _parse_vdf(contents)
    if not isinstance(data, dict):
        return ""
    found = []

    def visit(value):
        if not isinstance(value, dict):
            return
        mapping = value.get("CompatToolMapping")
        if isinstance(mapping, dict):
            found.append(mapping)
        for child in value.values():
            visit(child)

    visit(data)
    if len(found) != 1:
        return ""
    mapping = found[0]
    entry = mapping.get(steam_id)
    name = entry.get("name") if isinstance(entry, dict) else None
    return name if isinstance(name, str) and name else ""


def _selected_mapping(steam_id: str, roots: tuple[Path, ...]) -> str:
    names = set()
    for root in roots:
        config = Path(root) / "config/config.vdf"
        if not config.exists():
            continue
        try:
            if (config.is_symlink() or not config.is_file()
                    or config.resolve(strict=True) != config.absolute()):
                return ""
            contents = config.read_text(encoding="utf-8", errors="strict")
            if _parse_vdf(contents) is None:
                return ""
            name = _mapping_name(contents, steam_id)
        except (OSError, UnicodeError, RuntimeError):
            return ""
        if name:
            names.add(name)
    return next(iter(names)) if len(names) == 1 else ""


def _official_directories(name: str) -> tuple[str, ...]:
    if name == "proton_experimental":
        return ("Proton - Experimental",)
    match = _STABLE_MAPPING.fullmatch(name)
    if match:
        major = int(match.group(1))
        return (f"Proton {major}.0",)
    return ()


def _steam_selected_script(steam_id: str) -> tuple[Path | None, str]:
    """Resolve an explicit per-game Steam mapping, never stale config_info."""
    from Utils.launchers import steam

    roots = tuple(dict.fromkeys(Path(root).resolve() for root in steam._STEAM_CANDIDATES))
    mapping = _selected_mapping(steam_id, roots)
    directories = _official_directories(mapping)
    if not directories:
        return None, mapping
    for directory in directories:
        candidates = []
        for root in steam._all_proton_search_roots():
            script = Path(root) / "steamapps/common" / directory / "proton"
            if _canonical_selected_script(script):
                candidates.append(script.absolute())
        candidates = list(dict.fromkeys(candidates))
        if len(candidates) == 1:
            return candidates[0], mapping
        if len(candidates) > 1:
            return None, mapping
    return None, mapping


def supported_runner(identity: str, script: Path | None = None) -> bool:
    """Classify safe Steam-managed Proton evidence, without claiming game compatibility."""
    if (not isinstance(identity, str) or not _SAFE_IDENTITY.fullmatch(identity)
            or not _OFFICIAL_IDENTITY.fullmatch(identity)):
        return False
    if script is None:
        return True  # Historical receipt identity syntax; no live tool claim.
    try:
        return _steam_managed_tool(script, identity)
    except (OSError, RuntimeError, ValueError):
        return False


@dataclass(frozen=True)
class ProtonSelection:
    proton_script: Path | None
    tool_identity: str
    prefix_runtime: str
    steam_mapping: str = ""


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
    """Resolve Steam's per-game mapping and independent prefix runtime."""
    try:
        proton_script, mapping = _steam_selected_script(steam_id)
    except Exception:
        proton_script, mapping = None, ""
    return ProtonSelection(
        proton_script=Path(proton_script).absolute() if proton_script else None,
        tool_identity=_selected_tool_identity(proton_script),
        prefix_runtime=_prefix_runtime(prefix),
        steam_mapping=mapping,
    )
