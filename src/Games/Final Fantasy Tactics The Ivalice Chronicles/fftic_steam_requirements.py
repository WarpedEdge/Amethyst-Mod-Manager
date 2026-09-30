"""Pure analysis of FFTIC's required Steam Launch Options."""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from enum import Enum

REQUIRED_VALUES = {
    "WINEDLLOVERRIDES": "version=n,b",
    "DOTNET_ROOT": r"C:\Program Files\dotnet",
    "DOTNET_BUNDLE_EXTRACT_BASE_DIR": r"C:\users\steamuser\AppData\Local\Temp\.net",
}
COPY_READY_OPTIONS = (
    'WINEDLLOVERRIDES="version=n,b" '
    'DOTNET_ROOT="C:\\Program Files\\dotnet" '
    'DOTNET_BUNDLE_EXTRACT_BASE_DIR="C:\\users\\steamuser\\AppData\\Local\\Temp\\.net" '
    '%command%'
)
REQUIRED_OPTIONS_SHA256 = hashlib.sha256(COPY_READY_OPTIONS.encode("utf-8")).hexdigest()
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_SHELL_META = re.compile(
    r"(?:^|\s)(?:env|sh|bash|gamescope|gamemoderun|mangohud)(?:\s|$)|[;&|<>`]|\$\(")


class SteamOptionsStatus(str, Enum):
    CONFIGURED = "Configured"
    MISSING = "Missing"
    DIFFERENT = "Different"
    CONFLICT = "Conflict"


@dataclass(frozen=True)
class SteamOptionsAnalysis:
    status: SteamOptionsStatus
    original: str
    required_copy_text: str
    diagnostics: tuple[str, ...]
    preserved_unrelated: tuple[str, ...]


def analyze_steam_launch_options(options: str | None) -> SteamOptionsAnalysis:
    original = options or ""
    if not original.strip():
        return SteamOptionsAnalysis(
            SteamOptionsStatus.MISSING, original, COPY_READY_OPTIONS,
            ("Steam Launch Options are empty.",), ())
    if _SHELL_META.search(original):
        return SteamOptionsAnalysis(
            SteamOptionsStatus.CONFLICT, original, COPY_READY_OPTIONS,
            ("The existing wrapper or shell syntax cannot be composed safely.",), ())
    try:
        tokens = shlex.split(original, posix=True)
    except ValueError as exc:
        return SteamOptionsAnalysis(
            SteamOptionsStatus.CONFLICT, original, COPY_READY_OPTIONS,
            (f"The existing syntax cannot be parsed safely: {exc}",), ())
    command_indexes = [i for i, token in enumerate(tokens) if token == "%command%"]
    if len(command_indexes) != 1:
        return SteamOptionsAnalysis(
            SteamOptionsStatus.CONFLICT, original, COPY_READY_OPTIONS,
            (f"Expected exactly one %command% placeholder; found {len(command_indexes)}.",), ())
    command_index = command_indexes[0]
    assignments: dict[str, list[tuple[int, str]]] = {}
    unrelated: list[str] = []
    for index, token in enumerate(tokens):
        if token == "%command%":
            continue
        match = _ASSIGNMENT.match(token)
        if match:
            assignments.setdefault(match.group(1), []).append((index, match.group(2)))
            if match.group(1) not in REQUIRED_VALUES:
                unrelated.append(token)
        else:
            unrelated.append(token)
            if index < command_index:
                return SteamOptionsAnalysis(
                    SteamOptionsStatus.CONFLICT, original, COPY_READY_OPTIONS,
                    (f"Token before %command% may be a wrapper and cannot be proven safe: {token!r}.",),
                    tuple(unrelated))
    diagnostics: list[str] = []
    conflict = False
    different = False
    missing = False
    for name, expected in REQUIRED_VALUES.items():
        values = assignments.get(name, [])
        if not values:
            missing = True
            diagnostics.append(f"Missing required assignment {name}.")
            continue
        if len(values) != 1:
            conflict = True
            diagnostics.append(f"{name} is assigned more than once.")
            continue
        index, actual = values[0]
        if index > command_index:
            different = True
            diagnostics.append(f"{name} must be assigned before %command%.")
        if actual != expected:
            if name == "WINEDLLOVERRIDES":
                conflict = True
                diagnostics.append(
                    f"WINEDLLOVERRIDES conflicts: expected {expected!r}, found {actual!r}.")
            else:
                different = True
                diagnostics.append(f"{name} has a different value: {actual!r}.")
    if conflict:
        status = SteamOptionsStatus.CONFLICT
    elif different:
        status = SteamOptionsStatus.DIFFERENT
    elif missing:
        status = SteamOptionsStatus.MISSING
    else:
        status = SteamOptionsStatus.CONFIGURED
        diagnostics.append("All required assignments and %command% placement are valid.")
    return SteamOptionsAnalysis(
        status, original, COPY_READY_OPTIONS, tuple(diagnostics), tuple(unrelated))
