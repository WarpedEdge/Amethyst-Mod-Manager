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
    recommendation_is_composed: bool


def _safe_assignment(name: str, value: str) -> str:
    return f"{name}={shlex.quote(value)}"


def _has_unsafe_shell_syntax(text: str) -> bool:
    quote = ""
    escaped = False
    word_start = True
    for character in text:
        if character in "\r\n":
            return True
        if escaped:
            escaped = False
            word_start = False
            continue
        if quote == "'":
            if character == "'":
                quote = ""
            continue
        if character == "\\":
            escaped = True
            continue
        if quote == '"':
            if character == '"':
                quote = ""
            elif character in "$`":
                return True
            continue
        if character in "'\"":
            quote = character
            word_start = False
        elif character.isspace():
            word_start = True
        elif character == "#" and word_start:
            return True
        elif character in ";&|<>`()$":
            return True
        else:
            word_start = False
    return False


def _safe_composition(
    assignments_before: list[tuple[str, str]], arguments_after: list[str],
) -> str:
    before = [_safe_assignment(name, value)
              for name, value in assignments_before]
    required = [f'{name}="{value}"' for name, value in REQUIRED_VALUES.items()]
    after = [shlex.quote(value) for value in arguments_after]
    return " ".join((*before, *required, "%command%", *after))


def _conflict(original: str, diagnostic: str) -> SteamOptionsAnalysis:
    return SteamOptionsAnalysis(
        SteamOptionsStatus.CONFLICT, original, COPY_READY_OPTIONS,
        (diagnostic,
         "Unsafe or conflicting syntax could not be preserved automatically; "
         "the recommendation is the canonical safe replacement."),
        (), False)


def analyze_steam_launch_options(options: str | None) -> SteamOptionsAnalysis:
    original = options or ""
    if not original.strip():
        return SteamOptionsAnalysis(
            SteamOptionsStatus.MISSING, original, COPY_READY_OPTIONS,
            ("Steam Launch Options are empty; the canonical value is recommended.",),
            (), False)
    if _has_unsafe_shell_syntax(original):
        return _conflict(
            original, "The existing wrapper or shell syntax cannot be composed safely.")
    try:
        tokens = shlex.split(original, posix=True)
    except ValueError as exc:
        return _conflict(original, f"The existing syntax cannot be parsed safely: {exc}")
    command_indexes = [i for i, token in enumerate(tokens) if token == "%command%"]
    if len(command_indexes) != 1:
        return _conflict(
            original,
            f"Expected exactly one %command% placeholder; found {len(command_indexes)}.")
    command_index = command_indexes[0]
    assignments: dict[str, list[tuple[int, str]]] = {}
    unrelated: list[str] = []
    assignments_before: list[tuple[str, str]] = []
    arguments_after: list[str] = []
    for index, token in enumerate(tokens):
        if token == "%command%":
            continue
        match = _ASSIGNMENT.match(token)
        if match:
            assignments.setdefault(match.group(1), []).append((index, match.group(2)))
            if match.group(1) not in REQUIRED_VALUES:
                unrelated.append(token)
                if index < command_index:
                    assignments_before.append((match.group(1), match.group(2)))
                else:
                    arguments_after.append(token)
        else:
            unrelated.append(token)
            if index < command_index:
                return _conflict(
                    original,
                    f"Token before %command% may be a wrapper and cannot be proven safe: "
                    f"{token!r}.")
            arguments_after.append(token)
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
        return _conflict(original, " ".join(diagnostics))
    elif different:
        status = SteamOptionsStatus.DIFFERENT
    elif missing:
        status = SteamOptionsStatus.MISSING
    else:
        status = SteamOptionsStatus.CONFIGURED
        diagnostics.append("All required assignments and %command% placement are valid.")
    recommendation = _safe_composition(assignments_before, arguments_after)
    composed = recommendation != COPY_READY_OPTIONS
    if composed:
        diagnostics.append(
            "The recommendation safely composes the required assignments with "
            "the unrelated options shown separately; the original text is unchanged.")
    return SteamOptionsAnalysis(
        status, original, recommendation, tuple(diagnostics), tuple(unrelated), composed)
