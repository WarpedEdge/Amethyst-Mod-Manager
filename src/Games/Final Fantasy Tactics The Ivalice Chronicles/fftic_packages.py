"""Pure recognition and validation of existing FFTIC Reloaded packages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

CLASSIC_APP_ID = "fft_classic.exe"
ENHANCED_APP_ID = "fft_enhanced.exe"
SUPPORTED_APP_IDS = frozenset({CLASSIC_APP_ID, ENHANCED_APP_ID})
MANAGED_PACKAGE_IDS = frozenset({
    "Reloaded.Memory.SigScan.ReloadedII",
    "reloaded.sharedlib.hooks",
    "fftivc.utility.modloader",
})
MANAGED_PACKAGE_ID_KEYS = frozenset(value.casefold() for value in MANAGED_PACKAGE_IDS)
COMPILED_RUNTIME_EXTENSIONS = frozenset({
    ".asi",
    ".com",
    ".dll",
    ".dylib",
    ".exe",
    ".scr",
    ".so",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_CODE_FIELDS = (
    "ModDll", "ModR2RManagedDll32", "ModR2RManagedDll64",
    "ModNativeDll32", "ModNativeDll64",
)


class PackageClassification(str, Enum):
    ENHANCED_CONTENT = "Enhanced content mod"
    CLASSIC_CONTENT = "Classic content mod"
    DUAL_MODE_CONTENT = "dual-mode content mod"
    UNSUPPORTED_APPLICATION = "unsupported application"
    UNSUPPORTED_CODE = "unsupported compiled/runtime code mod"
    MALFORMED = "malformed package"
    MANAGED_INTERNAL = "managed internal package"


@dataclass(frozen=True)
class PackageManifest:
    source: str
    mod_id: str
    name: str
    author: str
    version: str
    dependencies: tuple[str, ...]
    optional_dependencies: tuple[str, ...]
    supported_app_ids: tuple[str, ...]
    managed_native_declarations: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class PackageResult:
    classification: PackageClassification
    manifest: PackageManifest | None
    diagnostics: tuple[str, ...]
    payload_paths: tuple[str, ...]

    @property
    def is_user_content(self) -> bool:
        return self.classification in {
            PackageClassification.ENHANCED_CONTENT,
            PackageClassification.CLASSIC_CONTENT,
            PackageClassification.DUAL_MODE_CONTENT,
        }


def _safe_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value)) and ".." not in value


def is_managed_package_id(value: str) -> bool:
    """Match reserved runtime package identities without changing diagnostics."""
    return value.casefold() in MANAGED_PACKAGE_ID_KEYS


def _string_field(data: dict, key: str, errors: list[str]) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{key} must be a non-empty string (received {value!r}).")
        return ""
    return value


def _identifier_list(data: dict, key: str, errors: list[str]) -> tuple[str, ...]:
    raw = data.get(key, [])
    if not isinstance(raw, list):
        errors.append(f"{key} must be a list (received {raw!r}).")
        return ()
    result: list[str] = []
    for value in raw:
        if not _safe_identifier(value):
            errors.append(f"{key} contains unsafe identifier {value!r}.")
        else:
            result.append(value)
    return tuple(result)


def _safe_relative_path(path: str) -> bool:
    if (not path or "\\" in path or "\0" in path or ":" in path
            or any(ord(char) < 32 for char in path)):
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and all(part not in ("", ".", "..") for part in pure.parts)


def inspect_package(root: Path) -> PackageResult:
    """Inspect an extracted package directory without modifying it."""
    root = Path(root)
    source = str(root)
    manifest_path = root / "ModConfig.json"
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: cannot parse ModConfig.json: {exc}",), ())
    if not isinstance(data, dict):
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: ModConfig.json root must be an object.",), ())

    errors: list[str] = []
    mod_id = _string_field(data, "ModId", errors)
    if mod_id and not _safe_identifier(mod_id):
        errors.append(f"ModId is unsafe: {mod_id!r}.")
    name = _string_field(data, "ModName", errors)
    author = _string_field(data, "ModAuthor", errors)
    version = _string_field(data, "ModVersion", errors)
    dependencies = _identifier_list(data, "ModDependencies", errors)
    optional_dependencies = _identifier_list(data, "OptionalDependencies", errors)
    supported = _identifier_list(data, "SupportedAppId", errors)

    declarations: list[tuple[str, str]] = []
    for key in _CODE_FIELDS:
        value = data.get(key, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            errors.append(f"{key} must be a string (received {value!r}).")
        elif value:
            declarations.append((key, value))
            normalized = value.replace("\\", "/")
            if not _safe_relative_path(normalized):
                errors.append(f"{key} contains unsafe path {value!r}.")

    package_files: list[str] = []
    payloads: list[str] = []
    unsafe: list[str] = []
    try:
        for item in root.rglob("*"):
            rel = item.relative_to(root).as_posix()
            if item.is_symlink() or not _safe_relative_path(rel):
                unsafe.append(rel)
                continue
            if item.is_file():
                package_files.append(rel)
                if rel.casefold().startswith("fftivc/"):
                    payloads.append(rel)
    except OSError as exc:
        errors.append(f"Cannot inspect package payload: {exc}")
    if unsafe:
        errors.extend(f"Unsafe package path: {path!r}." for path in sorted(unsafe))

    manifest = PackageManifest(
        source, mod_id, name, author, version, dependencies,
        optional_dependencies, supported, tuple(declarations),
    )
    if errors:
        return PackageResult(PackageClassification.MALFORMED, manifest,
                             tuple(errors), tuple(sorted(payloads)))
    if is_managed_package_id(mod_id):
        return PackageResult(PackageClassification.MANAGED_INTERNAL, manifest,
                             (f"{mod_id!r} is managed internally and cannot be a profile mod.",),
                             tuple(sorted(payloads)))
    supported_set = set(supported)
    unknown = supported_set - SUPPORTED_APP_IDS
    if not supported_set or unknown:
        exact = ", ".join(repr(value) for value in supported) or "<empty>"
        return PackageResult(PackageClassification.UNSUPPORTED_APPLICATION, manifest,
                             (f"SupportedAppId is not an FFTIC-only set: {exact}.",),
                             tuple(sorted(payloads)))
    compiled_files = [
        path for path in package_files
        if PurePosixPath(path).suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS
    ]
    if declarations or compiled_files:
        detail = [f"{key}={value!r}" for key, value in declarations]
        detail.extend(sorted(set(compiled_files)))
        return PackageResult(PackageClassification.UNSUPPORTED_CODE, manifest,
                             ("Compiled/runtime code is outside the supported content-mod scope: "
                              + ", ".join(detail),), tuple(sorted(payloads)))
    relevant = [p for p in payloads if p.casefold().startswith(("fftivc/data/", "fftivc/tables/"))]
    if not relevant:
        return PackageResult(PackageClassification.MALFORMED, manifest,
                             ("FFTIVC/data or FFTIVC/tables content is required.",),
                             tuple(sorted(payloads)))
    if supported_set == {ENHANCED_APP_ID}:
        kind = PackageClassification.ENHANCED_CONTENT
    elif supported_set == {CLASSIC_APP_ID}:
        kind = PackageClassification.CLASSIC_CONTENT
    else:
        kind = PackageClassification.DUAL_MODE_CONTENT
    return PackageResult(kind, manifest, (), tuple(sorted(payloads)))
