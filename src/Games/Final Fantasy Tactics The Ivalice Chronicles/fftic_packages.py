"""Pure recognition and validation of existing FFTIC Reloaded packages."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
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
    ".a",
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
    ENHANCED_MANAGED_CODE = "Enhanced managed Reloaded code/API mod"
    CLASSIC_MANAGED_CODE = "Classic managed Reloaded code/API mod"
    DUAL_MODE_MANAGED_CODE = "dual-mode managed Reloaded code/API mod"
    UNSUPPORTED_APPLICATION = "unsupported application"
    UNSUPPORTED_CODE = "unsupported native/external executable package"
    UNSUPPORTED_CONFIGURATION = "unsupported persistent mod configuration"
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
            PackageClassification.ENHANCED_MANAGED_CODE,
            PackageClassification.CLASSIC_MANAGED_CODE,
            PackageClassification.DUAL_MODE_MANAGED_CODE,
        }


# Unchanged author v3.3.0 GitHub asset 528229133; full inventory and static
# format/import review: FFTIC-Color-Customizer-3.3.0-Audit.md in the docs repo.
# This grants package retention only in the Windows x64 Reloaded/Proton host.
# Foreign RID files remain inert; Amethyst never loads them into native Python.
_COLOR_ID = "paxtrick.fft.colorcustomizer"
_COLOR_ARCHIVE_SIZE = 34_466_238
_COLOR_ARCHIVE_SHA256 = "faf854fd508e0095ee1c080b48d1adbb7ec557ce5433f894ea0d4ffb9cbd7005"
_COLOR_FILE_COUNT = 1323
_COLOR_TREE_SHA256 = "ec8559ecf7ae671b993646feade0c59fd964fb19c3279ca175a4440ae3b7be2a"
# Include every compiled member, including Windows support DLLs and WASM ar.
_COLOR_COMPILED_FILES = {
    'FFTColorCustomizer.dll': (1491968, '002f22efb95434662e7cc08753008afd0e91f3efd66b93f2d48f624694d9ecbe'),
    'Microsoft.Data.Sqlite.dll': (173088, '29981956955da36990b3cfc93fe50597eeacae669663e230bef519d5693bb2fb'),
    'Newtonsoft.Json.dll': (712464, '22c649f75fce5be7c7ccda8880473b634ef69ecf33f5d1ab8ad892caf47d5a07'),
    'Reloaded.Hooks.Definitions.dll': (59904, '6eff93e6eba62a441bc682812fdf169dedc8e9daec06cefc0a936da1611e2ba7'),
    'Reloaded.Hooks.ReloadedII.Interfaces.dll': (6144, 'b2661f2bc4a39a50ccd038b7b94201b422e53488ad5f4c6ef8caf337ff84d2be'),
    'Reloaded.Memory.SigScan.ReloadedII.Interfaces.dll': (5632, '9b470f74b372d3affa7da304901a1be1f17904d4d75d5c6b0df422b84c2ca99d'),
    'Reloaded.Memory.Sigscan.Definitions.dll': (6656, 'a433d3f9e5c752642cd0c5b70ae263a25fecbc70d2666cdddfcfa25eb71913cd'),
    'Reloaded.Memory.Sigscan.dll': (20480, '7d2acda95707add456513675111349b8c9496ea82d1120da9e72530de872895e'),
    'Reloaded.Memory.dll': (101888, '337fb8a9743289e0d31cc4d9aa98cfa3ca973acfbe346a3f5ccde44ff502eba7'),
    'Reloaded.Mod.Interfaces.dll': (22016, 'e287ee42b40ff2515aed997f5778a37b536e8404acfabea4a43bf3ca1d0f4ab9'),
    'Reloaded.Mod.Loader.IO.dll': (136704, '445ad0d809acbea84f495f0ea879442b6b3e9415e2166c401c1ed4f8e93dd595'),
    'SQLitePCLRaw.batteries_v2.dll': (5120, 'e2709fda3ee4137dcea3398221f0afcd6241db0ea6fa55fd31a33610be78cf02'),
    'SQLitePCLRaw.core.dll': (50688, 'c33995427edd44fa641cf702df8b63cc82cb7054dd984dc8277d15ee7c958874'),
    'SQLitePCLRaw.provider.e_sqlite3.dll': (36352, '2e7315a35cb86213200654b717f8cbe3c7643a6bec4a106f22fc8c744a94906c'),
    'e_sqlite3.dll': (1691648, 'dccbabb2bc7e7d4302c44d9ce41b70721a7d0914fa4d289e2f340d39766ad102'),
    'runtimes/browser-wasm/nativeassets/net8.0/e_sqlite3.a': (1122394, '01be7351d0d273d1516bdd96bd60453d1685b9bb177ae3e38b4c8e97ad5b3639'),
    'runtimes/linux-arm/native/libe_sqlite3.so': (827568, '851e33dfd50bcfac3b3317523d59e5897c1b41475f7c90d8d4b7666e409749ea'),
    'runtimes/linux-arm64/native/libe_sqlite3.so': (1285800, 'c159ef66bfed7fc5690c4fe6f2807027f627531538adeee7cdcc6d03ad0c662a'),
    'runtimes/linux-armel/native/libe_sqlite3.so': (1162812, '84606f9b96569fb9cb7e3d1549eb5bea685f5dd6cdba543e75edd4088874793e'),
    'runtimes/linux-mips64/native/libe_sqlite3.so': (1500256, '8309ddd190f301b936bc6d921f70d596064f34e76496d3880a7dd03d47d11130'),
    'runtimes/linux-musl-arm/native/libe_sqlite3.so': (1126664, '862d977ac6e1718c2fbf81f7ee7f73c86f91ed992112d8d699848a8cf72921b8'),
    'runtimes/linux-musl-arm64/native/libe_sqlite3.so': (1333800, '395f1b01ed51acac4d53e50ca7b80efd64bdb3c7ec64c985667f340e1eba9173'),
    'runtimes/linux-musl-x64/native/libe_sqlite3.so': (1228752, '12c1ae5551c2045efbe5231be42cad1a283dfbc2226022a39a83b77ee4ccc23b'),
    'runtimes/linux-ppc64le/native/libe_sqlite3.so': (1648888, '6bb95fa133e10254508fa623a9e4198a195b35d1e9c684dc1045af82fae5bc0c'),
    'runtimes/linux-s390x/native/libe_sqlite3.so': (1397832, '80968311d0c3e95d7ba3c46c7ba235ab84c697622124cc11f31a387251b2d7a1'),
    'runtimes/linux-x64/native/libe_sqlite3.so': (1249880, '14b1cd337aa1f6c64708e194fd3f5d467262a92a10d3da9724a8835d06567bd2'),
    'runtimes/linux-x86/native/libe_sqlite3.so': (1309268, 'c53204c3e467ad032f1c86650f5e46eb72ec275feca806e3d33998265e6f25d6'),
    'runtimes/maccatalyst-arm64/native/libe_sqlite3.dylib': (1091295, '5d4297bc345073af6ec432873bc26e84eb0afbd95e18a30e2ce16f3aacdcfa38'),
    'runtimes/maccatalyst-x64/native/libe_sqlite3.dylib': (1117336, '634c9fc110c6b84f4e29d6e507dda06e6a2bb3336570608c7c9d314bd3d0d9d1'),
    'runtimes/osx-arm64/native/libe_sqlite3.dylib': (1091359, 'fc6bb3a9aa7a83ec1936ff7a0418f2fc73f51b7acd5065911db2a94ee00259d2'),
    'runtimes/osx-x64/native/libe_sqlite3.dylib': (1116192, 'addd7a70661bca5eebc8eafca3b491722315149cf038b1b3f2f324703b289d8f'),
    'runtimes/win-arm/native/e_sqlite3.dll': (1192960, '6098739e729776b9a221e4266fd9b43fb8b04013fd2dff23b617d3202eafae38'),
    'runtimes/win-arm64/native/e_sqlite3.dll': (1485824, 'a56e35d6abac40a657e0445be007f6479b16b4f0566ca7b0b9a3e0794e87a969'),
    'runtimes/win-x64/native/e_sqlite3.dll': (1691648, 'dccbabb2bc7e7d4302c44d9ce41b70721a7d0914fa4d289e2f340d39766ad102'),
    'runtimes/win-x86/native/e_sqlite3.dll': (1308672, 'f80d5f5de3f7a82e684229028b946f6efa1682d27ec960ef18518542fd12a407'),
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
    if len({value.casefold() for value in result}) != len(result):
        errors.append(f'{key} contains duplicate or case-colliding identifiers.')
    return tuple(result)


def _safe_relative_path(path: str) -> bool:
    if (not path or "\\" in path or "\0" in path or ":" in path
            or any(ord(char) < 32 for char in path)):
        return False
    pure = PurePosixPath(path)
    return (not pure.is_absolute() and path == pure.as_posix()
            and all(part not in ("", ".", "..") and not part.endswith((' ', '.'))
                    and not any(c in part for c in '<>"|?*')
                    and part.split('.')[0].upper() not in {
                        'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                        *(f'LPT{i}' for i in range(1, 10))}
                    for part in pure.parts))


def is_managed_dll(path: Path) -> bool:
    """Static PE/CLR shape check, never a load or a claim that code is trustworthy.

    Require an x86/x64 DLL image, IL-only CLR header and mapped metadata signature. This separates
    managed user assemblies from undeclared native DLLs in the supported boundary.
    """
    try:
        with path.open('rb') as stream:
            size = path.stat().st_size
            def read(offset, count):
                if offset < 0 or offset + count > size:
                    raise ValueError('PE range')
                stream.seek(offset)
                value = stream.read(count)
                if len(value) != count:
                    raise ValueError('short PE')
                return value
            if read(0, 2) != b'MZ':
                return False
            pe = struct.unpack('<I', read(0x3c, 4))[0]
            header = read(pe, 24)
            if header[:4] != b'PE\0\0':
                return False
            sections = struct.unpack_from('<H', header, 6)[0]
            optional_size, flags = struct.unpack_from('<HH', header, 20)
            machine = struct.unpack_from('<H', header, 4)[0]
            if machine not in {0x14c, 0x8664} or not flags & 0x2000 or not 1 <= sections <= 96:
                return False
            optional = read(pe + 24, optional_size)
            magic = struct.unpack_from('<H', optional)[0]
            directory = 112 if magic == 0x20b else 96 if magic == 0x10b else -1
            if directory < 0 or optional_size < directory + 15 * 8:
                return False
            if struct.unpack_from('<I', optional, directory - 4)[0] < 15:
                return False
            rva, length = struct.unpack_from('<II', optional, directory + 14 * 8)
            section_table = read(pe + 24 + optional_size, sections * 40)
            def mapped(address, count):
                for i in range(sections):
                    virtual_size, virtual, raw_size, raw = struct.unpack_from('<IIII', section_table, i * 40 + 8)
                    delta = address - virtual
                    if 0 <= delta and delta + count <= min(virtual_size, raw_size):
                        return raw + delta
                raise ValueError('unmapped CLR')
            if length < 72:
                return False
            clr = read(mapped(rva, 72), 72)
            metadata_rva, metadata_size = struct.unpack_from('<II', clr, 8)
            clr_flags = struct.unpack_from('<I', clr, 16)[0]
            return (clr_flags & 1 and not clr_flags & 0x10
                    and struct.unpack_from('<I', clr)[0] >= 72 and metadata_size >= 4
                    and read(mapped(metadata_rva, metadata_size), 4) == b'BSJB')
    except (OSError, ValueError, struct.error):
        return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_reviewed_color_customizer_archive(archive: Path) -> bool:
    """Recognize only the unchanged ZIP bytes, never a version label or filename."""
    try:
        archive = Path(archive)
        info = archive.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_size == _COLOR_ARCHIVE_SIZE
                and _file_sha256(archive) == _COLOR_ARCHIVE_SHA256)
    except (OSError, TypeError):
        return False


def _is_reviewed_color_tree(root: Path, files: list[str], directories: list[str]) -> bool:
    # Called only AFTER the existing path, collision, link and special-file checks.
    # Full inventory prevents a known DLL/native set from blessing changed content,
    # manifests, absent members, or extra files/empty directories. No persisted
    # marker, caller flag, manifest assertion or cached result grants this policy.
    files = [path for path in files if path != "meta.ini"]
    if len(files) != _COLOR_FILE_COUNT:
        return False
    expected_dirs = {str(parent) for path in files for parent in PurePosixPath(path).parents
                     if str(parent) != "."}
    if set(directories) != expected_dirs:
        return False
    records = []
    compiled = {}
    try:
        for path in sorted(files):
            item = root / path
            size, digest = item.stat().st_size, _file_sha256(item)
            records.append(f"{path}\0{size}\0{digest}\n")
            if PurePosixPath(path).suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS:
                compiled[path] = (size, digest)
    except OSError:
        return False
    return (compiled == _COLOR_COMPILED_FILES
            and hashlib.sha256("".join(records).encode("utf-8")).hexdigest()
            == _COLOR_TREE_SHA256)


def validate_color_customizer_archive(root: Path, archive: Path | None) -> list[str]:
    """Check original ZIP identity at install; staged inspections use exact tree bytes.

    The package validator and profile-owned working-copy lifecycle remain mandatory.
    ZIP identity alone cannot grant lifecycle readiness.
    """
    result = inspect_package(root)
    if (result.manifest is None or result.manifest.mod_id.casefold() != _COLOR_ID
            or result.manifest.version != "3.3.0"):
        return []
    if archive is None or not is_reviewed_color_customizer_archive(archive):
        return ["Color Customizer archive is not the exact reviewed v3.3.0 ZIP "
                f"(SHA-256 {_COLOR_ARCHIVE_SHA256}); changed or repacked archives are refused."]
    return []


def inspect_package(root: Path) -> PackageResult:
    """Inspect an extracted package directory without modifying it."""
    root = Path(root)
    source = str(root)
    manifest_path = root / "ModConfig.json"
    if root.is_symlink() or not root.is_dir():
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: package root is missing or linked.",), ())
    try:
        manifest_mode = manifest_path.lstat().st_mode
    except OSError as exc:
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: cannot inspect ModConfig.json: {exc}",), ())
    if not stat.S_ISREG(manifest_mode) or manifest_path.lstat().st_nlink != 1:
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: ModConfig.json must be a regular non-symlink file.",), ())
    try:
        if manifest_path.stat().st_size > 1024 * 1024:
            raise ValueError("ModConfig.json exceeds 1 MiB")
        raw = manifest_path.read_text(encoding="utf-8")
        def unique_pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError(f'Duplicate manifest key: {key}')
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: cannot parse ModConfig.json: {exc}",), ())
    if not isinstance(data, dict):
        return PackageResult(PackageClassification.MALFORMED, None,
                             (f"{source}: ModConfig.json root must be an object.",), ())

    errors: list[str] = []
    mod_id = _string_field(data, "ModId", errors)
    if mod_id and (not _safe_identifier(mod_id) or not _safe_relative_path(mod_id)):
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
            if not _safe_relative_path(value):
                errors.append(f"{key} contains unsafe path {value!r}.")
            elif key.startswith("ModR2RManagedDll") and PurePosixPath(value).suffix.casefold() != ".dll":
                errors.append(f"{key} must name a managed DLL path.")

    package_files: list[str] = []
    package_directories: list[str] = []
    payloads: list[str] = []
    unsafe: list[str] = []
    seen_paths: dict[str, str] = {}
    try:
        for item in root.rglob("*"):
            rel = item.relative_to(root).as_posix()
            previous = seen_paths.setdefault(rel.casefold(), rel)
            if previous != rel:
                unsafe.append(f"{previous} / {rel} (case collision)")
            mode = item.lstat().st_mode
            if (not _safe_relative_path(rel) or not
                    (stat.S_ISREG(mode) or stat.S_ISDIR(mode))
                    or stat.S_ISREG(mode) and item.lstat().st_nlink != 1):
                unsafe.append(rel)
                continue
            if stat.S_ISDIR(mode):
                package_directories.append(rel)
            if stat.S_ISREG(mode):
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
                             tuple(f"{name} ({mod_id}) at {source}: {error}" for error in errors),
                             tuple(sorted(payloads)))
    if is_managed_package_id(mod_id):
        return PackageResult(PackageClassification.MANAGED_INTERNAL, manifest,
                             (f"{mod_id!r} is managed internally and cannot be a profile mod.",),
                             tuple(sorted(payloads)))
    supported_set = set(supported)
    unknown = supported_set - SUPPORTED_APP_IDS
    if not supported_set or unknown:
        exact = ", ".join(repr(value) for value in supported) or "<empty>"
        return PackageResult(PackageClassification.UNSUPPORTED_APPLICATION, manifest,
                             (f"{name} ({mod_id}) at {source}: SupportedAppId is not an "
                              f"FFTIC-only set: {exact}.",),
                             tuple(sorted(payloads)))
    compiled_files = [
        path for path in package_files
        if PurePosixPath(path).suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS
    ]
    declared_dll = data.get("ModDll") or ""
    native = [(key, value) for key, value in declarations
              if key in {"ModNativeDll32", "ModNativeDll64"}]
    forbidden = [path for path in compiled_files if PurePosixPath(path).suffix.casefold()
                 in {".a", ".asi", ".com", ".dylib", ".exe", ".scr", ".so"}]
    reviewed_color = (mod_id == _COLOR_ID and version == "3.3.0"
                      and _is_reviewed_color_tree(root, package_files, package_directories))
    if native or (forbidden and not reviewed_color):
        detail = [f"{key}={value!r}" for key, value in native]
        detail.extend(sorted(set(forbidden)))
        return PackageResult(PackageClassification.UNSUPPORTED_CODE, manifest,
                             (f"{name} ({mod_id}) at {source}: unsupported native/external executable: "
                              + ", ".join(detail),), tuple(sorted(payloads)))
    if not reviewed_color and not (mod_id.casefold() == _COLOR_ID and version == '3.3.0'):
        unknown_dlls = [p for p in compiled_files if PurePosixPath(p).suffix.casefold() == '.dll'
                        and not is_managed_dll(root / p)]
        scripts = [p for p in package_files if PurePosixPath(p).suffix.casefold() in {
            '.bat', '.cmd', '.ps1', '.sh', '.py', '.pyc', '.js', '.vbs', '.msi', '.wasm', '.jar'}]
        disguised = []
        for path in package_files:
            if path in compiled_files:
                continue
            with (root / path).open('rb') as stream:
                prefix = stream.read(4)
            if prefix.startswith((b'MZ', b'\x7fELF', b'#!', b'\x00asm', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')):
                disguised.append(path)
        if unknown_dlls or scripts or disguised:
            return PackageResult(PackageClassification.UNSUPPORTED_CODE, manifest,
                (f'{name} ({mod_id}): unknown native DLL or external code needs a separate policy: '
                 + ', '.join(unknown_dlls + scripts + disguised),), tuple(sorted(payloads)))
    if declared_dll:
        target = root / declared_dll
        if (declared_dll not in package_files or not target.is_file()
                or target.is_symlink() or target.suffix.casefold() != ".dll"):
            return PackageResult(PackageClassification.MALFORMED, manifest,
                                 (f"{name} ({mod_id}) at {source}: ModDll {declared_dll!r} "
                                  "must name an existing regular package DLL.",), tuple(sorted(payloads)))
        # The writable lifecycle applies only to the complete reviewed release.
        # A familiar ModId/version cannot authorize synthetic or edited code.
        if mod_id.casefold() == _COLOR_ID and version == "3.3.0" and not reviewed_color:
            return PackageResult(
                PackageClassification.UNSUPPORTED_CONFIGURATION, manifest,
                (f"{name} ({mod_id}) at {source}: Color Customizer requires the unchanged "
                 "reviewed 3.3.0 release; this package has not passed its exact payload policy.",),
                tuple(sorted(payloads)))
        kind = (PackageClassification.ENHANCED_MANAGED_CODE if supported_set == {ENHANCED_APP_ID}
                else PackageClassification.CLASSIC_MANAGED_CODE if supported_set == {CLASSIC_APP_ID}
                else PackageClassification.DUAL_MODE_MANAGED_CODE)
        return PackageResult(kind, manifest, (), tuple(sorted(payloads)))
    if any(key.startswith("ModR2RManagedDll") for key, _value in declarations):
        return PackageResult(PackageClassification.MALFORMED, manifest,
                             (f"{name} ({mod_id}) at {source}: managed DLL declarations "
                              "require an existing ModDll entry point.",), tuple(sorted(payloads)))
    undeclared_dlls = [path for path in compiled_files
                       if PurePosixPath(path).suffix.casefold() == ".dll"]
    if undeclared_dlls:
        return PackageResult(PackageClassification.UNSUPPORTED_CODE, manifest,
                             (f"{name} ({mod_id}) at {source}: {', '.join(undeclared_dlls)} "
                              "has no valid ModDll "
                              "declaration; user code requires a Reloaded manifest.",), tuple(sorted(payloads)))
    relevant = [p for p in payloads if p.casefold().startswith(("fftivc/data/", "fftivc/tables/"))]
    if not relevant:
        return PackageResult(PackageClassification.MALFORMED, manifest,
                             (f"{name} ({mod_id}) at {source}: FFTIVC/data or "
                              "FFTIVC/tables content is required.",),
                             tuple(sorted(payloads)))
    if supported_set == {ENHANCED_APP_ID}:
        kind = PackageClassification.ENHANCED_CONTENT
    elif supported_set == {CLASSIC_APP_ID}:
        kind = PackageClassification.CLASSIC_CONTENT
    else:
        kind = PackageClassification.DUAL_MODE_CONTENT
    return PackageResult(kind, manifest, (), tuple(sorted(payloads)))
