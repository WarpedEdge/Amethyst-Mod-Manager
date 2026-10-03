"""Strict archive validation and isolated extraction for reviewed FFTIC inputs."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

try:
    from .fftic_artifacts import ARTIFACTS, REVIEWED_LOADER_UPDATE, ArtifactPin, validate_file
except ImportError:
    from fftic_artifacts import ARTIFACTS, REVIEWED_LOADER_UPDATE, ArtifactPin, validate_file


class ExtractionError(RuntimeError):
    pass


class ExtractionCancelled(ExtractionError):
    pass


_PROVENANCE_TOKEN = object()


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    kind: str = "file"  # file, directory, symlink, hardlink, device, fifo, socket
    size: int = 0


@dataclass(frozen=True)
class ExtractedArchive:
    root: Path
    files: tuple[str, ...]


@dataclass(frozen=True)
class ExtractionLimits:
    member_count: int
    total_expanded_size: int
    largest_member_size: int


@dataclass(frozen=True)
class ExtractedFileIdentity:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class VerifiedArtifactTree:
    pin: ArtifactPin
    archive_path: Path
    root: Path
    files: tuple[ExtractedFileIdentity, ...]
    content_identity: str
    _attestation: object

    def revalidate(self) -> None:
        if self._attestation is not _PROVENANCE_TOKEN:
            raise ExtractionError("Artifact tree was not produced by the verified extractor")
        if not validate_file(self.pin, self.archive_path):
            raise ExtractionError(f"Pinned archive identity changed: {self.archive_path}")
        observed = _tree_identities(self.root)
        if observed != self.files or _tree_digest(observed) != self.content_identity:
            raise ExtractionError(f"Extracted artifact tree changed: {self.root}")


# Exact observed bounds from the reviewed release archives. Because the archive
# digest is also mandatory, these are compatibility facts rather than generic
# permissive bomb limits.
REVIEWED_EXTRACTION_LIMITS = {
    "reloaded-ii": ExtractionLimits(218, 46_488_482, 6_709_760),
    "nenkai-loader": ExtractionLimits(330, 8_459_152, 2_100_736),
    "sigscan": ExtractionLimits(9, 213_550, 160_120),
    "shared-hooks": ExtractionLimits(35, 3_656_160, 1_159_168),
}
LOADER_UPDATE_LIMITS = ExtractionLimits(340, 9_000_000, 2_200_000)


def validate_archive_members(members: list[ArchiveMember] | tuple[ArchiveMember, ...]) -> tuple[str, ...]:
    """Return normalized names or reject every ambiguous/unsafe member shape."""
    seen: dict[str, str] = {}
    names: list[str] = []
    for member in members:
        raw = member.name
        if not raw or "\0" in raw or "\\" in raw:
            raise ExtractionError(f"Unsafe or backslash-ambiguous archive member: {raw!r}")
        windows = PureWindowsPath(raw)
        pure = PurePosixPath(raw)
        parts = pure.parts
        if windows.drive or pure.is_absolute() or raw.startswith("/"):
            raise ExtractionError(f"Absolute or drive-qualified archive member: {raw!r}")
        if any(part in ("", ".", "..") or ":" in part for part in parts):
            raise ExtractionError(f"Traversing archive member: {raw!r}")
        if member.kind not in {"file", "directory"}:
            raise ExtractionError(f"Unsupported archive member type {member.kind}: {raw!r}")
        normalized = "/".join(parts).rstrip("/")
        key = normalized.casefold()
        if key in seen:
            detail = "duplicate" if seen[key] == normalized else "case-fold collision"
            raise ExtractionError(f"Archive {detail}: {seen[key]!r} and {normalized!r}")
        seen[key] = normalized
        names.append(normalized)
    return tuple(names)


def _validate_limits(members: tuple[ArchiveMember, ...], limits: ExtractionLimits) -> None:
    if len(members) > limits.member_count:
        raise ExtractionError("Archive exceeds its reviewed member-count bound")
    sizes = [member.size for member in members if member.kind == "file"]
    if any(size < 0 or size > limits.largest_member_size for size in sizes):
        raise ExtractionError("Archive member exceeds its reviewed expanded-size bound")
    if sum(sizes) > limits.total_expanded_size:
        raise ExtractionError("Archive exceeds its reviewed total expanded-size bound")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_identities(root: Path) -> tuple[ExtractedFileIdentity, ...]:
    return tuple(ExtractedFileIdentity(item, (root / item).stat().st_size, _sha256(root / item))
                 for item in _post_validate(root))


def _tree_digest(files: tuple[ExtractedFileIdentity, ...]) -> str:
    payload = "".join(f"{item.path}\0{item.size}\0{item.sha256}\n" for item in files)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reject_symlink_ancestors(path: Path) -> None:
    current = path.absolute()
    while current != current.parent:
        if os.path.lexists(current) and current.is_symlink():
            raise ExtractionError(f"Extraction path crosses a symbolic link: {current}")
        current = current.parent


def _fsync_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
    for path in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _zip_members(archive: Path) -> tuple[ArchiveMember, ...]:
    result: list[ArchiveMember] = []
    with zipfile.ZipFile(archive) as source:
        for info in source.infolist():
            mode = info.external_attr >> 16
            kind = "directory" if info.is_dir() else "file"
            if stat.S_ISLNK(mode):
                kind = "symlink"
            elif stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                kind = "device"
            result.append(ArchiveMember(info.filename, kind, info.file_size))
    return tuple(result)


def _seven_zip_members(archive: Path, tool: str) -> tuple[ArchiveMember, ...]:
    process = subprocess.run(
        [tool, "l", "-slt", "--", os.fspath(archive)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", check=False,
    )
    if process.returncode:
        raise ExtractionError(f"Cannot list 7z archive (exit {process.returncode}): {process.stdout[-2000:]}")
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in process.stdout.splitlines():
        if not line.strip():
            if "Path" in current:
                blocks.append(current)
            current = {}
        elif " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    if "Path" in current:
        blocks.append(current)
    members: list[ArchiveMember] = []
    archive_name = os.fspath(archive)
    for block in blocks:
        name = block.get("Path", "")
        # 7z emits an archive-summary block before member blocks.
        if name in {archive_name, archive.name} and "Type" in block:
            continue
        attributes = block.get("Attributes", "")
        kind = "directory" if attributes.startswith("D") or block.get("Folder") == "+" else "file"
        unix_mode = next((part for part in attributes.split() if len(part) >= 10
                          and part[0] in "-dlpscb"), "")
        if block.get("Symbolic Link") or unix_mode.startswith("l"):
            kind = "symlink"
        if block.get("Hard Link"):
            kind = "hardlink"
        if unix_mode.startswith(("p", "s", "c", "b")):
            kind = {"p": "fifo", "s": "socket", "c": "device", "b": "device"}[unix_mode[0]]
        members.append(ArchiveMember(name, kind, int(block.get("Size", "0") or 0)))
    if not members:
        raise ExtractionError(f"7z archive has no listed members: {archive}")
    return tuple(members)


def _post_validate(root: Path) -> tuple[str, ...]:
    root = root.resolve()
    files: list[str] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ExtractionError(f"Extraction produced a link or special file: {path}")
            if not path.resolve().is_relative_to(root):
                raise ExtractionError(f"Extraction escaped its root: {path}")
            if stat.S_ISREG(info.st_mode):
                files.append(path.relative_to(root).as_posix())
    return tuple(sorted(files, key=lambda value: (value.casefold(), value)))


def extract_archive(
    archive: Path,
    destination: Path,
    *,
    cancel=None,
    seven_zip_tool: str | None = None,
    required_members: tuple[str, ...] = (),
    limits: ExtractionLimits | None = None,
) -> ExtractedArchive:
    """Validate first, extract into a new sibling, validate again, then publish."""
    archive, destination = Path(archive), Path(destination)
    _reject_symlink_ancestors(destination.parent)
    if os.path.lexists(destination):
        raise ExtractionError(f"Extraction destination already exists: {destination}")
    if cancel is not None and cancel.is_set():
        raise ExtractionCancelled("Extraction cancelled before start")
    suffix = archive.suffix.casefold()
    if suffix == ".zip":
        members = _zip_members(archive)
    elif suffix == ".7z":
        tool = seven_zip_tool or shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
        if not tool:
            raise ExtractionError("A 7z-compatible extractor is required for this reviewed archive")
        members = _seven_zip_members(archive, tool)
    else:
        raise ExtractionError(f"Unsupported reviewed archive format: {archive.name}")
    normalized = validate_archive_members(members)
    if limits is not None:
        _validate_limits(members, limits)
    required_keys = {value.casefold() for value in required_members}
    missing = sorted(required_keys - {value.casefold() for value in normalized})
    if missing:
        raise ExtractionError(f"Archive is missing required members: {', '.join(missing)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.extract-", dir=destination.parent))
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive) as source:
                for info in source.infolist():
                    if cancel is not None and cancel.is_set():
                        raise ExtractionCancelled("Extraction cancelled")
                    relative = PurePosixPath(info.filename)
                    target = temporary.joinpath(*relative.parts)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with source.open(info) as incoming, target.open("xb") as outgoing:
                            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        else:
            process = subprocess.Popen(
                [tool, "x", "-y", f"-o{temporary}", "--", os.fspath(archive)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            while process.poll() is None:
                if cancel is not None and cancel.wait(0.1):
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    raise ExtractionCancelled("Extraction cancelled")
            output = process.stdout.read().decode("utf-8", "replace") if process.stdout else ""
            if process.returncode:
                raise ExtractionError(f"7z extraction failed (exit {process.returncode}): {output[-2000:]}")
        files = _post_validate(temporary)
        if limits is not None:
            sizes = [(temporary / item).stat().st_size for item in files]
            if (len(files) > limits.member_count
                    or any(size > limits.largest_member_size for size in sizes)
                    or sum(sizes) > limits.total_expanded_size):
                raise ExtractionError("Extracted content exceeds its reviewed expansion bounds")
        _fsync_tree(temporary)
        os.replace(temporary, destination)
        parent_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return ExtractedArchive(destination, files)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def verify_internal_file(path: Path, *, size: int, sha256: str) -> None:
    path = Path(path)
    if path.stat().st_size != size:
        raise ExtractionError(f"Internal file has wrong size: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest.casefold() != sha256.casefold():
        raise ExtractionError(f"Internal file has wrong SHA-256: {path}")


def extract_verified_artifact(pin: ArtifactPin, archive: Path, destination: Path, *,
                              cancel=None, seven_zip_tool: str | None = None,
                              required_members: tuple[str, ...] = (),
                              limits: ExtractionLimits | None = None) -> VerifiedArtifactTree:
    """Bind an exact pinned archive to the extracted tree published from a private snapshot."""
    reviewed = ARTIFACTS.get(pin.artifact_id)
    if limits is None:
        if pin == REVIEWED_LOADER_UPDATE:
            limits = LOADER_UPDATE_LIMITS
        elif reviewed != pin or pin.artifact_id not in REVIEWED_EXTRACTION_LIMITS:
            raise ExtractionError("Unreviewed archive requires an explicit extraction policy")
        else:
            limits = REVIEWED_EXTRACTION_LIMITS[pin.artifact_id]
    archive = Path(archive)
    if archive.is_symlink() or not validate_file(pin, archive):
        raise ExtractionError(f"Archive does not match pinned identity: {archive}")
    _reject_symlink_ancestors(destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    snapshot_dir = Path(tempfile.mkdtemp(prefix=".fftic-archive-snapshot-", dir=destination.parent))
    snapshot = snapshot_dir / pin.filename
    try:
        with archive.open("rb") as incoming, snapshot.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if not validate_file(pin, snapshot) or not validate_file(pin, archive):
            raise ExtractionError("Pinned archive identity changed at the extraction boundary")
        extracted = extract_archive(snapshot, destination, cancel=cancel,
                                    seven_zip_tool=seven_zip_tool,
                                    required_members=required_members, limits=limits)
        identities = _tree_identities(extracted.root)
        result = VerifiedArtifactTree(pin, archive.resolve(), extracted.root.resolve(),
                                      identities, _tree_digest(identities), _PROVENANCE_TOKEN)
        result.revalidate()
        if pin == REVIEWED_LOADER_UPDATE:
            validate_loader_update_tree(result.root)
        return result
    except BaseException:
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise
    finally:
        shutil.rmtree(snapshot_dir, ignore_errors=True)


def validate_loader_update_tree(root: Path) -> None:
    """Require the reviewed loader's runtime and Reloaded dependency shape."""
    import json
    try:
        config = json.loads((root / "ModConfig.json").read_text(encoding="utf-8"))
        deps = json.loads((root / "fftivc.utility.modloader.deps.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ExtractionError(f"Loader update metadata is unreadable: {exc}") from exc
    if (not isinstance(config, dict)
            or config.get("ModId") != "fftivc.utility.modloader"
            or config.get("ModVersion") != REVIEWED_LOADER_UPDATE.version
            or config.get("ModDll") != "fftivc.utility.modloader.dll"
            or config.get("ModDependencies") != [
                "Reloaded.Memory.SigScan.ReloadedII", "reloaded.sharedlib.hooks"]
            or config.get("SupportedAppId") != ["fft_classic.exe", "fft_enhanced.exe"]
            or config.get("CanUnload") is not False
            or config.get("HasExports") is not True
            or not (root / "fftivc.utility.modloader.dll").is_file()
            or not isinstance(deps, dict)
            or not isinstance(deps.get("runtimeTarget"), dict)
            or deps.get("runtimeTarget", {}).get("name") != ".NETCoreApp,Version=v9.0"):
        raise ExtractionError("Loader update ID, version, dependencies, or runtime shape changed")
