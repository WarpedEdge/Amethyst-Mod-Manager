"""Pinned, bounded artifact acquisition for the FFTIC managed runtime."""

from __future__ import annotations

import hashlib
import os
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

try:
    from .fftic_artifacts import ArtifactPin, validate_file
except ImportError:
    from fftic_artifacts import ArtifactPin, validate_file


class ArtifactError(RuntimeError):
    pass


class ArtifactCancelled(ArtifactError):
    pass


@dataclass(frozen=True)
class AcquiredArtifact:
    path: Path
    reused: bool
    size: int
    sha256: str


class _HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme.casefold() != "https":
            raise ArtifactError(f"Artifact redirect is not HTTPS: {newurl}")
        redirects = getattr(req, "_fftic_redirects", 0) + 1
        if redirects > 5:
            raise ArtifactError("Artifact download exceeded five HTTPS redirects")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected._fftic_redirects = redirects
        return redirected


class UrllibTransport:
    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_HttpsRedirectHandler())

    def open(self, url: str):
        request = urllib.request.Request(url, headers={
            "User-Agent": "Amethyst-Mod-Manager/FFTIC",
            "Accept-Encoding": "identity",
        })
        return self._opener.open(request, timeout=self.timeout)


def _cancelled(cancel) -> bool:
    return bool(cancel is not None and cancel.is_set())


def _quarantine(path: Path, quarantine_root: Path, reason: str) -> Path:
    quarantine_root.mkdir(parents=True, exist_ok=True)
    target = quarantine_root / f"{path.name}.{reason}.{uuid.uuid4().hex}"
    os.replace(path, target)
    return target


def acquire_artifact(
    pin: ArtifactPin,
    cache_root: Path,
    *,
    transport=None,
    cancel=None,
    progress=None,
    quarantine_root: Path | None = None,
    chunk_size: int = 1024 * 1024,
) -> AcquiredArtifact:
    """Acquire exactly *pin* and atomically publish it after verification."""
    if urlparse(pin.url).scheme.casefold() != "https":
        raise ArtifactError(f"Artifact URL must use HTTPS: {pin.url}")
    if Path(pin.filename).name != pin.filename:
        raise ArtifactError(f"Pinned filename is not a basename: {pin.filename!r}")
    cache_root = Path(cache_root)
    cache_root.mkdir(parents=True, exist_ok=True)
    quarantine_root = Path(quarantine_root or cache_root / "quarantine")
    destination = cache_root / pin.filename
    # Preserve abandoned partials even when a later run can reuse a complete
    # cache entry; otherwise suspicious leftovers would remain ambiguous.
    for stale in cache_root.glob(f".{pin.filename}.part-*"):
        if stale.is_symlink() or not stale.is_file():
            raise ArtifactError(f"Suspicious artifact staging entry: {stale}")
        _quarantine(stale, quarantine_root, "interrupted")
    if os.path.lexists(destination):
        if destination.is_symlink() or not destination.is_file():
            raise ArtifactError(f"Artifact cache target is not a regular file: {destination}")
        if validate_file(pin, destination):
            return AcquiredArtifact(destination, True, pin.size, pin.sha256)
        quarantined = _quarantine(destination, quarantine_root, "mismatch")
        if progress:
            progress(0, pin.size, f"Quarantined mismatched cache entry at {quarantined}")

    temporary = cache_root / f".{pin.filename}.part-{os.getpid()}-{uuid.uuid4().hex}"
    digest = hashlib.sha256()
    received = 0
    transport = transport or UrllibTransport()
    try:
        if _cancelled(cancel):
            raise ArtifactCancelled(f"Download cancelled before acquiring {pin.component}")
        with transport.open(pin.url) as response:
            final_url = getattr(response, "url", None) or getattr(response, "geturl", lambda: pin.url)()
            if urlparse(final_url).scheme.casefold() != "https":
                raise ArtifactError(f"Artifact response is not HTTPS: {final_url}")
            length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise ArtifactError(f"Invalid Content-Length for {pin.component}: {length!r}") from exc
                if declared != pin.size:
                    raise ArtifactError(
                        f"{pin.component} declared {declared} bytes; expected exactly {pin.size}")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                while True:
                    if _cancelled(cancel):
                        raise ArtifactCancelled(f"Download cancelled for {pin.component}")
                    chunk = response.read(min(chunk_size, pin.size + 1 - received))
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > pin.size:
                        raise ArtifactError(
                            f"{pin.component} exceeded expected size {pin.size} bytes")
                    digest.update(chunk)
                    output.write(chunk)
                    if progress:
                        progress(received, pin.size, f"Downloading {pin.component}")
                output.flush()
                os.fsync(output.fileno())
        observed = digest.hexdigest()
        if received != pin.size:
            raise ArtifactError(
                f"{pin.component} was truncated: received {received}; expected {pin.size} bytes")
        if observed.casefold() != pin.sha256.casefold():
            raise ArtifactError(
                f"{pin.component} SHA-256 mismatch: received {observed}; expected {pin.sha256}")
        if os.path.lexists(destination):
            raise ArtifactError(f"Artifact cache target appeared during download: {destination}")
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ArtifactError(f"Artifact cache target appeared during download: {destination}") from exc
        temporary.unlink()
        try:
            directory_fd = os.open(cache_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return AcquiredArtifact(destination, False, received, observed)
    except (urllib.error.URLError, OSError) as exc:
        raise ArtifactError(f"Could not acquire {pin.component}: {exc}") from exc
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
