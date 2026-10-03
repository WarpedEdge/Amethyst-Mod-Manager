"""Read-only GitHub release discovery for the managed FFTIC loader."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

try:
    from .fftic_artifacts import REVIEWED_LOADER_UPDATE
except ImportError:
    from fftic_artifacts import REVIEWED_LOADER_UPDATE


LATEST_URL = "https://api.github.com/repos/Nenkai/fftivc.utility.modloader/releases/latest"
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_RELEASE_ID = 399774110
_ASSET_ID = 600208145


@dataclass(frozen=True)
class LoaderRelease:
    version: str
    release_id: int
    asset_id: int | None
    asset_url: str
    asset_size: int
    asset_sha256: str
    notes_url: str
    installable: bool
    reason: str = ""


class ReleaseNoticeLedger:
    """App-local UI notice history; release checks never mutate this file."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def mark_if_new(self, release: LoaderRelease) -> bool:
        identity = f"{release.release_id}:{release.version}"
        if self.path.is_symlink():
            raise ValueError("Release notice history is a symbolic link")
        if self.path.exists():
            stored = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(stored, list) or any(
                    not isinstance(item, str) or len(item) > 80 for item in stored):
                raise ValueError("Release notice history is malformed")
            seen = stored
        else:
            seen = []
        if identity in seen:
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent,
                prefix=".fftic-notice-", delete=False) as output:
            temporary = Path(output.name)
            try:
                json.dump(seen + [identity], output)
                output.flush()
                os.fsync(output.fileno())
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        try:
            os.replace(temporary, self.path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
        return True


def _version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or not (match := _VERSION.fullmatch(value)):
        raise ValueError("GitHub supplied a malformed stable release version")
    return tuple(map(int, match.groups()))


def parse_release(data: object, installed: str) -> LoaderRelease | None:
    current = _version(installed)
    if not isinstance(data, dict) or type(data.get("id")) is not int:
        raise ValueError("GitHub supplied malformed release metadata")
    version = data.get("tag_name")
    available = _version(version)
    if data.get("draft") is not False or data.get("prerelease") is not False:
        raise ValueError("GitHub's latest release is a draft or prerelease")
    notes = f"https://github.com/Nenkai/fftivc.utility.modloader/releases/tag/{version}"
    if data.get("html_url") != notes:
        raise ValueError("GitHub supplied a malformed release notes URL")
    if available <= current:
        return None
    assets = data.get("assets")
    if not isinstance(assets, list):
        raise ValueError("GitHub supplied malformed release assets")
    matching = [asset for asset in assets if isinstance(asset, dict) and
                asset.get("name") == f"fftivc.utility.modloader{version}.7z"]
    if len(matching) != 1:
        return LoaderRelease(version, data["id"], None, "", 0, "", notes,
                             False, "The release has no unique loader archive asset.")
    asset = matching[0]
    url = (f"https://github.com/Nenkai/fftivc.utility.modloader/releases/"
           f"download/{version}/fftivc.utility.modloader{version}.7z")
    digest = asset.get("digest")
    if (type(asset.get("id")) is not int or type(asset.get("size")) is not int
            or not 0 < asset["size"] <= 8_000_000
            or not isinstance(digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or asset.get("browser_download_url") != url):
        return LoaderRelease(version, data["id"], None, "", 0, "", notes,
                             False, "The archive asset lacks valid identity or integrity metadata.")
    sha256 = digest[7:]
    reviewed = REVIEWED_LOADER_UPDATE
    allowed = (version == reviewed.version and data["id"] == _RELEASE_ID
               and asset["id"] == _ASSET_ID and url == reviewed.url
               and asset["size"] == reviewed.size and sha256 == reviewed.sha256)
    return LoaderRelease(version, data["id"], asset["id"], url, asset["size"],
                         sha256, notes, allowed,
                         "" if allowed else "This exact release asset requires compatibility review.")


class LoaderReleaseChecker:
    """Cache bounded metadata checks; force a fresh check before any update."""

    def __init__(self, *, opener=None, clock=time.monotonic):
        self._opener = opener or urllib.request.urlopen
        self._clock = clock
        self._cached = None
        self._checked_at = -float("inf")
        self._lock = threading.RLock()

    def invalidate(self) -> None:
        with self._lock:
            self._checked_at = -float("inf")

    def check(self, installed: str, *, force: bool = False) -> tuple[LoaderRelease | None, str]:
        with self._lock:
            return self._check_locked(installed, force=force)

    def _check_locked(self, installed: str, *, force: bool) -> tuple[LoaderRelease | None, str]:
        if not force and self._clock() - self._checked_at < 300:
            data, error = self._cached
        else:
            request = urllib.request.Request(LATEST_URL, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Amethyst-Mod-Manager/FFTIC",
            })
            try:
                with self._opener(request, timeout=8) as response:
                    payload = response.read(256_001)
                    if len(payload) > 256_000:
                        raise ValueError("GitHub release metadata exceeded the size limit")
                    data = json.loads(payload)
                error = ""
            except urllib.error.HTTPError as exc:
                data = None
                error = ("GitHub release API limit reached; recheck later."
                         if exc.code in (403, 429) else
                         f"GitHub release check failed (HTTP {exc.code}).")
            except (urllib.error.URLError, OSError, ValueError, UnicodeError) as exc:
                data = None
                error = f"Could not check FFTIC loader releases: {exc}"
            self._cached = data, error
            self._checked_at = self._clock()
        if error:
            return None, error
        try:
            return parse_release(data, installed), ""
        except ValueError as exc:
            return None, str(exc)


CHECKER = LoaderReleaseChecker()
