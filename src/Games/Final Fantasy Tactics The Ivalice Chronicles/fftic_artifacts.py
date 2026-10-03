"""Immutable reviewed artifact identities for the FFTIC managed runtime.

This module contains data and verification helpers only.  It never resolves a
remote version, downloads an artifact, extracts it, or executes it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType


class ArtifactDisposition(str, Enum):
    EXTRACT = "extract"
    EXECUTE = "execute"


@dataclass(frozen=True)
class ArtifactPin:
    artifact_id: str
    component: str
    version: str
    url: str
    filename: str
    size: int
    sha256: str
    architecture: str
    purpose: str
    license_review: str
    disposition: ArtifactDisposition
    requires_separate_transaction: bool

    @property
    def downloaded(self) -> bool:
        return True

    @property
    def extracted(self) -> bool:
        return self.disposition == ArtifactDisposition.EXTRACT

    @property
    def copied(self) -> bool:
        return False

    @property
    def executed(self) -> bool:
        return self.disposition == ArtifactDisposition.EXECUTE


@dataclass(frozen=True)
class InternalFilePin:
    artifact_id: str
    component: str
    source_member: str
    destination_name: str
    size: int
    sha256: str
    architecture: str
    purpose: str

    @property
    def downloaded(self) -> bool:
        return False

    @property
    def extracted(self) -> bool:
        return True

    @property
    def copied(self) -> bool:
        return True

    @property
    def executed(self) -> bool:
        return True

    @property
    def requires_separate_transaction(self) -> bool:
        return False


_PINS = (
    ArtifactPin(
        "reloaded-ii", "Reloaded-II", "1.31.0",
        "https://github.com/Reloaded-Project/Reloaded-II/releases/download/1.31.0/Release.zip",
        "Release.zip", 25_039_658,
        "c893da3ba8596d9266826bd5ca8aacd25fe3b53d09314324ab65c7b618a05f8c",
        "x86 and x64; FFTIC uses x64", "Private managed runtime generation",
        "GPL-3.0; setup-time official download preferred; final notice review remains",
        ArtifactDisposition.EXTRACT, False,
    ),
    ArtifactPin(
        "nenkai-loader", "Nenkai FFTIC Mod Loader", "1.7.3",
        "https://github.com/Nenkai/fftivc.utility.modloader/releases/download/1.7.3/fftivc.utility.modloader1.7.3.7z",
        "fftivc.utility.modloader1.7.3.7z", 1_917_639,
        "731709ae3a4ea7f25b508b8fc90a95828e751fe1e8450e3c77ba492b231c16aa",
        "managed; hosted in x64 game process", "Unchanged FFTIC loader",
        "MIT upstream with bundled mixed-license dependencies and incomplete notices; final review remains",
        ArtifactDisposition.EXTRACT, False,
    ),
    ArtifactPin(
        "sigscan", "Reloaded.Memory.SigScan.ReloadedII", "1.2.14",
        "https://github.com/Reloaded-Project/Reloaded.Memory.SigScan/releases/download/3.1.16/Reloaded.Memory.SigScan.ReloadedII1.2.14.7z",
        "Reloaded.Memory.SigScan.ReloadedII1.2.14.7z", 173_264,
        "52d48abcef5c3aa8c8cdc19666936e7cced19c92c6e71e1896bf0dfc75c23a2a",
        "managed / architecture-neutral", "Nenkai IStartupScanner dependency",
        "LGPL-3.0 project with GPL/LGPL dependencies; final notice review remains",
        ArtifactDisposition.EXTRACT, False,
    ),
    ArtifactPin(
        "shared-hooks", "Reloaded Shared Hooks", "1.16.3",
        "https://github.com/Sewer56/Reloaded.SharedLib.Hooks.ReloadedII/releases/download/1.16.3/Reloaded.Hooks.ReloadedII1.16.3.7z",
        "Reloaded.Hooks.ReloadedII1.16.3.7z", 741_775,
        "2b7c2e6118a3f1eb00a2e1e9105397b0d17a118a84596308c3a6a9ff3cb14b1b",
        "x86 and x64; FFTIC uses x64", "Nenkai IReloadedHooks dependency",
        "LGPL-3.0 project with bundled GPL/LGPL and notice-bearing dependencies; final review remains",
        ArtifactDisposition.EXTRACT, False,
    ),
    ArtifactPin(
        "dotnet-desktop-runtime", ".NET Desktop Runtime", "9.0.20",
        "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.20/windowsdesktop-runtime-9.0.20-win-x64.exe",
        "windowsdesktop-runtime-9.0.20-win-x64.exe", 60_851_384,
        "56ca2926e797c3d124e13766f84d4f3b75a0d86b0d877e384cda52fdd027e431",
        "x64", "Windows Desktop runtime in the FFTIC prefix",
        "Microsoft .NET MIT distribution and third-party notices; final packaging review remains",
        ArtifactDisposition.EXECUTE, True,
    ),
    ArtifactPin(
        "vc-runtime", "Microsoft Visual C++ 2015-2022 Runtime", "14.44.35211.0",
        "https://download.visualstudio.microsoft.com/download/pr/bd1c8d9d-ba95-4eee-bc6e-df1fcc876373/CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B/VC_redist.x64.exe",
        "VC_redist.x64.exe", 25_635_768,
        "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b",
        "x64", "Native runtime prerequisite in the FFTIC prefix",
        "Microsoft proprietary redistribution terms; do not bundle by default",
        ArtifactDisposition.EXECUTE, True,
    ),
)

ARTIFACTS = MappingProxyType({pin.artifact_id: pin for pin in _PINS})

# This candidate was inspected in isolation on 2026-10-03. GitHub's release
# asset digest and the downloaded archive agreed. The release is not an
# in-game compatibility claim; only this exact archive may use this policy.
REVIEWED_LOADER_UPDATE = ArtifactPin(
    "nenkai-loader", "Nenkai FFTIC Mod Loader", "1.7.5",
    "https://github.com/Nenkai/fftivc.utility.modloader/releases/download/1.7.5/fftivc.utility.modloader1.7.5.7z",
    "fftivc.utility.modloader1.7.5.7z", 1_990_741,
    "807b489aedbd51989a4ce0e732b785c3e079165e8131d51218665b38c5c3e52d",
    "managed; hosted in x64 game process", "Reviewed opt-in FFTIC loader update",
    "MIT upstream with bundled mixed-license dependencies; final notice review remains",
    ArtifactDisposition.EXTRACT, False,
)


def loader_pin(version: str) -> ArtifactPin:
    for pin in (ARTIFACTS["nenkai-loader"], REVIEWED_LOADER_UPDATE):
        if pin.version == version:
            return pin
    raise ValueError(f"Unreviewed FFTIC loader version: {version}")


def loader_pin_from_digest(sha256: str) -> ArtifactPin:
    for pin in (ARTIFACTS["nenkai-loader"], REVIEWED_LOADER_UPDATE):
        if sha256 == pin.sha256:
            return pin
    raise ValueError("Unreviewed FFTIC loader archive digest")

INTERNAL_FILES = MappingProxyType({
    "version-dll": InternalFilePin(
        "version-dll", "Ultimate ASI Loader", "Loader/Asi/UltimateAsiLoader.7z:ASILoader64.dll",
        "version.dll", 3_615_648,
        "22fda9c71eaae02460f311bf3441638340ab591586d78f1de213c4819dcb883c",
        "x64", "Game-root ASI proxy copied from the pinned Reloaded archive",
    ),
    "reloaded-bootstrapper-asi": InternalFilePin(
        "reloaded-bootstrapper-asi", "Reloaded x64 bootstrapper",
        "Loader/X64/Bootstrapper/Reloaded.Mod.Loader.Bootstrapper.dll",
        "Reloaded.Mod.Loader.Bootstrapper.asi", 153_088,
        "c052ca24f36f310c7273adda3d4e01b73017e717c4e8d0f2eb2e548e09a17171",
        "x64", "Game-root Reloaded ASI bootstrap copied from the pinned archive",
    ),
})


def validate_size(pin: ArtifactPin | InternalFilePin, observed_size: int) -> bool:
    return observed_size == pin.size


def validate_sha256(pin: ArtifactPin | InternalFilePin, observed_sha256: str) -> bool:
    return observed_sha256.casefold() == pin.sha256


def validate_bytes(pin: ArtifactPin | InternalFilePin, payload: bytes) -> bool:
    return validate_size(pin, len(payload)) and validate_sha256(
        pin, hashlib.sha256(payload).hexdigest())


def validate_file(pin: ArtifactPin | InternalFilePin, path: Path) -> bool:
    """Read-only validation of an already-present candidate file."""
    try:
        if not validate_size(pin, path.stat().st_size):
            return False
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return validate_sha256(pin, digest.hexdigest())
    except OSError:
        return False
