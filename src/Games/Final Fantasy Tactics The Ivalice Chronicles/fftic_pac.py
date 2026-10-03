"""Generated-PAC observation and exact-ownership planning."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from enum import Enum
from pathlib import Path

try:
    from .fftic_transaction_executor import file_sha256
except ImportError:
    from fftic_transaction_executor import file_sha256

GENERATED_PAC_PATHS = (
    "data/classic/modded.pac", "data/classic/modded.en.pac",
    "data/enhanced/modded.pac", "data/enhanced/modded.en.pac",
)


class PacOwnershipState(str, Enum):
    ABSENT = "absent"
    UNKNOWN = "unknown"
    OWNED_EXACT = "owned exact"
    DRIFT = "drift"


@dataclass(frozen=True)
class PacObservation:
    relative_path: str
    sha256: str
    generation_id: str
    profile_fingerprint: str
    launch_id: str
    transaction_id: str
    before_state: str
    before_sha256: str | None


@dataclass(frozen=True)
class PacBaseline:
    relative_path: str
    state: PacOwnershipState
    sha256: str | None
    backup_path: str | None = None


@dataclass(frozen=True)
class PacBaselineSet:
    generation_id: str
    profile_fingerprint: str
    activation_id: str
    transaction_id: str
    compatibility_fingerprint: str
    paths: tuple[PacBaseline, ...]
    prior_log_hashes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PacLaunchEvidence:
    generation_id: str
    profile_fingerprint: str
    launch_id: str
    transaction_id: str
    activation_id: str = ""
    compatibility_fingerprint: str = ""
    log_sha256: str = ""


def baseline_set_from_receipt(value: dict) -> PacBaselineSet:
    return PacBaselineSet(
        value["generation_id"], value["profile_fingerprint"],
        value["activation_id"], value["transaction_id"],
        value["compatibility_fingerprint"],
        tuple(PacBaseline(item["relative_path"], PacOwnershipState(item["state"]),
                          item["sha256"], item.get("backup_path"))
              for item in value["paths"]),
        tuple(value.get("prior_log_hashes", ())),
    )


def capture_pac_baseline(game_root: Path, *,
                         prior_observations: tuple[PacObservation, ...] = (),
                         prior_baseline: tuple[PacBaseline, ...] = ()) -> tuple[PacBaseline, ...]:
    prior = {item.relative_path: item for item in prior_observations}
    baselines = {item.relative_path: item for item in prior_baseline}
    result = []
    for relative in GENERATED_PAC_PATHS:
        path = Path(game_root) / relative
        if not path.exists():
            result.append(PacBaseline(relative, PacOwnershipState.ABSENT, None))
        elif path.is_symlink() or not path.is_file():
            result.append(PacBaseline(relative, PacOwnershipState.UNKNOWN, None))
        else:
            digest = file_sha256(path)
            recorded = prior.get(relative)
            baseline = baselines.get(relative) if recorded is None else None
            backup = Path(baseline.backup_path) if baseline and baseline.backup_path else None
            exact_baseline = (baseline is not None
                              and baseline.state == PacOwnershipState.OWNED_EXACT
                              and baseline.sha256 == digest
                              and backup is not None and not backup.is_symlink()
                              and backup.is_file() and file_sha256(backup) == digest)
            state = (PacOwnershipState.OWNED_EXACT
                     if (recorded is not None and recorded.sha256 == digest) or exact_baseline
                     else PacOwnershipState.UNKNOWN)
            result.append(PacBaseline(relative, state, digest))
    return tuple(result)


def capture_generated_pacs(game_root: Path, *, baseline: tuple[PacBaseline, ...],
                           evidence: PacLaunchEvidence) -> tuple[PacObservation, ...]:
    """Claim only an absent/new or exact-owned/controlled post-launch transition."""
    if not all((evidence.generation_id, evidence.profile_fingerprint,
                evidence.launch_id, evidence.transaction_id, evidence.activation_id,
                evidence.compatibility_fingerprint, evidence.log_sha256)):
        raise ValueError("Complete managed launch evidence is required")
    before = {item.relative_path: item for item in baseline}
    if set(before) != set(GENERATED_PAC_PATHS) or len(before) != len(baseline):
        raise ValueError("A complete unique PAC baseline is required")
    observations: list[PacObservation] = []
    for relative in GENERATED_PAC_PATHS:
        path = Path(game_root) / relative
        if path.is_file() and not path.is_symlink():
            prior = before[relative]
            if prior.state not in {PacOwnershipState.ABSENT, PacOwnershipState.OWNED_EXACT}:
                continue
            observations.append(PacObservation(
                relative, file_sha256(path), evidence.generation_id,
                evidence.profile_fingerprint, evidence.launch_id,
                evidence.transaction_id, prior.state.value, prior.sha256))
    return tuple(observations)


def exact_absent_output(game_root: Path, baseline: PacBaselineSet,
                        user_packages: list[dict]) -> bool:
    """Accept no output only for an all-disabled profile with exact retained baselines."""
    if (any(item["enabled"] for item in user_packages)
            or len(baseline.paths) != len(GENERATED_PAC_PATHS)
            or {item.relative_path for item in baseline.paths} != set(GENERATED_PAC_PATHS)
            or not any(item.state == PacOwnershipState.OWNED_EXACT for item in baseline.paths)):
        return False
    for item in baseline.paths:
        if os.path.lexists(Path(game_root) / item.relative_path):
            return False
        if item.state == PacOwnershipState.ABSENT:
            continue
        if item.state != PacOwnershipState.OWNED_EXACT or not item.backup_path:
            return False
        backup = Path(item.backup_path)
        if (backup.is_symlink() or not backup.is_file()
                or file_sha256(backup) != item.sha256):
            return False
    return True


def exact_absent_reversion_output(game_root: Path, baseline: PacBaselineSet,
                                  backup_root: Path) -> bool:
    """Permit an unconfirmed launch's absent PACs only with exact owned backups."""
    game_root, backup_root = Path(game_root), Path(backup_root)
    if (backup_root.is_symlink() or not backup_root.is_dir()
            or backup_root.resolve(strict=True) != backup_root.absolute()
            or len(baseline.paths) != len(GENERATED_PAC_PATHS)
            or {item.relative_path for item in baseline.paths} != set(GENERATED_PAC_PATHS)
            or not any(item.state == PacOwnershipState.OWNED_EXACT
                       for item in baseline.paths)):
        return False
    for item in baseline.paths:
        target = game_root / item.relative_path
        if os.path.lexists(target):
            return False
        current = game_root
        for part in Path(item.relative_path).parts[:-1]:
            current /= part
            if os.path.lexists(current) and (current.is_symlink() or not current.is_dir()):
                return False
        if item.state == PacOwnershipState.ABSENT:
            continue
        if item.state != PacOwnershipState.OWNED_EXACT or not item.backup_path:
            return False
        backup = Path(item.backup_path)
        if (not backup.is_absolute() or backup == backup_root
                or not backup.is_relative_to(backup_root)):
            return False
        current = backup_root
        for part in backup.relative_to(backup_root).parts[:-1]:
            current /= part
            if current.is_symlink() or not current.is_dir():
                return False
        if (backup.is_symlink() or not backup.is_file()
                or file_sha256(backup) != item.sha256):
            return False
    return True


def inspect_matching_launch_log(
    log_root: Path, *, baseline: PacBaselineSet, required_mod_ids: tuple[str, ...],
) -> PacLaunchEvidence | None:
    """Return durable evidence only for a completed launch of the bound generation."""
    root = Path(log_root)
    if root.is_symlink() or not root.is_dir():
        return None
    generation_marker = (
        "\\generations\\" + baseline.generation_id + "\\Mods\\").casefold()
    required = tuple(identity.casefold() for identity in required_mod_ids)
    candidates = []
    for path in root.glob("*.txt"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            payload = path.read_bytes()
            text = payload.decode("utf-8", errors="strict")
        except (OSError, UnicodeError):
            continue
        folded = text.casefold()
        if (generation_marker not in folded
                or "fftivc mod loader initialized" not in folded
                or "game successfully loaded modded pack" not in folded
                or any(f"- appid   : {identity}" not in folded for identity in required)):
            continue
        digest = hashlib.sha256(payload).hexdigest()
        if digest in baseline.prior_log_hashes:
            continue
        candidates.append((path.stat().st_mtime_ns, digest))
    if not candidates:
        return None
    _mtime, digest = max(candidates)
    return PacLaunchEvidence(
        baseline.generation_id, baseline.profile_fingerprint, digest,
        baseline.transaction_id, baseline.activation_id,
        baseline.compatibility_fingerprint, digest)


def pac_ownership(game_root: Path, relative_path: str,
                  receipt_observation: PacObservation | None) -> PacOwnershipState:
    if relative_path not in GENERATED_PAC_PATHS:
        raise ValueError(f"Unknown generated PAC path: {relative_path}")
    path = Path(game_root) / relative_path
    if not path.exists():
        return PacOwnershipState.ABSENT
    if path.is_symlink() or not path.is_file() or receipt_observation is None:
        return PacOwnershipState.UNKNOWN
    if (receipt_observation.relative_path != relative_path
            or not receipt_observation.generation_id
            or not receipt_observation.profile_fingerprint
            or not receipt_observation.launch_id
            or not receipt_observation.transaction_id
            or receipt_observation.before_state not in {
                PacOwnershipState.ABSENT.value, PacOwnershipState.OWNED_EXACT.value}):
        return PacOwnershipState.UNKNOWN
    return (PacOwnershipState.OWNED_EXACT
            if file_sha256(path) == receipt_observation.sha256
            else PacOwnershipState.DRIFT)
