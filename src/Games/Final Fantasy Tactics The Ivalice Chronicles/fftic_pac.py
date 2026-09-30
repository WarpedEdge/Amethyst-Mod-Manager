"""Generated-PAC observation and exact-ownership planning."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class PacLaunchEvidence:
    generation_id: str
    profile_fingerprint: str
    launch_id: str
    transaction_id: str


def capture_pac_baseline(game_root: Path, *,
                         prior_observations: tuple[PacObservation, ...] = ()) -> tuple[PacBaseline, ...]:
    prior = {item.relative_path: item for item in prior_observations}
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
            state = (PacOwnershipState.OWNED_EXACT if recorded and recorded.sha256 == digest
                     else PacOwnershipState.UNKNOWN)
            result.append(PacBaseline(relative, state, digest))
    return tuple(result)


def capture_generated_pacs(game_root: Path, *, baseline: tuple[PacBaseline, ...],
                           evidence: PacLaunchEvidence) -> tuple[PacObservation, ...]:
    """Claim only an absent/new or exact-owned/controlled post-launch transition."""
    if not all((evidence.generation_id, evidence.profile_fingerprint,
                evidence.launch_id, evidence.transaction_id)):
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
