"""Pure composition of an attested FFTIC readiness verification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

try:
    from .fftic_detection import InstallStatus
    from .fftic_readiness import ReadinessAspect, ReadinessVerification
    from .fftic_steam_requirements import SteamOptionsStatus
except ImportError:
    from fftic_detection import InstallStatus
    from fftic_readiness import ReadinessAspect, ReadinessVerification
    from fftic_steam_requirements import SteamOptionsStatus


class LifecycleState(str, Enum):
    GAME_MISSING = "game missing"
    INCOMPLETE_INSTALLATION = "incomplete installation"
    UNVERIFIED_GAME_BUILD = "unverified game build"
    VERIFIED_GAME_TUPLE = "verified game tuple"
    ARTIFACTS_MISSING = "artifacts missing"
    ARTIFACT_CORRUPT = "artifact corrupt"
    RUNTIME_GENERATION_MISSING = "runtime generation missing"
    GENERATION_INCOMPLETE = "generation incomplete"
    GENERATION_READY = "generation ready"
    PREFIX_UNRESOLVED = "prefix unresolved"
    PREREQUISITE_MISSING = "prerequisite missing"
    PREREQUISITE_READY = "prerequisite ready"
    BOOTSTRAP_MISSING = "bootstrap missing"
    BOOTSTRAP_DRIFT = "bootstrap drift"
    BOOTSTRAP_READY = "bootstrap ready"
    STEAM_OPTIONS_DIFFERENT = "Steam Launch Options Different"
    STEAM_OPTIONS_MISSING = "Steam Launch Options Missing"
    STEAM_OPTIONS_CONFLICT = "Steam Launch Options Conflict"
    STEAM_OPTIONS_CONFIGURED = "Steam Launch Options Configured"
    PROFILE_UNSYNCHRONIZED = "profile unsynchronized"
    PROFILE_SYNCHRONIZED = "profile synchronized"
    RECOVERY_REQUIRED = "recovery required"
    READY_TO_LAUNCH = "ready to launch"


@dataclass(frozen=True)
class LifecycleStatus:
    primary: LifecycleState
    states: tuple[LifecycleState, ...]
    ready: bool


def compose_lifecycle_status(value: ReadinessVerification) -> LifecycleStatus:
    """Render status only from the correlated read-only verifier result."""
    if not isinstance(value, ReadinessVerification) or not value.attested:
        return LifecycleStatus(
            LifecycleState.RECOVERY_REQUIRED,
            (LifecycleState.RECOVERY_REQUIRED,), False)
    states = [
        (LifecycleState.VERIFIED_GAME_TUPLE if value.game == ReadinessAspect.READY else
         LifecycleState.GAME_MISSING if value.install_status == InstallStatus.NOT_FOUND else
         LifecycleState.INCOMPLETE_INSTALLATION
         if value.install_status == InstallStatus.INCOMPLETE else
         LifecycleState.UNVERIFIED_GAME_BUILD),
        (LifecycleState.GENERATION_READY if value.generation == ReadinessAspect.READY else
         LifecycleState.RUNTIME_GENERATION_MISSING if value.generation == ReadinessAspect.MISSING else
         LifecycleState.GENERATION_INCOMPLETE),
        (LifecycleState.PREREQUISITE_READY if value.prerequisites == ReadinessAspect.READY else
         LifecycleState.PREREQUISITE_MISSING),
        (LifecycleState.BOOTSTRAP_READY if value.bootstrap == ReadinessAspect.READY else
         LifecycleState.BOOTSTRAP_MISSING if value.bootstrap == ReadinessAspect.MISSING else
         LifecycleState.BOOTSTRAP_DRIFT),
        ({SteamOptionsStatus.CONFIGURED: LifecycleState.STEAM_OPTIONS_CONFIGURED,
          SteamOptionsStatus.MISSING: LifecycleState.STEAM_OPTIONS_MISSING,
          SteamOptionsStatus.DIFFERENT: LifecycleState.STEAM_OPTIONS_DIFFERENT,
          SteamOptionsStatus.CONFLICT: LifecycleState.STEAM_OPTIONS_CONFLICT}[value.steam_status]),
        (LifecycleState.PROFILE_SYNCHRONIZED if value.profile == ReadinessAspect.READY else
         LifecycleState.PROFILE_UNSYNCHRONIZED),
    ]
    if value.artifacts != ReadinessAspect.READY:
        states.append(LifecycleState.ARTIFACTS_MISSING if value.artifacts == ReadinessAspect.MISSING
                      else LifecycleState.ARTIFACT_CORRUPT)
    if value.prefix != ReadinessAspect.READY:
        states.append(LifecycleState.PREFIX_UNRESOLVED)
    if value.recovery != ReadinessAspect.READY:
        states.append(LifecycleState.RECOVERY_REQUIRED)
    if value.ready:
        states.append(LifecycleState.READY_TO_LAUNCH)
        return LifecycleStatus(LifecycleState.READY_TO_LAUNCH, tuple(states), True)
    blockers = {
        LifecycleState.GAME_MISSING, LifecycleState.INCOMPLETE_INSTALLATION,
        LifecycleState.UNVERIFIED_GAME_BUILD,
        LifecycleState.ARTIFACTS_MISSING, LifecycleState.ARTIFACT_CORRUPT,
        LifecycleState.RUNTIME_GENERATION_MISSING, LifecycleState.GENERATION_INCOMPLETE,
        LifecycleState.PREFIX_UNRESOLVED, LifecycleState.PREREQUISITE_MISSING,
        LifecycleState.BOOTSTRAP_MISSING, LifecycleState.BOOTSTRAP_DRIFT,
        LifecycleState.STEAM_OPTIONS_MISSING, LifecycleState.STEAM_OPTIONS_DIFFERENT,
        LifecycleState.STEAM_OPTIONS_CONFLICT, LifecycleState.PROFILE_UNSYNCHRONIZED,
        LifecycleState.RECOVERY_REQUIRED,
    }
    primary = next(state for state in reversed(states) if state in blockers)
    return LifecycleStatus(primary, tuple(states), False)
