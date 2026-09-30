"""Read-only prerequisite classification and pure installer planning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

try:
    from .fftic_artifacts import ARTIFACTS, ArtifactPin
except ImportError:
    from fftic_artifacts import ARTIFACTS, ArtifactPin


class PrerequisiteState(str, Enum):
    MISSING = "missing"
    SUFFICIENT = "sufficient"
    INSUFFICIENT = "insufficient"
    UNKNOWN = "unknown"
    UNHEALTHY = "unhealthy"


DOTNET_COMPONENT = ".NET Desktop Runtime"
VC_COMPONENT = "VC++ 2015-2022 x64 Runtime"
REQUIRED_PREREQUISITES = (DOTNET_COMPONENT, VC_COMPONENT)
REQUIRED_PREREQUISITE_VERSIONS = {
    DOTNET_COMPONENT: "9.0.20",
    VC_COMPONENT: "14.30.0.0",
}


@dataclass(frozen=True)
class PrerequisiteHealth:
    component: str
    state: PrerequisiteState
    observed_version: str | None
    required_version: str
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class InstallerPlan:
    component: str
    artifact: ArtifactPin
    installer_path: Path
    prefix: Path
    runner_identity: str
    arguments: tuple[str, ...]
    success_exit_codes: tuple[int, ...]
    restart_exit_codes: tuple[int, ...]
    snapshot_required: bool
    cancellation_required: bool
    logging_required: bool
    shared_runtime_retained_on_removal: bool


@dataclass(frozen=True)
class PrefixPrerequisites:
    prefix: Path
    dotnet_desktop: PrerequisiteHealth
    vc_runtime: PrerequisiteHealth


def _version_tuple(value: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in value.split("."))
    except (AttributeError, ValueError):
        return None


def classify_prerequisite(*, component: str, required_version: str,
                          observed_version: str | None, healthy: bool | None,
                          present: bool) -> PrerequisiteHealth:
    if healthy is False:
        state, diagnostic = PrerequisiteState.UNHEALTHY, "The resolved FFTIC prefix is unhealthy."
    elif not present:
        state, diagnostic = PrerequisiteState.MISSING, f"{component} is not installed in the FFTIC prefix."
    elif healthy is None or observed_version is None:
        state, diagnostic = PrerequisiteState.UNKNOWN, f"{component} version could not be verified."
    else:
        observed, required = _version_tuple(observed_version), _version_tuple(required_version)
        if observed is None or required is None:
            state, diagnostic = PrerequisiteState.UNKNOWN, f"{component} version is not parseable."
        elif observed >= required:
            state, diagnostic = PrerequisiteState.SUFFICIENT, f"{component} {observed_version} satisfies {required_version}."
        else:
            state, diagnostic = PrerequisiteState.INSUFFICIENT, f"{component} {observed_version} is below {required_version}."
    return PrerequisiteHealth(component, state, observed_version, required_version, (diagnostic,))


def plan_installer(*, artifact_id: str, installer_path: Path, prefix: Path,
                   runner_identity: str, health: PrerequisiteHealth) -> InstallerPlan | None:
    pin = ARTIFACTS[artifact_id]
    if health.state == PrerequisiteState.SUFFICIENT:
        return None
    if health.state not in {PrerequisiteState.MISSING, PrerequisiteState.INSUFFICIENT}:
        raise ValueError(f"Cannot safely plan an installer for {health.state.value} health")
    arguments = (("/install", "/quiet", "/norestart")
                 if artifact_id == "dotnet-desktop-runtime"
                 else ("/install", "/quiet", "/norestart"))
    return InstallerPlan(
        pin.component, pin, Path(installer_path), Path(prefix), runner_identity,
        arguments, (0,), (3010,), True, True, True, True,
    )


def inspect_prefix_prerequisites(prefix: Path) -> PrefixPrerequisites:
    """Read the existing Wine health evidence without executing the prefix."""
    from Utils.wine import health as wine_health
    prefix = Path(prefix)
    pfx = wine_health.wine_reg.normalize_pfx(prefix)
    usable = (pfx / "drive_c").is_dir() and (pfx / "user.reg").is_file()
    if not usable:
        unhealthy = classify_prerequisite(
            component=DOTNET_COMPONENT, required_version="9.0.20",
            observed_version=None, healthy=False, present=False)
        unhealthy_vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version=None, healthy=False, present=False)
        return PrefixPrerequisites(prefix, unhealthy, unhealthy_vc)
    desktop_versions = wine_health._dotnet_desktop_versions(pfx)
    dotnet9 = [value for value in desktop_versions if value.split(".", 1)[0] == "9"]
    observed_dotnet = max(dotnet9, key=lambda value: _version_tuple(value)) if dotnet9 else None
    dotnet = classify_prerequisite(
        component=DOTNET_COMPONENT, required_version="9.0.20",
        observed_version=observed_dotnet, healthy=True, present=bool(dotnet9))
    vc_check = wine_health.check_vcredist(pfx)
    vc_tuple = wine_health.vcredist_x64_version(pfx)
    observed_vc = ".".join(map(str, vc_tuple)) if vc_tuple else None
    if vc_check.status == wine_health.HealthStatus.OK:
        vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version=observed_vc, healthy=True, present=True)
    elif vc_check.status == wine_health.HealthStatus.MISSING:
        vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version=None, healthy=True, present=False)
    elif vc_tuple is not None and vc_tuple < (14, 30, 0, 0):
        vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version=observed_vc, healthy=True, present=True)
    else:
        vc = classify_prerequisite(
            component=VC_COMPONENT, required_version="14.30.0.0",
            observed_version=observed_vc, healthy=False, present=True)
    return PrefixPrerequisites(prefix, dotnet, vc)
