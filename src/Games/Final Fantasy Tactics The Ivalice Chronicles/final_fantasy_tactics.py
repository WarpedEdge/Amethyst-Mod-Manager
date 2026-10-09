"""Game registration and explicit managed-lifecycle policy for FFTIC."""

from __future__ import annotations

import sys
from pathlib import Path

from Games.base_game import BaseGame
from Utils.config_paths import get_profiles_dir
from Utils.deployment import LinkMode

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.append(str(_MODULE_DIR))

from fftic_detection import (  # noqa: E402
    ExecutableHashCache, InstallationDetection, STEAM_APP_ID,
    detect_installation,
)
from fftic_packages import inspect_package, validate_color_customizer_archive  # noqa: E402
from fftic_orchestration import FfticOrchestrator  # noqa: E402
from fftic_production import create_production_executor  # noqa: E402

_PROFILES_DIR = get_profiles_dir()
_DIRECT_LAUNCH_MESSAGE = (
    "Final Fantasy Tactics: The Ivalice Chronicles requires normal Steam "
    "launch with its required Steam Launch Options. Amethyst's current direct "
    "Proton route does not preserve the verified S: drive identity."
)


class FinalFantasyTacticsTheIvaliceChronicles(BaseGame):
    """One game handler for the Classic and Enhanced executable modes."""

    def __init__(self) -> None:
        self._game_path: Path | None = None
        self._prefix_path: Path | None = None
        self._deploy_mode: LinkMode = LinkMode.HARDLINK
        self._staging_path: Path | None = None
        self._hash_cache = ExecutableHashCache()
        self._managed_support_controller = FfticOrchestrator(
            executor_factory=create_production_executor)
        self.load_paths()

    @property
    def name(self) -> str:
        return "Final Fantasy Tactics: The Ivalice Chronicles"

    @property
    def game_id(self) -> str:
        return "final_fantasy_tactics_the_ivalice_chronicles"

    @property
    def exe_name(self) -> str:
        return "FFT_enhanced.exe"

    @property
    def exe_name_alts(self) -> list[str]:
        return ["FFT_classic.exe"]

    @property
    def steam_id(self) -> str:
        return STEAM_APP_ID

    @property
    def nexus_game_domain(self) -> str:
        return "finalfantasytacticstheivalicechronicles"

    @property
    def auto_install_deps(self) -> list[str]:
        # FFTIC prerequisites are never installed implicitly by Add Game.
        return []

    @property
    def collections_disabled(self) -> bool:
        return True

    @property
    def mod_required_top_level_folders(self) -> set[str]:
        return {"fftivc"}

    @property
    def mod_auto_strip_until_required(self) -> bool:
        return True

    @property
    def conflict_ignore_filenames(self) -> set[str]:
        return {"modconfig.json", "preview.png"}

    @property
    def root_folder_deploy_enabled(self) -> bool:
        return False

    def get_game_path(self) -> Path | None:
        return self._game_path

    def get_mod_data_path(self) -> Path | None:
        # Profile content is published by the FFTIC managed synchronizer.
        return None

    def get_mod_staging_path(self) -> Path:
        if self._staging_path is not None:
            return self._staging_path / "mods"
        return _PROFILES_DIR / self.name / "mods"

    def set_staging_path(self, path: Path | str | None) -> None:
        self._staging_path = Path(path) if path else None
        self.save_paths()

    def get_prefix_path(self) -> Path | None:
        return self._prefix_path

    def set_prefix_path(self, path: Path | str | None) -> None:
        self._prefix_path = Path(path) if path else None
        self.save_paths()

    def get_deploy_mode(self) -> LinkMode:
        return self._deploy_mode

    def set_deploy_mode(self, mode: LinkMode) -> None:
        self._deploy_mode = mode
        self.save_paths()

    def compatibility(
        self, *, steam_build: str | None = None,
        pe_version: str | None = None,
    ) -> InstallationDetection:
        return detect_installation(
            self._game_path, steam_build=steam_build, pe_version=pe_version,
            hash_cache=self._hash_cache)

    def get_managed_support_controller(self) -> FfticOrchestrator:
        """Return the FFTIC status and explicitly confirmed lifecycle controller."""
        return self._managed_support_controller

    def validate_mod_package(self, source_root: Path) -> list[str]:
        result = inspect_package(source_root)
        if result.is_user_content:
            return []
        return list(result.diagnostics or (
            f"Unsupported FFTIC package classification: {result.classification.value}.",
        ))

    def validate_mod_archive(self, source_root: Path, archive: Path | None) -> list[str]:
        return validate_color_customizer_archive(source_root, archive)

    def retain_mod_archive(self, source_root: Path, archive: Path, staging_root: Path) -> None:
        result = inspect_package(source_root)
        if result.manifest and result.manifest.mod_id == 'paxtrick.fft.colorcustomizer':
            try:
                from .fftic_color_state import reviewed_source_archive
            except ImportError:
                from fftic_color_state import reviewed_source_archive
            reviewed_source_archive(staging_root, archive)

    def direct_proton_launch_blocked_reason(self, exe_path: Path) -> str:
        try:
            if exe_path.name.casefold() in {"fft_classic.exe", "fft_enhanced.exe"}:
                return _DIRECT_LAUNCH_MESSAGE
        except Exception:
            pass
        return ""

    def deploy(self, *args, **kwargs) -> None:
        raise RuntimeError(
            "FFTIC does not use generic root deployment. Use the explicit managed-runtime "
            "synchronization service after setup readiness passes. No files were changed.")

    def restore(self, *args, **kwargs) -> None:
        raise RuntimeError(
            "FFTIC does not use generic restore. Use the receipt-owned managed-runtime "
            "removal or rollback service. No files were removed.")
