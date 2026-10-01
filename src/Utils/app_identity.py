"""Build-flavor identity shared by packaging-sensitive runtime code."""

from __future__ import annotations

import os

STABLE_APP_ID = "io.github.Amethyst.ModManager"
FFTIC_APP_ID = "io.github.Amethyst.FFTIC.ModManager"

try:
    from Utils._build_identity import (
        APPLICATION_ID as APP_ID,
        CONFIG_NAMESPACE,
        DEFAULT_STAGING_ROOT,
        DISPLAY_NAME,
        FLAVOR,
    )
except ImportError:
    # Source checkouts have no Meson-generated module. Environment overrides
    # support packaging checks while the ordinary source/AppImage identity
    # remains exactly the stable application.
    APP_ID = os.environ.get("AMETHYST_APP_ID", STABLE_APP_ID)
    FLAVOR = os.environ.get("AMETHYST_FLAVOR", "stable")
    DISPLAY_NAME = os.environ.get(
        "AMETHYST_DISPLAY_NAME", "Amethyst Mod Manager")
    CONFIG_NAMESPACE = os.environ.get(
        "AMETHYST_CONFIG_NAMESPACE", "AmethystModManager")
    DEFAULT_STAGING_ROOT = os.environ.get(
        "AMETHYST_DEFAULT_STAGING_ROOT", "~/Games/Amethyst")


def is_fftic_build() -> bool:
    """Return whether this package is the isolated FFTIC flavor."""
    return FLAVOR == "fftic" or APP_ID == FFTIC_APP_ID


def main_window_title(version: str) -> str:
    """Return the versioned title for the active build display identity."""
    return f"{DISPLAY_NAME} - v{version}" if version else DISPLAY_NAME


def is_our_flatpak() -> bool:
    """Match only the Flatpak ID this package was built to use."""
    return os.environ.get("FLATPAK_ID") == APP_ID


def protocol_registration_allowed() -> bool:
    """The FFTIC flavor must never alter the stable host URL handlers."""
    return not is_fftic_build()


def official_updates_allowed() -> bool:
    """Only stable packages may install from Amethyst's official channels."""
    return not is_fftic_build()


def ipc_socket_name() -> str:
    """Return a flavor-specific socket basename, preserving stable's name."""
    return ("amethyst-fftic-mod-manager.sock" if is_fftic_build()
            else "amethyst-mod-manager.sock")
