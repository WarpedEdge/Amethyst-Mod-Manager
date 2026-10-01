#!/bin/bash
# Generate an isolated Flatpak manifest from the stable source manifest.
set -euo pipefail

if [ "$#" -ne 2 ] || [ "$1" != "fftic" ]; then
  echo "Usage: $0 fftic OUTPUT" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${SCRIPT_DIR}/io.github.Amethyst.ModManager.yml"
OUTPUT="$2"

sed \
  -e 's/io\.github\.Amethyst\.ModManager/io.github.Amethyst.FFTIC.ModManager/g' \
  -e 's/AMETHYST_FLAVOR=stable/AMETHYST_FLAVOR=fftic/' \
  -e 's/AMETHYST_DISPLAY_NAME=Amethyst Mod Manager$/AMETHYST_DISPLAY_NAME=Amethyst FFTIC Mod Manager/' \
  -e 's/AMETHYST_CONFIG_NAMESPACE=AmethystModManager$/AMETHYST_CONFIG_NAMESPACE=AmethystFFTICModManager/' \
  -e 's|AMETHYST_DEFAULT_STAGING_ROOT=~/Games/Amethyst$|AMETHYST_DEFAULT_STAGING_ROOT=~/Games/Amethyst-FFTIC|' \
  -e 's/-Ddisplay_name=Amethyst Mod Manager$/-Ddisplay_name=Amethyst FFTIC Mod Manager/' \
  -e 's/-Dflavor=stable$/-Dflavor=fftic/' \
  -e 's/-Dconfig_namespace=AmethystModManager$/-Dconfig_namespace=AmethystFFTICModManager/' \
  -e 's|-Ddefault_staging_root=~/Games/Amethyst$|-Ddefault_staging_root=~/Games/Amethyst-FFTIC|' \
  "$SOURCE" > "$OUTPUT"

require_line() {
  if ! grep -Fqx -- "$1" "$OUTPUT"; then
    echo "Generated FFTIC manifest is missing: $1" >&2
    exit 1
  fi
}

require_line "app-id: io.github.Amethyst.FFTIC.ModManager"
require_line "  - --env=AMETHYST_FLAVOR=fftic"
require_line "  - --env=AMETHYST_DISPLAY_NAME=Amethyst FFTIC Mod Manager"
require_line "  - --env=AMETHYST_CONFIG_NAMESPACE=AmethystFFTICModManager"
require_line "  - --env=AMETHYST_DEFAULT_STAGING_ROOT=~/Games/Amethyst-FFTIC"
require_line "      - -Dapplication_id=io.github.Amethyst.FFTIC.ModManager"
require_line "      - -Ddisplay_name=Amethyst FFTIC Mod Manager"
require_line "      - -Dflavor=fftic"
require_line "      - -Dconfig_namespace=AmethystFFTICModManager"
require_line "      - -Ddefault_staging_root=~/Games/Amethyst-FFTIC"
