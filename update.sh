#!/usr/bin/env bash
# Linux helper: sync the suit registry pak now, without starting the game (the game's version.dll does this by itself
# at every launch). Runs the installed version.dll's sync through the game's Proton.
#   ./update.sh            update if needed
#   ./update.sh --force    rebuild anyway (removes the registry pak first)
set -euo pipefail
steam="$HOME/.steam/debian-installation"
game="$steam/steamapps/common/Marvel's Midnight Suns"
paks="$game/MidnightSuns/Content/Paks"
dll="$game/MidnightSuns/Binaries/Win64/version.dll"
prefix="$steam/steamapps/compatdata/368260"
proton="$(ls -d "$steam"/compatibilitytools.d/GE-Proton*/proton "$steam/steamapps/common/Proton - Experimental/proton" 2>/dev/null | head -1)"
data="$prefix/pfx/drive_c/users/steamuser/AppData/Local/MidnightSunsSuitRegistry"
[ -f "$dll" ] || { echo "version.dll is not installed in $game"; exit 1; }
if pgrep -f "^[^ ]*MidnightSuns-Win64-Shipping\.exe" >/dev/null; then
  echo "Midnight Suns is running: close it first"; exit 2
fi
[ "${1:-}" = "--force" ] && rm -f "$paks/zz_MidnightSuns_SuitRegistry_P.pak"
mkdir -p "$data"
cp "$dll" "$data/SuitRegistrySync.dll"
: > "$data/SuitRegistry.log"
STEAM_COMPAT_CLIENT_INSTALL_PATH="$steam" STEAM_COMPAT_DATA_PATH="$prefix" \
  "$proton" run rundll32.exe 'C:\users\steamuser\AppData\Local\MidnightSunsSuitRegistry\SuitRegistrySync.dll',SuitRegistrySync \
  --quiet "Z:$paks" >/dev/null 2>&1 || true
tail -n +2 "$data/SuitRegistry.log"
! grep -q "^error" "$data/SuitRegistry.log"
