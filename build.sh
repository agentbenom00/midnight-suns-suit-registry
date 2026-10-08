#!/usr/bin/env bash
# Build the release: dist/MidnightSuns-SuitRegistry.zip =
#   MidnightSuns/Binaries/Win64/version.dll   (everything: launch hook + registry builder)
#   README.txt
# Needs zig (~/Tools/zig-*) to cross-compile the DLL.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
zig="${ZIG:-$(ls -d "$HOME"/Tools/zig-linux-x86_64-*/zig | tail -1)}"
out="$here/dist/MidnightSuns-SuitRegistry"
rm -rf "$out" "$here/dist/MidnightSuns-SuitRegistry.zip"
mkdir -p "$out/MidnightSuns/Binaries/Win64"
(cd "$here/src/proxy" && "$zig" cc -target x86_64-windows-gnu -shared -O2 -s -Wall -Wno-unused-function \
  -Wl,--image-base=0x180000000 -o "$out/MidnightSuns/Binaries/Win64/version.dll" \
  version.c util.c zlib.c pak.c oodle.c json.c registry.c sync.c version.def)
rm -f "$out/MidnightSuns/Binaries/Win64/version.lib"
cp "$here/README.txt" "$out/"
(cd "$out" && python3 -c 'import shutil; shutil.make_archive("../MidnightSuns-SuitRegistry", "zip", ".")')
ls -la "$out/MidnightSuns/Binaries/Win64/version.dll" "$here/dist/MidnightSuns-SuitRegistry.zip"
