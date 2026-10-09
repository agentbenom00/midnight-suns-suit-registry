# Midnight Suns Suit Registry

A single-file mod for **Marvel's Midnight Suns** that lets any number of new suit and palette mods work side by
side. Drop `version.dll` into the game folder once; from then on, adding or removing suit/palette paks just works,
on Steam and Epic.

## Why

Midnight Suns only shows outfits and palettes that are listed in its asset registry
(`CodaGame/AssetRegistry*.bin`, a main file plus 8 language variants), and there is only one registry. A mod that
adds a new suit has to ship a patched registry, so two such mods overwrite each other and only one shows up.

This mod builds one shared registry, `zz_MidnightSuns_SuitRegistry_P.pak`, from the game's own registry plus every
installed suit or palette mod, and keeps it up to date by itself at every launch.

## Install (players)

1. Download the latest release zip.
2. Drag its `MidnightSuns` folder into the game folder (the one with `MidnightSuns.exe`) and let it merge. This puts
   `version.dll` in `<game>\MidnightSuns\Binaries\Win64\`.
3. Put suit/palette mod paks in `<game>\MidnightSuns\Content\Paks\` as usual and start the game.

Linux (Proton): also set the Steam launch options to `WINEDLLOVERRIDES="version=n,b" %command%`
(Heroic: environment variable `WINEDLLOVERRIDES` = `version=n,b`).

Tested on Windows and on Linux (Steam with Proton).

When something changed (mod added, removed or updated, or a game update) a small window shows the rebuild for about
10 seconds before the game starts; otherwise the check takes a fraction of a second. The first rebuild downloads the
Oodle decompression library once (see Credits). Log: `%LOCALAPPDATA%\MidnightSunsSuitRegistry\SuitRegistry.log`.

See [README.txt](README.txt) (shipped in the zip) for the details players need.

## For mod authors

A suit or palette pak carries a manifest at `CodaGame/SuitMods/<id>.json` (the game ignores it):

```json
{"format": 1, "id": "Venom_SpaceKnight", "title": "Space Knight (Venom)",
 "sources": ["/Game/DLC_Venom/Templates/TacticalOutfits/VENM/TacticalOutfit_HR_VENM_Anti.TacticalOutfit_HR_VENM_Anti", "..."],
 "rules": [["AntiVenom", "SpaceKnight"]], "keep": []}
```

- `sources`: the original (donor) registry entries your mod's packages were cloned from: the outfit, its palettes,
  meshes, physics assets, materials and textures.
- `rules`: `[old, new]` text replacements applied in order to every name of each cloned entry, so the registry points
  at your packages. Names containing a `keep` string stay unchanged.
- A source can also be `{"source": path, "rules": [...]}` with its own rules, to clone one donor more than once
  (e.g. extra palettes made from one original palette).
- `id` must be unique. A manifest without an outfit that only adds palettes counts as a palette mod;
  `"kind": "suit"` / `"palette"` overrides that.
- Don't ship `AssetRegistry*.bin` files in your pak; the shared registry replaces them.
- New items need their own `EntitlementID`s and must be free (`bRequirePurchase` false; mod items can't be bought);
  new outfits also need `bUnlockedAtGameStart` true.

## How it works

- **Loading:** the game imports `version.dll`, and Windows looks next to the exe first. Exports that `kernelbase.dll`
  also has are real PE forwarders (`src/proxy/version.def`), so the game binds straight to the real code. The game's
  anti-tamper crashes it if an imported function starts with a `jmp`, or if a second `version.dll` is loaded during
  startup.
- **Quick check (every launch):** inside `DllMain` the DLL only reads files: the mod paks' manifests and the record
  (`CodaGame/SuitRegistry/state.json`) stored in the registry pak. If they match, nothing else happens.
- **Rebuild (when needed):** threads, downloads and windows aren't allowed under the loader lock, so the DLL copies
  itself to `%LOCALAPPDATA%\MidnightSunsSuitRegistry\SuitRegistrySync.dll` and runs
  `rundll32 SuitRegistrySync.dll,SuitRegistrySync --from-game <Paks>`, waiting for it before the game continues.
  It reads the game's registries straight from its paks, appends the cloned entries (existing indices never move)
  and writes the registry pak.
- Plain C, no dependencies besides Windows: pak reader (v3-v11, AES via bcrypt) and writer (v11, Zlib),
  inflate/deflate, CityHash64, a small JSON parser and the AssetRegistry v8 patcher.

| File | What |
|---|---|
| `src/proxy/version.c` | exports, the in-game check, the rundll32 entry point |
| `src/proxy/sync.c` | scanning mod paks and manifests, the state record, the rebuild |
| `src/proxy/pak.c` | pak reading and writing |
| `src/proxy/registry.c` | AssetRegistry (version 8, FixedTags) parsing and patching |
| `src/proxy/zlib.c`, `oodle.c`, `json.c`, `util.c` | compression, Oodle loading, JSON, buffers/log/hashes |

## Building

Cross-compiled from Linux with [zig](https://ziglang.org/) 0.13:

```sh
./build.sh      # -> dist/MidnightSuns-SuitRegistry.zip (MidnightSuns/Binaries/Win64/version.dll + README.txt)
```

`build.sh` looks for zig in `~/Tools/zig-linux-x86_64-*`; set `ZIG=/path/to/zig` otherwise. `update.sh` is a Linux
helper that runs the sync through the game's Proton without starting the game.

## Credits

- Oodle is downloaded at runtime from [WorkingRobot/OodleUE](https://github.com/WorkingRobot/OodleUE) builds (as
  [FModel](https://github.com/4sval/FModel) / [CUE4Parse](https://github.com/FabianFG/CUE4Parse) do); it is not
  part of this project.
- Pak and AssetRegistry formats as documented by CUE4Parse and [repak](https://github.com/trumank/repak).
- Not affiliated with or endorsed by Firaxis, 2K or Marvel.

## License

[MIT](LICENSE)
