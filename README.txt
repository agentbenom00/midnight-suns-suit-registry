MIDNIGHT SUNS SUIT REGISTRY
===========================

Marvel's Midnight Suns only shows outfits that are listed in its asset registry, and there is only one registry, so
standalone suit mods can't each bring their own. This mod is a single file, version.dll, that builds one shared
registry (zz_MidnightSuns_SuitRegistry_P.pak) from the suit paks you have installed - automatically, every time the
game starts, on Steam and Epic. Add or remove a suit pak, press Play: done.


INSTALL
-------
Drag the "MidnightSuns" folder from this zip into the game folder (the one with MidnightSuns.exe) and let it merge.
That puts version.dll in   <game>\MidnightSuns\Binaries\Win64\

  Steam: right-click the game > Manage > Browse local files
  Epic:  Library > the game's "..." > Manage > the folder icon next to Installation

Linux (Proton) only: also set the game's Steam launch options to
    WINEDLLOVERRIDES="version=n,b" %command%
(Heroic: game settings > Advanced > environment variables: WINEDLLOVERRIDES = version=n,b)

Uninstall: delete version.dll (and zz_MidnightSuns_SuitRegistry_P.pak in Content\Paks if you remove all suits).


WHAT TO EXPECT
--------------
- Every launch it checks the suit paks first; when nothing changed you won't notice it.
- When something changed (suit added/removed/updated, or a game update), a small window shows the rebuild for about
  10 seconds before the game starts.
- The very first rebuild downloads the Oodle decompression library once (needed to read the game's files). Offline?
  Put oodle-data-shared.dll or oo2core_9_win64.dll next to version.dll instead.
- If the game is in a protected folder (e.g. C:\Program Files\Epic Games) Windows asks for permission to update the
  registry pak.
- If something is wrong (e.g. a suit made for DLC you don't have) a message says so, and the game still starts.
- "Verify game files" on Steam/Epic may remove version.dll: just copy it in again.
- Another mod that also uses version.dll can't be used at the same time.
- Log: %LOCALAPPDATA%\MidnightSunsSuitRegistry\SuitRegistry.log (Linux: inside the game's Proton prefix).


FOR SUIT AUTHORS
----------------
Each suit pak carries a manifest at  CodaGame/SuitMods/<id>.json  (the game ignores it):

  {"format": 1, "id": "Venom_SpaceKnight", "title": "Space Knight (Venom)",
   "sources": ["/Game/.../TacticalOutfit_HR_VENM_Anti.TacticalOutfit_HR_VENM_Anti", "..."],
   "rules": [["AntiVenom", "SpaceKnight"]], "keep": []}

"sources" are the original (donor) registry entries: the outfit, its palettes, meshes, physics, materials and
textures. Each one is cloned with "rules" applied in order to every name ([old, new] text replacements); names
containing a "keep" string are left unchanged. "id" must be unique. Don't ship AssetRegistry files in a suit pak.
A manifest without an outfit that only adds palettes counts as a palette mod ("2 suits and 1 palette");
"kind": "suit" or "palette" overrides that.

To clone one donor more than once (e.g. extra palettes made from one original palette), give that source its own
rules, which replace the global ones for that entry:

  {"source": "/Game/.../HeroSkinPalette_HR_SPDR_DemonSpider.HeroSkinPalette_HR_SPDR_DemonSpider",
   "rules": [["HeroSkinPalette_HR_SPDR_DemonSpider", "HeroSkinPalette_HR_SPDR_BigTime4"], ["DemonSpider", "BigTime"]]}
