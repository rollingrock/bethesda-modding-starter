# The per-game stack

What to build against for each game, as actually used by rollingrock's projects. One row per
game; the pack's defaults are **bold**.

| Game | Script extender | CommonLib | Address library | Build system |
|---|---|---|---|---|
| Fallout 4 (flat) | F4SE | **[alandtse/CommonLibF4](https://github.com/alandtse/CommonLibF4)** (NG-style with runtime dispatch: one DLL serves pre-NG, NG *and* VR) | meh321 "Address Library for F4SE Plugins" (1.10.163 + 1.10.984 NG) | CMake + vcpkg |
| Fallout 4 VR | F4SEVR (runtime 1.2.72) | **alandtse/CommonLibF4** — same checkout, same DLL as flat | [VR Address Library for F4SEVR](https://www.nexusmods.com/fallout4/mods/64879) (alandtse, generated from [fallout_vr_address_library](https://github.com/alandtse/fallout_vr_address_library) CSVs) | CMake + vcpkg (this pack's `templates/f4sevr-plugin`) |
| Skyrim SE/AE/VR | SKSE64 / SKSEVR | **CommonLibSSE-NG lineage** — one DLL runtime-detects SE/AE/VR. NOTE: the canonical fork is contested (CharmedBaryon's original slowed; alandtse/CommonLibVR@vr and other forks are active). If you already have a working NG flow, keep it. | meh321 "Address Library for SKSE Plugins" (SE/AE); alandtse "VR Address Library for SKSEVR" | vcpkg registry (`commonlibsse-ng` via the [Colorglass registry](https://gitlab.com/colorglass/vcpkg-colorglass)) or xmake, per your template |
| Starfield | SFSE (ianpatt) | [libxse/commonlibsf](https://github.com/libxse/commonlibsf) (moved from the Starfield-Reverse-Engineering org) — or raw SFSE via **[rollingrock/sfse-template](https://github.com/rollingrock/sfse-template)** (what `New-Plugin.ps1 -Game SF` uses) | "Address Library for SFSE Plugins" (Nexus) | sfse-template: CMake. CommonLibSF itself: xmake only |

## Notes and traps

- **One CommonLibF4 — and one DLL — for flat, NG and VR.** Don't go hunting for a separate VR
  lib. alandtse's fork dispatches at runtime: `ENABLE_FALLOUT_F4`/`_NG`/`_VR` default ON and
  `REL::Module::IsVR()`/`IsNG()`/`IsF4()` decide at load time, so there is no `FALLOUTVR`
  compile-time define. The template's `windows-vcpkg-vr` preset sets `BUILD_FALLOUTVR=ON`,
  which only selects the deploy target and `buildvr/`; `windows-vcpkg` sets it OFF for
  `build/`. Gate runtime-specific code on `REL::Module`, never on a macro. VR/NG-specific
  structs are still early-stage; verify offsets against the actual binary before trusting a
  struct layout.
- **F4VR never updates.** Runtime is 1.2.72 forever, which is why RE work there ages well.
- **Address libraries let one DLL survive game patches** (flat games) by resolving IDs → offsets
  at runtime. On VR runtimes they are effectively a names database for RE plus a REL::ID source.
- **vcpkg registries only cover Skyrim.** CommonLibF4 and CommonLibSF are consumed as a git
  submodule / path (`external/CommonLibF4`), not as vcpkg ports. The template handles this.
- **`vr_address_tools`** (alandtse) also contains Python tooling for porting flat mods to VR
  (offset conversion, struct extraction) — not just the CSVs.
- **For RE name/type databases, BethesdaGhidraScripts bundles its own address libraries** for
  every game it supports — including Starfield versionlibs, which `vr_address_tools` lacks.
  See `GHIDRA_WORKFLOW.md`.
