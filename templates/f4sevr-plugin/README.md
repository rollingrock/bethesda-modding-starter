# starterplugin

F4SEVR plugin scaffolded from [bethesda-modding-starter](https://github.com/rollingrock/bethesda-modding-starter).
Build chain: CMake + vcpkg + [rollingrock/CommonLibF4](https://github.com/rollingrock/CommonLibF4) (NG-style — one lib for flat and VR) as the `external/CommonLibF4` submodule.

## Building

```powershell
git submodule update --init --recursive
cmake --preset vs2022-windows-vcpkg-vr
cmake --build buildvr --config Release
```

DLL lands in `buildvr/Release/`. To auto-deploy every build into an MO2 mod folder, copy
`CMakeUserPresets.json.template` to `CMakeUserPresets.json`, edit `MO2_INSTALL_PATH`, and configure
with `cmake --preset vr-mo2` instead.

Prerequisites (see the starter pack's `setup/` scripts): VS2022 + C++ workload, CMake, vcpkg with
**both** `VCPKG_ROOT` and `VCPKG_INSTALLATION_ROOT` set.

## Layout

- `src/main.cpp` — plugin entry; logging, config load, the single `F4SE::AllocTrampoline(256)` call, hook install point.
- `src/PCH.h` — precompiled header + hook helpers. Read the `write_thunk_call` comment before touching trampoline code.
- `src/Settings/Settings.h` — TOML-backed settings. One `MAKE_SETTING` line + one `LOAD` line per tunable; prefer a setting over a hardcoded constant.
- `Data/F4SE/Plugins/starterplugin.toml` — shipped config. Deployed by hand, not by the build, so a rebuild never clobbers values you are live-tuning.
- `cmake/sourcelist.cmake` / `cmake/headerlist.cmake` — **file lists are manual.** A new `.cpp` that is not added to `sourcelist.cmake` silently does not build; this is the classic mistake in this chain.

## Rules that keep you out of known crashes

1. **One `AllocTrampoline` for the whole plugin.** On F4SEVR, per-hook `AllocTrampoline` frees every previously written stub (no branch-pool interface, so it falls back to `Trampoline::create`, which releases the old buffer). The second hook crashes the game.
2. **14 bytes of trampoline per `write_call<5>` hook.** 256 covers ~18 hooks; raise it in `main.cpp` if you install more.
3. New source files go in `cmake/sourcelist.cmake` (and headers in `headerlist.cmake`).
