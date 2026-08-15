# devbench — look inside the running game without a debugger

[rollingrock/devbench](https://github.com/rollingrock/devbench) (branch `feat/multigame-core`,
a fork of [alandtse/devbench](https://github.com/alandtse/devbench) being prepared for
upstreaming) is a script-extender plugin that opens an MCP + REST server **on loopback only**
inside the game process. Your agent can then read memory, tail logs, list/dump render targets
and measure frame times **live**, with no rebuild and no debugger attach.

Why you want this: the single most expensive failure mode in game-plugin debugging is an
instrument that can't represent the failure state (e.g. a "is this pixel dark?" probe that
can't see NaN). devbench's tools were built after paying that cost — NaN/Inf are reported as
strings, never null; render-target dumps paint NaN pixels magenta.

## Ports (per game, per runtime)

| Game | Flat | VR |
|---|---|---|
| Skyrim | 8920 | 8921 |
| Fallout 4 | 8930 | 8931 |

If a default port is busy the server walks up and writes the bound port to
`Data/<extender>/Plugins/devbench/runtime.json`.

## Build + deploy (Fallout 4 / FO4VR — CMake side)

```powershell
cd C:\repos\devbench
cmake --preset fallout4          # needs VCPKG_ROOT; VS2022; x64-windows-static
cmake --build build --config Release --target devbench
```

Auto-deploy: set `FalloutPluginTargets` (`;`-separated game `Data` dirs — an MO2 mod folder's
`Data` works) and the DLL+PDB land in `<dir>/F4SE/Plugins/` post-build.

The Skyrim side builds with **xmake** (because CommonLibSSE-NG ships an xmake package):
`xmake build devbench`. Requires `git submodule update --init lib/commonlibsse-ng`.

## First-contact ritual (in game)

The server starts at **kGameDataReady** — load a save first, not just the main menu.

```powershell
irm http://127.0.0.1:8930/api/health      # 8931 for VR — proves load, identity, frame counter
irm http://127.0.0.1:8930/api/tool/rendertarget -Method Post -ContentType application/json -Body '{"action":"list"}'
```

## Registering your own tools from your mod

`include/DevBenchAPI.h` is a cross-plugin C-ABI (MIT-licensed so closed-source mods can use
it): after `kPostLoad`, `GetDevBenchInterface001()->RegisterTool("yourmod.dothing", schema,
handler, ctx)`. Ships as a vcpkg overlay port in `cmake/ports/devbench-api/`.

## Honest current state (2026-08-15)

- Fallout 4 target: **builds and links; unit-tested; never yet loaded in a live game.** The
  first `/api/health` + `rendertarget list` on a real machine is the acceptance test (it
  validates the renderer struct offsets, derived statically from two directions).
- `DevBenchAPI.h` is still **Skyrim-typed** (includes `<RE/Skyrim.h>`) — a Fallout mod cannot
  register its own tools until the discovery handshake is made game-neutral.
- The pytest suite (`tests/http/`) auto-discovers **Skyrim ports only** — for Fallout set
  `$env:DEVBENCH_URL = "http://127.0.0.1:8930"` explicitly; expect Skyrim-only tools to skip.
- Not yet ported from the older in-plugin bench: `/config` live get/set/reload, `/dump/now`,
  GPU stage timers.

## Security model

Bound to `127.0.0.1`, deliberately not configurable — it reads (and can write) arbitrary
process memory. Never ship it enabled in a released mod; it is a dev tool.
