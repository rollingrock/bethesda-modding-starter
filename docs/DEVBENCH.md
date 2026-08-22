# devbench — look inside the running game without a debugger

[rollingrock/devbench](https://github.com/rollingrock/devbench) (branch `main`, a fork of
[alandtse/devbench](https://github.com/alandtse/devbench) being prepared for upstreaming) is a
script-extender plugin that opens an MCP + REST server **on loopback only**
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

**The server starts at `kPostLoad`** — it is listening within a second of the process
starting, before any save is loaded. (It used to bind at `kGameDataReady`; on F4SEVR that
message either arrives ~7 s late or, on some installs, never at all, and the server simply
never started. Measured lifecycle from a live FO4VR run: `kPostLoad` and `kPostPostLoad` at
T+0.25 s, `kGameDataReady` and `kGameLoaded` together at T+7.2 s.)

**A save still matters for the tools, just not for the server.** Anything that needs a
main-thread task fails while the game sits at the main menu — the honest error, seen live:

```
tool 'inspect' failed [504]: main-thread task did not run within 5000ms and the game frame
counter has not advanced -- main thread hung or the game is fully paused
```

So: connect whenever you like, but load a save before expecting `console`, `rendertarget`,
`measure` or most of `inspect` to answer.

**Two probes are deliberately exempt**, because a diagnostic that goes silent exactly when the
game is stuck is worthless: `inspect kind='health'` and `inspect kind='ui'` are answered
*without* the main thread — `ui` reads the engine's own menu map under its read lock. Those are
what you ask when everything else 504s, and `ui` is how you find the modal that is holding the
main thread (and, since 2026-08-17, `menu accept` is how you dismiss it without a headset).

```powershell
irm http://127.0.0.1:8930/api/health      # 8931 for VR — proves load, identity, frame counter
irm http://127.0.0.1:8930/api/tools       # the tool catalogue — the live list, not this doc
irm http://127.0.0.1:8930/api/tool/rendertarget -Method Post -ContentType application/json -Body '{"action":"list"}'
```

`frame` rising between two `/api/health` calls is what proves the engine is rendering rather
than stuck at init. Note `/mcp` answers 400 to a bare GET and `/api/tool/list` is a 404 — the
catalogue is `/api/tools`.

## Registering your own tools from your mod

`include/DevBenchAPI.h` **and `DevBenchAPI.cpp`** are a cross-plugin C-ABI, MIT-licensed
separately from devbench's GPL-3.0 so closed-source mods can vendor them. Vendor *both*: the
header is plain C++ and game-neutral on purpose, and the `.cpp` is the only extender-aware
part — it is what picks SKSE or F4SE at compile time. Then
`GetDevBenchInterface001()->RegisterTool("yourmod.dothing", descriptorJson, handler, ctx)`.
Ships as a vcpkg overlay port in `cmake/ports/devbench-api/`.

**Ask for the interface at `kPostPostLoad` on Fallout** — not `kPostLoad`. F4SE runs every
plugin's `kPostLoad` handler in plugin *load order* and devbench sets itself up in its own, so
a consumer sorting before devbench asks before the provider exists and gets `nullptr`. (On
Skyrim: `kDataLoaded`.) `nullptr` is never an error — devbench is a development dependency and
must never become a load-order requirement — so retry at a later message. The header states
the whole contract, including which ABI revision each vtable slot needs; read it there.

## State (2026-08-16) — the Fallout 4 target is live-verified

Run on a real FO4VR 1.2.72 install under MO2, headless via SteamVR's null driver. Every one of
the seven tools that existed that day answered. (`menu` — detect and answer a blocking modal —
landed the next day in devbench `280348e`, making eight; it has not been through this run.)

| check | result |
|---|---|
| `/api/health` | `ok:true, game:fallout4, vr:true, extender:F4SE, port:8931` |
| frame counter | rising across calls (3733 → 3741) — engine really rendering |
| `inspect state` | `playerLoaded:true`, version 1.14.0 |
| `inspect scene` | `daysPassed 1.458, gameHour 11.0, position 2048/2048/0` |
| **`rendertarget list`** | **95 targets, 3024x1680, R11G11B10_FLOAT, all decodable** |
| `measure` | 135 fps, mean 7.41 ms, p50 7.20, p95 10.63, p99 18.18, 0 missed transitions |

`rendertarget list` was the acceptance test, because the renderer struct offsets were derived
statically from two directions and never checked against a running binary. 95 live targets at
a stereo 3024x1680 in the right HDR format is that check passing. The log records it plainly:
`gfx: renderer resolved (95 live render targets)`.

Still open:

- Nobody has played this in a headset; every run has been headless.
- The pytest suite (`tests/http/`) auto-discovers **Skyrim ports only** — for Fallout set
  `$env:DEVBENCH_URL = "http://127.0.0.1:8930"` explicitly; expect Skyrim-only tools to skip.
- Not yet ported from the older in-plugin bench: `/config` live get/set/reload, `/dump/now`,
  GPU stage timers.

## Security model

Bound to `127.0.0.1`, deliberately not configurable — it reads (and can write) arbitrary
process memory. Never ship it enabled in a released mod; it is a dev tool.
