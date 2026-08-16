# Ghidra MCP workflow

How to drive Ghidra from a Claude Code session via the `ghidra` MCP entry
([bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)). Distilled from months of
Skyrim VR + Fallout 4 VR reverse-engineering; every rule below was earned the hard way.

## Architecture — two servers, pick one

```
HEADLESS (default; no GUI, agent-drivable end to end)
Claude Code ─stdio─> bridge-mcp-ghidra.exe ─HTTP :8089─> GhidraMCPHeadlessServer (java, windowless)

GUI (only when you want to LOOK at the disassembly)
Claude Code ─stdio─> bridge-mcp-ghidra.exe ─HTTP :8089─> GhidraMCP extension (inside the Ghidra GUI)
```

`setup/36-ghidra-mcp.ps1 -Start` runs the headless one. Measured on a clean machine: up in
~5 s, 226 REST endpoints, bridge registers 225 MCP tools. It is a `GhidraLaunchable`, not a
fat jar — `java -jar` cannot work, because the build deliberately leaves the Ghidra jars out
("provided by Ghidra at runtime"). The launcher builds a ~194-jar classpath into a java
`@argfile`; `30-ghidra.ps1` writes it.

## Connecting

**Headless: there is no connect ritual. Just use the tools.** The bridge auto-connects over
TCP using `GHIDRA_MCP_URL` (the generated `.mcp.json` pins `http://127.0.0.1:8089`) and
registers everything at startup.

**`list_instances()` returns `[]` against a headless server. That is expected.** Discovery
probes `/mcp/instance_info`, an endpoint only the GUI plugin registers (`ServerManager.java`,
`GhidraMCPPlugin.java`). Headless doesn't serve it, so the 8089..8104 scan finds nothing and
`connect_instance()` has nothing to match. It *does* serve `/mcp/schema`, which is all the
TCP fallback needs. If you reach for `list_instances()` first out of habit and get an empty
list, **you are connected anyway** — check with any real tool, or
`36-ghidra-mcp.ps1 -Status`.

**GUI: the connect ritual still applies, in this order:**

```
list_instances()                 # ALWAYS first
connect_instance("<your project>")
list_open_programs()
```

Before `connect_instance`, only ~30 static tools exist; the ~200 analysis tools register on
connect. **If `decompile_function` "doesn't exist", you skipped the connect.** With more than
one Ghidra on the machine, an un-connected bridge can silently read the WRONG binary and
return confident nonsense. If one instance has several programs open, pass `program=` on
every call (or set `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`).

The GUI plugin starts its HTTP server automatically when the plugin loads — but it only loads
if `FrontEndTool.xml` names it, and `gradlew deploy`'s patch step can't create that file. It
doesn't exist until the GUI has run once, so on a fresh machine: launch Ghidra once, re-run
`setup/30-ghidra.ps1`, and subsequent launches auto-start the server.

## One writer at a time

A Ghidra project is single-writer. The enrichment pipeline, a GUI, and the headless server all
want the same lock, and the loser fails deep inside Ghidra with
`LockException: Unable to lock project!` — after which the server is up and healthy with
*nothing loaded*, so every tool call answers `No program loaded.`

**Do not decide "is it in use?" by looking for `java.exe`.** pyghidra embeds the JVM inside
the **python** process, so BethesdaGhidraScripts' pipeline — and any pyghidra-based MCP
server — holds a project while no process named java exists on the machine. A name-based scan
says "free" for a project that is very much in use, and acting on that is how databases get
corrupted. Ghidra's actual mutual exclusion is an OS file-channel lock on `<name>.lock~`; the
sibling `<name>.lock` is only hostname/user/timestamp metadata. So the test is simply *can I
open `<name>.lock~` exclusively* — `Test-GhidraProjectLocked` in `setup/_common.ps1`.

`36-ghidra-mcp.ps1` uses that, names the holder when it can, and starts without a project
rather than fighting. It will break a **provably** stale `<name>.lock` (nothing holds
`.lock~` *and* the lock names this host) so a crashed run doesn't need a human to delete a
file nothing owns — but it never touches `.lock~`. And `-Stop` shuts down over HTTP
(`/save_all_programs`, then `/exit_ghidra`) rather than killing the JVM, because a killed JVM
is what leaves the stale lock in the first place.

Note `/list_project_files` does **not** work headless — it answers *"Project listing requires
GUI mode (PluginTool not available)"*, the same GUI-only family as `/mcp/instance_info` and
the non-existent `/server_status`. Use the pipeline's import layout for program paths
(`/f4/vr/Fallout4VR.exe.unpacked.exe`).

## The version gate

The GhidraMCP extension only loads in the exact Ghidra version it was built for
(`extension.properties` version == Ghidra's `application.version`). `setup/30-ghidra.ps1`
builds **against whatever install you actually have** (`gradlew -PGHIDRA_INSTALL_DIR=…`, which
stamps the version at `processResources` time) and then re-reads the stamp out of the built
zip to prove it matches before deploying. Note ghidra-mcp's `pom.xml` names a different
version (12.1.2 at time of writing) — that is only a default, and `gradlew verifyVersion` will
fail on the mismatch even though the build itself is fine. If you upgrade Ghidra, re-run
`30-ghidra.ps1`.
Also: **never let a newer Ghidra upgrade an existing project unattended** — project upgrades
are one-way and analysis databases for game binaries are hours of work to rebuild.

## Working rules

1. **Writes are part of the work.** The bridge has `rename_function`, `rename_symbol`,
   `set_comment`, `create_struct`, `create_enum`, `set_function_prototype`, `save_program`.
   Record findings in the project as you make them — a read-only workflow re-derives the same
   layouts every session.
2. **Anything shaped "for each X tell me Y" is ONE `run_script_inline` call**, not N
   round-trips. It takes full Ghidra Java and runs in-process. Requires the user env var
   `GHIDRA_MCP_ALLOW_SCRIPTS=1` **on the machine** (it's read by the Ghidra JVM — putting it
   in `.mcp.json`'s `env` block does nothing).
3. **Code bytes are ground truth; labels are hints.** Auto-analysis can mislabel high `.data`
   addresses (section shifting) — before coding against a `DAT_*` global, re-derive it from the
   call sites that access it.
4. **The bridge's `debugger_*` tools are WinDbg/dbgeng proxies** (a separate server, usually not
   running). For live game debugging use the **`x64dbg` MCP entry** instead.
5. **Build the analysis database with BethesdaGhidraScripts, not by hand** (next section) —
   types, vtables, signatures and thousands of names make every later decompile readable.
6. Cross-binary signature matching (e.g. Skyrim ↔ Fallout, flat ↔ VR) = two Ghidra GUIs, one per
   binary, `connect_instance` to switch: `get_function_bytes` on the known side → wildcard the
   rel32 offsets → `search_byte_patterns` on the unknown side → `decompile_function` to confirm
   logic.

## For a new game binary: BethesdaGhidraScripts

Do NOT build the analysis database by hand.
[1001Bits/BethesdaGhidraScripts](https://github.com/1001Bits/BethesdaGhidraScripts) (cloned by
`setup/20-repos.ps1`) automates the whole thing for Skyrim SE/AE/VR, Fallout 4 (OG/NG/AE/VR),
Starfield and FNV: it clang-parses the CommonLib headers and imports **type definitions, vtable
layouts, function signatures and address-library names** — for the VR binaries it parses
CommonLibVR/CommonLibF4VR with the VR defines set, giving true VR struct layouts.

```powershell
cd C:\repos\BethesdaGhidraScripts
# drop your game EXE(s) into exes\<game>\<ver>\ (see its README for the exact paths)
python run.py     # menu: 1 (install prereqs incl. its own pinned Ghidra), 2 (submodules),
                  #       7 (full rebuild — generates importers + headless imports everything)
```

Auto-analysis takes hours per Bethesda binary; let it finish. Afterwards:

- Menu **6** opens Ghidra with the enriched project.
- Menu **9** improves an EXISTING project of yours (exact CommonLib importer → generic
  RTTI-walk vtable naming → name reconciler) — it only renames `FUN_*` placeholders and
  leaves hand-typed names alone.
- Menu **10** exports symbols as JSON / .map / **x64dbg database** / a synthetic **PDB** —
  feed the x64dbg export to the x64dbg MCP setup so live debugging shows real names.

`setup/30-ghidra.ps1` builds the GhidraMCP extension **against BGS's managed Ghidra**
(`tools/ghidra` inside the repo) when present, so one Ghidra serves both the pipeline and the
MCP bridge — and so the MCP server can open the very project the pipeline produced. Back up
the project directory before any mass-modifying script.

Because both halves share one Ghidra they also share one project lock: **do not run
`35-ghidra-analysis.ps1` and `36-ghidra-mcp.ps1 -Project` at the same time.** Analysis wins
(it is the long job); point the MCP server at the project once analysis is done.

**Fork note (verified 2026-08-15):** `alandtse/BethesdaGhidraScripts` is a fork **of
1001Bits** (not a sibling — 1001Bits itself forks doodlum), and the two have diverged:
1001Bits is 15 commits ahead, 119 behind. Checked rather than assumed, the split is real and
lopsided by topic:

- **1001Bits uniquely carries the true-VR support.** It vendors `extern/CommonLibF4VR`
  (ArthurHub) as a submodule; alandtse has no such submodule at all. Its `feat(vr): true VR
  struct + vtable layouts for Skyrim VR and Fallout 4 VR` commit is absent downstream, as are
  the IDA OG name-port, PDB generation and TTD dispatch xrefs.
- **alandtse's 119 commits are almost entirely `commonlibvr` type quality** — layout-drift
  detection, bitfield comparison, duplicate/cascade fixes, `LibraryRulesFormat`.

So the pack defaults to 1001Bits, and **for Fallout 4 VR that is not a preference but a
requirement** — the other fork cannot emit true-VR layouts. Worth re-checking alandtse before
deep *Skyrim VR type* work, where its enrichment fixes are the newer ones.

The single-file `../ghidra-scripts/ImportAddressLibrary.py` remains as a minimal fallback
(names only, needs the Jython extension) for when you don't want the full pipeline.
