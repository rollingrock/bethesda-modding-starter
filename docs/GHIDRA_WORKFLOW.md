# Ghidra MCP workflow

How to drive Ghidra from a Claude Code session via the `ghidra` MCP entry
([bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)). Distilled from months of
Skyrim VR + Fallout 4 VR reverse-engineering; every rule below was earned the hard way.

## Architecture

```
Claude Code ── stdio ──> bridge-mcp-ghidra.exe ── HTTP :8089 ──> GhidraMCP extension (in the Ghidra GUI)
```

- **The Ghidra GUI must be running** with your program open and `Tools > GhidraMCP > Start MCP
  Server` clicked. No GUI = no analysis tools.
- The bridge discovers running Ghidra instances via socket files in
  `%TEMP%\ghidra-mcp-<user>\` — stale files from crashed sessions show up as dead entries in
  `list_instances()`; ignore or delete them.

## The connect ritual (every session, no exceptions)

```
list_instances()                 # ALWAYS first
connect_instance("<your project>")
list_open_programs()
```

Before `connect_instance`, only ~30 static tools exist. The ~200 analysis tools
(`decompile_function`, `search_functions`, …) register only after connecting. **If
`decompile_function` "doesn't exist", you skipped the connect.** And if more than one Ghidra
runs on the machine, an un-connected bridge can silently read the WRONG binary and return
confident nonsense. If one instance has multiple programs open, pass `program=` on every call
(or set `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` for the bridge).

## The version gate

The GhidraMCP extension only loads in the exact Ghidra version it was built for
(`extension.properties` version == Ghidra's `application.version`). `setup/30-ghidra.ps1`
enforces this by downloading the stock Ghidra release matching ghidra-mcp's `pom.xml`. If you
upgrade Ghidra, rebuild + redeploy the extension (`python -m tools.setup build` / `deploy`).
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
5. **Import the address library early** (see `../ghidra-scripts/`) — thousands of free function
   names make every later decompile readable.
6. Cross-binary signature matching (e.g. Skyrim ↔ Fallout, flat ↔ VR) = two Ghidra GUIs, one per
   binary, `connect_instance` to switch: `get_function_bytes` on the known side → wildcard the
   rel32 offsets → `search_byte_patterns` on the unknown side → `decompile_function` to confirm
   logic.

## For a new game binary

1. Create a Ghidra project, import the EXE (with PDB if one exists — VR binaries shipped with
   partial ones historically; flat binaries rarely).
2. Run auto-analysis and let it FINISH (hours for a Bethesda binary; interrupting corrupts less
   than it tempts you to think, but the function list will be incomplete).
3. Run the RTTI analyzer — Creation Engine binaries are RTTI-rich, and class hierarchies are the
   fastest map of the engine.
4. Import the address library names.
5. Save. Back up the project directory before any mass-modifying script.
