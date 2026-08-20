"""Prove the MCP bridge can register tools against a HEADLESS GhidraMCP server.

Run with ghidra-mcp's own venv python:
    C:\\repos\\ghidra-mcp\\.venv\\Scripts\\python.exe probe_bridge.py [url]

Why this exists as a separate check from `curl /mcp/schema`:

The REST endpoints answering is NOT the same as an agent getting tools. The bridge is what
turns them into MCP tools, and it has two ways to find a server:

  1. discovery  -- scans ports 8089..8104 for /mcp/instance_info. That endpoint is
                   registered ONLY by the GUI plugin (ServerManager.java,
                   GhidraMCPPlugin.java), so against a headless server it finds nothing and
                   discover_instances() returns []. This is expected, not a failure.
  2. TCP fallback -- reads GHIDRA_MCP_URL (default http://127.0.0.1:8089) and fetches
                   /mcp/schema directly. Headless DOES serve that, so this is the path that
                   makes headless usable, and it is the one .mcp.json pins.

So the assertion is deliberately asymmetric: discovery finding 0 is fine, registration
coming up short of MIN_REGISTERED is a hard failure. If upstream ever adds
/mcp/instance_info to the headless server, discovery starts returning 1 and this still
passes -- it never asserts the bug.

Exit codes: 0 ok, 1 the schema fetch failed, too few tools registered, or a flagship tool
never made it into the registered set.
"""

import sys

DEFAULT_URL = "http://127.0.0.1:8089"

# A FLOOR on the registered count, because "registered something" is not the contract.
# register_tools_from_schema catches a per-tool exception into a failures list and returns
# only the SUCCESS count, and _report_tool_registration_failures then writes those to stderr
# and never raises -- so PARTIAL registration is a designed, quiet outcome that an
# `if count < 1` check cannot tell apart from full success. The server exposes ~110 tools
# (the bringup workflow refuses to continue under 100), and one of them is skipped by
# design where a schema name collides with a static bridge tool. A floor rather than an
# equality keeps a single unbuildable tool from turning CI red while still failing the run
# if a whole category of them stops registering.
MIN_REGISTERED = 100

# Tools an agent doing real RE work would reach for first. These are checked against the
# names the bridge ACTUALLY REGISTERED -- not against the fetched schema. A schema entry
# only proves the server advertises the endpoint, so checking it there would be the same
# stage confusion (counting what was validated instead of what was applied) that this
# probe exists to catch, and it would pass on a bridge that registered none of them.
EXPECTED = ("list_functions", "decompile_function", "rename_function", "get_metadata")


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL

    from bridge_mcp_ghidra import discovery, registry, state

    found = discovery.discover_instances()
    print(f"discover_instances(): {len(found)} "
          f"(0 is expected headless -- no /mcp/instance_info)")

    snapshot = state.build_connection_snapshot(mode="tcp", active_tcp=url)
    try:
        schema = registry._fetch_schema(connection=snapshot)
    except Exception as exc:
        print(f"FAIL: could not fetch {url}/mcp/schema: {exc}")
        return 1
    print(f"schema tools parsed : {len(schema)}")

    with state._tool_registry_lock:
        count = registry.register_tools_from_schema(schema, groups=None)
        # Read the registered names under the same (re-entrant) lock the registration ran
        # under, so nothing can re-register in between and make the two disagree.
        # _register_tool_def appends to this list at registry.py:180, as the last thing it
        # does once mcp.tool() has accepted the handler, which makes it the only honest
        # record of what an agent would actually see.
        dynamic = getattr(state, "_dynamic_tool_names", None)
    print(f"tools REGISTERED    : {count}")

    # Deliberately NO fallback to the schema names when that attribute is gone: a fallback
    # would quietly restore the check this probe was written to replace, and a probe that
    # degrades into the bug it guards is worse than one that stops. An upstream rename has
    # to be loud and get fixed here.
    if dynamic is None:
        print("FAIL: bridge_mcp_ghidra.state has no _dynamic_tool_names -- upstream "
              "renamed or removed the registered-tool list. Find its replacement; do not "
              "fall back to the schema, which proves nothing about registration.")
        return 1
    registered = set(dynamic)

    missing = [n for n in EXPECTED if n not in registered]
    for name in EXPECTED:
        print(f"  {'ok  ' if name in registered else 'MISS'} {name}")

    if count < MIN_REGISTERED:
        print(f"FAIL: only {count} of {len(schema)} schema tools registered "
              f"(floor {MIN_REGISTERED}) -- see the bridge's stderr for which ones threw; "
              f"an agent would be missing most of the server.")
        return 1
    if missing:
        print(f"FAIL: the bridge never registered {missing}; the server is up but not "
              f"useful.")
        return 1

    print("OK: a Claude session pointed at this server would get its tools.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
