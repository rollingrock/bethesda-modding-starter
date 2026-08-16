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
finding 0 is a hard failure. If upstream ever adds /mcp/instance_info to the headless
server, discovery starts returning 1 and this still passes -- it never asserts the bug.

Exit codes: 0 ok, 1 registered nothing (or the fetch failed).
"""

import sys

DEFAULT_URL = "http://127.0.0.1:8089"
# Tools an agent doing real RE work would reach for first. Presence of the endpoint in the
# schema is what we check -- not that it works on an unloaded program.
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
    print(f"tools REGISTERED    : {count}")

    names = {t.get("name") for t in schema}
    missing = [n for n in EXPECTED if n not in names]
    for name in EXPECTED:
        print(f"  {'ok  ' if name in names else 'MISS'} {name}")

    if count < 1:
        print("FAIL: the bridge registered no tools -- an agent would see nothing.")
        return 1
    if missing:
        print(f"FAIL: schema is missing {missing}; the server is up but not useful.")
        return 1

    print("OK: a Claude session pointed at this server would get its tools.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
