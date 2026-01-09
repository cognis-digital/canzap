"""CANZAP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from canzap.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-canzap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-canzap[mcp]'")
        return 1
    app = FastMCP("canzap")

    @app.tool()
    def canzap_scan(target: str) -> str:
        """Replay, fuzz, and assert on CAN bus traffic from a .pcap or SocketCAN interface with a tiny YAML DSL.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
