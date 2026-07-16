"""CANZAP MCP server — exposes the scan engine as an MCP tool.

Lets an AI agent (Claude Desktop, Cursor, Cognis.Studio, or any MCP client)
replay and heuristically scan a CAN capture as a single tool call. The heavy
lifting lives in :func:`canzap.core.scan`; this module only adapts it to the MCP
transport. The ``mcp`` extra is required:

    pip install "cognis-canzap[mcp]"
"""
from __future__ import annotations

from typing import Any

from canzap.core import scan, to_json


def build_app(mcp_module: Any = None):
    """Construct and return the FastMCP app with the ``canzap_scan`` tool.

    Separated from :func:`serve` so the wiring can be unit-tested without
    starting the blocking stdio event loop. ``mcp_module`` is injectable for
    tests; by default it imports ``mcp.server.fastmcp``.
    """
    if mcp_module is None:
        from mcp.server.fastmcp import FastMCP
    else:  # pragma: no cover - test injection path
        FastMCP = mcp_module.FastMCP

    app = FastMCP("canzap")

    @app.tool()
    def canzap_scan(target: str) -> str:
        """Replay and heuristically scan CAN bus traffic from a candump log or
        directory of logs. Returns a JSON findings report (severity-ranked)."""
        return to_json(scan(target))

    return app


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-canzap[mcp]"
    """
    try:
        app = build_app()
    except Exception:
        print("Install the MCP extra: pip install 'cognis-canzap[mcp]'")
        return 1
    app.run()
    return 0
