"""CANZAP MCP server - exposes check() as an MCP tool for Cognis.Studio."""
from __future__ import annotations


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-canzap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-canzap[mcp]'")
        return 1

    from canzap.core import (
        parse_candump_text,
        load_scenario_text,
        run_scenario,
        result_to_json,
    )

    app = FastMCP("canzap")

    @app.tool()
    def canzap_check(log_text: str, scenario_text: str) -> str:
        """Assert on CAN bus traffic: parse candump log text and evaluate a
        CANZAP scenario DSL. Returns JSON findings."""
        frames = parse_candump_text(log_text)
        scenario = load_scenario_text(scenario_text)
        result = run_scenario(frames, scenario)
        return result_to_json(result)

    app.run()
    return 0
