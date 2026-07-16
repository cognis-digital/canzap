"""Tests for the MCP server wiring (without starting the blocking event loop)."""
from __future__ import annotations

import json

import canzap.mcp_server as mcp_server


def test_module_imports_scan_and_to_json():
    # Regression: this module imports scan/to_json from core at import time.
    assert callable(mcp_server.scan)
    assert callable(mcp_server.to_json)
    assert callable(mcp_server.serve)
    assert callable(mcp_server.build_app)


def test_build_app_registers_tool_with_fake_mcp():
    """build_app must register exactly one tool and wire it to scan()."""
    registered = {}

    class FakeApp:
        def __init__(self, name):
            self.name = name

        def tool(self):
            def deco(fn):
                registered[fn.__name__] = fn
                return fn
            return deco

    class FakeModule:
        FastMCP = FakeApp

    app = mcp_server.build_app(FakeModule)
    assert isinstance(app, FakeApp)
    assert app.name == "canzap"
    assert "canzap_scan" in registered

    # the wired tool must return a JSON scan report for real candump text
    out = registered["canzap_scan"]("(1.0) can0 7DF#0201050000000000")
    report = json.loads(out)
    assert report["tool"] == "canzap"
    assert report["frame_count"] == 1


def test_serve_returns_1_without_mcp(monkeypatch, capsys):
    """serve() degrades gracefully when the app cannot be constructed."""
    def boom():
        raise RuntimeError("no mcp")
    monkeypatch.setattr(mcp_server, "build_app", boom)
    rc = mcp_server.serve()
    assert rc == 1
    assert "mcp" in capsys.readouterr().out.lower()
