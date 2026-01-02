"""UASLOG MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from uaslog.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-uaslog[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-uaslog[mcp]'")
        return 1
    app = FastMCP("uaslog")

    @app.tool()
    def uaslog_scan(target: str) -> str:
        """Counter-UAS telemetry/log analyzer that flags drone-detection events, RF bands, and track anomalies.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
