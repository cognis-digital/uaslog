"""UASLOG MCP server — exposes analyze_log() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from uaslog.core import ParseError, analyze, parse_log


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
    def uaslog_scan(log_text: str) -> str:
        """Analyze a C-UAS log (JSONL or CSV text).

        Returns JSON findings with severity, codes, and event references.
        Raises ValueError on unparseable input.
        """
        try:
            events = parse_log(log_text)
        except ParseError as exc:
            raise ValueError(str(exc)) from exc
        result = analyze(events)
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)

    app.run()
    return 0
