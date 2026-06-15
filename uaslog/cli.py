"""Command-line interface for UASLOG.

Usage:
    uaslog analyze LOGFILE [--format table|json] [--min-severity LEVEL]
    uaslog --version

Exit codes:
    0  parsed OK, no findings at or above --min-severity (default: low)
    1  parsed OK, findings present at or above threshold (triage required)
    2  usage / parse error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import ParseError, SEVERITY_ORDER, analyze, parse_log


def _read_input(path: str) -> str:
    if path == "-":
        try:
            return sys.stdin.read()
        except UnicodeDecodeError as exc:
            raise OSError(f"stdin contains non-UTF-8 data: {exc}") from exc
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return fh.read()
        except UnicodeDecodeError as exc:
            raise OSError(f"file is not valid UTF-8 (binary?): {exc}") from exc


def _render_table(result, min_rank: int) -> str:
    lines: list[str] = []
    s = result.stats
    lines.append(f"{TOOL_NAME} v{TOOL_VERSION} - C-UAS log triage")
    lines.append(
        f"events={s['event_count']} tracks={s['track_count']} "
        f"findings={s['finding_count']} max_severity={result.max_severity}"
    )
    sev = s["severity_counts"]
    if sev:
        parts = ", ".join(f"{k}={v}" for k, v in sorted(
            sev.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]))
        lines.append(f"by severity: {parts}")
    lines.append("")

    shown = [f for f in result.findings if SEVERITY_ORDER[f.severity] >= min_rank]
    if not shown:
        lines.append("No findings at or above threshold.")
        return "\n".join(lines)

    header = f"{'SEVERITY':<9} {'CODE':<20} {'TRACK':<10} {'SEQS':<14} MESSAGE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in shown:
        seqs = ",".join(str(x) for x in f.seqs[:4])
        if len(f.seqs) > 4:
            seqs += ".."
        tid = f.track_id if f.track_id is not None else "-"
        lines.append(
            f"{f.severity:<9} {f.code:<20} {tid:<10} {seqs:<14} {f.message}"
        )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Counter-UAS telemetry/log analyzer (defensive triage only).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("analyze", help="Analyze a C-UAS log file (JSONL/CSV).")
    a.add_argument("logfile", help="Path to log file, or '-' for stdin.")
    a.add_argument("--format", choices=["table", "json"], default="table",
                   help="Output format (default: table).")
    a.add_argument("--min-severity",
                   choices=list(SEVERITY_ORDER.keys()), default="low",
                   help="Minimum severity to display/treat as failure (default: low).")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":
        parser.print_help()
        return 2

    try:
        text = _read_input(args.logfile)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    try:
        events = parse_log(text)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = analyze(events)
    min_rank = SEVERITY_ORDER[args.min_severity]

    if args.format == "json":
        out = result.to_dict()
        out["min_severity"] = args.min_severity
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(_render_table(result, min_rank))

    # Non-zero exit when actionable findings exist at/above the threshold.
    actionable = any(
        SEVERITY_ORDER[f.severity] >= min_rank for f in result.findings
    )
    return 1 if actionable else 0


if __name__ == "__main__":
    raise SystemExit(main())
