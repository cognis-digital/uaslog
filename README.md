# UASLOG — Counter-UAS telemetry/log analyzer that flags drone-detection events, RF bands, and track anomalies.

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `defense`

[![PyPI](https://img.shields.io/pypi/v/cognis-uaslog.svg)](https://pypi.org/project/cognis-uaslog/)
[![CI](https://github.com/cognis-digital/uaslog/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/uaslog/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Counter-UAS telemetry/log analyzer that flags drone-detection events, RF bands, and track anomalies..**

*Defense Tech — defensive analysis, compliance, OSINT, and simulation (no offensive capability).*

## Why

UASLOG exists for one job — counter-uas telemetry/log analyzer that flags drone-detection events, rf bands, and track anomalies. — and does it without a SaaS bill or heavyweight setup.
Single-purpose, scriptable, CI-friendly, self-hostable, and callable by AI agents over MCP.

## Install

```bash
pip install cognis-uaslog
# or from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
uaslog --version
uaslog scan .                      # scan the current project
uaslog scan . --format json
uaslog scan . --fail-on high       # non-zero exit for CI gates
uaslog mcp                         # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

- [`demos/01-basic/`](demos/01-basic/SCENARIO.md)
- [`demos/02-clean/`](demos/02-clean/SCENARIO.md)
- [`demos/03-mixed/`](demos/03-mixed/SCENARIO.md)

## Inspiration / prior art

Built in the spirit of **counter-UAS logs**, re-framed for the Cognis approach: single-purpose, self-hostable,
MCP-native, and unified with the rest of the Suite. Missing a credit? Open a PR.

## How it fits the Cognis Neural Suite

`uaslog` is one of the **100+ tools** in the [Cognis Neural Suite](https://github.com/cognis-digital).
Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new rules, and demo scenarios welcome under the collaboration-pull model — see
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal,
internal-evaluation, research, and educational use; **commercial / production use requires a license**
(licensing@cognis.digital). See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today.*
