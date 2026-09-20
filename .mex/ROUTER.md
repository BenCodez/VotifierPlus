---
name: router
description: VotifierPlus protocol and security memory routes.
edges:
  - target: patterns/protocol-change.md
    condition: when parsing or negotiating vote formats
  - target: patterns/proxy-connection-change.md
    condition: when changing network or source-IP handling
last_updated: 2026-09-20
---

# VotifierPlus memory routes

| Task | Read |
| --- | --- |
| Packet versions or downgrade behavior | `context/protocol.md`, `patterns/protocol-change.md` |
| Network, proxy headers, throttling | `context/network.md`, `patterns/proxy-connection-change.md` |
| Event/platform boundaries | `context/architecture.md` |
| Security rationale and legacy concerns | `context/decisions.md` |
| Build and MEX limits | `context/stack.md`, `context/setup.md` |

Retrieve only relevant memory, then verify Java source, tests, and configuration defaults.
