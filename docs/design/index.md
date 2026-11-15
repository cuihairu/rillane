# Rillane v1 design

This directory maintains only the current v1 design. **Proposal, not implemented as a whole.** The design version is separate from the software release version.

| Document | Responsibility |
|---|---|
| [v1 architecture design](architecture-v1.md) | Six platforms, Clash compatibility, local process routing, concurrent scenarios, generations, ownership and independent delivery gates |
| [Concepts and rationale](architecture-concepts.md) | Responsibilities, rationale, benefits and costs of 32 core concepts |
| [IO and accounting contracts](io-and-accounting.md) | Inbound/outbound, executor, transport/pools and business/underlying accounting |
| [Protocol integration plan](protocol-roadmap.md) | Reuse gates and additional protocols/tunnels/transports |
| [UI prototypes and controls](ui-prototype-v1.md) | Routing modes, regions, DNS/sniff, streaming and developer interactions |
| [10-image prototype gallery](ui/README.md) | Six desktop and two screens per mobile platform, saved PNGs/prompts |
| [Debug, paths and optional MCP](debug-and-mcp.md) | Explanation, actual traces, active probes, privacy, authority and configuration lifecycle |
| [Upstream architecture study](../research/proxy-architectures-2026-11-14.md) | Primary evidence, SVGs and influences from Mihomo, sing-box and Surge |

The repository-root [todo.md](https://github.com/cuihairu/rillane/blob/main/todo.md) is the single execution backlog. Other pages do not duplicate completion checklists. Process routing is required only on local Windows/macOS/Linux hosts; OpenWrt/Android/iOS use available domain/IP/port/device evidence.

[Current implementation](../architecture.md), [configuration](../config.md) and [CLI reference](../cli.md) describe existing behavior, not completed v1 delivery. Old designs, roadmaps and audits have been removed from the active documentation tree; consult Git history for historical material.

[Minimal R logo concepts](brand/README.md): three unselected PNG concepts, with saved prompts and metadata.
