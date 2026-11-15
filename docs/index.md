---
layout: home

hero:
  name: Rillane
  text: One proxy core, six-platform design
  tagline: v1 targets Clash/Mihomo subscriptions, local process routing on three desktops, concurrent game/web policies and optional Debug/MCP. Implementation and targets are labelled separately.
  image:
    src: /logo.svg
    alt: Rillane logo
  actions:
    - theme: brand
      text: v1 architecture
      link: /design/architecture-v1
    - theme: alt
      text: Concepts and rationale
      link: /design/architecture-concepts
    - theme: alt
      text: Current implementation
      link: /architecture

features:
  - title: Shared core and platform ports
    details: Linux, OpenWrt, Windows, macOS, Android and iOS share contracts, with separate capture, identity and lifecycle gates.
  - title: Concurrent game and web
    details: Evidence-based classification, pinned sessions, bounded resources and measured objectives.
  - title: Diagnostics and optional AI
    details: Separate Explain, Trace and Probe; MCP disabled by default, reads before controlled writes.
---

Connection diagnostics follow real lists → per-flow timelines → rule explanation → active probes. See the [v1 diagnostic specification](design/debug-and-mcp.md). These remain design targets.
