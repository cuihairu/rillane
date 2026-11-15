[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="docs/public/logo.svg" width="64" alt="Rillane logo" /></p>

# Rillane

Rillane is a Rust proxy-core project. The current design baseline is **v1**: one core across six platforms, Clash/Mihomo subscriptions and concurrent game/web traffic. **v1 is a design version, not a completed implementation or a v1 software release.**

## Documentation

- [v1 design index](docs/design/index.md)
- [v1 architecture](docs/design/architecture-v1.md)
- [32 concepts and rationale](docs/design/architecture-concepts.md)
- [Debug, paths and optional MCP](docs/design/debug-and-mcp.md)
- [Upstream study and SVGs](docs/research/proxy-architectures-2026-11-14.md)
- [139 atomic tasks with priorities, dependencies and acceptance](todo.md)

Old designs, roadmaps and audits are removed from active documentation; use Git history. Process routing is required only on local Windows/macOS/Linux hosts, not arbitrary app PID lookup on OpenWrt/Android/iOS.

## Implementation and usage

Existing protocols, Linux TUN, presets, subscriptions and aggregates are reusable. Clash/Mihomo compatibility is partial; full platform integration, concurrent scenario policies, flow diagnostics and MCP still require implementation.

[Implementation](docs/architecture.md) · [Configuration](docs/config.md) · [CLI](docs/cli.md) · [Protocols](docs/PROTOCOLS.md) · [Subscriptions](docs/subscription.md) · [Capture](docs/networking.md) · [Optional Mesh](docs/mesh.md)

```bash
cargo run -p rillaned
cargo run -p rillanectl -- --help
cargo run -p rillanectl -- stats
cargo run -p rillanectl -- route status
```

`rillaned` reads `RILLANE_CONFIG`, defaulting to `config/rillane.yaml`, without a `--config` flag. Configure outbounds/routes before running. Consult `--help`; inspect potentially sensitive diagnose bundles before sharing.

## Layout

```text
apps/        rillaned / rillanectl
crates/      reusable core, routing, protocols, runtime and adapters
docs/        v1 design, research and current usage references
platforms/   hosts, packaging and installation templates
plugins/     optional WASM examples
```
