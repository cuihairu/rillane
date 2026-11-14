[English](README.md) | [中文](README.zh.md)

<p align="center">
  <img src="docs/public/logo.svg" width="64" alt="Rillane logo" />
</p>

<h1 align="center">Rillane</h1>

<p align="center"><a href="https://github.com/cuihairu/rillane/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a> <img src="https://github.com/cuihairu/rillane/actions/workflows/ci.yml/badge.svg" alt="CI" /> <img src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&amp;logoColor=DEA584" alt="Rust 2021" /> <img src="https://img.shields.io/badge/tokio-1.54-000000" alt="tokio 1.54" /> <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version 0.1.0" /> <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0" /> <img src="https://img.shields.io/badge/SOCKS5-CONNECT%20%2B%20UDP%20ASSOCIATE-2ea44f" alt="SOCKS5" /> <img src="https://img.shields.io/badge/HTTP-CONNECT-2ea44f" alt="HTTP CONNECT" /> <img src="https://img.shields.io/badge/Mixed-auto%20detect-2ea44f" alt="Mixed" /> <a href="https://cuihairu.github.io/rillane/"><img src="https://img.shields.io/badge/docs-blue" alt="docs"></a> <img src="https://img.shields.io/badge/Direct-TCP%20%2B%20UDP-2ea44f" alt="Direct" /> <img src="https://img.shields.io/badge/Shadowsocks-TCP%20%2B%20UDP-2ea44f" alt="Shadowsocks" /> <img src="https://img.shields.io/badge/Trojan-TLS-2ea44f" alt="Trojan" /> <img src="https://img.shields.io/badge/VLESS-tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VLESS" /> <img src="https://img.shields.io/badge/VMess-AEAD%20tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VMess" /> <img src="https://img.shields.io/badge/Hysteria2-TCP-2ea44f" alt="Hysteria2" /> <img src="https://img.shields.io/badge/WireGuard-TCP%20%2B%20UDP-2ea44f" alt="WireGuard" /> <img src="https://img.shields.io/badge/egress%20proxy-SOCKS5%20%2B%20HTTP-2ea44f" alt="egress SOCKS5 + HTTP" /> <img src="https://img.shields.io/badge/UDP-relay%20%2B%20egress-2ea44f" alt="UDP relay + egress" /> <img src="https://img.shields.io/badge/Mesh-mTLS%20multi--hop-2ea44f" alt="Mesh mTLS" /> <img src="https://img.shields.io/badge/Subscription-hot%20reload-2ea44f" alt="Subscription hot reload" /> <img src="https://img.shields.io/badge/Prometheus-metrics-2ea44f" alt="Prometheus metrics" /> <img src="https://img.shields.io/badge/Grafana-dashboards-2ea44f" alt="Grafana dashboards" /></p>

<p align="center">
  A proxy kernel in Rust, inspired by sing-box / Clash / Surge. The protocol stack is split into crates (core/config/routing/protocols/…), cross-platform glue lives under platforms/, and everything is maintained in a single monorepo.
</p>

<p align="center">
</p>

<p align="center">
</p>

<p align="center">
</p>

<p align="center">
</p>

## Workspace Layout

The project is now named **Rillane**. Existing installations must migrate to `rillaned` / `rillanectl`, `RILLANE_*` environment variables, `config/rillane.yaml`, and the new platform service paths. Metrics use the `rillane_` prefix and the Grafana template is updated. Rust crates, FFI/JNI symbols, the Android package and iOS App Group have also changed; rebuild native integrations. New installers do not automatically uninstall previous services: stop them and migrate configuration and credentials before switching.

```
apps/        # rillaned daemon, rillanectl CLI
crates/      # reusable libraries (core/config/routing/protocols/telemetry/platform/runtime/mesh/subscription/plugins/ffi)
docs/        # architecture documents and ADRs
platforms/   # platform integration scaffolding (Android/iOS/OpenWrt/desktop)
```

See `docs/architecture.md` for details, and `docs/cli.md` for the full `rillanectl` command reference (18 subcommands, flags, and control-plane endpoint semantics).

## Quick Start

Architecture planning (2026-11-14): [upstream study with 5 SVG diagrams](docs/research/proxy-architectures-2026-11-14.md), [32 concepts with reasons and costs](docs/design/architecture-concepts.md), and [six-platform target design](docs/design/architecture-v2.md). Local process routing targets Windows/macOS/Linux only; Android/iOS/OpenWrt remain proxy and concurrent game/web targets. These are proposals, not completed platform implementations; Clash/Mihomo compatibility is currently partial.

```bash
cargo run -p rillaned
cargo run -p rillanectl -- --help
cargo run -p rillanectl -- stats
cargo run -p rillanectl -- diagnose
cargo run -p rillanectl -- mtls --help
cargo run -p rillanectl -- import-clash https://example.com/clash.yaml
cargo run -p rillanectl -- import-rules geosite-cn.txt --target direct-main
cargo run -p rillanectl -- nodes
cargo run -p rillanectl -- udp-probe --socks5 127.0.0.1:7890 --host example.com --port 53 --payload-hex 0001
```

`rillanectl profile <proxy|game|web> --out <path>` (O-prof1) generates a runnable scenario skeleton with the profile expansion already baked in:

```bash
cargo run -p rillanectl -- profile game --out /tmp/game.yaml
RILLANE_CONFIG=/tmp/game.yaml rillaned
```

`rillaned` reads its configuration from the `RILLANE_CONFIG` environment variable (default `config/rillane.yaml`); there is no `--config` flag, and extra command-line arguments are ignored. The full field reference (blocks, defaults, and validation rules) lives in `docs/config.md`. For where each platform template expects its configuration, see the READMEs under `platforms/`.

Optional: with `telemetry.enable_tracing=true` (the default in `config/rillane.yaml` is `false`) and `RILLANE_CAPTURE_LOGS=1` set in the `rillaned` process environment, the control plane additionally serves `GET /logs` (used by `rillanectl diagnose` to fetch recent logs); when tracing is disabled the endpoint returns 404.

Currently available capabilities: a data plane connecting Socks5 / HTTP CONNECT / Mixed inbound to Direct / Socks5 / HTTP CONNECT / Shadowsocks / Trojan / Hysteria2 / VLESS / VMess / WireGuard outbound. Listening ports, authentication, and routing policy are configured through `config/rillane.yaml`. The UDP data plane (UDP ASSOCIATE relay for socks5/mixed, the `udp:` config block, disabled by default) supports per-ingress switches and the full set of timeout/limit parameters.
The control API listens on `control.api_bind` by default. Visit `http://127.0.0.1:9090/flows` for cumulative traffic statistics between inbound and outbound (or run `rillanectl stats` — the tail carries a UDP section: sessions / relay bytes / dropped / expired / mesh plane), visit `http://127.0.0.1:9090/udp/stats` for the UDP JSON snapshot, and visit `http://127.0.0.1:9090/nodes` or run `rillanectl nodes` for mesh node registration. Run `rillanectl group` (or visit `http://127.0.0.1:9090/routing/stats`) for per-group member quality — data source, p95/loss, SLO gate verdicts and the current latency-strategy pick. Run `rillanectl switches` (or visit `http://127.0.0.1:9090/mesh/switches`) for the chain-switch ledger (recent 100 events with from/to paths and reason). Run `rillanectl pool status` (or visit `http://127.0.0.1:9090/egress/pool/stats`) for the outbound connection pool snapshot — enablement, TLS resumption, reuse ratio, counters and per-key idle counts. Run `rillanectl tls-fingerprint` for the TLS fingerprint preset comparison table (none/chrome/ios/safari and their four-dimension shape_material). `rillanectl udp-probe` is a probing tool for SOCKS5 UDP ASSOCIATE (exit codes 0-4, see `--help`).
`rillanectl import-clash` attempts to fully convert Clash `proxies`/`proxy-groups`/`rules` (covering socks5/http/ss/trojan/vmess/vless/hysteria2/wireguard and others); if it encounters an outbound type that is not yet implemented, the runtime reports an explicit error at the build stage.
`rillanectl import-rules <source> --target <name> [--face routing|dns]` batch-imports v2fly text rule lists (geosite domains / chnroutes CIDRs) into a `routing.rules` or `network.dns.rules` YAML fragment; `regexp:`/`include:`/attributed lines are reported per-entry as skipped, and entries with no counterpart on the chosen face error out explicitly.
