<p align="center">
  <img src="docs/public/logo.svg" width="100" alt="Seep logo" />
</p>

<h1 align="center">Seep</h1>

<p align="center">
  Rust 单词代理内核，灵感来自 sing-box / Clash / Surge，但更加模块化、跨平台特性由一套 monorepo 维护。
</p>

<p align="center">
  <img src="https://github.com/cuihairu/seep/actions/workflows/ci.yml/badge.svg" alt="CI" />
  <img src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&amp;logoColor=DEA584" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/tokio-1.48-000000" alt="tokio 1.48" />
  <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version 0.1.0" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SOCKS5-CONNECT%20%2B%20UDP%20ASSOCIATE-2ea44f" alt="SOCKS5" />
  <img src="https://img.shields.io/badge/HTTP-CONNECT-2ea44f" alt="HTTP CONNECT" />
  <img src="https://img.shields.io/badge/Mixed-auto%20detect-2ea44f" alt="Mixed" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Direct-TCP%20%2B%20UDP-2ea44f" alt="Direct" />
  <img src="https://img.shields.io/badge/Shadowsocks-TCP%20%2B%20UDP-2ea44f" alt="Shadowsocks" />
  <img src="https://img.shields.io/badge/Trojan-TLS-2ea44f" alt="Trojan" />
  <img src="https://img.shields.io/badge/VLESS-tcp%2Fws-2ea44f" alt="VLESS" />
  <img src="https://img.shields.io/badge/Hysteria2-TCP-2ea44f" alt="Hysteria2" />
  <img src="https://img.shields.io/badge/WireGuard-TCP%20%2B%20UDP-2ea44f" alt="WireGuard" />
  <img src="https://img.shields.io/badge/egress%20proxy-SOCKS5%20%2B%20HTTP-2ea44f" alt="egress SOCKS5 + HTTP" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/UDP-relay%20%2B%20egress-2ea44f" alt="UDP relay + egress" />
  <img src="https://img.shields.io/badge/Mesh-mTLS%20multi--hop-2ea44f" alt="Mesh mTLS" />
  <img src="https://img.shields.io/badge/Subscription-hot%20reload-2ea44f" alt="Subscription hot reload" />
  <img src="https://img.shields.io/badge/Prometheus-metrics-2ea44f" alt="Prometheus metrics" />
  <img src="https://img.shields.io/badge/Grafana-dashboards-2ea44f" alt="Grafana dashboards" />
</p>

## Workspace 布局
```
apps/        # seepd 守护进程、seepctl CLI
crates/      # 可复用库 (core/config/routing/protocols/telemetry/platform/runtime)
docs/        # 架构文档与 ADR
platforms/   # 各平台集成脚手架 (Android/iOS/OpenWrt/desktop)
```

更多细节见 `docs/architecture.md`。

## 快速开始
```bash
cargo run -p seepd
cargo run -p seepctl -- --help
cargo run -p seepctl -- stats
cargo run -p seepctl -- diagnose
cargo run -p seepctl -- mtls --help
cargo run -p seepctl -- import-clash https://example.com/clash.yaml
cargo run -p seepctl -- nodes
cargo run -p seepctl -- udp-probe --socks5 127.0.0.1:7890 --host example.com --port 53 --payload-hex 0001
```

可选：在 `seepd` 进程环境中设置 `SEEP_CAPTURE_LOGS=1`，控制面会额外提供 `GET /logs`（用于 `seepctl diagnose` 抓取最近日志）。

当前可用能力：提供 Socks5 / HTTP CONNECT / Mixed 入站 + Direct / Socks5 / HTTP CONNECT / Shadowsocks / Trojan / Hysteria2 / VLESS / WireGuard 出站的数据通道，可通过 `config/seep.yaml` 配置监听端口、认证信息与路由策略；UDP 数据面（socks5/mixed 的 UDP ASSOCIATE 中继，`udp:` 配置块，缺省关闭）支持入口级开关与全套超时/上限参数。
后台控制接口默认监听 `control.api_bind`，可访问 `http://127.0.0.1:9090/flows` 查看入口/出口之间的累计流量统计（或 `seepctl stats`——尾部附 UDP 段：会话/中继字节/丢弃/过期/mesh 面），访问 `http://127.0.0.1:9090/udp/stats` 取 UDP JSON 快照，访问 `http://127.0.0.1:9090/nodes` 或 `seepctl nodes` 查看 mesh 节点注册信息；`seepctl udp-probe` 为 SOCKS5 UDP ASSOCIATE 联调探测（退出码 0-4，见 `--help`）。
`seepctl import-clash` 会尝试完整转换 Clash 的 `proxies`/`proxy-groups`/`rules`（含 socks5/http/ss/trojan/vmess/vless/hysteria2/wireguard 等），运行时若遇到暂未实现的出站类型会在构建阶段报错提示。
