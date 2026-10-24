[English](README.md) | [中文](README.zh.md)

<p align="center">
  <img src="docs/public/logo.svg" width="64" alt="Seep logo" />
</p>

<h1 align="center">Seep</h1>

<p align="center">
<a href="https://github.com/cuihairu/seep/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a>
</p>

<p align="center">
  Rust 代理内核，灵感来自 sing-box / Clash / Surge。协议栈按 crate 拆分（core/config/routing/protocols/…），跨平台 glue 收在 platforms/，由一套 monorepo 维护。
</p>

<p align="center">
<img src="https://github.com/cuihairu/seep/actions/workflows/ci.yml/badge.svg" alt="CI" /> <img src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&amp;logoColor=DEA584" alt="Rust 2021" /> <img src="https://img.shields.io/badge/tokio-1.48-000000" alt="tokio 1.48" /> <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version 0.1.0" /> <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0" />
</p>

<p align="center">
<img src="https://img.shields.io/badge/SOCKS5-CONNECT%20%2B%20UDP%20ASSOCIATE-2ea44f" alt="SOCKS5" /> <img src="https://img.shields.io/badge/HTTP-CONNECT-2ea44f" alt="HTTP CONNECT" /> <img src="https://img.shields.io/badge/Mixed-auto%20detect-2ea44f" alt="Mixed" />
</p>

<p align="center">
<img src="https://img.shields.io/badge/Direct-TCP%20%2B%20UDP-2ea44f" alt="Direct" /> <img src="https://img.shields.io/badge/Shadowsocks-TCP%20%2B%20UDP-2ea44f" alt="Shadowsocks" /> <img src="https://img.shields.io/badge/Trojan-TLS-2ea44f" alt="Trojan" /> <img src="https://img.shields.io/badge/VLESS-tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VLESS" /> <img src="https://img.shields.io/badge/VMess-AEAD%20tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VMess" /> <img src="https://img.shields.io/badge/Hysteria2-TCP-2ea44f" alt="Hysteria2" /> <img src="https://img.shields.io/badge/WireGuard-TCP%20%2B%20UDP-2ea44f" alt="WireGuard" /> <img src="https://img.shields.io/badge/egress%20proxy-SOCKS5%20%2B%20HTTP-2ea44f" alt="egress SOCKS5 + HTTP" />
</p>

<p align="center">
<img src="https://img.shields.io/badge/UDP-relay%20%2B%20egress-2ea44f" alt="UDP relay + egress" /> <img src="https://img.shields.io/badge/Mesh-mTLS%20multi--hop-2ea44f" alt="Mesh mTLS" /> <img src="https://img.shields.io/badge/Subscription-hot%20reload-2ea44f" alt="Subscription hot reload" /> <img src="https://img.shields.io/badge/Prometheus-metrics-2ea44f" alt="Prometheus metrics" /> <img src="https://img.shields.io/badge/Grafana-dashboards-2ea44f" alt="Grafana dashboards" />
</p>

## Workspace 布局
```
apps/        # seepd 守护进程、seepctl CLI
crates/      # 可复用库 (core/config/routing/protocols/telemetry/platform/runtime/mesh/subscription/plugins/ffi)
docs/        # 架构文档与 ADR
platforms/   # 各平台集成脚手架 (Android/iOS/OpenWrt/desktop)
```

更多细节见 `docs/architecture.md`；完整 `seepctl` 命令参考（18 个子命令、旗标与控制面端点语义）见 `docs/cli.md`。

## 快速开始
```bash
cargo run -p seepd
cargo run -p seepctl -- --help
cargo run -p seepctl -- stats
cargo run -p seepctl -- diagnose
cargo run -p seepctl -- mtls --help
cargo run -p seepctl -- import-clash https://example.com/clash.yaml
cargo run -p seepctl -- import-rules geosite-cn.txt --target direct-main
cargo run -p seepctl -- nodes
cargo run -p seepctl -- udp-probe --socks5 127.0.0.1:7890 --host example.com --port 53 --payload-hex 0001
```

`seepctl profile <proxy|game|web> --out <path>`（O-prof1）生成三选一即运行的场景骨架（profile 展开已内联）：

```bash
cargo run -p seepctl -- profile game --out /tmp/game.yaml
SEEP_CONFIG=/tmp/game.yaml seepd
```

`seepd` 配置经 `SEEP_CONFIG` 环境变量指定（缺省 `config/seep.yaml`）；无 `--config` 旗标，多余命令行参数被忽略。完整字段参考（各块、缺省值与构建期校验）见 `docs/config.md`。平台模板的配置落位见 `platforms/` 各 README。

可选：`telemetry.enable_tracing=true` 时（`config/seep.yaml` 缺省为 `false`），在 `seepd` 进程环境中设置 `SEEP_CAPTURE_LOGS=1`，控制面会额外提供 `GET /logs`（用于 `seepctl diagnose` 抓取最近日志）；未开启时该端点返回 404。

当前可用能力：提供 Socks5 / HTTP CONNECT / Mixed 入站 + Direct / Socks5 / HTTP CONNECT / Shadowsocks / Trojan / Hysteria2 / VLESS / VMess / WireGuard 出站的数据通道，可通过 `config/seep.yaml` 配置监听端口、认证信息与路由策略；UDP 数据面（socks5/mixed 的 UDP ASSOCIATE 中继，`udp:` 配置块，缺省关闭）支持入口级开关与全套超时/上限参数。
后台控制接口默认监听 `control.api_bind`，可访问 `http://127.0.0.1:9090/flows` 查看入口/出口之间的累计流量统计（或 `seepctl stats`——尾部附 UDP 段：会话/中继字节/丢弃/过期/mesh 面），访问 `http://127.0.0.1:9090/udp/stats` 取 UDP JSON 快照，访问 `http://127.0.0.1:9090/nodes` 或 `seepctl nodes` 查看 mesh 节点注册信息，运行 `seepctl group`（或访问 `http://127.0.0.1:9090/routing/stats`）查看各组实时质量——成员数据源、p95/丢包、SLO 门判定与 latency 组当前选点，运行 `seepctl switches`（或访问 `http://127.0.0.1:9090/mesh/switches`）查看链路切换账本（最近 100 次事件，含前后路径与原因）；运行 `seepctl pool status`（或访问 `http://127.0.0.1:9090/egress/pool/stats`）查看出站连接池快照——开关、TLS 复会话、复用率、计数族与每键 idle；运行 `seepctl tls-fingerprint` 查看 TLS 指纹形态预设对照表（none/chrome/ios/safari 及其四维 shape_material）；`seepctl udp-probe` 为 SOCKS5 UDP ASSOCIATE 联调探测（退出码 0-4，见 `--help`）。
`seepctl import-clash` 会尝试完整转换 Clash 的 `proxies`/`proxy-groups`/`rules`（含 socks5/http/ss/trojan/vmess/vless/hysteria2/wireguard 等），运行时若遇到暂未实现的出站类型会在构建阶段报错提示。
`seepctl import-rules <source> --target <name> [--face routing|dns]` 批量导入 v2fly 文本规则源（geosite 域名 / chnroutes CIDR）为 `routing.rules` 或 `network.dns.rules` YAML 片段；`regexp:`/`include:`/属性行逐条入跳过报告，所选面无对应模式的条目显式报错不静默降级。
