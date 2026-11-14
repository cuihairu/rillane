[English](README.md) | [中文](README.zh.md)

<p align="center">
  <img src="docs/public/logo.svg" width="64" alt="Rillane logo" />
</p>

<h1 align="center">Rillane</h1>

<p align="center"><a href="https://github.com/cuihairu/rillane/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a> <img src="https://github.com/cuihairu/rillane/actions/workflows/ci.yml/badge.svg" alt="CI" /> <img src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&amp;logoColor=DEA584" alt="Rust 2021" /> <img src="https://img.shields.io/badge/tokio-1.54-000000" alt="tokio 1.54" /> <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version 0.1.0" /> <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0" /> <img src="https://img.shields.io/badge/SOCKS5-CONNECT%20%2B%20UDP%20ASSOCIATE-2ea44f" alt="SOCKS5" /> <img src="https://img.shields.io/badge/HTTP-CONNECT-2ea44f" alt="HTTP CONNECT" /> <img src="https://img.shields.io/badge/Mixed-auto%20detect-2ea44f" alt="Mixed" /> <a href="https://cuihairu.github.io/rillane/zh/"><img src="https://img.shields.io/badge/%E6%96%87%E6%A1%A3-blue" alt="文档"></a> <img src="https://img.shields.io/badge/Direct-TCP%20%2B%20UDP-2ea44f" alt="Direct" /> <img src="https://img.shields.io/badge/Shadowsocks-TCP%20%2B%20UDP-2ea44f" alt="Shadowsocks" /> <img src="https://img.shields.io/badge/Trojan-TLS-2ea44f" alt="Trojan" /> <img src="https://img.shields.io/badge/VLESS-tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VLESS" /> <img src="https://img.shields.io/badge/VMess-AEAD%20tcp%2Fws%2Fgrpc%2Fh2-2ea44f" alt="VMess" /> <img src="https://img.shields.io/badge/Hysteria2-TCP-2ea44f" alt="Hysteria2" /> <img src="https://img.shields.io/badge/WireGuard-TCP%20%2B%20UDP-2ea44f" alt="WireGuard" /> <img src="https://img.shields.io/badge/egress%20proxy-SOCKS5%20%2B%20HTTP-2ea44f" alt="egress SOCKS5 + HTTP" /> <img src="https://img.shields.io/badge/UDP-relay%20%2B%20egress-2ea44f" alt="UDP relay + egress" /> <img src="https://img.shields.io/badge/Mesh-mTLS%20multi--hop-2ea44f" alt="Mesh mTLS" /> <img src="https://img.shields.io/badge/Subscription-hot%20reload-2ea44f" alt="Subscription hot reload" /> <img src="https://img.shields.io/badge/Prometheus-metrics-2ea44f" alt="Prometheus metrics" /> <img src="https://img.shields.io/badge/Grafana-dashboards-2ea44f" alt="Grafana dashboards" /></p>

<p align="center">
  Rust 代理内核，灵感来自 sing-box / Clash / Surge。协议栈按 crate 拆分（core/config/routing/protocols/…），跨平台 glue 收在 platforms/，由一套 monorepo 维护。
</p>

<p align="center">
</p>

<p align="center">
</p>

<p align="center">
</p>

<p align="center">
</p>

## Workspace 布局

项目现正式命名为 **Rillane**。改名前的安装需迁移至 `rillaned` / `rillanectl`、`RILLANE_*` 环境变量、`config/rillane.yaml` 和各平台新服务路径；指标前缀为 `rillane_`，Grafana 模板已同步。Rust crate、FFI/JNI 符号、Android 包名和 iOS App Group 也已更名，原生集成需要重新编译；旧安装不会被新安装脚本自动卸载，切换前须停止旧服务并迁移配置及凭证。

```
apps/        # rillaned 守护进程、rillanectl CLI
crates/      # 可复用库 (core/config/routing/protocols/telemetry/platform/runtime/mesh/subscription/plugins/ffi)
docs/        # 架构文档与 ADR
platforms/   # 各平台集成脚手架 (Android/iOS/OpenWrt/desktop)
```

更多细节见 `docs/architecture.md`；完整 `rillanectl` 命令参考（18 个子命令、旗标与控制面端点语义）见 `docs/cli.md`。

## 快速开始
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

`rillanectl profile <proxy|game|web> --out <path>`（O-prof1）生成三选一即运行的场景骨架（profile 展开已内联）：

```bash
cargo run -p rillanectl -- profile game --out /tmp/game.yaml
RILLANE_CONFIG=/tmp/game.yaml rillaned
```

`rillaned` 配置经 `RILLANE_CONFIG` 环境变量指定（缺省 `config/rillane.yaml`）；无 `--config` 旗标，多余命令行参数被忽略。完整字段参考（各块、缺省值与构建期校验）见 `docs/config.md`。平台模板的配置落位见 `platforms/` 各 README。

可选：`telemetry.enable_tracing=true` 时（`config/rillane.yaml` 缺省为 `false`），在 `rillaned` 进程环境中设置 `RILLANE_CAPTURE_LOGS=1`，控制面会额外提供 `GET /logs`（用于 `rillanectl diagnose` 抓取最近日志）；未开启时该端点返回 404。

当前可用能力：提供 Socks5 / HTTP CONNECT / Mixed 入站 + Direct / Socks5 / HTTP CONNECT / Shadowsocks / Trojan / Hysteria2 / VLESS / VMess / WireGuard 出站的数据通道，可通过 `config/rillane.yaml` 配置监听端口、认证信息与路由策略；UDP 数据面（socks5/mixed 的 UDP ASSOCIATE 中继，`udp:` 配置块，缺省关闭）支持入口级开关与全套超时/上限参数。
后台控制接口默认监听 `control.api_bind`，可访问 `http://127.0.0.1:9090/flows` 查看入口/出口之间的累计流量统计（或 `rillanectl stats`——尾部附 UDP 段：会话/中继字节/丢弃/过期/mesh 面），访问 `http://127.0.0.1:9090/udp/stats` 取 UDP JSON 快照，访问 `http://127.0.0.1:9090/nodes` 或 `rillanectl nodes` 查看 mesh 节点注册信息，运行 `rillanectl group`（或访问 `http://127.0.0.1:9090/routing/stats`）查看各组实时质量——成员数据源、p95/丢包、SLO 门判定与 latency 组当前选点，运行 `rillanectl switches`（或访问 `http://127.0.0.1:9090/mesh/switches`）查看链路切换账本（最近 100 次事件，含前后路径与原因）；运行 `rillanectl pool status`（或访问 `http://127.0.0.1:9090/egress/pool/stats`）查看出站连接池快照——开关、TLS 复会话、复用率、计数族与每键 idle；运行 `rillanectl tls-fingerprint` 查看 TLS 指纹形态预设对照表（none/chrome/ios/safari 及其四维 shape_material）；`rillanectl udp-probe` 为 SOCKS5 UDP ASSOCIATE 联调探测（退出码 0-4，见 `--help`）。
`rillanectl import-clash` 会尝试完整转换 Clash 的 `proxies`/`proxy-groups`/`rules`（含 socks5/http/ss/trojan/vmess/vless/hysteria2/wireguard 等），运行时若遇到暂未实现的出站类型会在构建阶段报错提示。
`rillanectl import-rules <source> --target <name> [--face routing|dns]` 批量导入 v2fly 文本规则源（geosite 域名 / chnroutes CIDR）为 `routing.rules` 或 `network.dns.rules` YAML 片段；`regexp:`/`include:`/属性行逐条入跳过报告，所选面无对应模式的条目显式报错不静默降级。
