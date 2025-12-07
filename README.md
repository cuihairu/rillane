# Seep

Rust 单词代理内核，灵感来自 sing-box / Clash / Surge，但更加模块化、跨平台特性由一套 monorepo 维护。

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
cargo run -p seepctl -- import-clash https://example.com/clash.yaml
cargo run -p seepctl -- nodes
```

当前 MVP：提供一个 Socks5 入站 + Direct 出站的数据通道，可通过 `config/seep.yaml` 配置监听端口、认证信息与路由策略。
后台控制接口默认监听 `control.api_bind`，可访问 `http://127.0.0.1:9090/flows` 查看入口/出口之间的累计流量统计（或 `seepctl stats`），访问 `http://127.0.0.1:9090/nodes` 或 `seepctl nodes` 查看 mesh 节点注册信息。
