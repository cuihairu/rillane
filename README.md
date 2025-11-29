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
```
