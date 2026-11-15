[English](README.md) | [中文](README.zh.md)

<p align="center"><img src="docs/public/logo.svg" width="64" alt="Rillane logo" /></p>

# Rillane

Rillane 是 Rust 代理内核项目。当前设计基线为 **v1**，目标是六平台共享核心，兼容 Clash/Mihomo 订阅，在同一数据面并行处理网页与游戏流量。**v1 是设计版本，目标尚未整体实现，不表示软件已发布 v1。**

## 当前文档

- [v1 设计入口](docs/zh/design/index.md)
- [v1 架构设计](docs/zh/design/architecture-v1.md)
- [32 个概念与抽象依据](docs/zh/design/architecture-concepts.md)
- [Debug、路径与可选 MCP](docs/zh/design/debug-and-mcp.md)
- [竞品研究与架构 SVG](docs/zh/research/proxy-architectures-2026-11-14.md)
- [103 项原子实施任务（含优先级、依赖和验收）](todo.md)

旧设计、路线图与历史审计已从当前文档移除；追溯使用 Git 历史。按进程分流仅要求 Windows/macOS/Linux 本机，OpenWrt/Android/iOS 不要求识别任意应用 PID。

## 当前实现与使用

现有代理协议、Linux TUN、配置预设、订阅和统计接口可以复用。Clash/Mihomo 目前部分兼容；跨平台完整代理、并列场景策略、逐流诊断和 MCP 仍有待实施。

[当前实现](docs/zh/architecture.md) · [配置](docs/zh/config.md) · [CLI](docs/zh/cli.md) · [协议](docs/zh/PROTOCOLS.md) · [订阅](docs/zh/subscription.md) · [网络接管](docs/zh/networking.md) · [可选 Mesh](docs/zh/mesh.md)

```bash
cargo run -p rillaned
cargo run -p rillanectl -- --help
cargo run -p rillanectl -- stats
cargo run -p rillanectl -- route status
```

`rillaned` 从 `RILLANE_CONFIG` 读取配置，缺省 `config/rillane.yaml`，没有 `--config` 旗标。启动前配置合适的出站/路由。命令详情以 `--help` 为准；`diagnose` 包含敏感运行信息，分享前检查。

## 目录

```text
apps/        rillaned / rillanectl
crates/      reusable core, routing, protocols, runtime and adapters
docs/        v1 design, research and current usage references
platforms/   hosts, packaging and installation templates
plugins/     optional WASM examples
```
