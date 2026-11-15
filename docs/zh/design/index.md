# Rillane v1 设计

本目录只维护当前 v1 设计。状态为**设计提案，尚未整体实现**；设计版本不等于软件发布版本。

| 文档 | 职责 |
|---|---|
| [v1 架构设计](architecture-v1.md) | 六平台范围、Clash 兼容、进程分流、并行场景、配置代际、模块职责及独立交付门禁 |
| [架构概念与抽象依据](architecture-concepts.md) | 32 个核心概念的职责、为什么抽象、收益与成本 |
| [接入、出口与统计契约](io-and-accounting.md) | 入口/出口、会话执行、传输/资源池、业务与底层统计的接口边界 |
| [协议接入计划](protocol-roadmap.md) | 外部实现优先、新协议/隧道/传输与选库门禁 |
| [UI 原型与控制语义](ui-prototype-v1.md) | 代理模式、区域、DNS/嗅探、流媒体与开发者代理交互 |
| [10 张原型图库](ui/README.md) | 桌面 6 页、iOS/Android 各 2 页，PNG/离线图库/提示词 |
| [Debug、路径解释与可选 MCP](debug-and-mcp.md) | 规则推演、真实轨迹、主动探测、脱敏、工具权限和配置闭环 |
| [竞品架构研究](../research/proxy-architectures-2026-11-14.md) | Mihomo、sing-box、Surge 的来源证据、SVG 与借鉴理由 |

实施任务统一维护在仓库根目录 [todo.md](https://github.com/cuihairu/rillane/blob/main/todo.md)，不在其他文档复制完成清单。按进程分流只要求 Windows/macOS/Linux 本机；OpenWrt/Android/iOS 按可得域名、IP、端口或设备证据分流。

[当前实现与边界](../architecture.md)、[配置参考](../config.md)、[CLI 参考](../cli.md)描述已有代码的用法，不代表 v1 设计已交付。旧设计、旧路线图与历史审计已从当前文档移除，需要追溯时查阅 Git 历史。
