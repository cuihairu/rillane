---
layout: home

hero:
  name: Rillane
  text: 一个代理内核，六平台设计
  tagline: v1 目标：Clash/Mihomo 订阅、三桌面本机进程分流、游戏与网页并行，以及可选 Debug/MCP。当前实现和目标分别标注。
  image:
    src: /logo.svg
    alt: Rillane logo
  actions:
    - theme: brand
      text: v1 架构设计
      link: /zh/design/architecture-v1
    - theme: alt
      text: 概念与依据
      link: /zh/design/architecture-concepts
    - theme: alt
      text: 当前实现
      link: /zh/architecture

features:
  - title: 单核心与平台端口
    details: Linux、OpenWrt、Windows、macOS、Android、iOS 共用核心；接管、身份与生命周期分别验收。
  - title: 并行游戏与网页
    details: 按证据分类、会话绑定出口、有界资源与质量目标；收益需要同线路测量。
  - title: 诊断与可选 AI
    details: 纯 Explain、真实 Trace、主动 Probe 分离；MCP 默认关闭，先只读后受控配置。
---

连接诊断按“真实连接列表 → 逐连接时间线 → 规则解释 → 主动探测”推进，详见 [v1 链路诊断规格](design/debug-and-mcp.md)。当前仍为设计目标。
