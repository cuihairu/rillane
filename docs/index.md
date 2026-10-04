---
layout: home

hero:
  name: Seep
  text: 一个代理内核，三种场景
  tagline: 通用代理 / 游戏加速 / 网页加速共享同一条数据通路（ingress → routing → egress/transport），混淆是横切层。Rust monorepo，灵感来自 sing-box / Clash / Surge，协议栈按 crate 拆分。
  image:
    src: /logo.svg
    alt: Seep logo
  actions:
    - theme: brand
      text: 架构总览
      link: /architecture
    - theme: alt
      text: 协议支持
      link: /PROTOCOLS
    - theme: alt
      text: 设计文档
      link: /design/positioning
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/seep

features:
  - icon: 🌐
    title: 通用代理
    details: socks5/http/mixed 入站，direct/socks5/http/shadowsocks/trojan/hysteria2/vmess/vless/wireguard 出站，规则路由、组策略选路与订阅热更新。
  - icon: 🎮
    title: 游戏加速
    details: NAT 式 UDP 会话表（P0-1）+ SOCKS5 UDP ASSOCIATE（P0-2）+ direct/ss/wg 出站承载（P0-3）+ mesh 多跳 UDP 面（P0-4）均已落地；UDP 观测与配置（P0-5）含 /udp/stats 快照与 seep_udp_* 指标族。
  - icon: ⚡
    title: 网页加速
    details: mesh 多跳链路与强制 mTLS、7 种组策略、故障回退与 Dry Run 预检；出站连接池 + TLS 会话恢复已落地（P1-5，/egress/pool/stats 可查）。
  - icon: 🧩
    title: 一个内核
    details: 三场景共享同一数据通路，场景差异收敛为路由规则与策略 profile（P2-3 预设），无独立代码路径——加速 = 路由 + 伪装，混淆 = 渗过识别。
  - icon: 🔗
    title: Mesh 协作
    details: 注册 / 健康上报 / 拓扑 / ACL 与配额；client → relay → exit 多跳转发，CA 轮换与双信任窗口（seepctl mtls）。
  - icon: 📊
    title: 可观测
    details: /metrics Prometheus 指标 + Grafana 模板，seepctl stats / diagnose 一键诊断，链路 Dry Run 策略模拟。
---
