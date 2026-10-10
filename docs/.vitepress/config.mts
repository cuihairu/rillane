import { defineConfig } from 'vitepress'

// Seep 文档站（VitePress）。站点根 = docs/（本配置所在 .vitepress 的上级）。
// 注意：todo.md 位于仓库根（站点外）——各设计稿头部的 todo 互链在 GitHub 源文件视图有意义，
// 但无法路由进站点，列入 ignoreDeadLinks；其余内链保持死链检查（构建期门禁）。
export default defineConfig({
  lang: 'zh-CN',
  title: 'Seep',
  description:
    '一个代理内核，三种场景——通用代理 / 游戏加速 / 网页加速，共享同一条数据通路；Rust monorepo，灵感来自 sing-box / Clash / Surge。',
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }]],
  ignoreDeadLinks: [/\/todo$/],   // 报文归一化剥掉 .md 后缀（./../todo）
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Seep',
    nav: [
      { text: '首页', link: '/' },
      { text: '架构', link: '/architecture' },
      { text: '协议', link: '/PROTOCOLS' },
      {
        text: '指南',
        items: [
          { text: 'Mesh & Chain', link: '/mesh' },
          { text: '系统路由与网络接管', link: '/networking' },
          { text: '订阅指南', link: '/subscription' },
        ],
      },
      {
        text: '设计文档',
        items: [
          { text: '定位与技术底座', link: '/design/positioning' },
          { text: '分阶段路线图', link: '/design/roadmap' },
          { text: 'UDP 数据通路（P0）', link: '/design/udp-dataplane' },
          { text: 'TUN 与 network（P1-1..P1-3）', link: '/design/tun-dataplane' },
          { text: '混淆 / 连接池（P1-4/P1-5）', link: '/design/obfuscation-middleware' },
        ],
      },
      { text: 'GitHub', link: 'https://github.com/cuihairu/seep' },
    ],
    sidebar: [
      {
        text: '概览',
        items: [
          { text: '首页', link: '/' },
          { text: '架构草图', link: '/architecture' },
          { text: '协议支持', link: '/PROTOCOLS' },
          { text: '订阅指南', link: '/subscription' },
        ],
      },
      {
        text: '指南',
        items: [
          { text: 'Mesh & Chain Guide (MVP)', link: '/mesh' },
          { text: '系统路由与网络接管', link: '/networking' },
          { text: 'Grafana 仪表板模板', link: '/grafana/README' },
        ],
      },
      {
        text: '设计文档 — 底座与路线',
        items: [
          { text: '产品定位与技术底座', link: '/design/positioning' },
          { text: '分阶段路线图', link: '/design/roadmap' },
          { text: '勘误重开条目核对报告', link: '/design/status-audit-tun-network-middleware' },
        ],
      },
      {
        text: '设计文档 — UDP 数据通路（P0）',
        items: [
          { text: 'S1 UDP 全链路设计稿', link: '/design/udp-dataplane' },
          { text: 'P0-1 UDP 会话表（实现级）', link: '/design/udp-session-table' },
          { text: 'P0-1 会话表 API 草案', link: '/design/udp-session-table-api' },
          { text: 'P0-2/P0-3 单跳 UDP 中继路径', link: '/design/udp-relay-path' },
          { text: 'P0-4 mesh data-plane UDP 转发', link: '/design/udp-mesh-dataplane' },
          { text: 'P0-5 UDP 观测与配置', link: '/design/udp-observability' },
        ],
      },
      {
        text: '设计文档 — TUN 与网络接管（P1-1..P1-3）',
        items: [
          { text: 'P1-1/P1-2 Linux TUN 真实现 + TunIngress', link: '/design/tun-dataplane' },
          { text: 'P1-1 实现落定稿（Linux TUN T0–T2）', link: '/design/tun-linux-impl' },
          { text: 'P1-3 network 配置区块 + seepctl route', link: '/design/network-route' },
        ],
      },
      {
        text: '设计文档 — 横切能力（P1-4/P1-5）',
        items: [
          { text: 'P1-4 混淆中间件 MVP（padding）', link: '/design/obfuscation-middleware' },
          { text: 'P1-5 出站连接池', link: '/design/egress-connection-pool' },
        ],
      },
      {
        text: '设计文档 — 调度、安全与场景（P2）',
        items: [
          { text: 'P2-1 per-link 细粒度指标', link: '/design/mesh-link-observability' },
          { text: 'P2-2 SLO 打分选路', link: '/design/slo-scoring' },
          { text: 'P2-3 场景 profile 预设', link: '/design/scenario-profiles' },
          { text: 'P2-4 混淆扩展（timing / shaping）', link: '/design/obfuscation-timing-shaping' },
          { text: 'P2-5 客户端 TLS 指纹模拟', link: '/design/tls-fingerprint' },
          { text: 'P2-6 mesh envelope 二进制化', link: '/design/mesh-envelope-binary' },
          { text: 'P2-7 mesh 高级安全（CRL + UDP 防重放）', link: '/design/mesh-advanced-security' },
          { text: 'P2-8 DNS 分流解析', link: '/design/dns-partition' },
        ],
      },
      {
        text: '设计文档 — 收尾与发布（P3）',
        items: [
          { text: 'P3-2 插件动态加载（WASM）', link: '/design/plugin-loader' },
          { text: 'P3-3 平台打包（systemd / launchd / Windows）', link: '/design/platform-packaging' },
          { text: 'P3-5 零拷贝 / 批量收发', link: '/design/performance-io' },
        ],
      },
    ],
    outline: { level: [2, 3], label: '本页目录' },
    docFooter: { prev: '上一篇', next: '下一篇' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '菜单',
    darkModeSwitchLabel: '主题',
    lightModeSwitchTitle: '切换到浅色',
    darkModeSwitchTitle: '切换到深色',
  },
})
