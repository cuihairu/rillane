import { defineConfig } from 'vitepress'

// Rillane docs site (VitePress). Site root = docs/ (parent of this .vitepress dir).
// Locale layout (fleet convention): English at the site root, Simplified Chinese
// under /zh/. Both trees hold the same page set (1:1), so VitePress's own locale
// switcher links root <-> /zh/ without any hand-written banner.
// Note: todo.md lives at the repo root (outside the site) -- the todo cross-links
// at the top of each design doc are meaningful in the GitHub source view but
// cannot route into the site, so they are listed in ignoreDeadLinks. Every other
// internal link stays under dead-link checking (build-time gate).
export default defineConfig({
  lang: 'en-US',
  title: 'Rillane',
  description:
    'One proxy kernel, three scenarios -- general proxy / game acceleration / web acceleration sharing a single datapath (ingress -> routing -> egress/transport); obfuscation is a cross-cutting layer. Rust monorepo, inspired by sing-box / Clash / Surge.',
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }]],
  ignoreDeadLinks: [/\/todo$/],   // link normalization strips the .md suffix (./../todo)
  locales: {
    root: { label: 'English', lang: 'en-US' },
    zh: { label: '简体中文', lang: 'zh-CN', link: '/zh/' },
  },
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Rillane',
    locales: {
      root: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'Protocols', link: '/PROTOCOLS' },
          {
            text: 'Guides',
            items: [
              { text: 'rillanectl CLI reference', link: '/cli' },
              { text: 'Mesh & Chain', link: '/mesh' },
              { text: 'System routing and network takeover', link: '/networking' },
              { text: 'Subscription guide', link: '/subscription' },
              { text: 'Configuration reference', link: '/config' },
            ],
          },
          {
            text: 'Design docs',
            items: [
              { text: 'Positioning and foundation', link: '/design/positioning' },
              { text: 'Architecture study & SVGs', link: '/research/proxy-architectures-2026-11-14' },
              { text: '32 concepts and rationale', link: '/design/architecture-concepts' },
              { text: 'Target architecture (proposal)', link: '/design/architecture-v2' },
              { text: 'Debug, paths and MCP (proposal)', link: '/design/debug-and-mcp' },
              { text: 'Phased roadmap', link: '/design/roadmap' },
              { text: 'UDP datapath (P0)', link: '/design/udp-dataplane' },
              { text: 'TUN and network (P1-1..P1-3)', link: '/design/tun-dataplane' },
              {
                text: 'Obfuscation / connection pool (P1-4/P1-5)',
                link: '/design/obfuscation-middleware',
              },
            ],
          },
          { text: 'GitHub', link: 'https://github.com/cuihairu/rillane' },
        ],
        sidebar: [
          {
            text: 'Overview',
            items: [
              { text: 'Home', link: '/' },
              { text: 'Architecture sketch', link: '/architecture' },
              { text: 'Architecture study & SVGs', link: '/research/proxy-architectures-2026-11-14' },
              { text: '32 concepts and rationale', link: '/design/architecture-concepts' },
              { text: 'Target architecture (proposal)', link: '/design/architecture-v2' },
              { text: 'Debug, paths and MCP (proposal)', link: '/design/debug-and-mcp' },
              { text: 'Protocol support', link: '/PROTOCOLS' },
              { text: 'Subscription guide', link: '/subscription' },
              { text: 'Configuration reference', link: '/config' },
            ],
          },
          {
            text: 'Guides',
            items: [
              { text: 'rillanectl CLI reference', link: '/cli' },
              { text: 'Mesh & Chain Guide (MVP)', link: '/mesh' },
              {
                text: 'System routing and network takeover',
                link: '/networking',
              },
              { text: 'Grafana dashboard template', link: '/grafana/README' },
            ],
          },
          {
            text: 'Design docs -- foundation and roadmap',
            items: [
              {
                text: 'Product positioning and technical foundation',
                link: '/design/positioning',
              },
              { text: 'Phased roadmap', link: '/design/roadmap' },
              {
                text: 'Reopened-items audit report',
                link: '/design/status-audit-tun-network-middleware',
              },
            ],
          },
          {
            text: 'Design docs -- UDP datapath (P0)',
            items: [
              { text: 'S1 full-chain UDP design', link: '/design/udp-dataplane' },
              {
                text: 'P0-1 UDP session table (implementation)',
                link: '/design/udp-session-table',
              },
              {
                text: 'P0-1 session table API draft',
                link: '/design/udp-session-table-api',
              },
              {
                text: 'P0-2/P0-3 single-hop UDP relay path',
                link: '/design/udp-relay-path',
              },
              {
                text: 'P0-4 mesh data-plane UDP forwarding',
                link: '/design/udp-mesh-dataplane',
              },
              {
                text: 'P0-5 UDP observability and config',
                link: '/design/udp-observability',
              },
            ],
          },
          {
            text: 'Design docs -- TUN and network takeover (P1-1..P1-3)',
            items: [
              {
                text: 'P1-1/P1-2 Linux TUN real impl + TunIngress',
                link: '/design/tun-dataplane',
              },
              {
                text: 'P1-1 implementation final spec (Linux TUN T0-T2)',
                link: '/design/tun-linux-impl',
              },
              {
                text: 'P1-3 network config block + rillanectl route',
                link: '/design/network-route',
              },
            ],
          },
          {
            text: 'Design docs -- cross-cutting capabilities (P1-4/P1-5)',
            items: [
              {
                text: 'P1-4 obfuscation middleware MVP (padding)',
                link: '/design/obfuscation-middleware',
              },
              {
                text: 'P1-5 egress connection pool',
                link: '/design/egress-connection-pool',
              },
            ],
          },
          {
            text: 'Design docs -- scheduling, security and scenarios (P2)',
            items: [
              {
                text: 'P2-1 per-link fine-grained metrics',
                link: '/design/mesh-link-observability',
              },
              { text: 'P2-2 SLO-scored path selection', link: '/design/slo-scoring' },
              {
                text: 'P2-3 scenario profile presets',
                link: '/design/scenario-profiles',
              },
              {
                text: 'P2-4 obfuscation extensions (timing / shaping)',
                link: '/design/obfuscation-timing-shaping',
              },
              {
                text: 'P2-5 client TLS fingerprint emulation',
                link: '/design/tls-fingerprint',
              },
              {
                text: 'P2-6 mesh envelope binary encoding',
                link: '/design/mesh-envelope-binary',
              },
              {
                text: 'P2-7 mesh advanced security (CRL + UDP anti-replay)',
                link: '/design/mesh-advanced-security',
              },
              { text: 'P2-8 DNS partitioned resolution', link: '/design/dns-partition' },
            ],
          },
          {
            text: 'Design docs -- wrap-up and release (P3)',
            items: [
              {
                text: 'P3-2 dynamic plugin loading (WASM)',
                link: '/design/plugin-loader',
              },
              {
                text: 'P3-3 platform packaging (systemd / launchd / Windows)',
                link: '/design/platform-packaging',
              },
              { text: 'P3-5 zero-copy / batched I/O', link: '/design/performance-io' },
            ],
          },
        ],
        outline: { level: [2, 3], label: 'On this page' },
        docFooter: { prev: 'Previous', next: 'Next' },
        returnToTopLabel: 'Back to top',
        sidebarMenuLabel: 'Menu',
        darkModeSwitchLabel: 'Theme',
        lightModeSwitchTitle: 'Switch to light theme',
        darkModeSwitchTitle: 'Switch to dark theme',
      },
      zh: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: '架构', link: '/zh/architecture' },
          { text: '协议', link: '/zh/PROTOCOLS' },
          {
            text: '指南',
            items: [
              { text: 'rillanectl CLI 参考', link: '/zh/cli' },
              { text: 'Mesh & Chain', link: '/zh/mesh' },
              { text: '系统路由与网络接管', link: '/zh/networking' },
              { text: '订阅指南', link: '/zh/subscription' },
              { text: '配置参考', link: '/zh/config' },
            ],
          },
          {
            text: '设计文档',
            items: [
              { text: '定位与技术底座', link: '/zh/design/positioning' },
              { text: '架构研究与 SVG', link: '/zh/research/proxy-architectures-2026-11-14' },
              { text: '架构概念与抽象依据', link: '/zh/design/architecture-concepts' },
              { text: '目标架构（提案）', link: '/zh/design/architecture-v2' },
              { text: 'Debug、路径与 MCP（提案）', link: '/zh/design/debug-and-mcp' },
              { text: '分阶段路线图', link: '/zh/design/roadmap' },
              { text: 'UDP 数据通路（P0）', link: '/zh/design/udp-dataplane' },
              {
                text: 'TUN 与 network（P1-1..P1-3）',
                link: '/zh/design/tun-dataplane',
              },
              {
                text: '混淆 / 连接池（P1-4/P1-5）',
                link: '/zh/design/obfuscation-middleware',
              },
            ],
          },
          { text: 'GitHub', link: 'https://github.com/cuihairu/rillane' },
        ],
        sidebar: [
          {
            text: '概览',
            items: [
              { text: '首页', link: '/zh/' },
              { text: '架构草图', link: '/zh/architecture' },
              { text: '架构研究与 SVG', link: '/zh/research/proxy-architectures-2026-11-14' },
              { text: '32 个概念与抽象依据', link: '/zh/design/architecture-concepts' },
              { text: '目标架构（提案）', link: '/zh/design/architecture-v2' },
              { text: 'Debug、路径与 MCP（提案）', link: '/zh/design/debug-and-mcp' },
              { text: '协议支持', link: '/zh/PROTOCOLS' },
              { text: '订阅指南', link: '/zh/subscription' },
              { text: '配置参考', link: '/zh/config' },
            ],
          },
          {
            text: '指南',
            items: [
              { text: 'rillanectl CLI 参考', link: '/zh/cli' },
              { text: 'Mesh & Chain Guide (MVP)', link: '/zh/mesh' },
              { text: '系统路由与网络接管', link: '/zh/networking' },
              { text: 'Grafana 仪表板模板', link: '/zh/grafana/README' },
            ],
          },
          {
            text: '设计文档 — 底座与路线',
            items: [
              { text: '产品定位与技术底座', link: '/zh/design/positioning' },
              { text: '分阶段路线图', link: '/zh/design/roadmap' },
              {
                text: '勘误重开条目核对报告',
                link: '/zh/design/status-audit-tun-network-middleware',
              },
            ],
          },
          {
            text: '设计文档 — UDP 数据通路（P0）',
            items: [
              { text: 'S1 UDP 全链路设计稿', link: '/zh/design/udp-dataplane' },
              {
                text: 'P0-1 UDP 会话表（实现级）',
                link: '/zh/design/udp-session-table',
              },
              {
                text: 'P0-1 会话表 API 草案',
                link: '/zh/design/udp-session-table-api',
              },
              {
                text: 'P0-2/P0-3 单跳 UDP 中继路径',
                link: '/zh/design/udp-relay-path',
              },
              {
                text: 'P0-4 mesh data-plane UDP 转发',
                link: '/zh/design/udp-mesh-dataplane',
              },
              {
                text: 'P0-5 UDP 观测与配置',
                link: '/zh/design/udp-observability',
              },
            ],
          },
          {
            text: '设计文档 — TUN 与网络接管（P1-1..P1-3）',
            items: [
              {
                text: 'P1-1/P1-2 Linux TUN 真实现 + TunIngress',
                link: '/zh/design/tun-dataplane',
              },
              {
                text: 'P1-1 实现落定稿（Linux TUN T0–T2）',
                link: '/zh/design/tun-linux-impl',
              },
              {
                text: 'P1-3 network 配置区块 + rillanectl route',
                link: '/zh/design/network-route',
              },
            ],
          },
          {
            text: '设计文档 — 横切能力（P1-4/P1-5）',
            items: [
              {
                text: 'P1-4 混淆中间件 MVP（padding）',
                link: '/zh/design/obfuscation-middleware',
              },
              { text: 'P1-5 出站连接池', link: '/zh/design/egress-connection-pool' },
            ],
          },
          {
            text: '设计文档 — 调度、安全与场景（P2）',
            items: [
              {
                text: 'P2-1 per-link 细粒度指标',
                link: '/zh/design/mesh-link-observability',
              },
              { text: 'P2-2 SLO 打分选路', link: '/zh/design/slo-scoring' },
              { text: 'P2-3 场景 profile 预设', link: '/zh/design/scenario-profiles' },
              {
                text: 'P2-4 混淆扩展（timing / shaping）',
                link: '/zh/design/obfuscation-timing-shaping',
              },
              { text: 'P2-5 客户端 TLS 指纹模拟', link: '/zh/design/tls-fingerprint' },
              {
                text: 'P2-6 mesh envelope 二进制化',
                link: '/zh/design/mesh-envelope-binary',
              },
              {
                text: 'P2-7 mesh 高级安全（CRL + UDP 防重放）',
                link: '/zh/design/mesh-advanced-security',
              },
              { text: 'P2-8 DNS 分流解析', link: '/zh/design/dns-partition' },
            ],
          },
          {
            text: '设计文档 — 收尾与发布（P3）',
            items: [
              { text: 'P3-2 插件动态加载（WASM）', link: '/zh/design/plugin-loader' },
              {
                text: 'P3-3 平台打包（systemd / launchd / Windows）',
                link: '/zh/design/platform-packaging',
              },
              { text: 'P3-5 零拷贝 / 批量收发', link: '/zh/design/performance-io' },
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
    },
  },
})
