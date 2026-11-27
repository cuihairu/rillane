import { defineConfig, type DefaultTheme } from 'vitepress'

function locale(zh: boolean): DefaultTheme.Config {
  const prefix = zh ? '/zh' : ''
  const page = (text: string, path: string) => ({ text, link: `${prefix}${path}` })
  const design = [
    page(zh ? 'v1 设计入口' : 'v1 design index', '/design/'),
    page(zh ? 'v1 架构设计' : 'v1 architecture design', '/design/architecture-v1'),
    page(zh ? '架构概念与抽象依据' : 'Concepts and rationale', '/design/architecture-concepts'),
    page(zh ? '接入、出口与统计契约' : 'IO and accounting contracts', '/design/io-and-accounting'),
    page(zh ? '协议接入计划' : 'Protocol integration plan', '/design/protocol-roadmap'),
    page(zh ? 'Debug、路径与 MCP' : 'Debug, paths and MCP', '/design/debug-and-mcp'),
    page(zh ? 'UI 原型与控制语义' : 'UI prototypes and controls', '/design/ui-prototype-v1'),
    page(zh ? '原型图库（10 张）' : 'Prototype gallery (10)', '/design/ui/README'),
    page(zh ? '竞品架构研究与 SVG' : 'Architecture study and SVGs', '/research/proxy-architectures-2026-11-14'),
  ]
  const guides = [
    page(zh ? '当前实现与边界' : 'Current implementation', '/architecture'),
    page(zh ? '平台支持与交付状态' : 'Platform support & delivery', '/platform-support'),
    page(zh ? '功能矩阵' : 'Feature matrix', '/feature-matrix'),
    page(zh ? '配置参考' : 'Configuration reference', '/config'),
    page(zh ? 'CLI 参考' : 'CLI reference', '/cli'),
    page(zh ? '安装、恢复与 Debug 示例' : 'Install, recover and Debug', '/usage-bridge'),
    page(zh ? '协议支持' : 'Protocol support', '/PROTOCOLS'),
    page(zh ? '订阅指南' : 'Subscription guide', '/subscription'),
    page(zh ? '系统路由与网络接管' : 'Network capture and routing', '/networking'),
    page(zh ? '可选 Mesh' : 'Optional Mesh', '/mesh'),
    page(zh ? 'Grafana 仪表板' : 'Grafana dashboard', '/grafana/README'),
    page(zh ? '验收证据' : 'Acceptance evidence', '/acceptance-evidence/README'),
  ]
  return {
    nav: [
      page(zh ? '首页' : 'Home', '/'),
      { text: zh ? 'v1 设计' : 'v1 design', items: design },
      { text: zh ? '使用参考' : 'Reference', items: guides },
      { text: 'GitHub', link: 'https://github.com/cuihairu/rillane' },
    ],
    sidebar: [
      { text: zh ? 'v1 设计（提案）' : 'v1 design (proposal)', items: design },
      { text: zh ? '当前实现与使用参考' : 'Implementation and reference', items: guides },
    ],
    outline: { level: [2, 3], label: zh ? '本页目录' : 'On this page' },
    docFooter: { prev: zh ? '上一篇' : 'Previous', next: zh ? '下一篇' : 'Next' },
    returnToTopLabel: zh ? '回到顶部' : 'Back to top',
    sidebarMenuLabel: zh ? '菜单' : 'Menu',
    darkModeSwitchLabel: zh ? '主题' : 'Theme',
    lightModeSwitchTitle: zh ? '切换到浅色' : 'Switch to light theme',
    darkModeSwitchTitle: zh ? '切换到深色' : 'Switch to dark theme',
  }
}

export default defineConfig({
  lang: 'en-US',
  title: 'Rillane',
  description: 'Rillane v1 design: one proxy core, six platforms, concurrent game/web policies and optional diagnostic MCP.',
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/brand/v1/final/web/favicon-32.png' }],
    ['link', { rel: 'apple-touch-icon', sizes: '180x180', href: '/brand/v1/final/web/apple-touch-icon.png' }],
  ],
  locales: {
    root: { label: 'English', lang: 'en-US' },
    zh: { label: '简体中文', lang: 'zh-CN', link: '/zh/' },
  },
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Rillane',
    locales: { root: locale(false), zh: locale(true) },
  },
})
