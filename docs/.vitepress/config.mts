import { defineConfig, type DefaultTheme } from 'vitepress'

function locale(zh: boolean): DefaultTheme.Config {
  const prefix = zh ? '/zh' : ''
  const page = (text: string, path: string) => ({ text, link: `${prefix}${path}` })
  const design = [
    page(zh ? 'v1 设计入口' : 'v1 design index', '/design/'),
    page(zh ? 'v1 架构设计' : 'v1 architecture design', '/design/architecture-v1'),
    page(zh ? '架构概念与抽象依据' : 'Concepts and rationale', '/design/architecture-concepts'),
    page(zh ? '接入、出口与统计契约' : 'IO and accounting contracts', '/design/io-and-accounting'),
    page(zh ? 'Debug、路径与 MCP' : 'Debug, paths and MCP', '/design/debug-and-mcp'),
    page(zh ? '竞品架构研究与 SVG' : 'Architecture study and SVGs', '/research/proxy-architectures-2026-11-14'),
  ]
  const guides = [
    page(zh ? '当前实现与边界' : 'Current implementation', '/architecture'),
    page(zh ? '配置参考' : 'Configuration reference', '/config'),
    page(zh ? 'CLI 参考' : 'CLI reference', '/cli'),
    page(zh ? '协议支持' : 'Protocol support', '/PROTOCOLS'),
    page(zh ? '订阅指南' : 'Subscription guide', '/subscription'),
    page(zh ? '系统路由与网络接管' : 'Network capture and routing', '/networking'),
    page(zh ? '可选 Mesh' : 'Optional Mesh', '/mesh'),
    page(zh ? 'Grafana 仪表板' : 'Grafana dashboard', '/grafana/README'),
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
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }]],
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
