# v1 UI 原型交付

已保存 **10 张独立原型图：桌面 6 张、iOS 2 张、Android 2 张**。当前为视觉与交互提案；全部数值为示例。

[离线/浏览器图库](/prototypes/v1/index.html) · [交互规格](../ui-prototype-v1.md) · [生成提示词与修改记录](https://github.com/cuihairu/rillane/blob/main/docs/design/ui/prompts.json)

保存目录：`docs/public/prototypes/v1/`。`index.html` 可直接用浏览器打开；`manifest.json` 包含尺寸、SHA-256 和修订号。使用内置 image_gen 生成，随后复制到仓库；生成提示词与四张图的修改提示词已落盘。

图片表达布局与主题，Logo/图标不是已冻结品牌。产品实现以交互规格为准：状态来自内核/宿主确认，业务流量不重复累计，流媒体不承诺持续解锁，移动不承诺任意PID归因。iMac已确认Clash Verge进程，但未获实时窗口截图；参考官方预览与App Store资料。

## D01 · 桌面 · 总览

连接、模式、并行场景、业务流量与媒体检测摘要。

![桌面 · 总览 原型示例](/prototypes/v1/desktop-overview.png)

## D02 · 桌面 · 节点与订阅

来源、分组选择、更新差异与能力状态。

![桌面 · 节点与订阅 原型示例](/prototypes/v1/desktop-nodes.png)

## D03 · 桌面 · 规则与区域

规则/全局/直连、区域预设、三桌面进程规则与切换影响。

![桌面 · 规则与区域 原型示例](/prototypes/v1/desktop-rules.png)

## D04 · 桌面 · 网络与 DNS

接管、fake-ip/redir-host、DNS出站、引导解析、按需嗅探。

![桌面 · 网络与 DNS 原型示例](/prototypes/v1/desktop-network.png)

## D05 · 桌面 · 连接诊断

实际轨迹、计划/实际出口、回退、未知原因与只读AI。

![桌面 · 连接诊断 原型示例](/prototypes/v1/desktop-diagnostics.png)

## D06 · 桌面 · 开发者代理

Git/SSH/GitHub路由、当前终端、配置预览与连通性。

![桌面 · 开发者代理 原型示例](/prototypes/v1/desktop-developer.png)

## I01 · iOS · 首页

原生列表、模式、场景、业务流量与常用工具。

![iOS · 首页 原型示例](/prototypes/v1/ios-home.png)

## I02 · iOS · 网络设置

DNS应答、查询出站、例外、嗅探与应用预览。

![iOS · 网络设置 原型示例](/prototypes/v1/ios-network.png)

## A01 · Android · 首页

Material风格、VPN状态、模式与并行场景。

![Android · 首页 原型示例](/prototypes/v1/android-home.png)

## A02 · Android · 网络设置

独立DNS/区域控制与变更预览。

![Android · 网络设置 原型示例](/prototypes/v1/android-network.png)
