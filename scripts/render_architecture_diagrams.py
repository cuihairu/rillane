#!/usr/bin/env python3
"""Rebuild standalone architecture SVGs; standard library only, no network."""
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/public/architecture"
FONT = "'Noto Sans CJK SC','Noto Sans',sans-serif"
INK, MUTED = "#172c38", "#526674"
DATA, CONTROL, FEEDBACK = "#197569", "#3469b0", "#b36b20"


def text(x, y, value, size=22, color=INK, weight=400):
    return f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" fill="{color}">{escape(value)}</text>'


def box(x, y, w, h, title, lines, proposed=False):
    assert y + 76 + (len(lines) - 1) * 29 <= y + h - 14
    stroke = "#b36b20" if proposed else "#adc3cc"
    fill = "#fff7e9" if proposed else "#ffffff"
    dash = ' stroke-dasharray="9 5"' if proposed else ""
    s = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>'
    s += text(x + 20, y + 36, title, 24, weight=650)
    for i, line in enumerate(lines):
        s += text(x + 20, y + 76 + i * 29, line, 20, MUTED)
    return s


def arrow(points, kind="data", label=None):
    color = {"data": DATA, "control": CONTROL, "feedback": FEEDBACK}[kind]
    dash = ' stroke-dasharray="9 6"' if kind != "data" else ""
    s = f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="3" stroke-linejoin="round" marker-end="url(#{kind})"{dash}/>'
    if label:
        x, y, label = label
        s += text(x, y, label, 17, color)
    return s


def frame(title, subtitle, height=1030):
    defs = "<defs>"
    for name, color in (("data", DATA), ("control", CONTROL), ("feedback", FEEDBACK)):
        defs += f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 Z" fill="{color}"/></marker>'
    defs += "</defs>"
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="{height}" viewBox="0 0 1600 {height}" role="img" aria-labelledby="title desc"><title id="title">{escape(title)}</title><desc id="desc">{escape(subtitle)} Solid green arrows: data. Dashed blue: configuration/control. Dashed amber: feedback. This is an architectural abstraction, not every call or packet.</desc>{defs}<rect width="1600" height="{height}" fill="#f4f7f8"/>' + text(50, 64, title, 34, weight=700) + text(50, 106, subtitle, 21, MUTED)


def save(name, s):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(s + "</svg>\n", encoding="utf-8")


def overview(name, title, subtitle, rows, sources, proposed=False):
    s = frame(title, subtitle)
    xs, ys = [50, 435, 820, 1205], [175, 435, 725]
    for label, y in zip(("CONTROL / 配置与生命周期", "DATA / 连接与数据报", "SERVICES / 共享服务与边界"), (155, 415, 705)):
        s += text(50, y, label, 18, MUTED, 600)
    # Connect adjacent data-plane abstractions, never through their labels.
    for i in range(3):
        s += arrow([(xs[i] + 345, 520), (xs[i + 1] - 8, 520)])
    for i in range(2):
        s += arrow([(xs[i] + 345, 255), (xs[i + 1] - 8, 255)], "control")
    s += arrow([(992, 350), (992, 426)], "control", (1010, 391, "policy / 策略"))
    s += arrow([(222, 725), (222, 641), (607, 641), (607, 620)], "control")
    s += arrow([(992, 725), (992, 620)], "feedback", (1010, 676, "quality / 质量"))
    for row, y in zip(rows, ys):
        for (heading, lines), x in zip(row, xs):
            s += box(x, y, 345, 185, heading, lines, proposed)
    s += arrow([(60, 958), (130, 958)]) + text(145, 965, "data", 18, MUTED)
    s += arrow([(265, 958), (335, 958)], "control") + text(350, 965, "control", 18, MUTED)
    s += arrow([(510, 958), (580, 958)], "feedback") + text(595, 965, "feedback", 18, MUTED)
    s += text(50, 1009, sources, 17, MUTED)
    save(name, s)


overview("mihomo.svg", "Clash / Mihomo — provider-driven proxy kernel", "代理内核 Meta 分支 + 官方文档的概念重建；不代表原 Clash 的全部历史实现。", [
 [("Sources / 配置来源", ["YAML / proxy-providers", "rule-providers / remote files", "节点与规则来源独立"]),
  ("Compile / 装配", ["config + hub/executor", "解析、校验、实例装配", "不是浏览器 HTTP 缓存"]),
  ("Policy / 策略对象", ["rules + proxy groups", "select / url-test / fallback", "providers 动态更新成员"]),
  ("Control / 管理", ["REST controller / clients", "配置、选择与连接观测", "控制面不等于流量入口"])],
 [("Capture / 流量入口", ["SOCKS / HTTP / mixed", "TUN / redirect / TProxy", "入口统一交给 tunnel"]),
  ("Metadata / 流上下文", ["地址、域名、网络类型", "sniff / process lookup", "身份取决于平台与权限"]),
  ("Route / 规则与选择", ["ordered rules → policy", "group → concrete adapter", "TCP 与 UDP 能力分别检查"]),
  ("Forward / 出站转发", ["protocol adapters / dialers", "DIRECT / proxy / dialer chain", "session / UDP NAT state"])],
 [("DNS / 名称服务", ["resolver / fake-IP mapping", "域名上下文与地址关联", "DNS 不是 HTTP 内容解密"]),
  ("Platform / 系统差异", ["process lookup / routing", "设备与权限适配", "TUN 本身不携带 PID"]),
  ("Health / 质量观测", ["provider health checks", "URL-test / connection stats", "健康不等于游戏端到端 RTT"]),
  ("Boundary / 吸收重点", ["订阅、规则、选择解耦", "动态成员与策略语义", "逐项兼容，不随机替代回退"])],
], "Sources M1–M7 · Meta 0455d0d28c45 · 2026-11-14 · references in proxy-architectures-2026-11-14.md")

overview("sing-box.svg", "sing-box — typed adapters and lifecycle composition", "官方 testing 源码快照的模块视图；开发分支存在不等于稳定版均可用。", [
 [("Options / 配置", ["typed option models", "protocol registries", "tag references / rule sets"]),
  ("Box / 生命周期", ["Box assembles managers", "staged start / close", "context supplies dependencies"]),
  ("Route / 策略模型", ["route actions / rule-set", "selector / URLTest", "DNS routing separately modeled"]),
  ("Host / 嵌入宿主", ["libbox / PlatformInterface", "CLI or platform app", "平台状态由宿主注入"])],
 [("Inbound / 接管", ["proxy listeners / TUN", "connection / packet inputs", "endpoint 不是普通出站别名"]),
  ("Context / 流上下文", ["InboundContext metadata", "sniff / resolve / owner", "platform-dependent identity"]),
  ("Router / 路由动作", ["match → action → outbound", "reject / route / sniff", "protocol and platform contracts"]),
  ("Outbound / 转发", ["protocol adapters / detour", "TCP streams / UDP packets", "direct / proxy / endpoints"])],
 [("DNS / 共享服务", ["DNS router + transports", "cache / fake-IP mapping", "resolver avoids tunnel loops"]),
  ("Platform / 适配边界", ["TUN / routes / network change", "platform callback interface", "移动生命周期不塞进路由器"]),
  ("Health / 观测", ["URLTest / logs / cache", "选择与连通性反馈", "不能推导出硬实时保证"]),
  ("Boundary / 吸收重点", ["typed contracts / registries", "core lifecycle vs OS host", "支持状态按版本与平台记录"])],
], "Sources S1–S6 · testing 3dd8aa48d403 · 2026-11-14 · official source + documentation")

overview("surge.svg", "Surge — documented functional architecture", "仅据官方公开文档重建；闭源产品，图中不是其私有类、线程或内部调用图。", [
 [("Profile / 配置", ["rules / policies / groups", "DNS / managed resources", "配置描述功能，不证明私有实现"]),
  ("Policy / 策略", ["direct / reject / proxy", "groups / proxy chains", "规则与具体出口分离"]),
  ("Selection / 自适应", ["Smart Group quality scores", "real connections + tests", "per-site preference / retries"]),
  ("Host / 产品宿主", ["macOS / iOS application", "control / diagnostics", "平台版本与权限影响能力"])],
 [("Takeover / 接管", ["proxy service / virtual NIC", "Apple platform integration", "接管先于请求处理"]),
  ("Requests / 请求上下文", ["destination / domain / protocol", "process rules: Mac only", "iOS 不执行进程规则"]),
  ("Rules / 选择策略", ["ordered rule matching", "policy / policy group", "web and game can coexist"]),
  ("Forward / 转发", ["DIRECT / proxy / chain", "TCP / supported UDP relay", "保持协议与会话边界"])],
 [("DNS / 名称服务", ["custom DNS / mapping", "resolve / policy support", "DNS 时未必知道发起进程"]),
  ("Inspection / 可选处理", ["capture / rewrite / scripts", "optional authorized MITM", "不是游戏 UDP 必经热路径"]),
  ("Quality / 质量反馈", ["first-response observations", "documented failure scoring", "Smart 不是固定 URL 最小值"]),
  ("Boundary / 吸收重点", ["可解释诊断与真实反馈", "功能按平台明确声明", "不模仿未知私有内部结构"])],
], "Sources G1–G4 · official documented behavior, not source audit · 2026-11-14")

overview("rillane-target.svg", "Rillane — proposed target architecture / 目标方案", "所有虚线框均为目标边界，未整体实现；复用现有模块，按迁移门禁逐项交付。", [
 [("Sources / 配置来源", ["Clash / Mihomo + local rules", "provider-scoped stable IDs", "sources never own local policy"]),
  ("Compiler / 配置编译", ["canonical typed IR + provenance", "validate refs / OS capabilities", "last-known-good on failure"]),
  ("Generation / 配置代际", ["immutable validated snapshot", "prepare → apply → publish", "new flows pin one generation"]),
  ("Control / 平台宿主", ["daemon / Android service", "Apple Packet Tunnel extension", "UI / IPC / optional MCP"])],
 [("CapturePort / 接管端口", ["socket / packet-batch inputs", "Linux / OpenWrt / Wintun", "Android VPN / Apple packetFlow"]),
  ("Flow / 流与应用上下文", ["TCP stream / UDP association", "OwnerResolver + DNS context", "known / unknown / unsupported"]),
  ("Policy / 并行场景", ["process + domain → route plan", "game / web objectives coexist", "target + queue + fail policy"]),
  ("Session / 会话执行", ["pin endpoint / bounded queues", "direct / standard proxy", "optional mesh adapter"])],
 [("Ports / 平台服务", ["DNS / owner / socket bypass", "route transaction / permissions", "iOS、路由器不伪造应用身份"]),
  ("Resources / 资源隔离", ["class budgets / queue bounds", "optional pools / UDP caps", "small build excludes WASM JIT"]),
  ("Quality / 可解释反馈", ["typed samples + age + source", "new-flow choice / hysteresis", "failure ratio ≠ packet loss"]),
  ("Mesh / 可选节点网", ["managed capabilities / crypto", "not imposed on subscriptions", "no seamless migration promise"])],
], "PROPOSED · ADRs A1–A10 and migration RV2 tasks · existing status is documented separately · 2026-11-14", True)

s = frame("Six platforms — shared core, explicit capability boundaries", "同一个 Rust 数据面设计；系统 helper、VPN service 或 extension 可以处于独立进程。", 1220)
columns = [(255, "CAPTURE / 接管"), (695, "IDENTITY / 应用归因"), (1135, "LIFECYCLE / 验收边界")]
for x, label in columns:
    s += text(x, 158, label, 19, MUTED, 600)
platforms = [
 ("Linux", "baseline → harden", ["TUN + route transaction", "SO_MARK / resolver bypass"], ["local PID / executable / UID", "permission + netns dependent"], ["systemd / cleanup / recovery", "current Linux path is reusable"]),
 ("OpenWrt", "gateway target", ["TUN; fw4/nftables integration", "musl / procd / bounded memory"], ["client IP / device / port", "cannot infer a LAN app PID"], ["router smoke + DNS recovery", "optional endpoint agent later"]),
 ("Windows", "new adapter", ["Wintun packet I/O", "route / DNS / loop prevention"], ["separate owner lookup", "WFP/ALE or owner tables spike"], ["SCM / privileges / signed deps", "cross-build is not runtime proof"]),
 ("macOS", "new adapter", ["supported Apple integration", "packet / app-flow ports differ"], ["host process attribution", "API + entitlement verification"], ["signed app / helper / extension", "no private-fd dependency"]),
 ("Android", "demo → data plane", ["VpnService + TUN fd", "protect sockets / network change"], ["no process-routing requirement", "optional package/UID features"], ["foreground service / revoke", "allowlist ≠ per-flow routing"]),
 ("iOS", "scaffold → extension", ["NEPacketTunnelProvider", "public packetFlow read/write"], ["ordinary VPN: no arbitrary PID", "managed per-app VPN: separate"], ["app + extension / IPC / memory", "game/web by domain/IP/port"]),
]
for i, (name, status, capture, identity, lifecycle) in enumerate(platforms):
    y = 190 + i * 151
    s += text(50, y + 42, name, 26, weight=700) + text(50, y + 77, status, 17, MUTED)
    for (x, _), lines in zip(columns, (capture, identity, lifecycle)):
        s += box(x, y, 410, 130, "Capability / 能力边界", lines, True)
s += text(50, 1145, "Process-based routing is required only on local Windows, macOS and Linux hosts.", 23, INK, 650)
s += text(50, 1185, "Proposed platform ports · OS references P1–P9 · OpenWrt / Android / iOS: proxy + concurrent game/web, no desktop PID requirement.", 17, MUTED)
save("platform-boundaries.svg", s)
s = frame("Rillane — Debug / MCP boundaries / 诊断与 AI 边界", "目标设计，尚未实现；蓝虚线是控制调用，橙虚线是观测，底部绿实线才是业务数据。", 1400)
# Draw connections before cards. AI/MCP never sit in the forwarding chain.
s += arrow([(1080, 260), (1038, 260)], "control")
s += arrow([(797, 360), (797, 445)], "control")
s += arrow([(282, 360), (282, 445)], "control")
s += arrow([(565, 540), (523, 540)], "control")
s += arrow([(1030, 540), (1072, 540)], "control")
s += arrow([(282, 640), (282, 750)], "control", (65, 700, "explain / 纯推演"))
s += arrow([(1312, 640), (1312, 750)], "control", (1110, 700, "approved / 授权后"))
s += arrow([(565, 845), (535, 845), (535, 690), (420, 690), (420, 648)], "feedback")
s += arrow([(282, 945), (282, 995), (700, 995), (700, 1042)], "control")
s += arrow([(850, 1050), (850, 953)], "feedback", (870, 1010, "events"))
s += arrow([(1312, 945), (1312, 995), (1000, 995), (1000, 1042)], "control")
for x1, x2 in ((515, 565), (1030, 1080)):
    s += arrow([(x1, 1135), (x2 - 8, 1135)])
rows = [
 [("CLI / UI", ["shared application service", "text / JSON / path view", "same diagnostic semantics"]),
  ("MCP adapter / 可选", ["local stdio; disabled by default", "no shell / generic admin proxy", "credentials stay outside model"]),
  ("AI client / 分析与建议", ["sanitized evidence and diff", "scoped reads / explicit probes", "writes require granted authority"])],
 [("Diagnostics / 诊断服务", ["Explain / Trace / Probe", "redacted field allowlists", "active probes: separate scope"]),
  ("Authority / 服务端权限", ["read / identity / probe / write", "size / rate / target limits", "annotations are not permission"]),
  ("Proposal / 配置提案", ["stored patch + base generation", "owner / expiry / exact approval", "conflict + idempotency checks"])],
 [("Explain / 共享求值", ["production routing evaluator", "frozen config / quality snapshot", "no DNS or connection side effect"]),
  ("Trace / 有界观测", ["flow / attempt / generation IDs", "planned vs actual endpoint", "TTL / sampling / drop counters"]),
  ("Apply / 发布事务", ["persist + OS effects + generation", "receipt / verify / compensate", "rollback + host watchdog"])],
 [("FlowContext / 业务输入", ["capture + owner + DNS evidence", "local PID: Win / Mac / Linux", "mobile: host IPC, no MCP default"]),
  ("Router + Session / 数据面", ["game / web policies coexist", "pin generation and endpoint", "works without AI or tracing"]),
  ("Egress / 实际出口", ["DIRECT / standard proxy", "optional managed Mesh", "provider internals are unknown"])],
]
for row, y in zip(rows, (175, 455, 760, 1050)):
    for (heading, lines), x in zip(row, (50, 565, 1080)):
        s += box(x, y, 465, 185, heading, lines, True)
s += text(50, 1300, "PROPOSED: prediction ≠ observation ≠ active network probe; path views show unknowns explicitly.", 22, INK, 650)
s += text(50, 1350, "A9–A10 / C31 refinements · debug-and-mcp.md · atomic backlog RIL-051–RIL-082 · 2026-11-14", 19, MUTED)
save("debug-mcp.svg", s)
print(f"Generated 6 standalone SVGs in {OUT}")
