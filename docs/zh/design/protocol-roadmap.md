# v1 协议接入计划

状态：**候选实施计划，未接入项不代表已支持**；核查日期 2026-11-15。覆盖本次对比的 sing-box/Mihomo 协议、隧道和传输能力，跟随各自版本核验，不把开发文档目录当成某个稳定包的保证。

## 复用原则与选库门禁

**只有确认没有可用的可复用实现时才自写。** 每个候选先记录所查项目/版本、许可证、维护、平台、公开 API、socket 旁路、取消与统计能力，再选择 Rust 库、稳定 FFI 或有理由的受管后端。已有实现仅缺集成能力时先适配/贡献补丁；缺少证据时保持待评估，不直接开始重写。

协议按目录适配，提供配置校验、Factory 注册、方向/传输/UDP 能力和生命周期契约；会话、业务计数和诊断共用 [IO 契约](io-and-accounting.md)。默认每协议一个后端，重依赖 feature 可裁剪。P1 优先服务订阅与游戏兼容，P2 是后续覆盖，不阻塞 Linux/Debug/只读 MCP 先交付。

## 新增与补齐清单

以下方向是拟议验收范围。逐项选库时确认协议版本、入站/出站、平台和数据报能力；不可实现的方向保留待评估/明确拒绝，不能伪造支持。通用库缺失时允许调整排期，不能跳过复用检索门禁。

| 任务 | 能力 | 优先级 | 计划边界 |
|---|---|---|---|
| RIL-105 | TUIC | P1 | 客户端/服务端；v4/v5 分别核验，不静默互换 |
| RIL-106 | AnyTLS | P1 | 客户端/服务端；复用与 UDP 表达按库实际能力 |
| RIL-107 | REALITY | P1 | 安全握手扩展；先客户端，服务端按选库能力另验 |
| RIL-108 | XTLS Vision | P1 | VLESS 流控/分帧扩展；与 REALITY 独立验收 |
| RIL-109 | Hysteria v1 | P2 | 兼容协议客户端/服务端；保留版本和参数边界 |
| RIL-110 | ShadowTLS | P2 | 承载/握手组件；明确后续代理协议组合 |
| RIL-111 | Snell | P2 | 客户端/服务端；逐版本与 UDP 能力核验 |
| RIL-112 | NaiveProxy | P2 | 客户端/服务端；HTTP/TLS 与平台构建要求 |
| RIL-113 | SSH | P2 | 出站隧道；认证、host key 与连接生命周期 |
| RIL-114 | Tor | P2 | 出站后端；嵌入或受管实例，身份与资源生命周期 |
| RIL-115 | ShadowsocksR | P2 | 出站兼容；cipher/obfs/protocol 组合 |
| RIL-116 | Mieru | P2 | 客户端/服务端；认证与 TCP/UDP 能力 |
| RIL-117 | Sudoku | P2 | 客户端/服务端；版本、密码学参数与传输 |
| RIL-118 | ShadowQUIC | P2 | 客户端/服务端；QUIC 与数据报能力 |
| RIL-119 | TrustTunnel | P2 | 客户端/服务端；TLS、认证与数据报能力 |
| RIL-120 | MASQUE | P2 | 客户端/服务端；CONNECT-UDP/IP 分别核验 |
| RIL-121 | OpenConnect | P2 | 客户端 endpoint；路由/DNS 与凭证集成 |
| RIL-122 | OpenVPN | P2 | 客户端/服务端 endpoint；模式与平台能力 |
| RIL-123 | Tailscale | P2 | 双向 endpoint；身份、控制连接与路由边界 |
| RIL-124 | ZeroTier | P2 | 组网 endpoint；授权、虚拟网络与退出恢复 |
| RIL-125 | EasyTier | P2 | 组网 endpoint；节点生命周期与路由所有权 |
| RIL-126 | Gost Relay | P2 | 出站兼容；区别于策略组 relay |
| RIL-127 | Tailcat | P2 | 入口/出口；先核实具体上游版本和实现可复用性 |
| RIL-128 | Cloudflared | P2 | 入口隧道集成；控制/认证与服务生命周期 |
| RIL-129 | XHTTP | P1 | 传输扩展；模式、参数与具体代理组合分项核验 |
| RIL-130 | 公共传输与复用矩阵 | P1 | TLS/WS/gRPC/H2/HTTPUpgrade、UoT/XUDP/多路复用；补齐实际缺口 |
| RIL-131 | Shadowsocks 算法矩阵 | P1 | 核实现有库算法，包含 SS2022 候选；已有能力复用不重写 |
| RIL-132 | SOCKS5 出站 UDP | P1 | 标准 UDP ASSOCIATE 与来源验证，区别入口现有能力 |
| RIL-133 | Hysteria2 UDP | P1 | 适配具有数据报公开 API 的后端，TCP/UDP 独立验收 |
| RIL-134 | Shadowsocks 服务端 | P2 | 规范 Inbound 与已有外部库接线 |
| RIL-135 | Trojan 服务端 | P2 | TLS/认证、两阶段接入与 UDP 关联 |
| RIL-136 | VLESS 服务端 | P2 | 入站握手/认证、流/数据报；Vision/REALITY 组合另验 |
| RIL-137 | VMess 服务端 | P2 | AEAD 认证/重放防护与流/数据报 |
| RIL-138 | Hysteria2 服务端 | P2 | QUIC/认证/数据报与生命周期 |
| RIL-139 | 透明接管入口 | P2 | redirect/TProxy/固定目标 tunnel；平台权限与恢复，复用现有 CapturePort |

## 已有能力与配置构件

Direct、HTTP CONNECT、SOCKS5/mixed、Shadowsocks、Trojan、VLESS、VMess、Hysteria2、WireGuard 的已有实现继续适配，核实后补缺，不重复列为零起点。现有 TUN/移动平台接入分别由平台任务负责；WireGuard 平台桩仍由对应适配验收处理。

selector/url-test/fallback/load-balance 属于策略组，DIRECT/REJECT/DNS/rematch/bridge 等按动作/服务语义归类，不冒充新增线上协议。Hysteria2 Realm 等协调能力归服务集成，单独评估，不增加第二套转发。入站与服务端只在对应任务验收后可宣称支持。

## 官方依据

[sing-box outbound](https://sing-box.sagernet.org/configuration/outbound/)、[inbound](https://sing-box.sagernet.org/configuration/inbound/)、[endpoint](https://sing-box.sagernet.org/configuration/endpoint/)、[Mihomo proxies/listeners](https://wiki.metacubex.one/en/config/proxies/)、[Mihomo transport](https://wiki.metacubex.one/en/config/proxies/transport/)。
