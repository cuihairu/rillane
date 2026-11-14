# Rillane 功能差距分析（对照 sing-box / mihomo / xray-core）

> 日期：2026-11-02 · 方法：对照 rillane 工作树代码（crates/apps/config/docs）与三个成熟实现的公开文档/发布说明逐域盘点。
> 对照版本口径：sing-box 1.14–1.15（含 OpenVPN/OpenConnect/Tailscale endpoint、rule action 体系）、mihomo 1.19.x、xray-core 25.x。
> 性质：**只审不改**。所有 rillane 现状均以代码/文档为准（docs/PROTOCOLS.md 顶部状态总表 + todo.md 已核实条目），未采信 README 宣传性描述。

---

## 1. 总评

rillane 的定位是「多协议代理内核 + mesh 协作面」，底座完成度高（P0–P3 主线 24/24 落地）。与三大成熟实现相比：

- **已达或接近项**：socks5/http/mixed 入站（含 UDP ASSOCIATE）、direct/ss/trojan/vless/vmess/hy2/wireguard 出站、tcp/ws/grpc/h2 传输矩阵、Clash 订阅双向转换、TUN(Linux)+进程归因、DNS 分流防污染、mesh mTLS 多跳、Prometheus 观测。
- **核心差距集中在四块**：① 路由规则引擎远弱于三者（无目的 IP-CIDR、无 GeoIP/GeoSite 数据库、无 rule-set 提供者、无逻辑组合规则、无协议嗅探）；② QUIC 生态协议缺位（tuic、hy2 UDP 面、REALITY、XTLS-Vision）；③ 服务端入站协议为零（三大项目都是 client+server 双面）；④ 透明代理仅 TUN(Linux) 单点（缺 redir/tproxy、缺 macOS/Windows TUN 实现）。
- **rillane 独有优势**：mesh 多跳 mTLS + 链路观测、SLO 打分选路、场景 profile、WASM 插件、移动端 FFI 骨架——三者均无同等能力（sing-box Tailscale endpoint 是最接近的 mesh 思路）。

---

## 2. 分域对比

### 2.1 入站协议

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| SOCKS5 (TCP) | ✅ | ✅ | ✅ | ✅ 含 RFC1929 认证 |
| SOCKS5 UDP ASSOCIATE | ✅ | ✅ | ✅ | ✅ P0-2，`udp:` 块默认关 |
| HTTP CONNECT / Mixed | ✅ | ✅ | ✅ | ✅ Basic+Bearer 认证；非 CONNECT 405（无完整 HTTP 转发面） |
| TUN | ✅ 全平台+auto_route/auto_redirect | ✅ 全平台 | ✅(tun2socks 生态) | ⚠️ 仅 Linux 真实现，smoltcp 用户态 TCP 栈 + /proc 进程归因 + fwmark 逃逸 |
| redir / tproxy 透明代理 | ✅ redirect/tproxy | ✅ redir/tproxy | ✅ dokodemo-door | ❌ 无 |
| **服务端入站**（ss/trojan/vless/vmess/hy2/tuic server） | ✅ | ✅ | ✅（全项目立身之本） | ❌ 仅本地代理型入站，无隧道协议服务端 |
| 隧道入站（tunnel/listen 转发） | ✅ | ✅ | ✅ dokodemo | ❌ |
| 协议嗅探（sniff 域名/协议覆盖路由） | ✅ sniff 规则动作 | ✅ sniffer | ✅ sniffing | ❌ 无嗅探层 |
| fallback（单端口多协议分流） | — | — | ✅ fallbacks | ❌ |

### 2.2 出站协议

| 协议 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| direct | ✅ | ✅ | ✅ | ✅ 含 RFC8305 Happy Eyeballs + fwmark |
| socks5 / http | ✅ | ✅ | ✅ | ✅ TCP 面；**socks5 出站 UDP 转发未实现** |
| shadowsocks | ✅ | ✅ | ✅ | ✅ TCP+UDP + SIP003 插件桥（v2ray-plugin/obfs 导入换算） |
| shadowsocksR | — | ✅ | — | ❌ |
| trojan | ✅ | ✅ | ✅ | ✅ tcp/ws/grpc（trojan-go 惯例）；**h2 被构建期拒绝** |
| vmess | ✅ | ✅ | ✅ | ✅ AEAD 头 xray 向量级互操作；tcp/ws/grpc/h2；alter_id=0 only；**UDP 面未实现** |
| vless | ✅ | ✅ | ✅ | ⚠️ tcp/ws/grpc/h2；**flow（XTLS-Vision）显式拒绝**；UDP 面未实现 |
| **XTLS / REALITY** | ✅ vision+reality | ✅ reality | ✅（发明方） | ❌ 两者皆无（订阅导入含 reality-opts 节点会构建失败） |
| hysteria v1 | ✅ | ✅ | — | ❌ schema+订阅转换支持，构建期报错 |
| hysteria2 | ✅ TCP+UDP+salamander+端口跳跃 | ✅ 同左+证书 pinning | — | ⚠️ 仅 TCP over QUIC；**UDP/salamander/端口跳跃均无**（hy2 crate API 受限，归 V2 quinn） |
| tuic | ✅ | ✅ | — | ❌ 订阅含 tuic 节点无法使用 |
| anytls | ✅ | ✅ | — | ❌ |
| shadowtls | ✅ | ✅ | — | ❌ |
| ssh / snell / naive / tor / mieru / trusttunnel / masque 等 | ✅(部分) | ✅(部分) | — | ❌ |
| wireguard | ✅ 内核+用户态+endpoint | ✅ +AmneziaWG | — | ⚠️ 依赖系统 WG 接口（不自做加解密）；TCP+UDP 面 |
| **block / reject 出站** | ✅ | ✅ | ✅(blackhole) | ❌ 无拒绝型出口（规则命中即断连场景不可表达） |
| dns 出站 | ✅ | ✅ | — | ❌ |

### 2.3 传输层矩阵（叠加于代理协议之上）

| 传输 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| tcp + TLS/SNI/ALPN | ✅ | ✅ | ✅ | ✅（rustls） |
| websocket | ✅ | ✅ | ✅ | ✅（RFC6455 最小客户端面） |
| gRPC | ✅ | ✅ | ✅ | ✅（vless/vmess/trojan，POST /Tun 单流） |
| h2 | ✅ | ✅ | ✅ | ✅（vless/vmess；trojan 拒绝） |
| **httpupgrade** | ✅ | ✅ | ✅ | ❌（订阅含 httpupgrade 节点无法使用） |
| **xhttp / splithttp** | — | — | ✅（当前主推） | ❌ |
| mKCP / QUIC 传输 | — | — | ✅ mkcp | ❌ |
| **REALITY** | ✅ | ✅ | ✅ | ❌ |
| multiplex (mux/smux/yamux/h2mux) | ✅ | ✅ | ✅ (XUDP/mux.cool) | ❌ 无多路复用（连接池只做握手摊销，文档明示复用归 V2） |
| uTLS 真指纹 | ✅ | ✅（含 ECH） | ✅（uToe） | ⚠️ rustls 扩展集形状预设 chrome/ios/safari（P2-5），非真 uTLS/BoringSSL；QUIC 面不含 |
| ECH | ✅ | ✅ | — | ❌ |

### 2.4 路由规则引擎

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| 域名 exact / suffix / keyword | ✅ | ✅ | ✅ | ✅ suffix/keyword（无 exact/full、无 regex、无通配符） |
| **目的 IP-CIDR** | ✅ | ✅ | ✅ | ❌ `MatchCondition::Network` 匹配的是 `client.cidr` **源**注解（rillane-routing/src/lib.rs:706），非目标地址段 |
| GeoIP（.dat/mmdb 数据库查询） | ✅ | ✅ | ✅ | ⚠️ 仅读 `geoip.country` **注解**，无数据库、无自动解析注入——实际等价于「无」 |
| GeoSite（v2fly 数据库 / geosite: 前缀） | ✅ | ✅ | ✅ | ❌（`import-rules` 只做文本清单一次性导入 YAML 片段） |
| rule-set / rule-provider（远程规则订阅+热更新） | ✅（srs/源格式，热更） | ✅（classical/domain/ipcidr + mrs） | ✅（geosite/geoip 文件+http 更新） | ❌ |
| 逻辑规则 AND/OR/NOT（invert） | ✅ | ✅ | ✅ | ⚠️ 仅隐式 AND（`matches.iter().all`），无 OR/NOT/invert |
| 端口/端口段 | ✅ | ✅ | ✅ | ⚠️ 仅目标端口枚举（`Vec<u16>`），无端口段、无源端口 |
| 进程名/路径 | ✅ | ✅ | — | ✅ TUN 面 `/proc/comm` 归因（P1-2） |
| 用户/UID、入站名、网络类型(TCP/UDP)、DSCP、源 MAC | ✅ | ✅(部分) | ✅(部分) | ❌ |
| 时间段规则 | — | ✅ | — | ❌ |
| 域名嗅探后重匹配（fake-ip 下域名规则先行） | ✅ | ✅ | ✅ | ❌ 无嗅探无 fake-ip，依赖客户端传域名（socks5/http 天然带域名；TUN IP 流靠 DNS 嗅探缺失而弱化） |
| 规则动作体系（route/dns/hijack/sniff/reject/bypass/resolve） | ✅ rule-action | ✅（TARGET+no-resolve 等） | ✅（ruleStrategy） | ⚠️ 仅「规则→目标组/节点」，无动作化 |
| 分组策略 | selector/urltest(+interval/tolerance) | select/url-test/fallback/load-balance(+strategy) | 负载均衡+观测 | ✅ **7 种策略+组嵌套+SLO 打分门（P2-2）**——表达力超过三者，但无 urltest 式实时 HTTP 测速基准（LatencyProbe 为探针面） |

### 2.5 DNS

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| UDP 53 上游 + 缓存 | ✅ | ✅ | ✅ | ✅（min/max TTL clamp、负缓存） |
| domestic/trusted 分组 + 分流 | ✅ | ✅ | ✅ | ✅（`network.dns` 块，rules→group，P2-8） |
| 防污染 | ✅（可信服务器/fake-ip） | ✅（fallback+GeoIP 校验） | ✅（nonIPQuery/pollution 面） | ✅ cross_check 并发双查分歧判定 |
| **DoH / DoT / DoQ** | ✅ | ✅ | ✅ | ❌ 上游仅裸 UDP `ip:port`（归 V2，dns-partition.md） |
| **fake-ip** | ✅ | ✅ | — | ❌ |
| hosts 映射 | ✅ | ✅ | ✅ | ❌ |
| nameserver-policy 细粒度（按域名指定服务器） | ✅ | ✅ | ✅ | ⚠️ 仅 pattern→domestic/trusted 二组 |
| 缓存防击穿 singleflight | ✅ | ✅（in-flight dedup） | ✅ | ❌（todo 已登记 2026-11-02 审核 P2 发现） |
| optimistic 缓存/持久化 | ✅ | ✅ | — | ❌ |
| localhost/系统解析、DHCP、mDNS、resolved | ✅ | ✅(部分) | ✅(部分) | ❌ |

### 2.6 TUN / 系统接管 / 透明代理

| 能力 | sing-box | mihomo | xray(生态) | rillane |
|---|---|---|---|---|
| TUN 数据面 | ✅ 自研栈（性能导向） | ✅ system+gvisor | ✅ | ✅ Linux：/dev/net/tun + smoltcp TCP 终结 + UDP 会话（P1-1/P1-2） |
| macOS/Windows TUN | ✅ utun/wintun | ✅ | ✅ | ❌ `rillane-platform` 仅 trait/占位 |
| auto_route / 全局接管（ip rule） | ✅ | ✅ | ✅ | ⚠️ MVP 仅显式路由表 `rillanectl route apply/clear`；ip rule 全局接管归 V2；fwmark 逃逸已落地 |
| auto_redirect（nftables DNAT） | ✅ | — | — | ❌ |
| ICMP/ping 代理 | ✅(1.13+) | ✅ | — | ❌ |
| L3 直通（bridge/L3 ICMP 到 endpoint） | ✅(1.14) | — | — | ❌ |
| redir/tproxy 入站 | ✅ | ✅ | ✅ | ❌ |

### 2.7 UDP 数据面

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| 入站 UDP 中继 | ✅ | ✅ | ✅ | ✅ socks5/mixed ASSOCIATE + TUN UDP |
| 出站 UDP（direct/ss/wg） | ✅ | ✅ | ✅ | ✅（P0-3，会话粘滞键+回收） |
| **UDP over vmess/vless/trojan/hy2** | ✅ | ✅ | ✅ | ❌ 四条主流加密通道均不载 UDP（构建期扫描报错） |
| full-cone NAT 行为 | ✅ | ✅ | ✅ | ⚠️ 会话表存在，未声明 full-cone 保证 |
| UDP over TCP（UoT） | ✅ | ✅ | — | ❌ |
| mesh UDP 多跳 | — | — | — | ✅ **独有**（P0-4，envelope+滑窗防重放 P2-7） |

### 2.8 订阅 / 节点管理

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| Clash 订阅转换导入 | ✅(生态) | ✅ 原生 | — | ✅ 全类型换算（含 grpc-opts/h2-opts/plugin_opts），未实现类型构建期显式报错 |
| Clash 导出 | — | — | — | ✅ clash_export.rs（**独有**） |
| proxy-provider（节点列表 URL 独立订阅+health-check） | ✅(类似 remote) | ✅ | — | ⚠️ 有订阅缓存+ETag+热更（P0/P2 面），无独立 provider 概念、无订阅级 url-test 常驻测速 |
| 订阅 DSL/自有格式 | — | — | — | ✅ rillane_dsl.rs（独有） |
| 面板生态（Clash API 兼容 /proxies /connections /traffic + Web UI） | ✅(1.14 API service+dashboard) | ✅ 生态最强 | — | ❌ 仅自有控制面（/flows /nodes /routing/stats /udp/stats /mesh/switches /egress/pool/stats 等）+ rillanectl 18 子命令；不兼容 Clash API，意味着 metacubexd/yacd 等面板无法直连 |

### 2.9 混淆 / 流量伪装

| 能力 | sing-box | mihomo | xray | rillane |
|---|---|---|---|---|
| TLS 指纹模拟 | ✅ uTLS | ✅ uTLS+ECH | ✅ | ⚠️ 形状预设（rustls 扩展集，非协议级实现） |
| REALITY / XTLS | ✅ | ✅ | ✅ | ❌ |
| 包长填充 | ✅ mux padding | — | ✅(部分) | ✅ 横切层（fixed/bucket/range，P1-4） |
| 时序/整形扰动 | — | — | — | ✅ **独有**（TimingMiddleware/PacedIo，P2-4） |
| salamander / obfs 传输 | ✅ hy2 obfs | ✅ | — | ❌（SS SIP003 插件桥可外挂 obfs-local） |

### 2.10 观测 / 控制面 / 平台

| 能力 | 三者 | rillane |
|---|---|---|
| Prometheus 指标 | sing-box 无原生/mihomo 有 /metrics | ✅ 面更细（mesh link RTT 分位/丢包/SLO/pool/tls/udp 族） |
| 连接级实时列表 | ✅ /connections | ⚠️ /flows 为累计流量，无活动连接表/实时速率/单连接切断 |
| 配置热重载 | ✅ | ✅ hot_reload+订阅热更（todo 已登记热交换非原子 P2） |
| 多平台打包 | ✅ | ✅ systemd/launchd/Windows Service/OpenWrt ipk + Docker；移动端 FFI（Android/iOS/OHOS cdylib）**独有深度** |
| WASM 插件 | — | ✅ wasmtime FlowMiddleware（rate-limit/content-filter 示例）**独有** |

---

## 3. rillane 相对领先项（不补齐也不影响「内核完整度」判断）

1. mesh 多跳（mTLS、链路 RTT 分位/丢包观测、切换账本、SLO 打分选路、UDP 多跳+防重放）。
2. 场景 profile（proxy/game/web 预设展开）+ 7 种组策略 + SLO 门。
3. WASM 插件中间件、时序/整形混淆横切层。
4. 移动端/多平台 FFI 骨架（Android/iOS/OHOS）+ `rillanectl` 一体化诊断（diagnose/udp-probe/dry-run）。
5. 出站连接池 + 进程级 TLS 会话恢复 + relay 缓冲参数化（性能面有基准佐证）。

---

## 4. 差距清单与优先级建议

> 优先级判据：A=影响日常可用性/生态兼容（订阅节点跑不起来、规则表达不了）；B=场景能力（游戏/全接管）；C=锦上添花。结合 rillane 定位（通用代理/游戏加速/网页加速三场景）排序。

### P0（建议最先补——直接决定「能当日常代理用」）

1. **路由规则补齐：目的 IP-CIDR 匹配器**。现 `MatchCondition::Network` 绑定 `client.cidr` 源注解（rillane-routing/src/lib.rs:706-710），目标网段分流表达不了——这是三大项目最基本的匹配器。实现成本低（解析 cidr + 对 `ctx.target` 地址判断；TUN 面有真实 dst IP，代理面需配合 DNS 命中缓存或 sniff）。
2. **GeoIP/GeoSite 数据库接入**（v2fly .dat 或 mmdb + 惰性加载），替换「注解等价物」；配套 `domain:full/regex/通配符` 匹配器与 OR/NOT 逻辑规则。
3. **协议嗅探层（sniff）**：TLS SNI / HTTP Host / QUIC SNI 提取 → 覆写路由域名。TUN 场景下没有它，IP 直连流量（大量 HTTPS）全部无法按域名分流，是 TUN 可用性的实际瓶颈。
4. **UDP over vmess/vless/trojan**：订阅生态的绝大多数节点走这三条通道，UDP 面缺失使游戏加速场景在非 direct/ss/wg 出口下退化。三者协议面均支持，实现为各协议已有数据面的 UDP 变体。
5. **`reject`/`block` 目标**：极小成本，广告拦截/断连规则的基本表达。

### P1（次优先——场景与生态）

6. **REALITY + XTLS-Vision**：目前主流机场节点形态（订阅含 reality-opts/flow 节点现为构建期报错）。VLESS flow 构建期校验已就位，可按「先 reality 后 vision」拆步。xray 向量级 VMess 互操作经验可直接复用。
7. **hysteria2 UDP 面**（quinn 自研载具，替换受限的 hysteria2 crate API）+ salamander/端口跳跃。游戏加速定位下 QUIC 通道无 UDP 是硬伤（现归 V2，建议提前）。
8. **DNS 加密上游 DoH/DoT**：现仅裸 UDP 53，防污染 cross_check 在深水区（443 加密上游）才有实战可靠性。
9. **rule-set / 远程规则提供者**（本地+URL+热更，格式可从 sing-box srs 或文本双选），配套订阅级 health-check 常驻测速（url-test 语义）。
10. **fake-ip + DNS 回填路由**（配合 P0-3 嗅探）：TUN 全接管的前提件。

### P2（补面——协议广度与管理面）

11. 透明代理 **redir/tproxy 入站**（Linux，覆盖存量软路由用户；TUN 之外的第三种接管方式）。
12. 服务端入站协议（trojan/vless/vmess/ss server 至少一种）——若 rillane 坚持纯客户端内核定位，可显式决策「不做」并在文档登记（三大项目均为双面，属定位分歧而非纯差距）。
13. **tuic / anytls / shadowtls** 出站（订阅兼容广度）。
14. **Clash API 兼容层**（/proxies /connections /traffic 只读子集 + 面板直连）：借力现成面板生态，成本集中在连接跟踪表。
15. httpupgrade / xhttp 传输；mux 多路复用（V2 已登记，可降半档）。
16. 真正的 uTLS/BoringSSL 指纹（替换 rustls 形状预设）+ ECH。

### P3（平台收尾）

17. macOS(utun)/Windows(wintun) TUN 真实现 + auto_route 全局接管（ip rule，V2 已登记）。
18. ICMP 代理、UoT、hosts 映射、DNS singleflight（后者已作为审核发现 P2 登记，随 DNS 面一起修）。

### 明确不建议补（有意的范围裁决，维持现状）

- hysteria v1（no plans）、splice/recvmmsg 批量 IO（范围外）、OCSP 直查/端到端 MAC（V2）、动态库插件加载（V2）。

---

## 5. 附：核对方法与边界

- rillane 现状取自代码与 docs/PROTOCOLS.md 状态总表（该表 2026-09 起逐项对照代码回填，可信度高）；未运行端到端连通性验证。
- 三大项目功能面取自其官方文档（sing-box outbound/changelog、mihomo wiki 与 release notes、xray-core 文档）与代码仓，取其稳定/当前版本口径；个别 nightly 独有项（如 sing-box 1.14 USB/IP）未计入差距。
- 本文件与 todo.md 新章节同步产出；工作树中他人未提交改动（socks5.rs / Cargo.lock / todo.md 既有条目）未被触碰。
