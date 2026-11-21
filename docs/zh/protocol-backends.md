# 协议目录与选库证据记录（RIL-104）

本页是出口协议的编目事实源：每个协议要么「已评审准入」（带选库结论与
证据），要么「明确未准入」（装配期拒绝）。机器口径在
`crates/rillane-config/src/protocol_catalog.rs`（`CATALOG`）；本页小节
（`## <kind>`）是其证据锚点，由该模块的契约测试逐字段校验。用户面承诺
边界见 [PROTOCOLS](PROTOCOLS.md)；UDP 能力口径见构建期扫描
（`scan_udp_capability`，runtime）。

## 注册规范（Factory 注册阶梯）

一个出口协议从「有想法」到「进热路径」必须整梯走完，缺级即拒绝：

1. **选库评估记录**：在本页对应小节记录候选库版本、许可、平台、公开
   API、旁路/取消/统计与复用结论。「无可选库」的结论本身也要留证——
   无实现证据是自写前置，不是自写许可。
2. **目录条目**：`protocol_catalog.rs` 增加条目（状态、UDP 能力列、
   `Backend` 结论）；目录条目数 = IR 出口变体数，契约测试强制同步。
3. **IR 变体**：`EgressConfig` 增加变体（封闭枚举——未编目类型无法进
   入配置面）。
4. **连接器接线**：`rillane-protocols`/runtime 装配工厂，注册进构建
   match；未准入类型在装配期以稳定原因码拒绝——
   `config.egress.not_admitted`（已编目未准入）/
   `config.egress.unknown`（目录外类型）。
5. **验收**：真实对端验证、不支持组合明确拒绝、订阅字段双向转换样本
   （各协议接入项的统一验收，见根目录 `todo.md` RIL-105..134）。

**feature 裁剪**（RIL-040 档位延伸）：协议后端如需按档位裁剪（如
`proto-<name>` feature），未编入的构建在配置校验期以稳定原因码
`config.combo.unsupported` 点名拒绝——不进热路径，不做隐藏降级。当前
全部后端为主体档位默认编入；平台例外（如 WireGuard 的 android/
armv7-ohos 桩）在对应小节如实记录。

## 评估记录模板

每个已准入小节必含以下字段（契约测试逐项校验，缺字段即测试失败）：

- **结论**：选库 / 自写（自写必须以「无可选库」留证为前提）
- **版本**：版本要求（Cargo.toml）+ lock 实测版本
- **许可**：SPDX 表达式
- **平台**：支持面与例外（桩不静默）
- **公开 API**：使用的库/模块公开面
- **旁路**：能否旁路库内部 IO（自带拨号/加密不接受外部流时，池与拨号
  策略无法组合——如实记录）
- **取消**：建立期取消/截止是否可达库内（库不可中断要写明）
- **统计**：可观测点（失败以什么形态透出；无观测点如实记 unknown）
- **复用**：连接复用/预热/多路复用组合结论

## reject

- **结论**：自写（一行拒绝面——不需要也不存在第三方库选项）
- **版本**：仓库内实现（无第三方依赖）
- **许可**：本仓库许可（自写）
- **平台**：全平台（纯逻辑，无网络 IO）
- **公开 API**：`rillane_core::udp::RejectUdpConnector`、runtime
  `RejectFlowOutput`（crates/rillane-core/src/udp）
- **旁路**：不适用（命中即断流，无传输可旁路）
- **取消**：不适用（不建立任何连接，无建立期）
- **统计**：命中以 forward 层错误口径上报，不做网络观测
- **复用**：不适用
- UDP 面注册为静默丢弃连接器——广告/黑名单可拦 UDP 流而不阻塞整机构
  建（G0-5 同口径）。

## direct

- **结论**：自写（直连面无可选库）
- **版本**：仓库内实现（无第三方依赖）
- **许可**：本仓库许可（自写）
- **平台**：六平台（tokio TcpStream/UdpSocket 基础面）
- **公开 API**：`DirectConnector`（crates/rillane-protocols/src/outbound/direct.rs）、
  `rillane_core::udp::DirectUdpConnector`
- **旁路**：系统旁路由 rillane-platform 拨号策略承担（接口绑定/fwmark）；
  连接器自身不改系统路由——TCP socket 的 fwmark 不代表所有 UDP 拨号
  已防环（PROTOCOLS.md 同口径）
- **取消**：遵守建立期检查（OpenContext 取消/截止）
- **统计**：建立/失败经 EgressConnector 统一面，可观测
- **复用**：支持 pre_dial_direct 预热池（`DirectConnector::with_pool`，
  §2.5/D-6——投机预拨默认关）
- UDP 面：direct 直连数据报。

## socks5

- **结论**：选库 `tokio-socks`（TCP 面）；UDP 面自写——0.5.2 源码仅
  error/io/lib/tcp，无 udp 模块，无可选库（结论留证后自写，RIL-132）
- **版本**：要求 `0.5`，lock 实测 0.5.2
- **许可**：MIT
- **平台**：全平台（tokio 兼容面，纯 Rust；UDP 面同栈）
- **公开 API**：`tokio_socks::TcpStream`（CONNECT + 用户名/密码认证）；
  包装为 `Socks5Connector`；UDP 面自写 `Socks5UdpConnector`/`Socks5UdpRelay`
  （RFC 1928 §6 ASSOCIATE + §7 数据报帧头，同文件 outbound/socks5.rs）
- **旁路**：TCP 面库自带拨号——不能旁路其内部 socket 建立；传输池/拨号
  策略与库内建连不可组合（如实记录）；UDP 面自写——控制流与数据报
  socket 全在本仓，可组合
- **取消**：库 `connect` 无取消参数——取消面在超时与任务丢弃层，库内
  建连不可中断（如实记录）；UDP 面控制流随 relay 生命周期持有，drop
  即关闭 ASSOCIATE（RFC 1928 §7：控制流关闭即中继失效，对端可观测 EOF）
- **统计**：库无观测点——失败以 io::Error 形态透出（observed 口径）；
  UDP 面带来源校验/分片丢弃计数（foreign_dropped/frag_dropped）与丢弃日志
- **复用**：无连接池组合——每次 CONNECT 独立建连，不支持预热；UDP 面经
  `from_connector` 复用 TCP 连接器同节点配置（地址/凭据一致）
- UDP：出站 UDP ASSOCIATE 自写面已交付（目录 udp=true）——tokio-socks
  0.5.2 无 UDP 模块，无可选库结论留证后自写；来源验证（只接受中继端点
  数据报）、FRAG≠0 丢弃、控制流生命周期绑定均有真实对端契约测试。

## http

- **结论**：自写（CONNECT 隧道逻辑量小、传输组合需求高——库绑定反而受限）
- **版本**：仓库内实现；头解析用 httparse（公共件，非协议库）
- **许可**：本仓库许可（自写）；httparse MIT/Apache-2.0
- **平台**：全平台
- **公开 API**：`HttpConnector`（crates/rillane-protocols/src/outbound/http.rs；
  CONNECT 隧道、Basic 认证、可叠 TLS）
- **旁路**：自写面——TLS/传输组合经 TlsConnectorFactory，可组合
- **取消**：建立期检查
- **统计**：连接错误经统一面
- **复用**：无预热组合
- UDP：无（目录 udp=false）。

## shadowsocks

- **结论**：选库 `shadowsocks`（shadowsocks-rust 内核）
- **版本**：要求 `1.25`（default-features=false + aead-cipher + aead-cipher-2022），lock
  实测 1.25.0（shadowsocks-crypto 0.8.0）
- **许可**：MIT
- **平台**：全平台（纯 Rust，aead-cipher 特性集）
- **公开 API**：`ShadowsocksConnector::new` + shadowsocks crate 客户端层
  （ServerConfig 加密解析、TCP/UDP 数据面；
  crates/rillane-protocols/src/outbound/shadowsocks.rs）
- **旁路**：复用库的加密状态机但不让库自拨号——连接器在自有流上做协议
  包装，可与传输池组合
- **取消**：建立期检查；数据面随流取消（无独立阻塞段）
- **统计**：加密方法解析失败构建期点名；SIP003 插件模式为进程桥接——
  插件自身 IO 不在本仓观测点内（如实记录）
- **复用**：UDP 面复用 TCP 面同一份 server_config（`from_connector`）；
  插件（SIP003）模式 UDP 判负（SIP003 仅定义 TCP 数据面）
- **算法矩阵（RIL-131）**：承载算法随依赖编译面——v1 AEAD `aes-128-gcm` /
  `aes-256-gcm` / `chacha20-ietf-poly1305`；SS2022 `2022-blake3-aes-128-gcm` /
  `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`（特性
  `aead-cipher-2022`）。构建期点名拒绝：`none`（无加密不进数据面）、stream
  时代方法名如 `rc4-md5`（特性未编译）。SS2022 的 password 语义是 base64
  密钥，长度须与算法密钥长精确一致（aes-128 为 16 字节，aes-256/chacha20
  为 32 字节），构建期校验。六算法全部对真实 crate 服务端对端验收通过
  （TCP 往返+统计、UDP 往返+协议头解码地址、错密码静默、取消/资源释放），
  见 `crates/rillane-protocols/tests/shadowsocks_matrix_contract.rs`。
- **服务端面（RIL-134）**：复用同库 server 面——`ProxyListener`（TCP accept +
  handshake 解出目标 `Address`，解密流即 Flow io）与 `ProxySocket`
  （`UdpSocketType::Server` 数据报解包/封包）。自写无增益：密码学状态机
  正确性归库（客户端/服务端同一加密核，RIL-131 六算法已在该 server 面真
  实对端验收双向）。入库角色：`ShadowsocksIngress`（TCP 面全量 + UDP 面
  随 `udp.enabled`/`udp_enabled` 门），SIP003 插件服务端面未交付（点名）；
  method/password 校验与 egress 同口径（none/未编译面点名拒绝、SS2022
  base64 密钥形状）；UDP 会话生命周期归 `UdpSessionTable`（与 socks5
  ASSOCIATE 同机制：粘滞路由、空闲回收、链路失败吊销）。

## shadowsocks-shadow-tls

- **结论**：自写载具（RIL-110）——无可用后端。评估扫描（2026-11-17，crates.io API + GitHub 源码核对）：官方 `shadow-tls` crate（ihciah/shadow-tls，registry 最高 0.2.20，MIT，最后发布 2023-04-18——三年半未更新）是唯一 registry 发布的 ShadowTLS 工件，且不可嵌入本仓：(1) lib 根带 `#![feature(impl_trait_in_assoc_type)]`——仅 nightly 可编译，本仓门禁跑在 stable 工具链上；(2) 底座是 monoio（thread-per-core io_uring）而非 tokio——本仓数据面端到端 tokio，且其公开 API 是监听转发二进制面（`ShadowTlsClient::new(listen_addr, target_addr, …)` + `serve()`），没有可包成 EgressConnector/IngressEndpoint 的流级 connect/accept API；(3) v3 另需 rustls 0.20 fork（`rustls-fork-shadow-tls 0.20.9-mod.2`）签 session_id——为载具引入第二套陈旧 TLS 栈与共享 rustls 0.23.46 面并存，代价失当。registry 检索其余命中的只是同一项目的 rustls/monoio fork——无其他 ShadowTLS 协议库。结论=自写，以官方协议文档与源码为线格式基准（ihciah/shadow-tls tag `v0.2.20` 浅读 2026-11-17：`docs/protocol-en.md`（v2 规格）+ `src/helper_v2.rs` + `src/server.rs` `relay_v2`/`copy_until_handshake_finished` + `src/client.rs` `relay_v2`/`connect_v2` + `src/util.rs` 封帧常量）。
- **版本**：仓内实现（无第三方协议依赖）；ShadowTLS **仅 v2**。v1 点名拒绝——官方最后实现停在 v0.1.4，其握手后流量为无帧裸内层数据、无主动探测防御（官方设计文档以 v2 为其替代）。v3 点名拒绝——抗劫持机制不交付：4 字节 session_id HMAC、ServerRandom 提取 + 对每个握手服务器帧的 XOR SHA256(PreSharedKey+ServerRandom) 变换、双向 4 字节流 HMAC、muddled-request 回退、strict 模式仅 TLS1.3 握手中继。载具 rustls fork 0.23.46 / tokio 全仓已钉；客户端 v2 无需 TLS 库 fork（挑战经后握手写侧流包装注入，不改 rustls）。
- **许可**：仓库许可（自写）
- **平台**：随目标平台 TCP 支持（纯 TCP 载具——无 QUIC/io_uring 面）
- **公开 API**：`ShadowsocksShadowTlsConnector`（crates/rillane-protocols/src/outbound/shadowtls.rs——SS TCP 面承载于 v2 载具，经 `ProxyClientStream::from_stream`（shadowsocks crate 流注入构造器）组合）+ `ShadowTlsIngress`（crates/rillane-protocols/src/inbound/shadowtls.rs——向所配握手站点中继握手、按 v2 挑战应答切换、切换后流交给所配内层数据服务器）。无任何 UDP 面：ShadowTLS 不承载 UDP（mihomo 仅在 SS TCP 面建模 shadow-tls 插件），SS 节点经 shadow-tls 承载不配 UDP 连接器。
- **旁路**：载具自有 TCP 连接（普通拨号）——无底层 socket 旁路。载具本身无寻址面；目标寻址归内层协议——这就是组合边界（Shadowsocks 在内，其路由/fake-ip 语义不变）。
- **取消**：开局段检查（拨号 + TLS 握手 deadline）；切换后中继为两个双向 copy 半程——任一端丢弃即收束连接（对端可观测释放）
- **统计**：经统一 EgressConnector 面的中继字节计数（FlowReport）；切换结局具名（switched / 无辜中继 / 畸形记录）——协议无逐包观测点
- **复用**：每条内层 SS 流一条载具连接（官方 v2 无多路复用）；无预热组合
- **交付边界（线格式忠实 v2，点名拒绝）**：挑战 = HMAC-SHA1 以 password 为键、对握手站点发往客户端的每个字节计算、截断 8 字节、握手完成后前置进首条伪 application-data 记录（0x17，版本字节 0x03 0x03）；服务端保留最近 10 个哈希窗口（容忍在途竞态），3 条不匹配 app-data 记录或任一畸形记录形（首记录须 0x16、记录主版本 0x03、次版本 ∈ {0x01, 0x03}）后永久回退无辜中继；切换后数据双向伪记录封帧，记录以官方 4096 字节 copy 缓冲定尺寸（内容 ≤4091 字节；首条客户端记录在内层数据前携 8 字节挑战）。通配 SNI / 多 SNI 分流不交付（单一所配握手站点）；v3 strict 模式不交付；无辜访客须到达真实握手站点（这是主动探测防御——验收覆盖）。

## vmess

- **结论**：自写（本仓现状；如出现维护良好且许可兼容的第三方库，按
  注册规范重走评估阶梯）
- **版本**：仓库内实现（无第三方协议库）
- **许可**：本仓库许可（自写）
- **平台**：全平台
- **公开 API**：`VmessConnector`（crates/rillane-protocols/src/outbound/vmess.rs；
  限 AEAD、alter_id=0——legacy MD5 拒绝，构建期点名）
- **旁路**：自写面与 TLS/WS/gRPC/H2 传输工厂组合
- **取消**：建立期检查
- **统计**：security/network 白名单构建期校验；握手错误经统一面
- **复用**：无预热组合；UDP 面（仅 network=tcp）复用同一节点配置
- UDP：仅 network=tcp（ws/grpc/h2 的 UDP 面未实现，构建期扫描判负）。
- **服务端面（RIL-137）**：评估扫查（2026-11-16，crates.io API 检索 `vmess` + 元数据/tarball 核验）——不存在轻量 VMess 服务端库 crate。vmess-rs 0.0.0（MIT，2026-07-17 发布）自称「lightweight VMess inbound proxy server」，但整个 crate 仅 869 字节、**零依赖**（无 AES/HMAC/crc32/tokio）且无仓库——是占位桩不是实现；下载量 26。tobira 0.4.0（2026-06-22）为 VMess relay，但 **AGPL-3.0-or-later**（与本仓 Apache-2.0 许可不兼容，与 trojan 族 GPL 判定同口径）且仅二进制（`path = "src/main.rs"`，无 lib target），拖整个应用内核（clap/toml/notify/reqwest/hyper/h2/tokio-tfo）。既有留证判定原样沿用：xray-rs 1.0.3 单包无特性门 1192 文件内核移植（RIL-136 已拒）；shoes 0.3.2 应用面模块私有；corduit 0.3.8 许可非标；jets 0.4.3 无 VMess 入站；meow-proxy 仅出站。结论=自写，与仓内经真实对端互验的客户端面（outbound/vmess.rs，仅 AEAD/alter_id=0）镜像互源：封头 `authID(16) ‖ 长度块 AEAD-GCM(18, AAD=authID) ‖ connNonce(8) ‖ 头块 AEAD-GCM(AAD=authID)`（KDF 盐序同 xray kdf.go，cmdKey = MD5(uuid ‖ 盐)）；authID 校验走 AES-128-ECB 单块解密 → `[8B unix BE][4B rand][CRC32-IEEE 4B]`，CRC 校验 + ±120 秒时间窗 + 已见 authID 防重放缓存；明文头 `[0x01][reqIV 16][reqKey 16][V][option][(pad<<4)|security][0x00][CMD][port BE][ATYP addr][padding][FNV1a32]` 带校验和；响应头 = 两段 AES-128-GCM（密钥自 `SHA256(reqKey/reqIV)[:16]` 派生，resp len/resp pay 盐），载荷首字节回声 V；数据块 `[掩码后 2B BE 长度][AEAD(明文)][明文 padding]`，SHAKE128(iv) 流（先抽 padding `%64` 再抽掩码，逐块次序固定），nonce `[2B BE 计数器 ‖ iv[2..12]]`，空块 = 半关闭；UDP CMD 0x02 = 单连接单目标 raw 面，每数据报一块双向。服务端两种 AEAD security（0x03/0x04）均接受——客户端自选，无配置旋钮；option 固定为客户端面的 `0x0D`（chunk+mask+global padding），其余点名拒绝。服务端 ws/grpc/h2 载体未交付（RIL-137 口径为 tcp 面）。入库角色：`VmessIngress`（无 TLS——VMess AEAD 头即认证面）；UDP 会话归 `UdpSessionTable`。

## vless

- **结论**：VLESS 协议面自写；REALITY 传输面选库 `rustls` 的
  cfal/rustls fork——上游 049d39b9（0.23.46）+ 5 个 REALITY 提交
  （client hooks / server hello 构造 / 隔离加固 / rebase 验证），
  以 `[patch.crates-io]` 固定 rev `d17d0fc304c03fe6e2c96ade6cd39c33b951c3af`
  全仓换用。fork 的 REALITY 面显式不认证对端（认证与证书策略留给调用
  方）——认证（x25519 + HKDF + AES-GCM session-id seal/open，格式同
  xray REALITY 规范）与证书绑定由 rillane-protocols 自写装配（RIL-107）。
  备选评估在案：xray-rs（abc15018045126）1.0.3 仅 279 行加密原语
  （derive_auth_key/seal_session_id），无 TLS 传输与 ClientHello 构造
  ——不可作传输后端（其 MIT 认证格式作参考）；shoes（cfal）0.3.x
  REALITY 完整（2940 行）但 `mod reality` 私有、无库面——不可作后端；
  xray-rust（aimalygin）0.10.0 有客户端面 + Go oracle 向量严谨，但
  MPL-2.0 许可、不在 crates.io、无服务端面、重依赖（quinn/h3/ml-dsa）
  ——备选在案不取；reality-rs（YC-Lammy）为死占位。
- **版本**：要求 `rustls = "0.23"` + `[patch.crates-io]` git pin
  `d17d0fc3`（fork 内版本保持 0.23.46）；lock 实测 rustls 0.23.46
  （fork 源）、aws-lc-rs 1.18.1
- **许可**：Apache-2.0 OR ISC OR MIT（上游 rustls 同许可，fork 未改许可）
- **平台**：全平台；REALITY 记录层填充依赖 aws-lc-rs 后端（见下
  提供者约束），需 C 工具链——本机与 CI 实测构建+测试通过
- **公开 API**：VLESS 面 `VlessConnector`
  （crates/rillane-protocols/src/outbound/vless.rs）；REALITY 面 fork 的
  `ClientHooks`（start_key_exchange/session_id/server_hello）+
  `ClientConnection::new_reality`（拒绝 TLS1.2 配置）、
  `PreparedServerHello::new`（校验目标形 ServerHello——仅 TLS1.3、
  session_id 32 字节回显相等、禁 HRR/PSK/early-data/未知扩展、套件白
  名单三件、只替换目标 key-share 字节）+ `ServerConnection::new_reality`
  （拒绝 ALPN/客户端认证/early-data/分片设置非零）
- **旁路**：无旁路——fork 拥有 ClientHello 字节级构造与记录层填充
  （REALITY 本体所在）；拨号与目标连接仍由 rillane 组合（与既有 TLS
  面同构）
- **取消**：fork 连接面是标准 tokio AsyncRead/AsyncWrite——建连取消
  在任务丢弃层（与既有 TLS 面同口径，如实记录）
- **统计**：VLESS 面同前；REALITY 握手失败以 rustls `Error` 命名错误
  透出（如 `PeerIncompatible::RealityUnsupported`——session_id 回显
  不等/短 id 不匹配即此形态），不静默降级
- **复用**：无预热组合；REALITY 连接禁 resumption/early-data/压缩
  （fork 显式禁用——每连接一次完整握手），如实记录；UDP 面（仅
  network=tcp）同节点配置
- **提供者约束**：REALITY 双面的握手指令流（finish_reality →
  send_reality_record → encrypt_with_padding）按目标真实记录长度做
  记录层填充；`encrypt_with_padding` 默认实现拒绝非零填充，仅
  aws_lc_rs 后端实现——REALITY 连接显式传入 aws_lc_rs provider，
  与全局 ring 默认 provider 共存（按配置显式传入，不影响既有 TLS 面）
- **指纹诚实声明**：fork 用 rustls 自身编码构造 ClientHello——是
  rustls 形指纹，非 uTLS 浏览器克隆；防探测强度弱于 uTLS 面；订阅
  client-fingerprint 不入 IR（转换报告点名损失，宁缺毋滥）
- **角色边界**：仅出站客户端（`Vless { reality }` 装配）；fork 的
  服务端面（PreparedServerHello/ServerConnection::new_reality）用于
  测试真实对端；rillane 入站面不编目 REALITY 监听。合法组合：
  reality 必带 public_key，short_id 可选；flow 精确接受
  `xtls-rprx-vision`（RIL-108 已交付——仅 tcp + TLS/REALITY，UDP 拒绝；
  其余 flow 取值照旧拨号期点名拒绝，防静默降级）
- UDP：仅 network=tcp（ws/grpc/h2 的 UDP 面未实现，构建期扫描判负）；
  vless+reality 的 UDP 面走 VLESS UDP 面（RIL-107 放开 gate）。
- **服务端面（RIL-136）**：评估扫查（2026-11-16，crates.io API 检索 `vless`/`xtls` + 仓库/tarball 核验）——不存在轻量 VLESS 服务端库 crate。xray-rs（abc15018045126）1.0.3（2026-10-05 发布；MIT）实为完整 1:1 Xray-core 移植——RIL-107 记录的「仅加密原语」只描述其 REALITY 传输面——且其 `proxy/vless/inbound` Handler 确有可组合形状的面（`handle_connection(BoxStream, SocketAddr) -> InboundResult{stream, session}`：请求头解码 + UUID 校验 + 响应头写出；CMD 0x02 原样交回流，长度前缀数据报中继留在调用侧）。不采纳：该 crate 为单包无特性门（无 `[features]` 段，已发布 1192 文件）——引入即拖整个内核进工作区（两套 TUN 栈 `tun`+`tun-rs`、`ipstack`、Windows `wintun`、`tokio-tungstenite`、prost/pb 机器、clap），只为换一副本仓客户端面已逐字节实现、并经真实 Xray 对端校验（RIL-107，含 ATYP=3=IPv6 纠偏）的线格式镜像。备选留证：meow-proxy 0.29.0（MIT）仅出口面（「Outbound proxy protocol implementations ... for the meow-rs kernel」）；jets 0.4.3（Apache-2.0，clash-rs 族）只有 `inbound-http`/`inbound-tun`——无 VLESS 入站；corduit 0.3.8 许可为非标准；shoes 0.3.2（MIT）为应用面且模块私有。结论=自写，与仓内已验收客户端面（outbound/vless.rs）镜像互源：请求 `[0x00][UUID 16B][OptLen][addons][CMD 0x01 TCP / 0x02 UDP][Port BE][ATYP addr]`（ATYP 1=v4 / 2=域名 / 3=v6，xray 口径），UUID 16 字节等值认证（恒时比对），中继前写响应头 `[Version][OptLen][Opt]`，UDP 单连接单目标、双向 `[2B BE len][payload]` 帧；Vision/REALITY 服务端组合另验（RIL-136 另验口径）。入库角色：`VlessIngress`；UDP 会话归 `UdpSessionTable`。

## vless-xtls-vision

- **结论**：分帧自写（RIL-108）——无可用后端。评估清扫（2026-11-16，
  crates.io API 查询 `xtls`/`vision`/`xray` + GitHub 核实）：crates.io
  无任何 crate 以可复用库面交付 XTLS Vision（xtls-rprx-vision）分帧；
  XTLS-Fork/Rust 为死占位（1 commit、0 star、仅 README）；xray-wasm
  （xrayTun）以纯 Rust 重写 VLESS+Vision+REALITY 但交付形为 wasm32-wasip2
  组件（wasmtime 下运行），非进程内原生库面；xray-rust（aimalygin）有
  Vision 但 MPL-2.0 且不在 crates.io（与 RIL-107 评估同款阻碍——记为参考
  不取）；xray-rs（abc15018045126）1.0.3 仅密码原语无分帧（RIL-107 已在
  案）；jets 为 Java 实现。分帧因此在 rillane-protocols 自写，语义以
  Xray-core 源码为准（2026-11-16 浅克隆精读：`proxy/proxy.go`
  TrafficState/VisionReader/VisionWriter/XtlsFilterTls/XtlsPadding/
  XtlsUnpadding，`proxy/vless/encoding/{encoding,addons}.go`，
  `proxy/vless/outbound/outbound.go`），符合"无可用后端结论留证后才
  允许自写"；cfal/rustls fork 不动（Vision 在 TLS 之上，无需 TLS 层
  配合——direct 直传切换只要求持有外层 TLS 之下的裸 TCP socket，
  rillane 本就持有）。
- **线规格**（源码核实）：请求 addons 以 protobuf `Addons{Flow=1}`
  携带 flow 串（`0x0A 0x10 "xtls-rprx-vision"`，OptLen=18；其余 flow
  维持 OptLen=0）。填充帧：每方向首帧前置一次 16 字节用户 UUID，随后
  `[command(1) contentLen(2 BE) paddingLen(2 BE)] + content + padding`。
  命令：Continue=0x00（后续还有帧）、End=0x01（填充结束，流量留在
  外层 TLS 之内）、Direct=0x02（双侧停帧并切到外层 TLS 之下的裸 TCP
  socket）。填充预算（testseed 缺省 `[900, 500, 900, 256]`）：content
  < 900 且长填充 → `rand(0..500) + 900 - content`，否则 `rand(0..256)`；
  上限 `2048 - 21 - content`。
- **状态机**：上行写侧在过滤窗（8 包）内边填充边嗅探应用流量的内层
  TLS 记录；ServerHello 携带 TLS1.3 supported_versions 扩展即置位
  EnableXtls；首个完整内层 ApplicationData 记录（`17 03 03`、长度
  自洽）随后发出 Direct 并切到裸 TCP 直写。内层非 TLS 或 TLS1.2 的
  流量在过滤窗后以 End 收束填充，全程留在外层 TLS 之内。下行读侧
  镜像：UUID 门控逐帧解析，Continue 继续，End 回归普通 TLS 读，
  Direct 切裸读。
- **角色边界**：仅出站客户端，flow 精确等于 `xtls-rprx-vision`
  （其余取值照旧点名拒绝）；须 network=tcp 且叠加 TLS/REALITY 面
  （外层 TLS 须 TLS1.3——握手后校验，与 xray 同口径）；vision 下
  UDP 命令拒绝；不入池（仅 inline 路径——直传切换与池借出语义不
  相容）。

## xhttp

- **结论**：自写传输面（RIL-129）——无可用后端。评估扫查（2026-11-16，
  crates.io API 查询 `xhttp`：6 项无一承载 XHTTP 传输——代理安装器、
  Web SDK、面板 API 客户端、HTTP/1.1 客户端/服务端库、两个占位；
  GitHub 核验：jacek4yang/rust-xhttp 是线格式兼容的 XHTTP **服务端
  守护进程**（`src/main.rs` 入口 + 安装器 + systemd 生命周期，无库面、
  未发布 crates.io、单作者 pre-1.0、无安全审计）——仅服务端，不能充当
  出站客户端；jets 是规则隧道二进制）。故按 Xray-core 源码真源自写
  （浅克隆读 2026-11-16：`transport/internet/splithttp/{config,dialer,
  client}.go`——请求/URL 塑形、模式判定、POST 语义对照 dialer 与 client
  实现逐项核验）。
- **版本**：仓内实现；载具 h2 0.4.19 + rustls fork 0.23.46 全仓已 pin
  （无新依赖）
- **许可**：仓库许可（自写）
- **平台**：随既有 TLS+H2 面（全平台）
- **公开 API**：`xhttp_tunnel`（crates/rillane-protocols/src/outbound/
  xhttp.rs）——TLS+H2 io 入、AsyncRead+AsyncWrite 双工出；以
  `network: "xhttp"` 接入 VLESS
- **旁路**：连接器自持 TLS+H2 会话（与 h2 传输同形）；请求目标携带节点
  path/host，无底层 socket 旁路
- **取消**：开工期校验；下行 EOF / 上行 POST 失败毒化隧道（具名错误），
  中继在统一面收束；传输租约在中继结束时归还弃置（h2 连接归隧道驱动
  任务所有——与 h2 同一「不入池」边界）
- **统计**：字节量经统一 FlowReport；POST 失败按状态行具名；session/seq
  面貌由镜像对端在验收中逐项断言
- **复用**：stream-one 整条中继单 H2 请求；packet-up 单 H2 连接同时承载
  GET 下载流与全部 POST 上行（无预热组合）
- **模式与参数**（对照 dialer.go/client.go 核验）：承载 `auto`/
  `packet-up`/`stream-one`；TLS+H2 且无 REALITY、无 download settings 时
  auto 判为 packet-up（xray 自身判定）。已交付线形状——下载
  `GET {path}{session}` → 200，响应体流即下行；packet-up 上行
  `POST {path}{session}/{seq}`（seq 自 0，body=分块，Content-Length 置位，
  每个 POST 期望 200；非 200 按状态具名毒化隧道）；stream-one 单条
  `POST {path}`（无 session 段）+ `Content-Type: application/grpc`，
  上行体开放（关闭即 EOS），响应体即下行。session id 为不透明随机串
  （path 放置，xray 缺省放置）。不承载——点名拒绝：`stream-up`（须
  download settings 第二连接）、HTTP/3 与 HTTP/1.1 载具（TLS 拨号强制
  ALPN h2）、xmux、browser dialer、填充 obfs（XPaddingObfsMode；零填充
  服务端合法，客户端不发送）、session/seq 的 cookie/header 放置（仅
  path 放置——xray 缺省）。
- **角色边界**：仅 VLESS 载体（vmess+xhttp 由 vmess network 白名单构建期
  拒绝；reality/vision + xhttp 由既有 tcp-only 门拒绝）；恒叠 TLS
  （h2-over-TLS 语义，与 grpc/h2 同规则）。订阅面：vless 节点
  `network: xhttp` + `xhttp-opts: {mode, path, host}`，双向转换逐字段。

## trojan

- **结论**：自写（协议面小、传输组合需求高）
- **版本**：仓库内实现
- **许可**：本仓库许可（自写）
- **平台**：全平台
- **公开 API**：`TrojanConnector`（crates/rillane-protocols/src/outbound/trojan.rs；
  恒叠 TLS，TCP/WS/gRPC/H2 组合）
- **旁路**：TLS 经 TlsConnectorFactory（rustls）
- **取消**：建立期检查
- **统计**：tls=false 构建期点名拒绝；握手错误经统一面
- **复用**：无预热组合；UDP 面（TLS + network=tcp）同节点配置
- UDP：仅 TLS + network=tcp。
- **服务端面（RIL-135）**：无可选可接线后端——crates.io 全部 Trojan 协议 crate 均 GPL-3.0-only（`trojan`/`trojan-rs` 0.6/0.18 全家族含 `trojan-server`/`trojan-proto`/`trojan-auth`、`nsproxy-trojan-proto` 0.4），与本仓 Apache-2.0 不兼容；且 `trojan-server` 面为整装 `run(config)` 监听循环，不可组合进 `IngressEndpoint`。「无可用库」结论留证于此，作为自写前置：TLS 走 tokio-rustls（测试 rcgen 自签夹具），口令 = SHA224 hex 恒时比对（core `constant_time_eq`），TCP 请求帧 `[56-hex][CRLF][CMD][ATYP addr port][CRLF]`（CMD 0x01 CONNECT / 0x03 UDP ASSOCIATE——无应答，镜像参考实现直进 UDP_FORWARD 循环的口径；UDP 数据报走同一条 TLS 流，帧形 `[ATYP addr port][len][CRLF][payload]`），帧原语与仓内客户端面（outbound/trojan.rs）镜像互源。入库角色：`TrojanIngress`；UDP 会话归 `UdpSessionTable`（与 socks5 ASSOCIATE 同机制）。

## anytls

- **结论**：选库 `anytls`（ssrlive/anytls-rs）——客户端/服务端双面库；
  备选 anytls-rs（jxo-me，同名不同仓）评估在案：0.5.4 后自 2025-11 未再
  发版，维护弱于前者——取活跃维护者。角色边界：出口客户端本项装配（RIL-106）；
  服务端面库内可用（Session::new_server + run + accept_stream + read_auth），
  rillane 入站面未编目 AnyTLS 监听——真实对端验收即以库自带服务端面承载
- **版本**：要求 `0.5`，lock 实测 0.5.4（2026-11-11 发版；2026-04 首版
  以来 36 个版本，活跃维护）
- **许可**：MIT
- **平台**：全平台（纯 Rust，tokio/rustls 栈，edition 2024）
- **公开 API**：`Client::new(dialer, padding, idle_timeout, max_session_age)`
  + `create_stream()`（内建 idle 会话池）；`StreamIo`（AsyncRead/AsyncWrite
  适配）；`write_auth_with_client_id`（会话认证）；UoT 面
  `uot_sentinel_destination`/`UotRequest`/`uot_encode_packet`/
  `uot_get_packet_from_stream`；包装为 `AnytlsConnector`/`AnytlsUdpConnector`
  （crates/rillane-protocols/src/outbound/anytls.rs）；测试对端用服务端面
  `Session::new_server`/`run`/`accept_stream` + `read_auth_with_client_id`
- **旁路**：库不拥有拨号与 TLS——`Dialer` 闭包由调用方供给，本仓经
  TlsConnectorFactory 组合（skip_cert_verify/sni 可控）；会话帧/多路复用/
  填充在库内（不旁路，如实记录）
- **取消**：`Client::shutdown`；库导出 tokio-util CancellationToken；流
  drop → FIN 关闭；会话认证读写无超时参数——建连取消在任务丢弃层
  （如实记录）
- **统计**：库面无统计观测点（traffic_status 是库自带 CLI 应用面，不入
  库 API）——失败以 io::Error 形态透出（observed 口径）；流量统计沿用
  FlowReport 上/下行字节（copy_bidirectional 口径）
- **复用**：会话复用是协议本体——Client 内建 idle 会话池（idle_timeout/
  max_session_age 参数化），`create_stream` 优先复用空闲会话开新流，
  无需外接连接池
- UDP：库 uot 特性（UDP-over-TCP，按库实际能力交付）——上行
  `uot_encode_packet(UotMode::Datagram, dest, payload)`、下行
  `uot_get_packet_from_stream`，会话流首写 sentinel destination +
  UotRequest 声明数据报模式；目录 udp=true。订阅侧 alpn/
  client-fingerprint 不入 IR（转换报告点名损失，宁缺毋滥）。

## hysteria

- **结论**：自写（RIL-109）——无可用后端。评估扫查（2026-11-17，crates.io
  API + GitHub 源核验）：crates.io 不存在名为 `hysteria` 的 crate（404），
  注册表 "hysteria" 查询只出 Hysteria **2** 产物（仓内在用 `hysteria2`
  0.1.6 v2 客户端、`rsteria2` 0.1.1 v2 客户端与无关工具）——无任何 v1。
  GitHub 扫查同样全为 v2：协议相关命中皆是 Hysteria2 客户端/服务端重写
  （`xray-rust` MPL-2.0 且不在 crates.io——按 VLESS 评估口径以许可证 +
  供应链判负；`rusteria` v2 服务端、无 license 字段；`crapthings/hysteria-rust`
  v2 已在 RIL-138 判负；`differs/RUST-HYSTERIA`、`Ashrafty/miro`——0-1 star、
  无 license 字段、无发布已死、不在 crates.io）。维护中的上游
  （apernet/hysteria）为 Go、MIT——无任何可从 Rust 链接之物。结论=自写，
  以官方 v1 源码为线格式地面真值（apernet/hysteria tag `v1.3.5` 浅读
  2026-11-17：`core/cs/protocol.go` + `core/cs/client.go`/`server.go` +
  `core/pktconns/obfs/obfs.go` + `app/cmd/client.go`）。
- **版本**：仓内实现（零第三方协议依赖）；线版本字节 `0x03`（v1.3.5
  `protocolVersion`，控制流首字节）；载具 quinn 0.11.9 / rustls fork
  0.23.46 已由 RIL-133/RIL-107 全工作区钉版
- **许可**：仓库许可（自写）
- **平台**：以目标平台 QUIC（quinn 生态）支持为准——与 hysteria2 同面
- **公开 API**：`HysteriaConnector`/`HysteriaUdpConnector` +
  `HysteriaIngress`（路径 crates/rillane-protocols/src/outbound/hysteria.rs +
  inbound/hysteria.rs，已交付）——认证握手走控制流（版本字节 + 官方 `struc` 形状的
  大端结构（该库默认大端打包，v1 线结构不带端序标签）：clientHello{Rate SendBPS/RecvBPS u64, AuthLen u16, Auth} →
  serverHello{OK, Rate, Message}；`OK=false` → QUIC 应用错误码 2 auth
  error）；TCP = 逐流 clientRequest{UDP=false, HostLen u16, Host, Port u16}
  → serverResponse{OK, UDPSessionID u32, Message}；UDP =
  `udpMessage{SessionID u32, HostLen u16, Host, Port u16, MsgID u16,
  FragID u8, FragCount u8, DataLen u16, Data}` 走 QUIC 不可靠数据报，
  按 MsgID 重装配（v1 `defragger` 语义）；QUIC 应用错误码 0 generic /
  1 protocol / 2 auth
- **旁路**：连接器自持 QUIC 会话（quinn）——不做底 socket 旁路；UDP
  数据报按包在协议头携带真源地址（与 hysteria2 同面）
- **取消**：开启前检查 + 显式拨号超时（15s，single-flight 持锁与
  hysteria2 同口径）；v1 协议无具名会话收束——TCP 收搬运流、UDP 收
  QUIC 连接即释放面
- **统计**：官方 v1 无逐包观测点——仅会话计数（外来会话丢弃/分片丢弃），
  与 hysteria2 同口径
- **复用**：单条 QUIC 连接承载控制流 + 全部 TCP 请求流 + 全部 UDP 数据报
  （single-flight 建连 + 复用、出错失效重连——与 hysteria2/TUIC 同形）；
  无预热组合
- **交付边界（构建/拨号期点名拒绝）**：传输面 = 原生 UDP 上的 QUIC——
  v1 的可插拔包传输（`obfs` XPlus sha256(key‖salt) XOR 载荷、`wechat`、
  `faketcp`）不交付（换整个 QUIC 载荷——与 hysteria2 salamander 同判负
  族）；Brutal 拥塞控制不交付（用 QUIC 缺省 CC；hello Rate 字段如实
  携带，不伪装带宽协商）；端口跳跃接受不消费（与 hysteria2 mport 同）；
  ACL 路由、ACME、流量统计 API 不交付。ALPN 在 v1 是配置旋钮（客户端
  `NextProtos: []string{config.ALPN}`，TLS 最低 1.3，`app/cmd/client.go`）
  ——仓内面钉缺省 `hysteria` 且要求 TLS 1.3。

## hysteria2

- **结论**：选库 `hysteria2`（TCP 面）+ 官方 UDPMessage 数据报面自写
  （RIL-133——crate 无数据报公开 API，评估留证见 UDP 行）
- **版本**：要求 `0.1.6`，lock 实测 0.1.6
- **许可**：MulanPSL-2.0
- **平台**：以目标平台 QUIC（quinn 生态）支持为准
- **公开 API**：`Hysteria2Connector`/`Hysteria2UdpConnector`
  （crates/rillane-protocols/src/outbound/hysteria2.rs；TCP stream over QUIC
  + 官方 UDPMessage 数据报面）
- **旁路**：库承载 QUIC 会话——连接器不做底层 socket 旁路；UDP 面协议头
  逐包携带真实源地址（平台旁路语义由 UDPMessage 头承载，验收面逐字段断言）
- **取消**：建立期检查 + 库会话关闭面；UDP 面 relay drop 即 QUIC 连接
  close（对端可观收束，验收面计数）
- **统计**：库无逐包观测点——loss 类统计不可用（不伪装游戏丢包率，
  mesh.md 观测口径同源）；UDP 面会话统计（外来会话丢弃/分片丢弃计数）
- **复用**：无预热组合
- UDP（RIL-133）：数据报面已交付。前置评估：hysteria2 crate 0.1.6 无
  数据报公开 API（网络帧格式模块全部私有，仅 connect/DuplexStream TCP
  面）——「无可选数据报 API」留证后按官方 PROTOCOL.md 自写：UDPMessage
  over QUIC 不可靠数据报（session/packet/frag 定界头 + varint 地址），
  认证复用官方 HTTP/3 /auth 面（状态码 233 + Hysteria-UDP 声明，未声明
  即点名拒绝）；分片/重装配与外来会话过滤，丢弃/中继计数可观测；载具
  quinn/h3/h3-quinn 与 crate 同源单版本入锁。obfs（salamander）换整个
  QUIC 载荷，UDP 面判负；mport 为 TCP 面重连策略不适用。验收：镜像对端
  契约测试（成功往返/双向分片/认证拒绝/无 UDP 拒绝/取消释放/统计/协议头
  源地址）。
- **服务端面（RIL-138）**：评估扫查（2026-11-17，crates.io API + GitHub 源核验）——不存在注册表发布的 Hysteria2 服务端库。hysteria2 0.1.6（仓内 TCP 客户端面在用）按其自述即纯客户端库，且 RIL-133 已证其网络帧模块全部私有；rsteria2 0.1.1（2026-06-10，592 下载）同为客户端（"A clean async Rust client for the Hysteria2 proxy protocol"），crates.io 元数据无 license 字段（仓库 MIT）。crapthings/hysteria-rust v0.1.0-rc.7（MIT，活跃——2026-11-14 推送）是唯一真候选：`hysteria-transport` 确有可组合服务端面（`HysteriaServer` bind/from_endpoint、`ServerHandshake`、`AuthenticatedConnection` accept_bi/quinn()），CI 跑真实 Go 客户端/Rust 服务端互操作（对上游 v2.13.0）。四项判负：(1) 全工作区 `publish = false`——crates.io 无此 crate，采纳即 git-only 依赖、无注册表审计面（本仓唯一在先 git 依赖是 cfal/rustls fork，其来源为上游 + 5 个有记录的 REALITY 提交）；(2) 传递拖带 `hysteria-realm`（STUN/打洞/UPnP/NAT-PMP 栈）与 `hysteria-obfs` 入 protocols 包只为一个服务端面；(3) 成熟度——rc 级、首次发布不足半年、4 star，却要承载带认证的入口面；(4) 工具链耦合——edition 2024 / rust-version 1.91 把本仓门禁绑上外部仓库的 MSRV 政策。载具卫生已核验、**不是**判负项：本仓 `[patch.crates-io]` 的 rustls 钉把他们的 crates.io rustls 0.23.46 重定向到 fork，quinn（0.11.9→0.11.12 搬升）、h3 0.0.8、h3-quinn 0.0.10 语义版本可统一——判负依据是供应链、拖带与成熟度。结论=自写，与仓内已互验的客户端线格式（outbound/hysteria2.rs，RIL-133）镜像互源：服务端 = quinn Endpoint 接受环 + HTTP/3 /auth 处理（校验 base64 userpass → 状态码 233 + Hysteria-UDP 声明头回写；未启用 UDP 即不带声明——客户端面点名拒绝语义的服务端镜像）；TCP = accept_bi → TCPRequest（varint 地址）→ 拨目标 → 双向搬运（响应/错误面同源镜像）；UDP = UDPMessage over QUIC 不可靠数据报（session/packet/frag 定界头 + varint 地址）→ 会话表 → 回程 UDPMessage。obfs（salamander）服务端面不交付（换整个 QUIC 载荷，与 RIL-133 客户端判负同口径）；masquerade/ACME/Brutal 带宽协商/流量统计 API 不交付（认证后裸拨号面为交付口径）。入库角色：`Hysteria2Ingress`；UDP 会话归 `UdpSessionTable`。

## tuic

- **结论**：自写（RIL-105）——无可用后端。评估扫描（2026-11-16，
  crates.io API + GitHub 源码核验）：EAimTY `tuic` 家族（`tuic`、
  `tuic-quinn`、`tuic-client`、`tuic-server`）**全部已发布版本均被
  yanked**（最高 5.0.0；crates.io max_version 回落 0.0.0 占位——作者已
  弃管该族），且整族 **GPL-3.0-or-later**——与本仓 Apache-2.0 工作区
  链接不兼容，无论维护状态如何都不可选。crates.io 上无其它以库形态提供
  TUIC 协议的 crate（"tuic" 查询 48 项，其余均为无关工具/占位）。维护中
  的 MetaCubeX/tuic fork 同为 GPL 且交付的是 client/server 二进制而非
  库。自写因此按官方 wire 规范进行（EAimTY/tuic master `SPEC.md`，与
  MetaCubeX fork `tuic/src/marshal.rs`/`protocol/*.rs` 源码交叉核对）。
- **版本**：仓库自写实现（无第三方协议依赖）；载具 quinn 0.11.9 /
  rustls fork 0.23.46 已由 RIL-133/RIL-107 全仓锁定
- **许可**：仓库许可（自写）
- **平台**：以目标平台 QUIC（quinn 生态）支持为准——与 hysteria2 同面
- **公开 API**：`TuicConnector`/`TuicUdpConnector`
  （crates/rillane-protocols/src/outbound/tuic.rs；TCP Connect 流面 +
  UDP Packet 数据报面，精确 TUIC v5）
- **旁路**：连接器自持 QUIC 会话（quinn）——无底层 socket 旁路；UDP 面
  协议头逐包携带真实源地址
- **取消**：建立期检查 + 显式拨号超时（15s，single-flight 持锁与
  hysteria2 同口径）；relay drop 发送 Dissociate（具名会话收束），会话
  关闭即 QUIC 连接收束（对端可观释放，验收面计数）
- **统计**：认证/流/数据报失败经统一 EgressConnector 面具名浮出；UDP 面
  会话统计（外来会话丢弃/分片丢弃计数）；协议无错误响应面——Connect 目标
  不可达由流收束形态承载（本仓镜像对端以流重置点名；对真实对端，干净
  零字节收束如实报告为空隧道，绝不伪装成功）
- **复用**：TUIC v5 天然多路复用——单条 QUIC 连接承载该节点全部
  Connect/Packet 面（single-flight 连接 + 复用，出错失效重连与 hysteria2
  同口径）；中继存续期 Heartbeat 数据报保活；无预热组合
- 版本边界（v4/v5）：仅 v5。TUIC v4（EAimTY/tuic 的 impl-0.6..1.0 分支
  线）是不同的 wire 协议——Authenticate 仅 32 字节 digest（无 UUID）、
  assoc_id 为 u32、Packet 无 pkt_id/frag_total/frag_id 字段、存在
  Response 命令；v5 帧为 UUID+TOKEN、u16 assoc_id、可分片 Packet、无
  响应命令。两者绝不静默互换：客户端只发 VER=0x05，镜像对端对 VER≠0x05
  具名拒绝，不存在 v4 代码路径。`congestion-controller` 非 `cubic`
  （bbr/new_reno）拨号期具名拒绝——自写面乘 quinn 缺省 cubic，不静默
  降级。
- UDP（RIL-105）：数据报面随客户端交付——官方 v5 Packet 命令 over QUIC
  不可靠数据报（native 模式；quic-stream 中继模式不承载），服务端按
  assoc_id 建 socket（full-cone 回包回卷），客户端侧分片/重装配（首片
  携带地址、后续片仅单字节 0xff None——经 marshal.rs 核验），Dissociate
  收束、Heartbeat 保活。验收：镜像对端契约测试（认证成功/错误 token 具名
  拒绝/v4 具名拒绝/TCP 往返/拨号失败收束/UDP 往返/分片/Dissociate 资源
  释放/统计/取消）。

## wireguard

- **结论**：选库 `defguard_wireguard_rs`（boringtun 内核）
- **版本**：要求 `0.11`，lock 实测 0.11.2
- **许可**：Apache-2.0
- **平台**：六平台主体；例外——android 与 armv7-ohos 为拒绝桩
  （defguard_boringtun 无平台支撑 / ohos 32 位 libc 字段冲突，见
  platforms/ohos/README.md），交叉编译不能证明可用
- **公开 API**：`WireguardConnector`/`WireguardUdpConnector`
  （crates/rillane-protocols/src/outbound/wireguard.rs；用户态承载）
- **旁路**：用户态 WireGuard 帧面按 allowed_ips 自管路由，不做系统
  接口接管
- **取消**：建立期检查
- **统计**：握手失败经统一面
- **复用**：会话保持 + persistent_keepalive
- UDP：数据报面（目录 udp=true）。

## snell

- **结论**：自写（RIL-111）——无可用 Rust 后端。评估扫查（2026-11-18，
  crates.io 注册表 + GitHub 真源核验）：注册表 “snell” 查询唯一命中
  `snells` 0.1.0（2021-11-26 发版、12.9KB、7 个版本全弃于 0.1.0、无
  license 字段、累计下载约 500）——占位符，不含任何协议 API。活跃的
  实现是 Go：sagernet/sing-snell（Apache-2.0/MIT，活跃维护）与闭源
  上游 Surge——Rust 侧无可链接物。结论 = 自写，线格式以真源
  sagernet/sing-snell master 为基准（2026-11-18 浅读：`snell.go` 常量、
  `crypto.go` Argon2id/AES-128-GCM、`snellv4/record.go` 记录封帧、
  `snellv4/client.go` 请求/应答面、`request.go` 负载布局、`address.go`
  目标握手数据、`internal/reuse/reuse.go` 应答分发），并与 sing-box
  `protocol/snell/outbound.go`（v4/v6 分派、UDP 走 TCP 连接）交叉核对
- **版本**：仓库内实现（无第三方协议依赖）；加密载体 `argon2` 0.6.0
  （要求 `0.6`，关默认特性只留 `alloc`——本面只用 KDF，PHC 口令串面
  是死重）+ `aes-gcm` 0.10.3（工作区既有 pin）
- **许可**：仓库许可（自写）；载体 argon2 MIT OR Apache-2.0，
  aes-gcm MIT OR Apache-2.0
- **平台**：全平台（纯 Rust；`argon2` 0.6.0 为 edition 2024 /
  rust-version 1.85，本仓工具链 1.100.0，六平台面沿用 tokio
  TcpStream 基座）
- **公开 API**：`SnellConnector`
  （crates/rillane-protocols/src/outbound/snell.rs）——线格式同文件：
  记录封帧（`SnellStream`，7 字节明文头 + 16 字节 tag，首记录携
  16 字节 salt 与初始填充，填充与负载密文按偶数下标互换）、请求负载
  `{0x01, 0x05, len(userkey), userkey, 1 字节长(host), host, port u16 大端}`、
  应答码 `0x00` 隧道 / `0x02` 错误（`{code u8, SockString 消息}`，
  不得有尾随数据）；镜像对端按 `address.go` 的目标握手数据读请求
  （CONNECT 目标是 host 串，字面 IP 亦然）
- **旁路**：连接器同时拥有 TCP 拨号与记录加密——无底层 socket 旁路；
  snell 是裸 TCP 承载、无传输组合面，故传输池/拨号策略组合不适用
  （如实记录，口径同 wireguard 用户态承载）
- **取消**：建立期检查 + 显式拨号超时；snell 会话无具名拆除——丢弃
  TCP 连接即释放（对端在其记录读取面看到 EOF）
- **统计**：协议无逐记录观测点；失败以 io::Error 经统一
  EgressConnector 面透出（observed 口径）；流量统计沿用 FlowReport
  上/下行字节（copy_bidirectional 口径）
- **复用**：官方实现的连接器复用是协议本体（`CommandConnectV2`、
  `snellv4/reuse.go`）——本段不交付（具名）；首段为一流程一 TCP 记录
  上下文，无预热组合
- UDP：本段不交付（目录 udp=false）——官方 UDP 面是
  `snellv4/packet.go` 的 UDP-over-TCP 数据报面（`CommandUDP` 0x06 +
  `UDPCommandForward` 0x01 + 字面 IP 的 `0x00` 族帧），列为后续阶段；
  sing-box 的 snell 出口声明 UDP 走 TCP 连接，故本列是交付边界而非
  协议缺失
- 服务端面：不交付（具名）——rillane 入站面未编目 snell 监听；验收对
  镜像对端，非真实 snell 服务器
- 版本边界：仅 v4 + obfs=none。v5/v6 是另一握手族（sing-box 的 snell
  出口只接受 version 4 与 6；`snellv6/{handshake,salt,profile,mixing}.go`
  未镜像）——配置期具名拒绝，绝不静默降级。obfs `http`/`tls` 不交付
  （它替换 TLS/HTTP 握手段，判负家族同 hysteria 的 salamander obfs）。
  v4 UDP、连接器复用、填充 one-ratio 整形皆为具名边界：填充内容由
  接收方不作校验（读取侧换回即丢弃），本客户端出均匀随机填充——官方
  `fillPadding` 的 one-ratio 整形是指纹启发式而非线结构，具名判负。
  镜像对端以 Rust 镜像官方 reader/writer 记录代码（验证席无 Go 工具
  链）；Go 源码为线格式基准。

## ssh

- **结论**：库承载（RIL-113）——存在可嵌入的维护中后端，不触发自写阶梯。评估排查（2026-11-18，crates.io registry + 探针实证）：`russh` 0.65.2（Apache-2.0，活跃维护，thrussh 血统的延续；edition 2024 / rust-version 1.89 对照本仓工具链 1.100.0）是唯一纯 Rust 异步 SSH-2 流库且带可嵌入客户端面（`client::connect` + `Handler` + `channel_open_direct_tcpip().into_stream()` 产出 AsyncRead/AsyncWrite）。落选备选如实留证：`thrussh` 0.35（前身，2022 起无维护）；`ssh2`/`async-ssh2-lite`（libssh2 **C 绑定**——引入原生 C 工具链依赖，且 `ssh2` 仅同步 API）；`openssh`（包一层系统 `ssh` **二进制**起进程——非可嵌入流面）。探针实证（`/tmp/sshprobe`，russh 0.65.2）：连接、host key 指纹采集、公钥认证（含带口令的 OpenSSH 私钥）、direct-tcpip 回环——全部打在本机真实 OpenSSH sshd 上。
- **版本**：载具 `russh` 0.65.2（requirement `0.65`）+ `ssh-key` 0.7.0-rc.12（requirement 钉死 `=0.7.0-rc.12`——rc 线漂移，不钉死会在不兼容的 rc API 间静默浮动；russh 以 `russh::keys` 再导出同一 crate）
- **许可**：russh Apache-2.0；ssh-key Apache-2.0 OR MIT——均与本仓许可兼容
- **平台**：russh 协议层纯 Rust，但其加密提供者树牵入 `ring`/`aws-lc-rs`（aws-lc-rs 部分目标构建需 cmake——本机 linux-amd64 实证，交叉编译不证可用，口径同 wireguard）
- **公开 API**：`SshConnector`（crates/rillane-protocols/src/outbound/ssh.rs）——`client::connect` 携 `Handler`，其 `check_server_key` 以 SHA256 指纹（`SHA256:` base64，`ssh_key::HashAlg::Sha256`）对照配置 `host_key` 钉扎服务器主机钥；认证恰一选一 `password` / `private_key`（`authenticate_password` 或 `authenticate_publickey` 携 `PrivateKeyWithHashAlg`，OpenSSH 格式私钥可带口令解码）；数据面 `channel_open_direct_tcpip(host, port, originator_ip, originator_port)` → `into_stream()`——通道流按统一 EgressConnector 面作流 IO
- **旁路**：`russh::client::connect_stream` 接受现成流，底部拨号旁路结构性存在；首段用 russh 内建拨号（`client::connect`）——无传输池组合（具名）
- **取消**：拨号超时（15s 族）包连接相；认证与开通道失败具名呈现；流随连接 drop 一并收束（对端 sshd 观测到连接关闭）
- **统计**：SSH 通道无逐包观测点；流量对账复用 FlowReport 上下行字节数（copy_bidirectional 语义）；认证失败经统一 EgressConnector 面具名呈现
- **复用**：SSH 本体即在单条传输连接上多路复用通道（每流 `channel_open`）——协议内建复用首段未交付（每流一条 SSH 连接，具名）；无预热组合
- UDP：本段不交付（catalog udp=false）——direct-tcpip 仅 TCP；SSH 无通用部署中的标准化 UDP 转发面
- 服务端面：不交付（具名）——rillane 入口面不编目 SSH 监听；验收打在本机真实 OpenSSH sshd（独立配置，端口 23411，探针钥料）
- 版本边界：仅 SSH-2（russh 说 SSH-2，无 SSH-1 路径）。主机钥钉扎**必填**——无 `host_key` 节点构造期拒绝（不钉扎的 SSH 客户端默认首用即信，是本面按名拒绝的降级面）；指纹比对先剥可选 `SHA256:` 前缀。认证面：password / private-key 恰一选一，双带或缺一均构造期拒绝。direct-tcpip 目标寻址用 host 字符串原样（由 sshd 解析）——本面不查 fake-ip 池。

## shadowsocksr（ShadowsocksR）

- **结论**：**受阻——无许可兼容后端**（RIL-115，评估留证 2026-11-18；未交付任何东西，无目录条目、无 IR 变体）。评估扫查，全部载具带证据拒绝：
  - `ssr-client-rs` 0.1.1（crates.io，创建 2026-09-26，44 下载，MSRV 1.82，tarball 已核验）是全部生态中唯一真正的 SSR 客户端库：自称 ssr-n C 实现的字节兼容移植（28 种密码实现 21、14 protocol、6 obfs、TCP+UDP 中继），自报对自家 C 参考服务端的 e2e 矩阵——但 **GPL-3.0-or-later**。链入本 Apache-2.0 工作区是许可错配，无论维护状态如何都不可选（与 GPL trojan 族、yanked GPL tuic 族同一判定）。
  - `ssr-native-rs`（同作者，GitHub，客户端+服务端）为 **GPL-3.0**——同理由拒绝。
  - crates.io 扫查（2026-11-18，查询 `shadowsocksr`）：其余匹配无关——Clash API TUI 工具、eggress 应用的出口链 crate（**crates.io 许可字段全空**，非标许可族，与 corduit 同姿态）、引擎占位。GitHub 扫查（`shadowsocksr language:rust`）返回 MIT 桌面客户端应用（二进制应用，非可嵌入库 crate）、SSPanel manyuser 服务端后端（角色错位）、GPL 订阅转换器。主流维护的 Shadowsocks 族（shadowsocks/shadowsocks-rust 1.25.0）只实现 Shadowsocks 线格式——README 零 SSR 字样（2026-11-18 核验）；SSR 线（EVP_BytesToKey-MD5 KDF 派钥的传统流密码 + protocol/obfs 插件层）明确不在其范围。
  - 自写梯子的真实对端景观：唯一库自身的验收锚（`ssr-n` C 服务端）不公开——crate 仓库 2026-09-25 移除了 vendored 上游源码（68 MB），GitHub 检索无该名的公开仓库（2026-11-18）。python 参考实现是 python2 时代（Debian 13 无 python2）。C 实现（shadowsocksr-native，GPL-3.0）可作外部对端**二进制**——GPL 对端进程是仓内合法的（ssh 项就是对系统 OpenSSH sshd 验收），可构建或预构建的 SSR 对端二进制原则上仍是可行的验收锚；本席本次未尝试此类构建，也未闻有维护中的 linux-amd64 构建。
  - 自写梯子：**触发**（无可用后端），且原语层许可干净（RustCrypto `rc4`/`cfb-mode`/`aes` 加 EVP_BytesToKey(MD5) KDF 均 MIT/Apache）——代码量不是绑定约束，验收锚才是。线横跨三层插件（crypto；protocol——部署面是 auth_aes128_md5/sha1 与 auth_chain 族；obfs——http_simple 与 tls1.2_ticket_auth）加 UDP 面，逐项验收要求对真实对端的成功/失败/取消/统计；两边都自写就是「从未运行的自己对自己」交付族，本仓拒绝（与 naive 的指纹拒绝同判定族：交付了传输却静默丢掉协议存在的理由——此处即与部署中的旧服务端的兼容）。
- 版本/许可/平台/公开 API/旁路/取消/统计/复用/UDP/服务端面：**不钉**——无后端交付；无载具 crate、无线镜像、无连接器面。
- 复开条件：crates.io 出现维护中的许可兼容（MIT/Apache/BSD）SSR 客户端库，或验收席出现可运行的真实 SSR 服务端对端（预构建二进制，或 GPL 对端的干净构建——外部进程合法），届时自写梯子按实际可部署的 cipher/protocol/obfs 组合推进并补订阅往返字段样本。

## naive（NaiveProxy）

- **结论**：**受阻——无可嵌入后端**（RIL-112，评估留证 2026-11-18；未交付任何面，无目录条目、无 IR 变体）。评估排查，全部载具落选并留证：
  - crates.io（2026-11-18）：不存在 NaiveProxy 客户端 crate——`naive` 检索仅命中字符串查找 / 朴素贝叶斯 / 定时器类 crate，无一与代理相关。
  - 官方 `naiveproxy`（klzgrad/naiveproxy，BSD-3-Clause，活跃——2026-11-01 有推送）是 **Chromium overlay**：其 `src/` 树即 Chromium 网络栈加构建脚本，客户端本体就是 Chromium 二进制。无法嵌入 Rust 工作区——C++ Chromium 网络栈构建（重型原生工具链 + 平台矩阵），与 libssh2 C 绑定、openssh 二进制同族落选理由，但重量远超。
  - 维护中的 Go 生态同样不复刻协议：sing-box 的 naive 出站经 `cronet-go`（"Go bindings for naiveproxy"，CGo，非标准许可）内嵌 Chromium——`client *cronet.NaiveClient`。Go 侧也是扛着 C++ 栈走而非镜像线格式——线格式并非 sing-snell 那类小型自包含 spec 的有力旁证。
  - 自写阶梯：**触发**（无可用后端）但**以具名伪装判定婉拒**。NaiveProxy 的首要目的是经 Chrome 同形 TLS/HTTP-2 指纹（ClientHello、ALPN、SETTINGS/HEADERS 顺序、C116123 填充）抗探测。纯 Rust TLS + h2 CONNECT 客户端对 forwardproxy 服务器线功能可用但指纹发散——交付了传输却静默丢掉协议存在的理由，与「relay 组映射成一致性哈希」同族（伪装成功即拒绝）。填充组件（C116123）是挂在 Chrome 栈上的指纹启发式，不是 sing-snell 记录那种自包含线 spec。
- 版本 / 许可 / 平台 / 公共 API / 旁路 / 取消 / 统计 / 复用 / UDP / 服务端面：**不钉载**——无后端交付；无载具 crate、无线镜像、无连接器面。
- 重开条件：crates.io 出现维护中的纯 Rust NaiveProxy 客户端且带可嵌入流面，或显式姿态决策接受指纹发散客户端作为留证降级（本仓现行姿态拒绝该类静默降级）。

## tor

- **结论**：库载具承接（RIL-114，评估 + 探针留证 2026-11-18；载具钉定 `arti-client`）。评估排查（2026-11-18，crates.io 仓库 + 缓存源码核读 + 真实网络探针）：Rust 的 Tor 生态就是 arti 栈本体——`arti-client` 0.48.0（MIT OR Apache-2.0，活跃，rust-version 1.92，本座工具链 1.100.0）暴露真正的可嵌入客户端面（`TorClient::create_bootstrapped` → `client.connect((host, port))` → `TorTcpStream`，AsyncRead/AsyncWrite）——这是所有语言里唯一的可嵌入 Tor 客户端库。落选姿态留证：sing-box 的 tor 出站是**托管 tor 进程**（github.com/cretz/bine 控制端口：torrc + DataDir + ProcessCreator，监护外部 `tor` 守护二进制）——与 `openssh` 二进制包装同族落选理由：是进程监护，不是库载具。C tor 本体是 C 工程（无法作为 Rust 库链接）。
- 探针留证（本座，真实 Tor 网络，`/tmp/torprobe` 临时 crate，arti-client 0.48.0）：冷引导 25.6s，热（磁盘缓存）2.4s；真实电路连 `example.com:80` 完整 HTTP/1.0 GET → `HTTP/1.1 200 OK`（488 字节）往返；`isolated_client()` 每流隔离面已验证。引导经**通道级代理前置**完成，因为本座原始出网被防火墙拦截（全部直连 TCP 不通；仅局域网 HTTP 代理可达外网）：arti 0.48 原生支持每条通道经出站代理前置（`tor-chanmgr` `ProxyProtocol`：`socks5://`/`socks4a://`/`http://` CONNECT，仅 IP 主机，按 curl 代理 URI 语法解析，空串视为未设置）。这让 Tor 在前置网络上无需任何 bridge/PT 机械即可用——交付面将携带为可选 `proxy` 字段。
- 探针验证过的坑（交付相关）：`TorTcpStream` 写后必须显式 `flush().await`——未 flush 的写只在本地缓冲、永不离开客户端（tor_proto 层追踪：BEGIN 已发、CONNECTED 已收、零 DATA 单元出站、出口约 15s 后关闭闲置流、读得 EOF）。`tokio::io::copy_bidirectional` 从不调 flush，在该流上**不可用**；交付的连接器必须每个方向跑显式的读→写→flush 泵。
- **版本**：`arti-client` 0.48.0（requirement `0.48`），features `tokio` + `rustls` + `compression`，默认 features 关闭（默认拉 `native-tls`/OpenSSL——本仓纯 rustls）。本仓 rustls fork 缺省无 process 级 crypto provider（与仓内其余 TLS 面一致）——连接器在引导前安装 `rustls::crypto::ring::default_provider()`，已装则尊重既有（仓内 `let _ =` 同款；mesh_transport/dns_engine 同姿态）。同线钉定的类型级伴随依赖：`tor-chanmgr` 0.48（`ProxyProtocol`，arti 自家的通道前置代理 URI 解析器，用于构造期校验）、`tor-rtcompat` 0.48（`PreferredRuntime` 类型）、`toml` 0.8（配置面——连接器以 toml 字符串构建 `TorClientConfig`，即探针验证过的形状）
- **许可**：MIT OR Apache-2.0——与本仓许可兼容
- **平台**：纯 Rust；63 个直接依赖 crate 为第一方 tor-* 为主；rust-version 1.92，本座工具链 1.100.0；仅在本座 linux-amd64 验证（交叉构建不作运行时证明，与 wireguard/russh 同措辞）
- **公开 API**：`TorConnector`（crates/rillane-protocols/src/outbound/tor.rs）——每连接器一枚共享 `TorClient`，首次流经 `OnceCell` 惰性引导（`create_bootstrapped`，冷 25.6s / 热 2.4s 探针实测，180s 闸；引导失败不清槽，下一流重试）；每流 `isolated_client()` 派生隔离客户端（共享目录信息、不共享电路）；`proxy` 构造期经 arti 自家 `ProxyProtocol` 解析器校验（坏方案/域名主机/缺端口均具名拒绝）；数据面 = `connect((host, port))` → `DataStream`，统一 EgressConnector 面下的流 IO
- **旁路**：arti 结构性接受现成运行时/通道工厂（`TorClient::with_runtime`）；首段在 arti 内部拨号（可选经配置 `proxy` 做通道级前置）——不与传输池组合（具名）
- **取消**：引导闸 180s、出口流建立闸 30s（电路搭建 + 出口 BEGIN/CONNECTED）；流拆线走中继泵：任一方向 EOF → flush 排空 → 半关闭（出口收到 END 单元）——流丢弃触发 arti 的尽力异步通道收束；另一方向给 5s 排空宽限，残余按 0 记（具名）
- **统计**：Tor 流无逐单元观测点；流量核算来自显式泵计数进 FlowReport up/down（15s 闲置 EOF 失效面是静默无数据而非报错——验收断言非零计数，flush 回归不可能蒙混过关）；失败经统一 EgressConnector 面具名透出
- **复用**：每流 `isolated_client()` 是已交付的隔离姿态——流间不共享电路（与 ssh 每流一连接同族）；arti 缺省的跨流电路共享未交付（具名）；无预热组合。多 tor 节点各自引导（同一缺省存储路径，并发由 sqlite 锁面承载；跨节点客户端共享池未交付）
- UDP：不交付（catalog udp=false）——arti 客户端流仅 TCP；常见部署中 Tor 数据报面不存在（tor-spec UDP 为实验性，不在 arti 客户端面内）
- 服务端面：不交付（具名）——onion service 是 arti 的独立特性（`onion-service-service`）；本仓入口面不编目 tor 监听
- 版本边界：交付面仅 arti 客户端面——首段无 bridge/可插拔传输（可选 `proxy` 是经普通代理的通道级前置，与 bridge 是不同机制；在封锁 Tor 的网络上它未必够用——本席探针验证的正是这一面）。目标寻址 host 字符串原样（出口侧 DNS——本面不查 fake-ip 池，与 ssh 同措辞）。存储用 arti 缺省路径（`~/.cache/arti`、`~/.local/share/arti`）——探针验证的配置形状钉定 `[storage] permissions.denied = []`。flush 坑是承重的：未来任何把显式 flush 泵换成 `copy_bidirectional` 的重构都会重新引入探针追踪到的静默无数据失效面。

## sudoku（Sudoku/ASCII）

- **结论**：**无后端——自写受限于线格式规范缺失**（RIL-117，评估留证 2026-11-18；未交付任何东西，无目录条目、无 IR 变体）。评估扫查：
  - crates.io（2026-11-18）：**零**协议 crate——`sudoku` 全部匹配都是数独游戏（解题器/生成器）；协议与游戏同名，注册表里只有游戏。
  - 参考实现是 **SUDOKU-ASCII/sudoku**（GPL-3.0，Go，437 星，推送 2026-10-31，发行 v0.5.2-1）：协议自家 README 宣告「已完成最后一次大更新」并转入慢速维护模式。代理**应用**——包二进制属 openssh/Chromium 拒绝族，且无论许可如何都无库面可链。
  - 生态是单实现：据 README，官方支持仅存在于 Mihomo（其本身 GPL）；Xray 携带同名协议但明确**不兼容**真实 Sudoku 协议；sing-box 支持仅限非官方分支。不存在可交叉核对线格式的第二独立实现。
  - 无线格式规范：README 只有概念与流程（预共享钥生成同一数独映射表；握手 = 加密时间戳 + nonce；上行路径 数据 → AEAD（AES-128-GCM 或 ChaCha20-Poly1305，逐连接钥带轮换、严格 nonce 去重 + 时间戳偏差防重放）→ 切片 → 4x4 数独线索映射 → 任意填充；两种下行模式——纯数独编码，或 6-bit 切片复用填充池；畸形输入不掐断而是转发到诱饵站），但**没有**握手、目标寻址、掩码方案编码的任何字节级布局——精确线格式只存在于 GPL Go 源码中。从该源码派生的自写是本工作区不采取的 GPL 衍生姿态；剩余基础是对已发行对端二进制（`sudoku-linux-amd64.tar.gz`，v0.5.2-1——GPL 对端进程作为外部锚是仓内合法的，ssh/OpenSSH 同例）的黑盒探测，原则上可行但本矩阵中面最大（288 个非同构 4x4 数独枚举、多掩码方案含用户自定义 XVP、两种下行模式、PFS 钥轮换）且无规范可核对——「从未运行的自己对自己」拒绝在此甚至不能干净适用，因为不存在可判错的第二实现。
  - 自写梯子：**原则开启、缺基础受阻**——记录为前置姿态；线基础不存在，范围不钉。
- 版本/许可/平台/公开 API/旁路/取消/统计/复用/UDP/服务端面：**不钉**——无后端交付；无载具 crate、无线镜像、无连接器面。
- 复开条件：出现字节级线格式规范、非 GPL 参考实现、或维护中的许可兼容 Rust sudoku 协议库——三者任一即解锁梯子。

## shadowquic

- **结论**：**库承载——`shadowquic` 0.4.12 连接器交付（RIL-118，交付 2026-11-18）**。评估扫查（2026-11-18，crates.io + 缓存源码核验 + 进程内探针）：`shadowquic`（MIT，crates.io 创建 2026-02-09，约 4 万下载，隔数日一发版，最新 2026-11-16）是该协议自身的 Rust 实现，也是唯一实现——客户端（`ShadowQuicClient`）与服务端（`ShadowQuicServer`）皆为可嵌入库面，且直连连接器路径无需该 crate 的应用机械（`Manager`/SOCKS 挂具）：`ShadowQuicClient::new(cfg, resolver)` → `get_conn()`（地址解析 → QUIC 连接——直连路径逐流新建 QUIC 连接，zero_rtt 启用时握手 0-RTT 复用（探针实测二次 `get_conn()` 0.64ms）；客户端内 `prepare_conn` 的连接缓存属应用机械面，直连路径不经）→ `squic::outbound::connect_tcp(&conn, SocksAddr) -> Unsplit`（打开双向流并预编码 `SQConnect(dst)` 请求，AsyncRead/AsyncWrite）。伴生 crate `shadowquic-macros`（同版本，线格式 derive 支持）随行。crates.io 无其他实现该协议的 crate；README 具名的客户端生态（nekobox、v2rayN）经同一线格式互操。
- **版本**：要求 `0.4.12`，缺省特性（`shadowquic-quinn` + `sunnyquic-noq` + `ring` + `statistics`）——探针实测面
- **许可**：MIT——与本仓许可兼容
- **平台**：未声明 MSRV；工作区工具链 1.100.0 缺省特性编译干净；仅在本席 linux-amd64 验证（交叉编译不是运行时证明，与 wireguard/russh/arti 同措辞）
- **公开 API**：`ShadowQuicConnector`（crates/rillane-protocols/src/outbound/shadowquic.rs）——构建期具名校验：username/password 非空；ALPN 空表拒绝（无公共 ALPN 握手必败）；拥塞控制在支持集内归一（`bbr` 缺省 / `new-reno`（mihomo 键形 `new_reno` 同收）/ `cubic`；`brutal` 需 mihomo 私有 up/down 参数面、`bbr3` 在 crate 文档支持集外——均具名拒绝）；SNI 缺省回落 server（crate 文档具名须与服务器 `jls_upstream` 域一致）；ALPN 缺省 `["h3"]`；`zero_rtt` 缺省 **false**（mihomo 文档缺省——官方服务器 ≤v0.3.11 有具名 zero-rtt 断连 bug；crate 自身缺省 true 不迁移）。探针钉定载具值：`initial_mtu = 1200`（crate 下界）、`over_stream = true`。forward = `get_conn`（15s 拨号超时）→ `connect_tcp`（15s 流打开超时）→ `copy_bidirectional_with_sizes` → FlowReport 字节计数
- **旁路**：无——载具自持 UDP 套接字与整个 QUIC/TLS 栈（JLS 伪装），无底层套接字接缝可供传输池组合（anytls/tuic 同姿态）
- **取消**：分阶段拨号超时（连接 15s、流打开 15s）；流中取消即丢弃该流 duplex/stream——QUIC 连接由 QUIC 空闲语义收口；端点持于连接器（`Arc<ShadowQuicClient>`），流存活期间绝不丢弃
- **统计**：FlowReport 上/下行字节（copy_bidirectional 语义）；crate 的逐用户统计 API 未交付（具名）
- **复用**：直连路径 QUIC 连接逐流新建（zero_rtt 启用时握手 0-RTT 软化）；无连接器级预热/复用组合——具名边界
- 探针留证（本席，`/tmp/sqprobe` 临时 crate，进程内客户端对库自身服务端面——anytls 验收姿态）：QUIC 握手冷 3.1ms（127.0.0.1），双向流打开 96µs，TCP 回声全栈字节精确往返 4.7ms（SQConnect 请求 → 服务端 accept → 中继到真实 TCP 回声对端），写半关闭被对端尊重。探针实证的收尾毛刺（交付成形）：后台任务仍在轮询时丢弃 QUIC 端点会在 crate 内 panic（"Quic endpoint closed"，`quinn_wrapper/wrapper.rs:486`）——交付的连接器把客户端整体 `Arc` 持于连接器生命周期
- 认证面（crate 源码核验）：username/password 走 JLS 伪装 TLS 握手层承载——服务端在连接受理时经 `authed_user()` 取用户、无此用户即拒接；凭据错误在 QUIC 握手期暴露（测试钉定：错密码在拨号超时内 forward 失败，绝不静默成功）。直连 TCP 路径不另发 `SQAuthenticate` 流（那是 sunnyquic/UDP 面）
- UDP：未交付（catalog udp=false）——库自带两种 UDP 面（over-datagram 与 over-stream），均具名未交付；mihomo `udp-over-stream` 键导入容忍读取、落 IR 不落行为（无 UDP 面可切）
- 服务端面：未交付（具名）——库的 `ShadowQuicServer` 仅作进程内验收镜像对端（anytls 同姿态）
- 版本边界：QUIC 版本族仅 v1——mihomo `quic-versions` 键缺省 `[v1]`；显式非 v1（v2 为不同线格式族）导入期具名拒绝。mihomo 私有调参键（`up`/`down` brutal、`cwnd`、`bbr-profile`、`recv-window` 族、`max-datagram-frame-size`、`max-open-streams`、`disable-mtu-discovery`）不入 IR——具名边界

## mieru

- **结论**：自写（RIL-116，交付 2026-11-18）——仅以官方 protocol.md 文档面为实现真源，**GPL 源码未读未派生**（ssh/snell 先例口径：官方 GPL 参考二进制作外部黑盒对端合法，源码不进仓）。crates.io 无该协议的 Rust 实现（评估扫查 2026-11-18：`mieru`/`mita`/相关查询零命中协议 crate）。线格式全部经官方参考二进制 **mieru/mita v3.39.0 的 wire 捕获逐字节 AEAD 验证钉定**（本席常驻对端 `/tmp/mierupeer`：mita 服务端 127.0.0.1:23420 + mieru 客户端 daemon（socks5 11080）+ 被动字节日志中继，捕获留证 `cap2/`；两段干净探针会话，c2s/s2c 双向）——密钥排程、盐取整、nonce 形、计数方向、段框架、负载段省略规则、SOCKS5 隧道内载荷、关闭握手次序皆为捕获实证，非文档推断
- **版本**：仓库内实现（无第三方协议依赖）；加密载体 `chacha20poly1305` 0.10（XChaCha20Poly1305 无条件导出——24 字节 nonce AEAD，官方 protocol.md 口径）+ 工作区既有 `hmac`/`sha2`（PBKDF2-SHA256 手写单块面）
- **许可**：仓库许可（自写）；载体 chacha20poly1305/hmac/sha2 MIT OR Apache-2.0——官方实现 GPL-3.0 仅作黑盒对端，不进依赖树
- **平台**：全平台（纯 Rust，tokio TcpStream 基座，六平台面无平台门）
- **公开 API**：`MieruConnector`（crates/rillane-protocols/src/outbound/mieru.rs）——线格式同文件。密钥 = PBKDF2-SHA256(hashedPassword, timeSalt, 64, 32)，hashedPassword = SHA-256(password ‖ 0x00 ‖ username)（官方 `mieru describe config` 回显钉定向量），timeSalt = SHA-256(be64(round_2min(unix)))，round_2min 半分钟向上取整；接收侧 3 盐候选 [R−120, R, R+120]（跨分钟会话容忍 ±4 分钟窗口）逐试钉定。nonce 24B = 随机 20B + SHA-256(username ‖ nonce[0..16])[0..4] 用户定位标记（双向捕获偏移 0 命中）；计数器随每次加密大端 +1（payload tag 于 meta nonce +1 命中、小端失配——捕获钉定），实现取尾 8 字节口径（捕获的计数范围区分不了全 24 位与尾 64 位，真实计数永不达 2^64，两种宽度逐字节同形）。段框架 = [nonce 仅每方向首段][meta 密文 32][tag 16][padding1 仅数据段][payload 密文][tag 仅 plen>0][padding2]——**plen=0 时 payload 段整个不存在**（捕获实证：openSessionResponse 134B = 24+48+62 padding2）。openSessionRequest 载荷 = 原样 SOCKS5 请求字节（捕获向量 `05 01 00 03 0e "api.github.com" 01bb` / `05 01 00 01 7f000001 46a0`）；**mita 把 SOCKS5 回复以首个 dataS2C 载荷原样注入隧道**（BND.ADDR/BND.PORT = 目标连接结果）——连接器消化该回复（VER/REP/ATYP 解析，REP≠0 具名拒绝——目标不可达浮出，绝不漏回复字节进隧道）后即纯目标字节面。关闭握手：双侧各发 closeSessionRequest(4) + 回 closeSessionResponse(5)，顺序容忍（conn1 服务端先关、conn2 客户端先关捕获均实证）；连接器 poll_shutdown 发 4（协议半关，**不发 TCP FIN**——回程 5/4 还要写回）+ 读侧见对端 4 即回 5 并 EOF
- **旁路**：连接器同时拥有 TCP 拨号与段加密——无底层 socket 旁路；mieru 是裸 TCP 承载（无传输组合面），传输池/拨号策略组合不适用（snell 同口径如实记录）
- **取消**：分阶段拨号超时（连接 15s、openSessionResponse 15s）；凭据错误在首段钉钥期具名失败（盐候选逐试 + nonce 标记校验）；关闭握手为协议具名拆除（双向 4/5），wire TCP 随流 drop 收口
- **统计**：FlowReport 上/下行字节（copy_bidirectional 语义）；协议无逐段观测点，失败以 io::Error 经统一 EgressConnector 面透出（observed 口径）
- **复用**：官方默认即 MULTIPLEXING_OFF 同形——每流一条 wire 连接、每连接新 nonce（捕获两连接 nonce 相异实证）；协议内建多路复用面未交付（具名）；无预热组合。mihomo `multiplexing` 键导入容忍读取不落行为
- 验收（本席实机）：`connector_roundtrip_via_in_process_echo`（进程内镜像服务器回环——镜像侧实现同一捕获钉定线格式的服务端面：盐候选钉钥 + SOCKS5 隧道内回复 + 双向关闭握手；文本 + 10KB 越段界逐字节还原 + FlowReport 对账）、`tunnel_socks5_rep_nonzero_fail_named`（REP≠0 具名拒绝）、`wrong_credentials_fail_named`（错凭据快速具名失败不悬挂）、`real_official_mita_server_roundtrip`（**官方 mita v3.39.0 实机对端**——缺席记名跳过；用户 ril116，allowLoopbackIP，回声上游，"official hello" + 10KB 逐字节还原）。向量测试钉定密钥排程（官方 describe config 回显）、段元数据线格式（捕获 hex 逐字段解码 + 重编码等值）、socks5 请求构造（捕获向量）、盐取整边界（半分钟向上）
- UDP：未交付（catalog udp=false）——官方 UDP 载具（QUIC 上的 mieru 数据报面）未实现；mihomo `transport: udp` 导入具名拒绝（防静默按 TCP 误连致隧道必败），`udp` 键容忍读取
- 服务端面：未交付（具名）——mita 仅作外部验收对端，rillane 入站面未编目 mieru 监听
- 版本边界：仅 TCP 载具 + 标准握手（HANDSHAKE_STANDARD）；multiplexing 复用面、UDP 载具、端口区间键形（`port-range` 导入具名拒绝）、协议内建 ACK/窗口流控（连接器声明 win=u16::MAX、不回 ACK——小流捕获未出现 ACK 段，读取侧容忍跳过）皆为具名边界；元数据时间戳字段服务端不严格校验（容忍面，捕获实证）——连接器发分钟精度当前值

## trusttunnel

- **结论**：自写（RIL-119，交付 2026-11-18）——以官方规范 TrustTunnel/TrustTunnel `PROTOCOL.md` v1.0（2025-12-24，端点仓自述「使独立实现可与现有 TrustTunnel 客户端/端点互操作」）为唯一实现真源，TCP + UDP 两面交付。评估扫查（2026-11-18）：crates.io `trusttunnel` 查询零匹配；参考实现家族 TrustTunnel org（AdGuard VPN 开源，活跃——端点仓推送 2026-11-18）三仓皆 Apache-2.0（许可兼容——与 mieru GPL 拒绝族相反）：端点仓是 Rust VPN **服务端应用**（`lib` crate 0.1.0 path-dep 未发行，端点侧终结面 only——**无客户端拨号 API**；依赖栈 boring BoringSSL + quiche boringssl 载具 + cc/net_utils.c，`http 0.2`/`h2 0.3` 与工作区 semver 冲突——嵌入不可行）；客户端仓是 **C++**（CMake/conan）——库承载无 Rust 面可链，自写从官方规范出发（tuic/mieru 同姿态）。**验收对官方端点 linux-x86_64 预构建二进制实机回环通过**（trusttunnel_endpoint v1.1.0 stable，Apache-2.0 黑盒对端，本席常驻 `/tmp/trusttunnelpeer`：127.0.0.1:23430，自签证书 SNI=localhost + Basic 凭据 + allow_private_network_connections 回环回声面——snell/mita 口径）。
- **版本**：仓库内实现（无第三方协议依赖）；TLS 载体工作区既有 `rustls` 0.23 + `tokio-rustls` 0.26（ALPN h2 + 证书校验 + 可选 uTLS 指纹面），HTTP/2 载具工作区既有 `h2` 0.4——零新依赖
- **许可**：仓库许可（自写）；规范与验收对端 Apache-2.0（端点二进制仅作外部黑盒对端，不进依赖树）
- **平台**：全平台（纯 Rust，tokio TcpStream + rustls 基座，六平台面无平台门）
- **公开 API**：`TrustTunnelConnector` / `TrustTunnelUdpConnector`（crates/rillane-protocols/src/outbound/trusttunnel.rs）——线格式同文件。TCP 面：authority 形 CONNECT（`:authority` = host:port，IPv6 加方括号——注入字符具名拒绝，spec §11.3 向量钉定）+ 必发 `user-agent: <platform> rillane` 与 `proxy-authorization: Basic`（§9.1 向量钉定）——200 即双向字节流（`h2::H2Stream` 承载 + copy_bidirectional）、407 具名认证失败族、其余非 200 连接失败；分阶段拨号超时（连接 15s、TLS+h2+CONNECT 应答 15s）。UDP 面：每关联一条 `_udp2` CONNECT 流（spec §6），上行组帧 `[len u32 BE][src 16B][sport][dst 16B][dport][appname-len u8][appname][payload]`（v4 零填充 16B——首 12B 全零且非 ::1 判 v4，§11.2 向量钉定；appname = "rillane"）、下行解帧无 appname 形（半包容忍 + 粘包逐帧消费，§6.4 向量钉定）；demux 任务按 dst == 进程伪源（127.0.0.1 + 逐关联递增端口）回拼（异元组残留帧丢弃族——端点 4 元组跟踪/复用流容忍面），relay drop 发 END_STREAM 收流（端点闲置 120s 释放 4 元组）。构建期校验：空用户名/密码/服务器具名拒绝。凭据错误在 CONNECT 应答期暴露（407 具名失败，绝不静默成功）
- **旁路**：连接器自持 TCP+TLS+h2 拨号——无底层 socket 旁路；带工厂时经 TlsConnectorFactory 组合 TLS 拨号（与既有 TLS 协议族同形），裸 TCP 载具无传输组合面
- **取消**：分阶段拨号超时（连接 15s、隧道握手 15s）；407/非 200 即期具名失败；流关闭即连接拆除（END_STREAM 优雅半关 / RST abrupt——spec §5.2 口径）；UDP relay drop 即发 EOS 收流
- **统计**：FlowReport 上/下行字节（copy_bidirectional 语义）；端点 metrics API（`[metrics]` 监听面）非连接器消费面——不交付（具名）
- **复用**：TCP 面每流一条 CONNECT——协议无连接级复用交付面（mihomo 复用旋钮 max-connections/min-streams/max-streams 导入容忍读取不落行为——每流单连接 = 复用关闭缺省同形）；UDP 面协议内建 `_udp2` 单流复用（多数据报共用一条 CONNECT 流）；HTTP/2 连接面 h2 自持（无连接器级预热组合）
- 验收（本席实机）：`real_official_endpoint_roundtrip`（**官方 trusttunnel_endpoint v1.1.0 实机对端**——缺席记名跳过；TCP "official hello" + 10KB 越帧界逐字节还原 + FlowReport 对账；UDP `_udp2` 关联 + 4 元组回拼）、`connector_roundtrip_via_tls_mirror`（进程内 TLS h2 镜像——全产线路径 TLS+ALPN h2+CONNECT+双向中继：文本 + 10KB 越帧界逐字节还原 + FlowReport 对账）、`udp_relay_roundtrip_via_tls_mirror`（`_udp2` 全链：异元组残留帧丢弃 + 真应答回拼 src=应答方/proto=Udp）、`connect_407_fail_named`（407 具名失败族）、向量组（authority §11.3 / Basic §9.1 / 上行组帧 §6.3 逐字节 / 下行解帧 §6.4 半包+粘包 / v6 判定 §11.2 / 构建期具名拒绝）。**h2 镜像面注记**：h2 0.4 的 `send_response` 仅入队——HEADERS/DATA 冲刷依赖连接被并发 poll（外圈 accept 循环保推进；grpc/xhttp 镜像同经验）——镜像对端与测试对端都循此形
- UDP 伪源语义：官方客户端发 TUN 接口地址作 src，代理出口场景无 TUN——连接器伪造进程内稳定伪源（127.0.0.1 + 递增端口），端点仅以 4 元组回拼不路由 src（语义等价，模块头注具名）
- 导入边界：`quic: true`（H3/QUIC 载具）导入具名拒绝（防静默按 TCP 误连）；`name-cert-verify: false` 具名拒绝（降级不校验语义——spec 证书校验必须）；alpn 携带但不含 h2 具名拒绝（spec 钉死 h2）；`udp` 键容忍读取（UDP 面已交付，按路由需求注册）；复用三键 / health-check / congestion-controller / bbr-profile 容忍读取不落行为
- 服务端面：未交付（具名）——trusttunnel_endpoint 仅作外部验收对端；`_icmp`（VPN 概念，非代理出口面）与 `_check`（端点策略面）保留伪主机不交付
- 版本边界：HTTP/2 初始窗口取 h2 crate 缺省（spec 131072 是官方客户端取值非线格式约束——流控自协商）；H3/QUIC 载具（spec 有完整规范）不交付；ICMP 面不交付

## masque

MASQUE / CONNECT-UDP（RFC 9298 / 9297）——HTTP/3 数据报能力代理客户端面。

- **结论**：**已交付**（RIL-120；在仓内 HTTP/3 载具上自写客户端面，零新增依赖；两面均通过仓内 h3 镜像对端验收，UDP 面另通过本席自构的真实 `quic-go/masque-go` `cmd/proxy` 对端验收）。下述评估钉定（规范、载具、对端）贯穿交付全程——无需重新评估。交付范围：`crates/rillane-protocols/src/outbound/masque.rs`（`MasqueConfig` / `MasqueConnector` TCP 面 / `MasqueUdpConnector` + `MasqueUdpRelay` + `MasqueUdpStats` UDP 面）；配置 IR `EgressConfig::Masque { server, port, sni, skip_cert_verify, uri_template }`；目录条目（RFC 9298 CONNECT-UDP 代理客户端面，`udp: true`）；runtime_builder 接线（UDP 关联臂 + TCP 转发臂）；订阅边界（mihomo `type: masque` 为密钥隧道——异协议族——导入=具名拒绝，导出=具名跳过）。
- 规范钉定（RFC 9298 / 9297 逐节口径，交付面直接照此实现）：
  - 请求（§3.4，HTTP/2 与 HTTP/3 同形）：HTTP Extended CONNECT——`:method = CONNECT`、`:protocol = connect-udp`、`:authority` = UDP 代理 authority、`:scheme`/`:path` 取 URI 模板展开结果，并带 `capsule-protocol = ?1`。缺省 URI 模板 `https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/`（§2；Well-Known URI 见 §8.2）。
  - 目标地址形态（§2/§3）：`target_host` = DNS 名 / IPv4 字面 / IPv6 字面（**冒号必须百分号编码**，如 `2001%3Adb8%3A%3A42`）；IPv6 scoped zone id **不支持**；`target_port` = 1..65535；两者均不得为空。DNS 名由**代理**解析，解析失败须以 4xx + `Proxy-Status`（`dns_error`）拒绝（§3.1）。
  - 应答（§3.5）：2xx 且满足 Capsule Protocol 应答要求即成功；**其余任一应答即失败，客户端 MUST 中止请求**。
  - 载荷（§5 + RFC 9297 §2.1）：HTTP/3 上 HTTP Datagrams 直接承载于 **QUIC DATAGRAM 帧**（非 capsule 包装）——帧体 = `Quarter Stream ID`(varint) + `HTTP Datagram Payload`；MASQUE 的 payload = `Context ID`(varint，**0 保留给 UDP 载荷**) + **未改动的原始 UDP 字节**（无地址头——目标地址在 URI 里）。`Context ID` 为 62 位变量长整数；非零值动态分配（偶数=客户端、奇数=代理），同一 HTTP 命名空间内不得重复分配；未知 Context ID 静默丢弃或按 RTT 量级短时缓冲。
  - 上限与失败（§5/§3.1/§6.1）：Context ID 0 的 UDP 载荷 **>65527 字节 MUST 中止该流**；代理在 IP 层 MUST NOT 引入分片（IPv4 可设 DF 则 MUST 设），过大报静默丢弃；MUST NOT 为批处理而排队；因不活动关闭 socket 的空闲期 SHOULD NOT 低于 2 分钟；UDP 数据报的 socket 存活期与请求流绑定，socket 不可用 MUST 关闭请求流。
  - HTTP/3 特化：数据报与请求以 Quarter Stream ID（请求流 ID ÷ 4）关联；HTTP/3 数据报仅在对应流发送侧开放时可发；在 HTTP/3 上收到与无语义请求关联的数据报 → 以 `H3_DATAGRAM_ERROR (0x33)` 中止请求流（RFC 9297 §2）；启用需交换 `SETTINGS_H3_DATAGRAM`（RFC 9297 §2.1.1）。
  - TCP 隧道面不属 RFC 9298（该 RFC 仅规范 UDP）——CONNECT-IP 面由同族 draft 级规范覆盖；本项 CONNECT-UDP/IP 分离口径即此。
- 载具核验（2026-11-19，本仓源码核读）：h3 0.0.8 **已支持 Extended CONNECT**——`:protocol` 伪头发射点 `src/proto/headers.rs:185`、解析点 `:306`（`Field::Protocol`）；quinn 0.11.9 / quinn-proto 0.11.19 提供 QUIC DATAGRAM 帧面；`[patch.crates-io]` 的 rustls fork 与上述版本共存已在 Hysteria2 面实证。**结论：零新增依赖即可承载**（与 RIL-119 trusttunnel 的 h2 路线相比，此处新增的是 QUIC/H3 流控面）。
- 验收对端定位（2026-11-19，本席取证，**对端可得**）：
  - 权威实现 = **`quic-go/masque-go`**（MIT，266★，2026-11-15 推送即活跃，最新 tag v0.6.0）：「MASQUE: Proxying UDP in HTTP/3, RFC 9298」，同时提供客户端与代理实现，基于 quic-go。服务端入口 `cmd/proxy/main.go`——`flag` 参数 `-t <URI 模板>` `-b <bind ip:port>` `-k <key>` `-c <cert>`，`http3.Server{ EnableDatagrams: true }`（数据报面已启用），模板路径经 `uritemplate` 展开后注册 `http.HandleFunc`，`masque.Proxy{}.Proxy(w, req)` 拨目标并中继。
  - 本席取该对端的通路取证：GitHub REST API 经本席**代理**出口 IP（共享代理 13.230.254.187）未认证限额已耗尽（全 403），但**直连** `api.github.com` 可用（`/rate_limit` 200、59/60 余量、1.3s）；`raw.githubusercontent.com` 无论直连还是经代理都返回损坏的 404（对照组 `tokio-rs/tokio/main/LICENSE-MIT` 确定存在亦 404），故**文件内容须经 API `contents` 端点（base64）取**——本段引用的 go.mod / README / cmd/proxy/main.go 即该口径取回。
  - crates.io sparse index：`masque` / `masque-quic` / `masque-proxy` / `masque-client` / `quic-masque` / `h3-masque` / `masque-connector` 全 404——**Rust 侧无 MASQUE 库落点**，故载具只能自写（h3 + quinn 已在仓）。注意：先前记忆的 `miekg/masque-quic` 经 API 核实**不存在**（404），真实名是 `quic-go/masque-go`。
  - 工具链：本席原无 Go（`go version` 不存在），Go module proxy 可达（`golang.org/x/net` 200、`github.com/quic-go/quic-go` 正常返回版本列表）；已下载 **go1.26.11.linux-amd64.tar.gz**（64M，sha256 `9849f4e0…710ec` 与 go.dev 公布值逐字一致）满足 `go.mod` 的 `go 1.26.0` 要求——**对端可本席构建**（无预构建发布资产，须自构）。
  - 已交付面：TCP = HTTP/3 无 `:protocol` 的 CONNECT（RFC 9298 不覆盖 TCP，该面由同族 draft 规范；masque-go 代理侧只注册 URI 模板路径处理器，**未注册通用 CONNECT 处理器**——故 TCP 面以仓内镜像对端验收 + 具名边界记录）；UDP = `:protocol = connect-udp` + QUIC DATAGRAM 帧（`Quarter Stream ID` + `Context ID` 0 + 原始 UDP 字节）+ `capsule-protocol: ?1`，经仓内 h3 镜像对端与真实 `quic-go/masque-go` `cmd/proxy` 对端双重验收。
- **版本 / 许可 / 平台 / 公开 API / 旁路 / 取消 / 统计 / 复用 / UDP / 服务端面**：按下述钉定交付——**公开 API** = `MasqueConnector` / `MasqueUdpConnector` / `MasqueUdpRelay` / `MasqueUdpStats`（crates/rillane-protocols/src/outbound/masque.rs，自 `rillane_protocols` 再导出）；**旁路** = 客户端不解析目标主机（由代理解析——`target_host` `.invalid` 保留域往返实证平台旁路）；**取消** = 关联丢弃/转发任务中止即释放对端连接（镜像 `closed` 计数）；**统计** = `MasqueUdpStats` datagrams_sent / datagrams_recv / datagrams_dropped；**复用** = 每关联一条 QUIC 连接（无连接复用池交付）；**UDP** = 已交付（`udp: true`，RFC 9298 CONNECT-UDP）；**服务端面** = 未交付（具名——入口侧不在本项范围，RIL-120 为客户端面）。**版本 / 许可 / 平台**：无外部库——载具为仓内 h3 0.0.8 + h3-quinn 0.0.10 + quinn 0.11.9 / quinn-proto 0.11.19（零新增依赖）；对照 RFC 自写；真实对端（`quic-go/masque-go` v0.6.0，MIT，本席自构）仅作进程内验收对端。
- 复开条件：**已交付——无复开待办**。上述评估钉定（规范、载具、对端）贯穿交付全程；剩余具名边界（服务端面、连接复用池、mihomo 密钥隧道等价性）为独立事项，不构成本项复开。

## 公共传输面（跨协议共享）

| 库 | 版本（要求 / lock 实测） | 许可 | 角色 |
|---|---|---|---|
| rustls | 0.23 / 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS 传输 |
| tokio-rustls | 0.26 / 0.26.4 | MIT OR Apache-2.0 | TLS 异步桥 |
| h2 | 0.4 / 0.4.19 | MIT | HTTP/2 传输 |

传输组合（TLS/WS/gRPC/H2/HTTPUpgrade）是协议字段的正交面，单独验收；
本页不逐协议重复其结论。

## 公共传输与复用矩阵（RIL-130）

- **结论**：盘点 + 三处实际缺口补齐——httpupgrade 订阅导出面、vless UDP 包编码
  （raw/xudp/packetaddr）、gRPC gun 流复用；不引入新外部后端（新增全部自写，
  真源对照逐字节核验）。评估扫查（2026-11-16）。
- **现状矩阵（代码面，构建期白名单 + 拨号期具名拒绝已覆盖）**：vless =
  tcp/ws/grpc/h2/httpupgrade/xhttp（RIL-129）；vmess = tcp/ws/grpc/h2/httpupgrade；
  trojan = tcp/ws/grpc（恒叠 TLS）；shadowsocks = tcp（SIP003 插件桥）；
  anytls/tuic/hysteria2 = 原生面（TLS/QUIC 内建，无 network 字段）。
- **UoT（UDP-over-TCP）**：已交付，无缺口——anytls 出站 UDP 面（RIL-106）由
  anytls crate UoT 模块承载（uot_sentinel_destination/UotRequest/
  uot_encode_packet/uot_get_packet_from_stream，仓内已 pin）；mihomo 出站 schema
  中 vless/vmess 无 uot 传输字段（其 SupportUOT() 是 UDP 面能力声明而非配置面）。
- **XUDP / packetaddr（vless UDP 包编码）**：无库后端——crates.io 无
  xudp/packetaddr 独立库；Xray-core 内嵌非库面；sing-vmess 为 Go 库。按真源自写：
  - 编码判定 = mihomo adapter/outbound/vless.go（2026-11-16 读源）：`packet-encoding:
    packetaddr|packet` → packetaddr，其余缺省 xudp（`packet-addr`/`xudp` 遗留布尔
    兼容）。仓内语义取：缺省 raw（Xray 原生 UDP 面，既有验收在测）、显式
    `xudp`/`packetaddr` 启用对应编码——mihomo「缺省 xudp」不镜像（文档记边界）。
  - xudp 帧 = sing-vmess v0.2.4 xudp.go 逐行（mihomo go.mod pin v0.2.5 同构）：
    首报 `[2B BE 元长][0x00 0x00][0x01 New][0x01 opt-data][0x02 NetworkUDP][地址]
    [8B GlobalID（零则省）][2B BE 载荷长][载荷]`；后续报 `[2B BE 元长][0x00 0x00]
    [0x02 Keep][0x01][0x02][地址][2B][载荷]`；下行同构（元长==4 时目标即会话目标；
    3=End→EOF、4=KeepAlive 忽略——sing 与 xray 在 3/4 语义上互换，客户端按
    「2=数据、3/4=会话收束」容忍面收束；opt 位 0x01 有载荷、0x02 对端故障）。
  - 地址序列化 = sing-vmess protocol.go AddressSerializer（port-first：
    `[2B BE port][0x01 v4 | 0x02 域名(1B 长+串) | 0x03 v6][地址]`，与 Xray
    PortThenAddress 同）。
  - vless 载具头 = mihomo transport/vless/conn.go：Mux 分支写命令 0x03 且**不带
    目标地址**（版本+uuid+addons 长+addons+0x03），目标只在首帧 New 里。
  - packetaddr 帧 = sing-vmess packetaddr/conn.go：报文 =
    `[0x01 v4 | 0x02 v6][地址][2B BE port][载荷]`（family-first、无域名面——
    ErrFqdnUnsupported）；vless 载具头 = 命令 0x02 + magic 地址
    `sp.packet-addr.v2fly.arpa`:443（packetaddr.SeqPacketMagicAddress）；上下行同构。
  - vmess 载具不自写：sing-vmess mux/chunk 流（AEAD 面）与仓内 vmess UDP 面
    （raw 单目标）不同构——vmess 非 raw 包编码构建期具名拒绝。
- **多路复用**：mihomo 出站复用面 = gRPC gun 流复用（grpc-opts
  `{max-connections, min-streams, max-streams}`——连接数上限 × 每连接流上下限）；
  smux/yamux **不在 mihomo 出站 schema**（vless/vmess/trojan 三个 Option 结构体均
  无 smux 字段；wiki 样例页残留 `smux:` 键位为无效装饰）。Rust smux 候选评估
  （2026-11-16 crates.io）：`smux` 0.2.0（iberryful，MIT，2025-07，edition 2024，
  「compatible with the Go smux protocol」）、`tokio_smux` 0.2.0（oyyd，MIT，
  2024-01）、`async_smux` 0.4.0（black-binary，MIT，2026-09）——均不引入：schema
  无 smux 面，引入即无对端。gun 流复用按 gun 语义自写（h2 0.4.19 已在仓，
  pool.rs `TransportReuse::Multiplexed` 契约位已留迄今仅测试引用），订阅
  grpc-opts 补 max-connections/min-streams/max-streams 三键位。
- **httpupgrade**：已自写交付（vless/vmess，G2-15/G3-16 回环在测）——缺口在
  订阅导出面：clash_export 无 httpupgrade 分支（network=httpupgrade 节点导出既无
  network 键也无 httpupgrade-opts，回读退化为 tcp），且 config.md/PROTOCOLS.md
  未记载。本项补齐导出分支与两语文档。
- **交付边界（点名拒绝）**：vmess 非 raw 包编码（载具未交付）；vless
  packet-encoding 白名单外取值；grpc-opts 流键位出现在非 grpc 传输（构建期拒绝）。
