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
- **公开 API**（规划）：`HysteriaConnector`/`HysteriaUdpConnector` +
  `HysteriaIngress`（规划路径 crates/rillane-protocols/src/outbound/hysteria.rs +
  inbound/hysteria.rs）——认证握手走控制流（版本字节 + 官方 `struc` 形状的
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
