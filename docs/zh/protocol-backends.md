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

**未准入**——无已评审后端。配置 schema 与订阅字段存在不代表连接器
（PROTOCOLS.md 同口径）：装配期以稳定原因码 `config.egress.not_admitted`
拒绝，不静默当 direct。

- 前置：RIL-109 选库评估（版本/许可/平台/公开 API/旁路/取消/统计/复用
  逐项留证）；UDP 载具 quinn 未决。
- 恢复路径：评估记录补齐 → 目录条目改准入 → 连接器接线 → 真实对端验收。

## hysteria2

- **结论**：选库 `hysteria2`
- **版本**：要求 `0.1.6`，lock 实测 0.1.6
- **许可**：MulanPSL-2.0
- **平台**：以目标平台 QUIC（quinn 生态）支持为准
- **公开 API**：`Hysteria2Connector`（crates/rillane-protocols/src/outbound/hysteria2.rs；
  TCP stream over QUIC）
- **旁路**：库承载 QUIC 会话——连接器不做底层 socket 旁路
- **取消**：建立期检查 + 库会话关闭面
- **统计**：库无逐包观测点——loss 类统计不可用（不伪装游戏丢包率，
  mesh.md 观测口径同源）
- **复用**：无预热组合
- UDP：当前连接器没有可用 UDP 出口（载具 quinn 未决，归 V2；构建期
  扫描判负口径一致）。

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
