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
- **版本**：要求 `1.25`（default-features=false + aead-cipher），lock
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
- 算法矩阵以实际依赖/校验为准（RIL-131 前置留证）。

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

- **结论**：自写（同 vmess——REALITY 依赖 ClientHello 字节级控制，
  rustls 路线不支持；RIL-107 按注册规范单独评估）
- **版本**：仓库内实现
- **许可**：本仓库许可（自写）
- **平台**：全平台
- **公开 API**：`VlessConnector`（crates/rillane-protocols/src/outbound/vless.rs）
- **旁路**：与传输工厂组合
- **取消**：建立期检查
- **统计**：flow/REALITY 拨号期点名拒绝（G1-6——配置保留不判负，防静
  默降级）
- **复用**：无预热组合；UDP 面（仅 network=tcp）同节点配置
- UDP：仅 network=tcp。

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
