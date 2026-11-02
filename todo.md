# Seep TODO

> **定位**：一个代理内核，三种场景 —— 通用代理 / 游戏加速 / 网页加速。三者共享同一条数据通路（ingress → routing → egress/transport），混淆是横切层。
>
> **设计文档**：[docs/design/positioning.md](docs/design/positioning.md) · [docs/design/roadmap.md](docs/design/roadmap.md) · [docs/architecture.md](docs/architecture.md) · [docs/mesh.md](docs/mesh.md) · [docs/PROTOCOLS.md](docs/PROTOCOLS.md)
>
> **优先级映射**：P0 → roadmap S1（UDP 全链路）；P1 → S2 + S3 前半（TUN / 混淆 MVP / 连接池）；P2 → S3 后半 + S4（调度闭环 / 安全 / profile）；P3 → 收尾（文档 / 插件 / 打包）。2026-09 对照代码核实后重排。

---

## 勘误：原清单与代码不符的条目（已重新打开）

原 todo.md 以下条目标注为 `[x]`，经 2026-09 对照代码核实为部分完成或未完成，重新归入对应优先级：

| 原条目 | 实际状态 | 去向 |
|---|---|---|
| 实现 TunIngress/TunEgress（TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel） | `seep-platform` 仅有 trait 与数据结构；各平台 Provider 为占位实现；runtime 未接线 | → P1 |
| 配置新增 network 区块（mode: tun/redir；bypass/include）+ CLI route apply/clear | `SeepConfig` 无顶层 network 区块；`seepctl` 无 route 子命令 | → P1 |
| FlowMiddleware 支持 WASM/动态库加载，示例（限速、统计、内容过滤） | 仅有 `LatencyProbe` 一个实现，无动态加载机制 | → P3（降级） |

---

## 已完成底座（对应 roadmap S0）

- [x] `GroupDescriptor` 组策略（latency/bandwidth/random/weighted 等 7 种，组嵌套）+ `RouteDecision` 表达逻辑组与最终节点（`seep-routing`）。
- [x] Mesh/协作节点模块（`seep-mesh`：注册、client/relay/exit 角色、健康上报、拓扑、ACL/配额、link-state）。
- [x] `RuntimeBuilder`/控制面消费 Mesh 拓扑构建多跳链路（源 → relay → exit）+ Dry Run 预检（`seep-runtime::chain`）。
- [x] `FlowSession/ChainContext` 多跳状态、用量统计、故障回退（`seep-core`）。
- [x] `seep-platform::network` trait 层与规则模型（`TunProvider`/`RouteManager`/`PacketFilter`/`DnsHandler`）。
- [x] `seep-subscription`：Clash 订阅转换 + 自有 DSL + 定时刷新/ETag 缓存 + 热更新；`seepctl subscription`/`import-clash`。
- [x] mesh data-plane TCP hop-by-hop 转发 + mTLS（强制策略、`seepctl mtls` 生成/轮换/CA bundle 双信任窗口/最小撤销列表）。
- [x] `seepctl diagnose` 一键诊断（控制面快照 + 脱敏配置 + 本机路由/DNS/接口 + events + logs）。
- [x] 链路 Dry Run / 策略模拟（`POST /chains/dry-run`、`seepctl chain dry-run`）。
- [x] `/metrics` Prometheus 基础指标（mesh/chain/subscription/per-link 计数）+ Grafana 模板。

---

## P0 — UDP 全链路（roadmap S1 · 游戏加速地基）

> 设计稿：[docs/design/udp-dataplane.md](docs/design/udp-dataplane.md)（技术方案、复用/新增清单与风险编号 R*/V*/O* 均在该稿）。

- [x] **P0-1 `seep-core` UDP 会话语义**：NAT 式 UDP 会话表（映射、超时回收、会话粘滞键=进程/五元组），与 `FlowSession` 打通。
  evidence：`crates/seep-core/src/udp/`（table/ledger/reclaim/config/…）· 测试 `udp_session_table.rs` 22 项 · 设计稿 `udp-session-table.md` / `udp-session-table-api.md` §9。
- [x] **P0-2 SOCKS5 UDP ASSOCIATE 入站**：按 RFC 1928 实现 UDP 中继，接入 FlowRouter。
  evidence：`udp/associate.rs` + `inbound/socks5.rs`（0x01/0x03/其他分派）+ `seep-config` `udp:` 块 + runtime 接线 · 测试 `udp_associate.rs` 13 项 · 设计稿 `udp-relay-path.md` §2。
- [x] **P0-3 出站 UDP 载荷**：direct / shadowsocks / wireguard 出站承载 UDP；hy2 按设计 §3.4 移 P0-4。
  evidence：`udp/relay.rs` + `ShadowsocksUdpConnector`/`WireguardUdpConnector` · 测试 `udp_egress_selection.rs` 3 项 + `udp_egress.rs` 7 项 + runtime 能力扫描 4 项，全仓 118 通过 · 设计稿 `udp-relay-path.md` §3。
- [x] **P0-4 mesh data-plane UDP 转发**：多跳 UDP（envelope over UDP/QUIC 数据报），与现有 TCP 面共存。
  evidence：`mesh_transport.rs` + `udp_chain.rs`（UdpChainRouter/ MeshUdpBridge/MeshUdpRelay）· P0-4 合计 27 测，全仓 145 通过 · 设计稿 `udp-mesh-dataplane.md` §S0–S6（hy2 出站维持改判 V2）。
- [x] **P0-5 UDP 观测与配置**：ingress/egress UDP 开关与超时配置；`/metrics` 增加 UDP 会话数/字节数。
  evidence：S0–S6 分步落地（一步一 commit）· P0-5 合计 25 测，全仓 170 通过 · 设计稿 `udp-observability.md` §10。

## P1 — TUN 系统接管 + 混淆 MVP（roadmap S2 + S3 前半）

- [x] **P1-1 Linux TUN 真实现**：`/dev/net/tun` + TUNSETIFF、包读写循环，替换 `platform.rs` 占位。
  evidence：T0–T2 `c076fb8`/`75c7747`/`92f12ba`（trait 裁剪+四工厂分派 / 设备生命周期+读写 / RouteManager+AppliedStep 回滚）+ T3 收口 `a9f11dc` · 设计稿 `tun-dataplane.md` §1/§5、`tun-linux-impl.md`（musl 交叉验收归 P3-3）。
- [x] **P1-2 TunIngress 接线 runtime**：IP 流重组 → `FlowContext`（注入进程/端口），TUN 作为新 ingress 类型接入。
  evidence：T3 `a9f11dc`（UDP 全链路 + `/proc` 归因）+ T4 `b5785c2`（smoltcp TCP 用户态栈）+ T5 `7a3024d`（`seep_tun_*` 指标族）+ 归因优化 `6f4b0e9`（冷归因 345→86ms）· 设计稿 `tun-dataplane.md` §2（direct 出口自环正解已由 fwmark 批落地，见待派任务）。
- [x] **P1-3 network 配置区块 + `seepctl route apply/clear`**（勘误重开）：`SeepConfig` 顶层 `network` 区块；CLI 幂等应用/撤销系统路由。
  evidence：R0/R1 `1e1a7c0` + R2–R4 `1befbe7`（RouteControl 契约 + 控制面三端点 + `seepctl route`）· 设计稿 `network-route.md` §8（MVP 不触碰 `ip rule`，全局接管归 V2）。
- [x] **P1-4 混淆中间件 MVP（padding）**：`FlowMiddleware` 形态包长填充策略，按 profile 开关。
  evidence：M0–M4 `484a4f7`/`c78f0f7`/`1c50565`/`8838f04`/`33cef4c` · 测试 37 项新增（189 基线 → 226 全绿）· 设计稿 `obfuscation-middleware.md` §8。
- [x] **P1-5 出站连接池**：同出口同 SNI keep-alive 复用 + TLS 会话恢复（网页加速核心项）。
  evidence：M0–M5 `0ecb477`/`d1d0478`/`97dbdf7`/`1e90d04`/`54df7cc` · loopback TLS 集成测 N=12（hit 11/miss 1/前台拨号 1，握手 2 full/11 resumed）· 设计稿 `egress-connection-pool.md` §9。

## P2 — 调度闭环与高级安全（roadmap S3 后半 + S4）

- [x] **P2-1 per-link 细粒度指标**：时延分布、丢包、切换原因、节点间流量。
  evidence：M1 `a9c7e11`（样本环+账本+存量缺陷修缮）+ M2 本提交（控制面+文档回填）· 设计稿 `mesh-link-observability.md`。
- [x] **P2-2 SLO 打分选路**：以 p95 RTT/丢包为目标打分，升级 `latency` 组策略；游戏 profile 默认启用。
  evidence：M1 `067577b`（SloPolicy+评分核心）+ M2 本提交（质量桥 + slo_watch watcher）· §7 五测全绿 · 设计稿 `slo-scoring.md`（「游戏 profile 默认启用」归 P2-3）。
- [x] **P2-3 场景 profile 预设**：`proxy` / `game` / `web` 三套配置模板（路由规则 + 混淆开关 + 调度目标），底层同一引擎。
  evidence：M0 `2369c0d`（机制+单测）+ M1 本提交（示例+集成测）· 设计稿 `scenario-profiles.md`。
- [x] **P2-4 混淆中间件扩展（timing/shaping）**：微抖动注入、流形状归一。
  evidence：M0 `7d56d06`（配置镜像+转换）+ M1 `16d9eb2`（两 middleware + PacedIo）+ M2 本提交 · 设计稿 `obfuscation-timing-shaping.md`。
- [x] **P2-5 客户端 TLS 指纹模拟**：uTLS 类能力挂载到出站 TLS 公共层（`tls.rs`）。
  evidence：M0 `48f633a`（hello 五元组+捕获测试）+ M1 本提交（配置面+池键+工厂）· 设计稿 `tls-fingerprint.md`（rustls 扩展集成员固定，真 uTLS 归 V2）。
- [x] **P2-6 mesh envelope 二进制化**：替换 JSON 头降低固定开销（UDP 面尤其重要）。
  evidence：M0–M1 同步完成（TCP 面补二进制编解码 + 接收侧嗅探 + `pad_len` 进二进制头）· 设计稿 `mesh-envelope-binary.md`。
- [x] **P2-7 mesh 高级安全**：UDP 面流级防重放 + 撤销生效面运行期可查；OCSP/端到端 MAC 归 V2。
  evidence：M0 `fffc103`（`revoked_snapshot()` + `GET /mtls/revoked` + `seepctl mtls revoke status`）+ M1 R2 `26e923d`（UDP 帧 v2 序号化 + `ReplayWindow` 64 位滑窗）+ R3 `7a8a209`（发送三源序号 + 接收两校验点 + `replay_dropped` 计数）+ R4 本提交（文档回填）· 设计稿 `mesh-advanced-security.md`。
- [x] **P2-8 DNS 分流**：国内外 DNS 分流、缓存、防污染，对接 `seep-platform::network::dns` 设计。
  evidence：M0 `750de34`（`dns_engine.rs` 全量 + 17 测）+ M1 本提交（`network.dns` 子块 + `DnsService` + `GET /dns/stats`）· 设计稿 `dns-partition.md`（DoT/DoH/DoQ 归 V2）。

## P3 — 文档、插件与平台发布（roadmap S4 收尾）

- [x] **P3-1 文档对齐实现**：`architecture.md` 四章节改写为现状+边界口径 + `PROTOCOLS.md` 顶部实现状态总表 + 15 处就地状态标注 + 新增 `subscription.md`/`networking.md`。
  evidence：随 P0/P1/P2 各批落地回填（P2-7 落地随回填：UDP 面滑窗防重放+计数、撤销生效面运行期可查；端到端 MAC 归 V2）。
- [x] **VMess 出站**（P2/P3 原遗留）：PROTOCOLS.md 已承诺，Clash 订阅转换会产出 vmess 节点。
  evidence：2026-10-02 落地（`outbound/vmess.rs` 约 1.9k 行 + `ws.rs` RFC6455 客户端最小面 + runtime_builder 接线，xray v1.8.24 实测互操作）· PROTOCOLS.md vmess 行与 §VMess 节已改已实现。
- [x] **P3-2 插件动态加载**（勘误降级）：WASM `FlowMiddleware` 加载器 + 限速/内容过滤示例。
  evidence：`crates/seep-plugins`（wasmtime 49，engine 进程级单例 + Store Mutex 串行化）+ `plugins/` 示例（rate-limit/content-filter）+ 控制面 `GET /plugins/stats` · 隔离面内联 WAT 单测（trap 不毒化 Store / fuel 耗尽）+ 插件宿主侧纯逻辑单测 · 设计稿 `plugin-loader.md`（同进程动态库无崩溃隔离边界，libloading 归 V2）。
- [x] **P3-3 平台打包**：systemd / launchd / Windows Service / OpenWrt init.d 模板与脚本，`platforms/` 样板完善。
  evidence：`platforms/{openwrt,systemd,windows,launchd}/`（三 ipk + 双 deb + zip 六件产出冒烟）+ windows-gnu 编译破损修复（TUN 三模块 `#[cfg(target_os="linux")]` 门控）· 设计稿 `platform-packaging.md`（L4 真平台面未验，如实登记）。
- [x] **P3-4 移动端 FFI 骨架**：Android（VpnService）/ iOS（NEPacketTunnel）cdylib + C ABI 最小通路。
  evidence：`crates/seep-ffi`（C ABI 八函数）+ `platforms/{android,ios}` · 宿主 346 测试全绿；模拟器 API33 x86_64 全链路 `ping -c 3 10.111.0.1` 三发三收（arm64 真机未验）。
- [x] **P3-5 零拷贝/批量收发**：零拷贝与批量处理描述超前且无近期落地计划，自设计口径降级为登记项；落地时以基准佐证并回填 PROTOCOLS.md。
  evidence：R0–R4（R1 relay 缓冲参数化 + R2 帧写 vectored + R3 基准 8K→256K 中位 214→357 MiB/s +67%）· 设计稿 `performance-io.md`（splice/UDP 批量收发范围外）。

## 待派任务（杂项，未入优先级序列）

- [x] **鸿蒙 FFI 填空**（aarch64-unknown-linux-ohos 编译面）：验收口径「编译过」。
  evidence：OHOS SDK 5.0.0 native 流式落 `/opt/ohos-sdk` + `.cargo/config.toml` target 段 + `aws-lc-sys` 0.45 ohos 面 + `linux.rs` ioctl 两包装特化 · `cargo check`/`cargo build` 过，ELF64/AArch64/DYN，宿主 483 测试 0 失败（L4 真机面未验）。
- [x] **hyper 0.14 → 1.x 迁移**（连带 h2 0.4，清 RUSTSEC-2026-0258）。
  evidence：`hyper 1.8.1` + `h2 0.4.19` 入锁、hyper 0.14 零残留，`cargo audit` 全绿；ci.yml 去 `--ignore`；serve() 改 `TcpListener` accept 循环 + hyper-util auto Builder + `GracefulShutdown`。
- [x] **修 CI coverage 上传与 cross 交叉 job**（含 wireguard Windows 编译门）。
  evidence：coverage `fail_ci_if_error: false` + cross 0.2.5 + darwin 出列 + windows 源码缺口修复（`WGApi<Userspace>` 门控）· 本地 `cross check` 三非 host 目标全绿零警告。
- [x] **修 CI Docker 镜像构建**。
  evidence：Dockerfile 重写（11 成员枚举 + 虚拟源桩）+ `.dockerignore` + `seepd --version` 参数面 · 本地 `docker build`（seep:test 190MB）+ `docker run --rm --version` 冒烟通过。
- [x] **修 CI 四 job 连红**（MSRV / audit / docker / coverage）。
  evidence：MSRV 基线随锁上调 1.96.0 + Dockerfile 预热层补 seep-plugins + nightly `continue-on-error` + 双步 `--locked` · 新 run 十四 job 仍红系**私有仓 Actions 配额耗尽/付款阻断**（`6c74dd1` run 37196348814，job 14 秒/runner 空/日志未上传），非代码红，配额恢复后生效。
- [x] **Trojan over WS 出站传输**（trojan-go 惯例）。
  evidence：`trojan.rs` 双路 ws（恒叠 TLS）+ `WsWriter::write_close`（Close 帧半关传播）· 验收 459 通过 0 失败。
- [x] **direct 出口 Happy Eyeballs**（RFC 8305，统一拨号面）。
  evidence：`seep_core::net_mark::connect_tcp`（`order_candidates` 双栈交错 + `connect_racing` 250ms 错峰）· `cargo test -p seep-core` 56 通过 0 失败。
- [x] **出站 fwmark 自环逃逸**（半边① SO_MARK + 半边② ip rule escape 表）。
  evidence：半边① `b72e8a4`/`f961674`/`9670d17`（`connect_tcp` SO_MARK + 9 处接线）+ 半边② `83e6393`（`ip rule add fwmark` escape 表）+ CI 连红修复 `270e654` · `net_mark` 7 测全绿（真实逃逸以带 CAP_NET_ADMIN 的 TUN 环境实测为准）。
- [x] **VLESS flow 构建期校验**。
  evidence：RuntimeBuilder Vless arm 装配前 `flow.is_some()` 即报错（错误含节点名）· 新增 `build_egress_outputs_rejects_vless_flow_at_build_time`（拒绝 + 缺省照常装配两态）。
- [x] **入站认证补全（Mixed/Http）**。
  evidence：`IngressConfig::Mixed`/`Http` 加 `auth` 字段 + `HttpIngress` `Proxy-Authorization: Basic` 校验（407 + `Proxy-Authenticate: Basic realm="seep"`）· 测试 8 新增。
- [x] **SS 出站 SIP003 插件桥**（v2ray-plugin/obfs 等）。
  evidence：`Shadowsocks` 加 `plugin`/`plugin_opts` + SIP003 四环境变量 + 就绪探测（探测连接复用为 outbound）+ 子进程随连接收尾 · 测试 3 新增（UDP 面 plugin 模式判负，构建期报错）。
- [x] **clash 订阅 SS 插件导入换算**（SIP003）。
  evidence：`ClashProxy` 加 `plugin_opts` + `clash_ss_plugin_to_sip003`（obfs 族/v2ray-plugin 键值透传，嵌套结构拒导）· 测试 3 新增（未知插件拒导含插件名断言）。
- [x] **出站 gRPC 传输**（trojan/vless/vmess + clash grpc-opts 导入导出）。
  evidence：`outbound/grpc.rs`（h2 客户端握手 + 5 字节前缀帧）+ 三协议接线 + 订阅面 grpc-opts · 验收 469 通过 0 失败、clippy 零警告。
- [x] **出站 h2 传输**（vless/vmess + clash h2-opts 导入导出）。
  evidence：`outbound/h2.rs`（h2_tunnel + H2Stream 裸字节流）+ 两协议接线 + 订阅面 h2-opts · 验收全绿 0 失败（run 37974566358，14/14 job）。
- [x] **rustls-pemfile 出仓**（RUSTSEC-2025-0134）+ **UDP 能力报错口径过时修正**。
  evidence：`rustls-pki-types`（PemObject API）直迁，锁内 rustls-pemfile 清零；`scan_udp_capability` 错误消息改「hysteria2 归 V2，载具 quinn 未决」· audit 剩 2 条传递 warning。
- [x] **依赖处置：shadowsocks 1.25 + defguard_wireguard_rs 0.11**（清 paste/spin 两条传递 warning）。
  evidence：`cargo update -p shadowsocks --precise 1.25.0`（spin→0.12.3）+ `-p defguard_wireguard_rs --precise 0.11.2`（paste 出锁）· audit **0 warning**。
- [x] **HTTP 入站 Bearer Token 认证**。
  evidence：`IngressConfig::Http`/`Mixed` 加 `bearer_tokens` + `verify_bearer_auth`（RFC 6750）+ 407 按已配置 scheme 动态通告 · 测试 7 新增（483 passed），clippy 零警告。

---

## 统计

| 优先级 | 条目 | 对应阶段 | 状态 |
|---|---|---|---|
| P0 | 5 | S1 UDP 全链路 | 5/5（P0-1 会话表、P0-2 ASSOCIATE、P0-3 出站载荷、P0-4 mesh UDP 面、P0-5 观测与配置，S0–S6 全部落地） |
| P1 | 5 | S2 TUN + S3 前半 | 5/5（P1-1/P1-2 2026-10-03 收口、P1-3 2026-10-03 收口、P1-4 M0–M4、P1-5 M0–M5） |
| P2 | 8 | S3 后半 + S4 | 8/8（P2-7 2026-10-04 落地，余项 2026-10-02 全步落地） |
| P3 | 5+1 | S4 收尾 | 6/6（P3-1 文档对齐、VMess 出站 2026-10-02、P3-2 插件、P3-3 平台打包、P3-4 移动端 FFI、P3-5 零拷贝（范围）） |

已完成底座（S0）条目见上文归档清单；原 19 条清单中 10 项核实为真实完成、3 项勘误重开、其余并入 P0–P3 对应条目。
