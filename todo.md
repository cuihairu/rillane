# Rillane TODO

> **定位**：一个代理内核，三种场景 —— 通用代理 / 游戏加速 / 网页加速。三者共享同一条数据通路（ingress → routing → egress/transport），混淆是横切层。
>
> **设计文档**：[docs/design/positioning.md](docs/design/positioning.md) · [docs/design/roadmap.md](docs/design/roadmap.md) · [docs/architecture.md](docs/architecture.md) · [docs/mesh.md](docs/mesh.md) · [docs/PROTOCOLS.md](docs/PROTOCOLS.md)
>
> **优先级映射**：P0 → roadmap S1（UDP 全链路）；P1 → S2 + S3 前半（TUN / 混淆 MVP / 连接池）；P2 → S3 后半 + S4（调度闭环 / 安全 / profile）；P3 → 收尾（文档 / 插件 / 打包）。2026-09 对照代码核实后重排。

---

## 勘误：原清单与代码不符的条目（已重新打开）

2026-11-14 架构研究更新：拉取/转换/重载链路不等于完整 Clash/Mihomo 兼容，provider/use、规则集、进程规则导入及组策略保真仍有缺口。见 [源码研究](docs/zh/research/proxy-architectures-2026-11-14.md)；新架构 [RV2-01–RV2-24 工作包](docs/zh/design/architecture-v2.md#migration) **全部待实施**，包含六平台、订阅兼容、本地三桌面进程分流、网页/游戏并行与测量门禁。Android/iOS/OpenWrt 不要求桌面进程归因。下方历史完成项按当时验收范围保留，不据此宣称新方案已交付。

- [x] 架构研究文档交付：Mihomo Meta / sing-box testing 源码快照、Surge 官方功能模型、32 个概念的职责/抽象理由/收益/代价、5 张可重建 SVG、六平台目标与迁移门禁；这是设计交付，非实现完成。
- [ ] 按 RV2-01–RV2-24 顺序实施架构迁移；每包依赖与验收见目标方案表，完成须补代码/fixture/平台证据。

原 todo.md 以下条目标注为 `[x]`，经 2026-09 对照代码核实为部分完成或未完成，重新归入对应优先级：

| 原条目 | 实际状态 | 去向 |
|---|---|---|
| 实现 TunIngress/TunEgress（TUN/TAP/Wintun/utun/VpnService/NEPacketTunnel） | `rillane-platform` 仅有 trait 与数据结构；各平台 Provider 为占位实现；runtime 未接线 | → P1 |
| 配置新增 network 区块（mode: tun/redir；bypass/include）+ CLI route apply/clear | `RillaneConfig` 无顶层 network 区块；`rillanectl` 无 route 子命令 | → P1 |
| FlowMiddleware 支持 WASM/动态库加载，示例（限速、统计、内容过滤） | 仅有 `LatencyProbe` 一个实现，无动态加载机制 | → P3（降级） |

---

## 已完成底座（对应 roadmap S0）

- [x] `GroupDescriptor` 组策略（latency/bandwidth/random/weighted 等 7 种，组嵌套）+ `RouteDecision` 表达逻辑组与最终节点（`rillane-routing`）。
- [x] Mesh/协作节点模块（`rillane-mesh`：注册、client/relay/exit 角色、健康上报、拓扑、ACL/配额、link-state）。
- [x] `RuntimeBuilder`/控制面消费 Mesh 拓扑构建多跳链路（源 → relay → exit）+ Dry Run 预检（`rillane-runtime::chain`）。
- [x] `FlowSession/ChainContext` 多跳状态、用量统计、故障回退（`rillane-core`）。
- [x] `rillane-platform::network` trait 层与规则模型（`TunProvider`/`RouteManager`/`PacketFilter`/`DnsHandler`）。
- [x] `rillane-subscription`：Clash 订阅转换 + 自有 DSL + 定时刷新/ETag 缓存 + 热更新；`rillanectl subscription`/`import-clash`。
- [x] mesh data-plane TCP hop-by-hop 转发 + mTLS（强制策略、`rillanectl mtls` 生成/轮换/CA bundle 双信任窗口/最小撤销列表）。
- [x] `rillanectl diagnose` 一键诊断（控制面快照 + 脱敏配置 + 本机路由/DNS/接口 + events + logs）。
- [x] 链路 Dry Run / 策略模拟（`POST /chains/dry-run`、`rillanectl chain dry-run`）。
- [x] `/metrics` Prometheus 基础指标（mesh/chain/subscription/per-link 计数）+ Grafana 模板。

---

## P0 — UDP 全链路（roadmap S1 · 游戏加速地基）

> 设计稿：[docs/design/udp-dataplane.md](docs/design/udp-dataplane.md)（技术方案、复用/新增清单与风险编号 R*/V*/O* 均在该稿）。

- [x] **P0-1 `rillane-core` UDP 会话语义**：NAT 式 UDP 会话表（映射、超时回收、会话粘滞键=进程/五元组），与 `FlowSession` 打通。
  evidence：`crates/rillane-core/src/udp/`（table/ledger/reclaim/config/…）· 测试 `udp_session_table.rs` 22 项 · 设计稿 `udp-session-table.md` / `udp-session-table-api.md` §9。
- [x] **P0-2 SOCKS5 UDP ASSOCIATE 入站**：按 RFC 1928 实现 UDP 中继，接入 FlowRouter。
  evidence：`udp/associate.rs` + `inbound/socks5.rs`（0x01/0x03/其他分派）+ `rillane-config` `udp:` 块 + runtime 接线 · 测试 `udp_associate.rs` 13 项 · 设计稿 `udp-relay-path.md` §2。
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
  evidence：T3 `a9f11dc`（UDP 全链路 + `/proc` 归因）+ T4 `b5785c2`（smoltcp TCP 用户态栈）+ T5 `7a3024d`（`rillane_tun_*` 指标族）+ 归因优化 `6f4b0e9`（冷归因 345→86ms）· 设计稿 `tun-dataplane.md` §2（direct 出口自环正解已由 fwmark 批落地，见待派任务）。
- [x] **P1-3 network 配置区块 + `rillanectl route apply/clear`**（勘误重开）：`RillaneConfig` 顶层 `network` 区块；CLI 幂等应用/撤销系统路由。
  evidence：R0/R1 `1e1a7c0` + R2–R4 `1befbe7`（RouteControl 契约 + 控制面三端点 + `rillanectl route`）· 设计稿 `network-route.md` §8（MVP 不触碰 `ip rule`，全局接管归 V2）。
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
  evidence：M0 `fffc103`（`revoked_snapshot()` + `GET /mtls/revoked` + `rillanectl mtls revoke status`）+ M1 R2 `26e923d`（UDP 帧 v2 序号化 + `ReplayWindow` 64 位滑窗）+ R3 `7a8a209`（发送三源序号 + 接收两校验点 + `replay_dropped` 计数）+ R4 本提交（文档回填）· 设计稿 `mesh-advanced-security.md`。
- [x] **P2-8 DNS 分流**：国内外 DNS 分流、缓存、防污染，对接 `rillane-platform::network::dns` 设计。
  evidence：M0 `750de34`（`dns_engine.rs` 全量 + 17 测）+ M1 本提交（`network.dns` 子块 + `DnsService` + `GET /dns/stats`）· 设计稿 `dns-partition.md`（DoT/DoH/DoQ 归 V2）。

## P3 — 文档、插件与平台发布（roadmap S4 收尾）

- [x] **P3-1 文档对齐实现**：`architecture.md` 四章节改写为现状+边界口径 + `PROTOCOLS.md` 顶部实现状态总表 + 15 处就地状态标注 + 新增 `subscription.md`/`networking.md`。
  evidence：随 P0/P1/P2 各批落地回填（P2-7 落地随回填：UDP 面滑窗防重放+计数、撤销生效面运行期可查；端到端 MAC 归 V2）。
- [x] **VMess 出站**（P2/P3 原遗留）：PROTOCOLS.md 已承诺，Clash 订阅转换会产出 vmess 节点。
  evidence：2026-10-02 落地（`outbound/vmess.rs` 约 1.9k 行 + `ws.rs` RFC6455 客户端最小面 + runtime_builder 接线，xray v1.8.24 实测互操作）· PROTOCOLS.md vmess 行与 §VMess 节已改已实现。
- [x] **P3-2 插件动态加载**（勘误降级）：WASM `FlowMiddleware` 加载器 + 限速/内容过滤示例。
  evidence：`crates/rillane-plugins`（wasmtime 49，engine 进程级单例 + Store Mutex 串行化）+ `plugins/` 示例（rate-limit/content-filter）+ 控制面 `GET /plugins/stats` · 隔离面内联 WAT 单测（trap 不毒化 Store / fuel 耗尽）+ 插件宿主侧纯逻辑单测 · 设计稿 `plugin-loader.md`（同进程动态库无崩溃隔离边界，libloading 归 V2）。
- [x] **P3-3 平台打包**：systemd / launchd / Windows Service / OpenWrt init.d 模板与脚本，`platforms/` 样板完善。
  evidence：`platforms/{openwrt,systemd,windows,launchd}/`（三 ipk + 双 deb + zip 六件产出冒烟）+ windows-gnu 编译破损修复（TUN 三模块 `#[cfg(target_os="linux")]` 门控）· 设计稿 `platform-packaging.md`（L4 真平台面未验，如实登记）。
- [x] **P3-4 移动端 FFI 骨架**：Android（VpnService）/ iOS（NEPacketTunnel）cdylib + C ABI 最小通路。
  evidence：`crates/rillane-ffi`（C ABI 八函数）+ `platforms/{android,ios}` · 宿主 346 测试全绿；模拟器 API33 x86_64 全链路 `ping -c 3 10.111.0.1` 三发三收（arm64 真机未验）。
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
  evidence：Dockerfile 重写（11 成员枚举 + 虚拟源桩）+ `.dockerignore` + `rillaned --version` 参数面 · 本地 `docker build`（rillane:test 190MB）+ `docker run --rm --version` 冒烟通过。
- [x] **修 CI 四 job 连红**（MSRV / audit / docker / coverage）。
  evidence：MSRV 基线随锁上调 1.96.0 + Dockerfile 预热层补 rillane-plugins + nightly `continue-on-error` + 双步 `--locked` · 新 run 十四 job 仍红系**私有仓 Actions 配额耗尽/付款阻断**（`6c74dd1` run 37196348814，job 14 秒/runner 空/日志未上传），非代码红，配额恢复后生效。
- [x] **Trojan over WS 出站传输**（trojan-go 惯例）。
  evidence：`trojan.rs` 双路 ws（恒叠 TLS）+ `WsWriter::write_close`（Close 帧半关传播）· 验收 459 通过 0 失败。
- [x] **direct 出口 Happy Eyeballs**（RFC 8305，统一拨号面）。
  evidence：`rillane_core::net_mark::connect_tcp`（`order_candidates` 双栈交错 + `connect_racing` 250ms 错峰）· `cargo test -p rillane-core` 56 通过 0 失败。
- [x] **出站 fwmark 自环逃逸**（半边① SO_MARK + 半边② ip rule escape 表）。
  evidence：半边① `b72e8a4`/`f961674`/`9670d17`（`connect_tcp` SO_MARK + 9 处接线）+ 半边② `83e6393`（`ip rule add fwmark` escape 表）+ CI 连红修复 `270e654` · `net_mark` 7 测全绿（真实逃逸以带 CAP_NET_ADMIN 的 TUN 环境实测为准）。
- [x] **VLESS flow 构建期校验**。
  evidence：RuntimeBuilder Vless arm 装配前 `flow.is_some()` 即报错（错误含节点名）· 新增 `build_egress_outputs_rejects_vless_flow_at_build_time`（拒绝 + 缺省照常装配两态）。
- [x] **入站认证补全（Mixed/Http）**。
  evidence：`IngressConfig::Mixed`/`Http` 加 `auth` 字段 + `HttpIngress` `Proxy-Authorization: Basic` 校验（407 + `Proxy-Authenticate: Basic realm="rillane"`）· 测试 8 新增。
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

## 2026-11-01 代码深审发现（P2/P3，源自 docs/review/2026-11-01-code-review.md）

P2（下一步修）：
- [x] **订阅缓存 cleanup 持 memory_cache 写锁跨同步磁盘 IO**——`:360/:411/:470`（cleanup→fs::remove_file）。异步上下文阻塞执行线程并串行化全部缓存操作。
  evidence：`cache.rs:150` `memory_cache.write()` 持锁调 `load_from_disk`（fs::read_to_string）。
  已修一半（2026-11-02 `bec9785`）：get() 持锁跨 load_from_disk 实为**自锁死锁**（:557 重取同锁，RwLock 不可重入；重启带热盘缓存/条目过期两路径必触），非仅阻塞——守卫先行释放再交 load_from_disk，2 回归测试；本条剩余面仅 cleanup 同步 IO 一项。
  **已修全（2026-11-03 `12c35ee`）**：三个 cleanup 的磁盘删除移到所有锁外（`cache.rs:418/486/548`），内存突变在锁内、磁盘路径收集后锁外删除；回归 3 测（cleanup_expired/cleanup_lru/cleanup_lru_by_count），8 缓存测全绿。
- [x] **配置热交换非原子（check-then-act）**——`runtime_builder.rs:1120-1146` / `update_config:1384-1408`：读 config → 长 await（egress 构建拨号）→ 四次独立写（config/router/flow_outputs/egress_connectors）。窗口内丢失更新 + 路由表引用未就绪 egress 名。
  evidence：2026-11-03 修复——新增 `Runtime.config_apply_lock`（tokio Mutex，三方共用：update_config / merge_config_delta / 订阅刷新循环），覆盖「读 config→构建 egress→落四态」全程；写序改为 flow_outputs→egress_connectors→router.reload→config（先装 egress 面再 reload 路由，消除「规则引用未就绪名」窗口）。回归：`update_config_waits_for_config_apply_lock` + `concurrent_merge_config_delta_keeps_both_deltas`。
- [x] **mesh TLS 重载在 write 锁下做同步文件 IO**——`mesh_transport.rs:2136-2153` `maybe_reload`：`inner.write().await` 下 `MeshTlsInner::load` 读 CA/私钥/吊销列表；慢盘阻塞所有 mesh 握手快路径。generation 双检正确，仅 IO-under-lock 问题。
  evidence：`mesh_transport.rs` `let mut guard = self.inner.write().await;` 后同步 fs 读。
  **已修（2026-11-03）**：`maybe_reload` 增 `reload_lock` 串行门（tokio Mutex），磁盘载入移出 `inner` 写锁并经 `spawn_blocking`（`mesh_transport.rs:2155-2192`）；写锁仅覆盖内存交换短临界，三处双检保留；回归 `maybe_reload_reloards_only_on_fingerprint_change`（真实 rcgen 证书夹具，指纹不变不重载/触摸触发重载），rillane-runtime 138+2 测全绿。
- [x] **DNS 解析缓存未命中 stampede**——`dns_engine.rs:695-738`：N 并发冷名全部 miss 全部上游 `query_group`/`cross_check` 再各自插入，无 singleflight；突发时击穿上游解析器。
  evidence：`dns_engine.rs:695` check-then-act，`724/726` await 上游后 `728` insert。
  **已修（2026-11-03）**：`DnsResolver` 增 `inflight`（tokio Mutex<HashMap<键, watch::Sender>>）singleflight——首个调用者查上游并经 watch 广播结果（含负缓存），其余等待者直接取结果不重复查；tokio Mutex 守卫可跨 await 且锁不跨上游查询。回归 `resolver_concurrent_cold_miss_singleflight`（8 并发同名 miss → 上游到达计数 1），rillane-platform 49 测全绿。
- [x] **control-plane 无 token 时鉴权门整体跳过**——`control_plane.rs:129-140`：`admin_token=None`（serde 缺省）+ 非回环 `api_bind` 时 mutating 端点与 `/runtime/config`、`/events`、`/logs` 全开放。建议非回环绑定无 token 时启动告警/拒启。
  evidence：`control_plane.rs:135-137` `(is_mutating||is_sensitive_read) && admin_token.is_some() && !is_authorized`——None 即短路放行。注释 "if token configured" 示有意设计，故 P2。
  **已修（2026-11-03）**：`rillaned` 启动路径（`main.rs`）fail-closed——`api_bind` 非回环且 `admin_token=None` 时拒启（bail，错误含绑定地址与处置建议）；回环绑定保留无 token 能力（本机开发/诊断）。rillaned 27+2 测全绿。

P3（收尾）：
- [x] **hysteria2 连接器持 client mutex 跨 QUIC/HTTP3 握手**——`hysteria2.rs:119-124`：cache-miss 持锁跨 `connect_client()`（秒级或挂起拨号）；有意的 single-flight（防连接风暴），但握手无显式超时则永久钉住全部该出站流。建议 connect 超时。
  evidence：`hysteria2.rs:119` `client.lock().await` 持至 `:124` `connect_client().await?` 完成。
  **已修（2026-11-03）**：`get_or_connect_client` 的 `connect_client()` 包 `tokio::time::timeout(CONNECT_TIMEOUT=15s)`——挂起握手超时后失败释放互斥、不缓存半成品（fail-closed），后续调用可重试；single-flight 语义保留。rillane-runtime `build_egress_outputs_supports_hysteria2` 测绿，rillane-protocols clippy 零警告。
- [x] **无界 pong/keepalive 通道**——`vless.rs:630` / `trojan.rs:473` / `vmess.rs:1349` `mpsc::unbounded_channel`：对端洪泛 PONG 时队列无界内存增长（流量生命周期有界）。
  **已修（2026-11-03）**：`WsReader::pong_tx` 改有界 `mpsc::Sender<Vec<u8>>(64)`；PONG 帧经 `try_send`（满则丢弃控制帧，不阻塞读帧、不积压）。三调用点（vless/trojan/vmess）统一改 `mpsc::channel(64)`。rillane-protocols 71+5+6+7 测全绿，clippy 零警告。
- [x] **mesh 信封 `as u8` 长度截断**——`mesh_transport.rs:379-386/616-631`（flow_id/target_host/path 长度）+ `trojan.rs:99` / `udp/associate.rs:96`（域名长度）：无 `>255` 守卫，超长静默截断长度字节产畸形帧；对照 `vless.rs:165` 有守卫。
  **已修（2026-11-03）**：`trojan::build_request` 与 `encode_udp_header`（SOCKS5 UDP）加 `>255` 守卫（拒发畸形帧，返回 Result/错误）。`encode_mesh_envelope_binary` 已含 flow_id/target_host/path 守卫（mesh_transport.rs:366-375/580-589），无需改动。rillane-core 26+13+3+4+10 测、rillane-protocols 71+5+6+7 测全绿，clippy 零警告。
- [x] **padding.rs range span 下溢**——`middleware/padding.rs:71` `spec.max - spec.min + 1`：仅 config validate 保证 min≤max；绕过校验（或未来路径）即 usize wrap。
  **已修（2026-11-03）**：`decide_padding` range 分支健壮化——`max < min` 时回退为固定 min（`(hi-lo+1).max(1)` 保证 span≥1，防 `% 0` panic）；掷点确定性保留。回归 `range_mode_max_below_min_does_not_panic`，rillane-protocols 72+5+6+7 测全绿，clippy 零警告。
- [x] **rillane-core 链路质量 NaN**——`rillane-core/lib.rs:744-745`：`hop_bandwidths` 空而 `hop_latencies` 非空时 `0.0/0.0=NaN` 传播进 `calculate_quality_score`；两 pub 向量常规同长（update_path），需外部独立变更。
  **已修（2026-11-03）**：`calculate_quality_score` 判 `hop_bandwidths.is_empty()`（与 latencies 同判）——任一为空视为无有效样本，回退 `reliability_score`（非 NaN）。回归 `quality_score_no_nan_when_bandwidths_empty`，rillane-core 11+4+13+3+26 测全绿，clippy 零警告。
- [x] **非常量时间认证比对**——`inbound/http.rs:262/276` + `socks5.rs:253` + `control_plane.rs:266`：`String ==` 短路径；网络时序攻击对本地代理密码实际难利用，防御纵深。
  **已修（2026-11-03）**：`rillane_core::constant_time_eq`（字节切片恒时 XOR 累积，异长亦完整遍历长侧防长度侧信）替换三处明文 `==`（http.rs Basic+Bearer / socks5.rs 用户名密码 / control_plane.rs admin_token Bearer+X-Admin-Token）。回归 `constant_time_eq_matches_and_rejects`，rillane-core 12+4+13+3+26、rillane-protocols 72+5+6+7、rillaned 27 测全绿，clippy 零警告。
- [x] **runtime 无限循环任务无 stop 标志、JoinHandle 丢弃**——`runtime_builder.rs:1007-1225/2924-2954`（mesh stats/chain health/mesh quality/health checker/topology updater）+ `pool.rs:714-725`（sweeper）：重载路径每轮泄漏一组 loopers（各持 Arc）；单进程守护进程生命周期内良性，rillaned 以进程退出掩盖。
  **已修（2026-11-03 `e9612ff`）**：runtime 三条周期 loop（mesh stats :1017 / chain stats :1210 / mesh quality :1236）改 `while *running.read()` 受 `stop()`（:1368 置 false）控制；pool sweeper 增 `sweeper_running` AtomicBool（pool.rs:346）+ `stop_sweeper()`（pool.rs:738），`Runtime::stop` 接线（runtime_builder.rs:1373）；mesh registry 内嵌 health/topology updater 生命周期与 registry 同属（单进程 daemon 退出即回收，重载不重建 registry）。回归 `sweeper_stops_after_stop_flag`，rillane-protocols 16 测 + rillane-runtime 138 测全绿，clippy 零警告。
- [x] **DNS start() shutdown_tx mutex 跨 await**——`dns_engine.rs:1072-1086`：持 `shutdown_tx` tokio mutex 跨取 `task` 与 spawn；生命周期串行化，有界。
  **已修（2026-11-03 `b880ad4`）**：`start()`/`stop()` 统一锁序 task→shutdown_tx；`shutdown_tx` 获取后仅同步赋值/发送，不再跨 `task.lock().await`（dns_engine.rs:1116-1128/1132-1140）。rillane-platform 49 测全绿，clippy 零警告。
- [x] **FFI raw-pointer 别名（UB 风险）**——`rillane-ffi/lib.rs`：`rillane_ffi_tun_start/stop` 取 `&mut *handle` 而 `is_running/stats_json` 取 `&*handle`；内嵌方并发调用即数据竞争 UB，无内部同步。
  **已修（2026-11-03 `e9741a7`）**：`rillane_ffi_tun_start`/`rillane_ffi_tun_stop`/`stop_inner`/`tun_start_inner`/`tun_stop_inner` 改取 `&FfiHandle`——`FfiHandle` 内全部可变面已走内部可变性（`tun_stop` AtomicBool / `tun_thread` Mutex / `tun_fd` AtomicI32），共享引用即可完成；消除 `&mut *handle` 与 `&*handle` 跨线程别名（lib.rs:221/238/271/316/326）。rillane-ffi 10 测全绿，clippy 零警告。
- [x] **connect_racing 落选候选不中止**——`net_mark.rs:111-145`：胜出后落选拨号任务不自中止（channel drop 时自终止），慢候选短暂持套接字/TLS 握手。
  **已修（2026-11-03 `1623604`）**：`connect_racing` 收集在途 `JoinHandle`，胜出时 `abort()` 全部落选候选（net_mark.rs:98-170）——取消在途拨号/握手，资源随取消释放，不再持 socket 等待超时。回归 `racing_winner_aborts_in_flight_losers`（次选指向不可达段，首选胜出即时返回即证 abort），rillane-core 13 测全绿，clippy 零警告。
- [x] **订阅刷新 read-modify-write 复活已删订阅**——`subscription/lib.rs:380-455`：`refresh_subscription` 克隆后长 fetch，`update_subscription_in_map` 回写；fetch 期间热更删除的订阅被复活。
  **已修（2026-11-04 `40d986c`）**：`SubscriptionManager` 增 `subscription_epoch`（AtomicU64，删除/重载递增）；`refresh_subscription` 在克隆快照时同步读 epoch，写回改走 `update_subscription_in_map_checked`——epoch 已变（订阅被删）即跳过插入，不复活旧状态。回归 `refresh_does_not_revive_subscription_removed_during_fetch`（本地慢端点，fetch 中删除，断言 map 无该键；未修复时该测试红）。evidence：`crates/rillane-subscription/src/lib.rs:346` / `:383-391` / `:598-617` / `:736-781`；`cargo test -p rillane-subscription` 57 测 + `cargo test --workspace` 全绿。
- [x] **process 归因缓存重复工作**——`tun_process.rs:165-178`：并发 miss 重复扫 /proc 并插入等价值；幂等仅性能。
  **已修（2026-11-04 `6499b63`）**：`attribute` 增 inflight 单flight（OnceCell+Notify，同 key 并发 miss 合并为一次扫描，其余等待复用；完成后移除 cell 保 TTL 过期重扫）。回归 `concurrent_miss_singleflights_one_scan`（8 并发断言 scan_count=1，TTL 过期后重扫=2；禁用合并时测试红 scan_count=8）。evidence：`crates/rillane-runtime/src/tun_process.rs:140-152` / `:186-227` / `:347-411`；rillane-runtime 139+1 测 + `cargo test --workspace` 全绿。
- [x] **事件广播 fire-and-forget**——`runtime_builder.rs:538`：`broadcast::channel(1024)` 首 receiver 丢弃；生产 `ControlPlane::new` 立即订阅且 Lagged 已处理，订阅前事件静默丢失。
  **已修（2026-11-04 `f7a61cc`）**：`spawn_event_log_task` 从 `serve()` 提前到 `ControlPlane::new()` 构造完成即订阅（早于 `runtime.start()`），消除「new 后/serve 前」事件丢弃窗口；`serve()` 不再重复订阅。回归 `events_before_serve_are_captured`（new 后 update_config 触发 ConfigUpdated，断言 /events 含该事件；订阅移回 serve 时测试红 /events 空）。evidence：`apps/rillaned/src/control_plane.rs:58-63` / `:3324-3351`；rillaned 28 测 + `cargo test --workspace` 全绿。
- [x] **TUN 设备锁全生命周期持有**——`tun_ingress.rs:221-268`：`tun.lock()` 跨多 await 持进程生命周期；有意单主设计，正确性依赖该不变式。
  **核查保留（2026-11-04）**：确认为有意设计而非缺陷——`run_internal` 单任务独占 `tun_guard` 贯穿设备生命周期（创建→configure→包循环→teardown→销毁），`packet_loop` 注释明确「guard 已由本循环独占，无锁竞争面」（`tun_ingress.rs:309-314`）；select 四事件枚举模式依赖该独占不变式，拆锁反而引入并发读写/事件序风险。全锁生命周期是设备独占语义的正确实现，无外部条件缺失，不修；代码与注释已自证设计。evidence：`crates/rillane-runtime/src/tun_ingress.rs:221` / `:268` / `:303-314`；rillane-runtime 139+1 测全绿（本轮 `cargo test --workspace` 通过）。
- [x] **poll_read/poll_write 内 std Mutex**——`tun_tcp.rs:502,538`：无 await 持锁（短临界），争用下可 stall tokio worker。
  **核查保留（2026-11-04）**：`StackInner` 单锁注释明确「全同步、不跨 await」（`tun_tcp.rs:163`）；`poll_read`/`poll_write` 临界区仅做 `flow_live`/`recv_slice`/`send_slice` 等 smoltcp 纯内存操作（无 IO/await，微秒级），之后立即 drop(inner) 并 notify。这是 Rust 标准做法：短同步临界用 std Mutex（tokio Mutex 更重且为跨 await 设计）；换锁反而增加开销且无法消除单状态竞争。该条目是可接受设计而非缺陷，不改。
- [x] **DefaultHasher 缓存文件名**——`cache.rs:584-595`：确定性哈希（跨进程稳定），非密码用途可接受；文件名碰撞极低。
  **核查保留（2026-11-04）**：确认 `DefaultHasher::new()` 为固定 key 的 SipHasher13（std 文档：固定 key），跨进程稳定，**非** RandomState；仅作缓存文件名（非密码/非安全用途），64-bit 碰撞概率极低。经实验验证：两个独立 `SubscriptionCache` 实例同 key 的 `get_disk_path` 一致（DefaultHasher 版通过确定性测试），设计正确不改。evidence：`crates/rillane-subscription/src/cache.rs:729-738`。
- [x] **wasmtime Engine 初始化 expect**——`plugins/loader.rs:26`：进程级全局 `LazyLock` init，平台不支持/feature 不匹配时首插件加载即 panic（罕见且致命）。
  **已修（2026-11-04 `59a7745`）**：`ENGINE` 改 `LazyLock<Result<wasmtime::Engine, String>>`，`engine()` 返回 `Result`，`load_plugin_from_bytes` 以 `?` 传播 `Err` 而非 panic——引擎初始化失败可观测可降级，不再首插件加载即杀进程。evidence：`crates/rillane-plugins/src/loader.rs:22-34` / `:58-60`；rillane-plugins 10 测 + `cargo test --workspace` 全绿。
- [x] **TLS CryptoProvider get_default().expect**——`protocols/tls.rs:57`：ring feature 缺失或竞争 provider 时首次 TLS 握手 panic；`let _ =` 忽略 install 失败致仅剩 expect。
  **已修（2026-11-04 `4ad96fe`）**：`tls_crypto_provider` 的 `get_default().expect` 移除——`get_default()` None 时回退显式 `ring::default_provider()`（`install_default` Err=已有安装，尊重既有），调用方总获可用提供方，不再 panic。evidence：`crates/rillane-protocols/src/tls.rs:51-60`；rillane-protocols 71+6+7 测 + `cargo test --workspace` 全绿。
- [x] **HotReloadManager Default panic + reload_rx 一次性槽位**——`hot_reload.rs:623`（Default 恒 panic）/`:353`（`take().expect("reload_rx already taken")`）：现无双重调用，不变式仅由 expect 维持。
  **已修（2026-11-04 `233950f`）**：`handle_reload_events` 的 `take().expect("reload_rx already taken")` 改为 match——`None`（二次 start / 外部 take_reload_rx 已取走）时 warn 并静默 return，不再 panic。`Default` 恒 panic 保留为显式 API 拒绝（`HotReloadManager` 需 config_path/router，不可 Default，注释已声明）；不变式不再依赖运行时 expect。回归 `handle_reload_events_after_rx_taken_returns_quietly`（先 take 再调用，未修复 panic/修复后返回）。evidence：`crates/rillane-runtime/src/hot_reload.rs:356-371` / `:843-866`；hot_reload 4 测 + `cargo test --workspace` 全绿。
- [x] **不变式 expect（结构上恒真，重构漂移即启动 panic）**——`tun_ingress.rs:214`（flow_router 未注入）/`runtime_builder.rs:479`（tun_enabled 蕴含 network_config）。
  **已修（2026-11-04 `ee33690`）**：`runtime_builder.rs:479` 的 `.expect("tun_enabled 蕴含 network_config")` 改 `ok_or_else` 传播 `Err`（build() 返回 Result，不变式破坏可观测不 panic）；`tun_ingress.rs` 在 `run_internal` 开头增前置 fail-fast（`flow_router`/`flow_output` 未注入即 `bail`，不再运行期每包在 `router()` 热路径 panic——`router()` 的 `expect` 保留为启动后已注入的防御断言）。回归 `run_internal_fails_fast_without_endpoints`（未注入断言 Err 含「未注入」）。evidence：`crates/rillane-runtime/src/runtime_builder.rs:479-485` / `crates/rillane-runtime/src/tun_ingress.rs:221-226` / `:1017-1028`；rillane-runtime 139+1 测 + `cargo test --workspace` 全绿。
- [x] **插件/FFI mutex poison 级联**——`plugins/plugin.rs:133`（std Mutex 跨 wasm 调用，宿主 panic 即毒化后续全插件流）/`ffi/lib.rs:302,328`（tun_thread lock）。
  **已修（2026-11-04 `b9abae5`）**：`plugin.rs` `vm.lock()` 与 `ffi/lib.rs` 两处 `tun_thread.lock()` 的 `expect` 改 poison 恢复（`Err(p) => p.into_inner()`，恢复底层值继续；恢复时 tracing warn / set_last_error 记录）——宿主 panic 后级联终止消除；wasm trap 本经 `classify_call_err` 转为 Err 不 panic。evidence：`crates/rillane-plugins/src/plugin.rs:133-143` / `crates/rillane-ffi/src/lib.rs:302-309` / `:328-335`；rillane-plugins 10 测 + `cargo test --workspace` 全绿。
- [x] **unmaintained 依赖**——`serde_yaml`/`unsafe-libyaml`（RUSTSEC-2024-0449）、`basic-toml`（RUSTSEC-2026-0374）：cargo audit 信息级；升级候选。
  **已修（2026-11-04 `466367c`）**：`serde_yaml 0.9`（弃用）迁 `serde_yaml_ng 0.10`（维护 fork，API 兼容，`Cargo.toml` 用 `package = "serde_yaml_ng"` 保留 crate 名，全仓无源码改动）；`cargo audit` 原 2 条 serde_yaml 弃用消除，`cargo test --workspace` 全绿。**传递依赖保留**：`unsafe-libyaml`（serde_yaml_ng 底层 C FFI，配置 YAML 为可信输入）、`basic-toml`（askama_derive 构建期 proc-macro）仍 unmaintained 信息级——替换需纯 Rust YAML 重写 / uniffi+askama 大版本迁移，收益低风险高，接受并记录。evidence：`Cargo.toml:31`；`cargo audit` 仅剩 2 条信息级 warning；`cargo test --workspace` 全绿。

## 2026-11-02 代码深审补充（P2/P3，源自 docs/review/2026-11-01-code-review.md 第二轮补充节）

P2（下一步修）：
- [x] **TUN UDP 下行只续 last_active 不续 expiry**——`tun_ingress.rs:812-813`：上行（:432-434）续两者、下行续一者，清扫（:714）按 `expiry<=now` 驱逐。纯下行推送流（客户端 udp_idle_secs 内无上行）被中途逐出。
  **已修（2026-11-04 `bcd6d1c`）**：`downlink_task` 增 `udp_idle_secs` 参数，下行续期口径与上行一致——同时续 `last_active` 与 `expiry = now + udp_idle_secs`（原仅续 last_active，sweep 按 expiry 驱逐纯下行流）。回归 `downlink_packet_renews_expiry`（feed 下行包断言 expiry 推进；未修复 expiry 不变红）。evidence：`crates/rillane-runtime/src/tun_ingress.rs:510-517` / `:782-787` / `:813-818` / `:1040-1090`；rillane-runtime 141+1 测 + `cargo test --workspace` 全绿。
  evidence：`tun_ingress.rs:812` `e.last_active = now`（无 `e.expiry` 续期）；`:714` `.filter(|e| e.expiry <= now)`。
- [x] **scan_udp_capability BFS 无 visited 集（组环挂起 build）**——`runtime_builder.rs:2266-2280`：组环（g1→g2→g1）队列永不空，`udp.enabled` 时 build() 无限挂起；`RoutingConfig::validate`（rillane-config:1489）仅查 SLO 无环守卫。
  **已修（2026-11-04 `2bef0c8`）**：`scan_udp_capability` 增 `visited_groups: HashSet<&str>`——同组二次遇及（环/重复）跳过展开，队列有界、build 不再无限挂起。回归 `udp_capability_scan_terminates_on_group_cycle`（g1→g2→g1，线程+2s 超时断言终止；无 visited 时 Timeout 红）。evidence：`crates/rillane-runtime/src/runtime_builder.rs:2317-2326` / `:4572-4601`；rillane-runtime 142+1 测 + `cargo test --workspace` 全绿。
  evidence：`runtime_builder.rs:2266` `while let Some((name, source)) = queue.pop()` 无 visited；`continue` 在 `reachable.entry` 前。
- [x] **chain 故障转移复用已消费 flow.io（协议流损坏）**——`runtime_builder.rs:1919/2025`：首 `dial_and_tunnel`（mesh_transport.rs:1569 copy_bidirectional 读 io）中途失败即部分消费；重试拼接尾流+新信封。正确恢复=中止应用连接（RST）非重接。
  **已修（2026-11-04）**：`forward_chain` mesh `dial_and_tunnel` 失败不再重放尾流到新链/回退出口（`flow.io` 已被部分消费会拼出损坏协议流）；链路/事件面簿记照常（`chain_failure_tx`、`PathUpdated`、注解），随后无条件 `return Err(e)` 让上游 TUN `retire` 中止应用连接（RST/FIN）。回归 `forward_chain_mesh_failure_aborts_without_fallback_forward`（mesh 首跳连接失败断言 `Err` 且回退出口未调用；旧重试逻辑时该测试红）。evidence：`crates/rillane-runtime/src/runtime_builder.rs:2070-2075` / `:3149-3233`；rillane-runtime 144+1 测 + `cargo test --workspace` 全绿。
  evidence：`runtime_builder.rs:2025` `&mut *flow.io` 与 :1919 同一流复用。
- [x] **串行 UDP serve 循环内联 lookup_host（头阻塞整面）**——`mesh_transport.rs:1852`：单任务无 per-packet spawn（§13-5），一个不可解析 `target_host`（线上可控）阻塞所有流。
  **已修（2026-11-04）**：保留 §13-5 单任务顺序处理设计（不 per-packet spawn），为 exit 首包 `lookup_host` 加 3s 上界（`EXIT_LOOKUP_TIMEOUT`，测试可经 `with_dns_lookup_timeout` 调小）；超时/解析失败按单包错误丢弃并继续 serve，错误带 target host 便于定位。回归 `exit_uplink_dns_lookup_is_bounded`（有界性 + 错误上下文）与 `serve_udp_survives_bad_host_packet`（bad-host FULL 后 serve 存活且继续处理 good-host 建流）。evidence：`crates/rillane-runtime/src/mesh_transport.rs:33-38` / `:1274-1280` / `:1287-1294` / `:1877-1906` / `:3820-3967`；rillane-runtime 146 测 + `cargo test --workspace` 全绿。
  evidence：`mesh_transport.rs:1852` `lookup_host(...).await?` 在 serve 循环内。
- [x] **瞬时 recv_from 错误终止 UDP serve 任务**——`mesh_transport.rs:1946`：`Ok(Err(e))=>return Err`（ENOBUFS/EINTR 瞬时亦毙）；应 continue 或按瞬时/致命分类。
  **已修（2026-11-04）**：`serve_udp` 的 `recv_from` 错误按瞬时/致命分类——`is_transient_recv_error`（EINTR/EAGAIN/ENOBUFS）记 debug 并 `continue` 保留 serve 任务；其余仍 `return Err` 终止。rillane-runtime 增 `libc = "0.2"` 依赖取 ENOBUFS 常量。回归 `udp_recv_transient_error_classification`（三瞬时 true、ConnectionRefused false）。evidence：`crates/rillane-runtime/src/mesh_transport.rs:40-52` / `:1997-2011` / `:4000-4018`；`crates/rillane-runtime/Cargo.toml`；rillane-runtime 147 测 + `cargo test --workspace` 全绿。
- [x] **瞬时 accept 错误终止 TCP mesh 监听任务**——`mesh_transport.rs:1330`：`listener.accept().await?`（ECONNABORTED/EMFILE/EINTR 瞬时亦毙）。
  **已修（2026-11-04）**：`serve` 的 `accept` 错误按瞬时/致命分类——`is_transient_accept_error`（ECONNABORTED/EINTR/EMFILE/ENFILE/ENOBUFS）记 debug + 10ms 退避后 `continue` 保留监听任务；其余仍 `return Err` 终止。回归 `tcp_accept_transient_error_classification`（五瞬时 true、ConnectionRefused false）。evidence：`crates/rillane-runtime/src/mesh_transport.rs:54-63` / `:1390-1403` / `:4049-4071`；rillane-runtime 148 测 + `cargo test --workspace` 全绿。

P3（收尾）：
- [x] **active_chains.len()-1 下溢**——`chain.rs:907`：`drop(chain)`（:901）后读 len；并发 `terminate_chain`（:924 remove）移除 → 0-1 下溢（release 裹 usize::MAX 指标污染）；宜 `saturating_sub(1)` 或由 terminate 自减。
  **已修（2026-11-04）**：`handle_chain_failure` 备用耗尽分支 `active_chains.len() - 1` 改 `saturating_sub(1)`——并发 `terminate_chain` 在 drop 分片守卫后窗口内移除本链时不再下溢裹 usize::MAX（若已移除则 len 本身已正确，不再二次自减）。回归 `concurrent_terminate_and_failure_no_active_chains_underflow`（64 轮并发 failure×terminate，断言 active_chains 不裹 MAX 且终态 0）。evidence：`crates/rillane-runtime/src/chain.rs:900-904` / `:1308-1360`；rillane-runtime 149 测 + `cargo test --workspace` 全绿。
- [x] **mesh UDP 下行序号归零瞬态丢包**——`mesh_transport.rs:1877`：exit 建流归零下行序号而客户端窗口仍在（last>63）→ 序号 0..36 判回退拒、≥37 自愈；瞬态 ~37 包突发丢包（非永久拒收）。
  **已修（2026-11-04）**：`ExitFlow` 增加 `down_seq: Arc<AtomicU32>`，FULL 重关联到新 target 时在 `retire_flow` 前捕获旧序号源，新 ExitFlow 继续复用同一 Arc——下行序号跨重关联单调续接，不再归零触发客户端回退窗口拒绝（瞬态丢包）。回归 `exit_full_reassociation_preserves_downlink_sequence`（旧流 down_seq=100，重关联后仍 100；旧归零逻辑红）。evidence：`crates/rillane-runtime/src/mesh_transport.rs:1064-1073` / `:1910-1918` / `:1967-1998` / `:4051-4110`；rillane-runtime 150 测 + `cargo test --workspace` 全绿。
- [x] **缓存满插入 O(n) 驱逐扫描**——`mesh_transport.rs:868-876`：满（65536）时每次插入全 `min_by_key` 扫描；文档化权衡（"O(n) 无新依赖"），需认证 peer + 6.5 万流触发。
  **已修（2026-11-04）**：`UdpFlowCache::insert` 满时驱逐合并为单遍扫描——一次遍历同时收集过期条目（清扫，不计驱逐）与最早未过期 expiry（= 同 TTL 最久未触 LRU，§11-6）；仍满再逐该条目。旧实现先全表 `sweep_expired`、再全表 `min_by_key`，满时每插两次 O(n) 扫，合并为一遍。LRU 语义与计数口径不变。回归 `udp_flow_cache_full_insert_mixed_expired_and_live_evicts_earliest_live`（过期清扫不计驱逐 + 最早未过期被逐）。evidence：`crates/rillane-runtime/src/mesh_transport.rs:895-929` / `:3532-3577`；rillane-runtime 151 测 + `cargo test --workspace` 全绿。
- [x] **订阅转换配置硬编码 admin_token="rillane"**——`clash.rs:768-771`/`rillane_dsl.rs:413-418`：回环绑定约束暴露面；建议省略或随机生成。
  **已修（2026-11-04）**：`ClashConverter::convert_to_rillane` 与 `RillaneDslConverter::convert_to_rillane` 的 `ControlConfig.admin_token` 由 `Some("rillane")` 改 `None`——不再生成众所周知的固定 token（回环 API 暴露面收敛，与 runtime 其余 `admin_token: None` 配置一致；token 由用户显式配置）。回归断言两转换器产出 `control.admin_token.is_none()`。evidence：`crates/rillane-subscription/src/clash.rs:770` / `:1587-1590`；`crates/rillane-subscription/src/rillane_dsl.rs:417` / `:1403-1406`；rillane-subscription 57 测 + `cargo test --workspace` 全绿。
- [x] **shaping 抖动 jitter_ms+1 裹 0（% 0 panic）**——`shaping.rs:45`：jitter_ms=interval_ms=u64::MAX 时裹 0；validate（rillane-config:908-918）无上界；`wrapping_add(1).max(1)` 或上界校验。
  **已修（2026-11-04）**：`decide_shaping_offset` 的 jitter 域计算改 `jitter_ms.checked_add(1).unwrap_or(u64::MAX)`（满值截为 `% u64::MAX`，域 [0, u64::MAX-1]，不裹 0）；随后 `k×interval + jitter` 改 `saturating_add` 防第二处加法溢出，末值仍 `.min(u64::MAX/2)` 有界。回归 `shaping_offset_max_jitter_does_not_panic`（interval/jitter/max 均 u64::MAX，多 k 值不 panic 且 offset ≤ u64::MAX/2；旧 `+1` 表达式红）。evidence：`crates/rillane-protocols/src/middleware/shaping.rs:41-52` / `:238-256`；rillane-protocols 74 测 + `cargo test --workspace` 全绿。
- [x] **save_to_disk 固定 {hash}.tmp 路径（并发交错写）**——`cache.rs:588-601`：并发 `set()` 同键交错写临时文件 → 损坏缓存条目（重取可恢复）；唯一临时名或锁下写。
  **已修（2026-11-03）**：`SubscriptionCache` 增 `disk_io_lock`（std Mutex），`save_to_disk` 持锁落盘（`cache.rs`），与 cleanup 删盘串行；同键并发 set 落盘不再交错。

---

## 统计

| 优先级 | 条目 | 对应阶段 | 状态 |
|---|---|---|---|
| P0 | 5 | S1 UDP 全链路 | 5/5（P0-1 会话表、P0-2 ASSOCIATE、P0-3 出站载荷、P0-4 mesh UDP 面、P0-5 观测与配置，S0–S6 全部落地） |
| P1 | 5 | S2 TUN + S3 前半 | 5/5（P1-1/P1-2 2026-10-03 收口、P1-3 2026-10-03 收口、P1-4 M0–M4、P1-5 M0–M5） |
| P2 | 8 | S3 后半 + S4 | 8/8（P2-7 2026-10-04 落地，余项 2026-10-02 全步落地） |
| P3 | 5+1 | S4 收尾 | 6/6（P3-1 文档对齐、VMess 出站 2026-10-02、P3-2 插件、P3-3 平台打包、P3-4 移动端 FFI、P3-5 零拷贝（范围）） |

已完成底座（S0）条目见上文归档清单；原 19 条清单中 10 项核实为真实完成、3 项勘误重开、其余并入 P0–P3 对应条目。

---

## 审核发现（16c7c13a5de5037c7dfae22026b68fbc478afb4a..HEAD；#1-#6 已随本批修复，#7 部分覆盖）

- [x] 审核发现：`load_from_disk` 将磁盘条目插回内存缓存（`cache.insert`）未更新 `current_size`——`get()` 修复后该路径由自锁死锁变为可达，但 `current_size` 漏计使 `set_with_ttl` 的容量上限（`*current_size + content_size > max_size_bytes`，cache.rs:198）被削弱，热盘加载后实际占用可超上限（cache.rs:558）。
- [x] 审核发现：flow miss（并发 `forget_flow` 拆除）时本包被静默丢弃（mesh_transport.rs:1905-1906），但 `forwarded_up` 仍无条件 +1（mesh_transport.rs:1909），转发成功计数被抬高，且与 send 失败返回 Err 不计数的路径不一致。
- [x] 审核发现：`host_has_injection_chars` 仅拦截 CR/LF/控制字符/DEL（b<0x20 或 b==0x7F），允许空格(0x20)与 authority 元字符 `@`/`/`/`?`/`#`——空格产生畸形 CONNECT 请求行，`@` 可被上游按 `userinfo@host` 解析致目标混淆（请求走私/SSRF 变体），作为出口"最后防线"不完整（rillane-protocols/src/lib.rs:44）。
- [x] 审核发现：ReplayWindow 段首注释仍述旧语义"1..=64 前进接受（越 64 位窗历史全丢）"，与新实现（1..=63 滑窗、≥64 跳变重置 bits=0）不符，属文档漂移易误导后续维护（mesh_transport.rs:757）。
- [x] 审核发现：订阅内容超限经 `bail!`（fetcher.rs:267/277）抛出后被 `fetch()`（fetcher.rs:144）视为可重试错误，对持续返回超大/分块超限端点会重复下载（chunked 路径每次至多 50MiB）`max_retries` 次；宜将终态错误与瞬时错误分类。
- [x] 审核发现：`merge_subscription_config` 仅语句级持 `current_config` 写锁克隆（hot_reload.rs:565-566）、末段重取写锁写回（hot_reload.rs:616），中途 `fs::write` await 让锁——若与 `apply_config`（hot_reload.rs:461）并发会丢失其更新（lost-update）；现调用方串行，属潜在竞态。
- [x] 审核发现：测试缺口——本区间多项 P1/正确性修复无回归测试：pool.rs `maybe_refill` inflight 并发门（pool.rs:579-597，pool.rs 全文件 0 测试）；rillane-mesh 健康检查写锁复检（rillane-mesh/src/lib.rs:982-990）；chain.rs `handle_chain_failure` 分片守卫释放（chain.rs:860-890）；http.rs 出口注入守卫（http.rs:119/164，仅 socks5 入口被覆盖）；fetcher.rs 分块超限与非 UTF-8 拒绝（fetcher.rs:277/279）；mesh_transport.rs flow miss 丢弃路径（mesh_transport.rs:1905-1906）。全部子项已核实：pool `crates/rillane-protocols/src/pool/tests.rs:237` `maybe_refill_no_spawn_when_key_at_capacity`（旧门失效 inflight=32 红，修复后全绿）；mesh `crates/rillane-mesh/src/lib.rs:869` 重构 `health_check_once`/`stale_candidates`/`mark_stale_offline` + `health_check_reread_under_write_lock_keeps_refreshed_node_online`（旧逻辑无条件标记红，复检后绿）；chain `crates/rillane-runtime/src/chain.rs:1232` `switch_ledger_records_failure_and_exhaustion` + `:1310` `concurrent_terminate_and_failure_no_active_chains_underflow` 已覆盖；http `crates/rillane-protocols/src/outbound/http.rs:294` `forward_inline_rejects_authority_metachar_hosts` + `:315` `forward_pooled_rejects_authority_metachar_hosts_before_connect` 已覆盖两路径；fetcher `crates/rillane-subscription/src/fetcher.rs:701` `fetch_terminal_chunk_overlimit_and_not_utf8` 已覆盖两分支；mesh_transport `crates/rillane-runtime/src/mesh_transport.rs:4266` `send_existing_flow_miss_does_not_count_forwarded_up` 已覆盖。`cargo test --workspace` 全绿（44 二进制 `test result: ok`）。

---

## 功能差距分析（2026-11-02，对照 sing-box/mihomo/xray-core）

> 完整报告：[docs/gap-analysis-2026-11-02.md](docs/gap-analysis-2026-11-02.md)。只审不改；未触碰工作树既有未提交改动。

**核心结论**：底座完成度高，差距集中在四块——① 路由规则引擎（无目的 IP-CIDR、无 GeoIP/GeoSite 数据库、无 rule-set、无 OR/NOT、无嗅探）；② QUIC 生态（tuic/REALITY/XTLS-Vision/hy2 UDP 全缺）；③ 服务端入站协议为零；④ 透明代理仅 TUN(Linux)（缺 redir/tproxy、macOS/Windows TUN）。rillane 独有优势：mesh mTLS 多跳+SLO 打分、场景 profile、WASM 插件、移动端 FFI。

建议优先级（新条目，未编号入现有 P 序列）：
- [x] **G0-1 目的 IP-CIDR 匹配器**——现 `MatchCondition::Network` 绑定 `client.cidr` 源注解（rillane-routing/src/lib.rs:706），目标网段分流表达不了；三大项目最基本匹配器。
  **已实现（2026-11-04 `a262735`）**：`MatchCondition` 增 `IpCidr { cidrs }` 变体（rillane-config/src/lib.rs:1785），路由匹配器 `ip_in_cidr`（rillane-routing/src/lib.rs:24）对目标 host 为 IP 字面量按 IPv4/IPv6 前缀匹配（主机形式按精确地址；域名不命中，路由面不做 DNS）；`RillaneRule::IpCidr`/`ClashRule::IpCidr`/rule_source 的 `IpCidr` 规则改走新变体（rillane_dsl.rs:1126、clash.rs:1147、rule_source.rs:60），`Network`（源注解）保留；`clash_export` 导出 IP-CIDR 兼容。回归 `tests::ip_cidr_matches_target_ip_prefix`（IPv4/IPv6 前缀、主机精确、域名不命中；旧逻辑恒 false 红）。`cargo test --workspace` 全绿（44 二进制）。
- [x] **G0-2 GeoIP/GeoSite 数据库接入 + domain full/regex + OR/NOT 逻辑规则**——替换 `geoip.country` 注解等价物（无数据库）。
  **已实现（2026-11-05 `a95cb76`）**：
  - **GeoIP 数据库**：`RoutingConfig` 增 `geoip_db`（MaxMind DB Country `.mmdb`，rillane-config/src/lib.rs:1490）；`geo.rs` 惰性加载（`GeoDatabases::geoip`），按目标 IP 字面量查国家码（域名不解析，路由面不做 DNS），缺失/加载失败恒不命中（fail-open 仅 WARN 一次）。
  - **GeoSite 数据库**：`RoutingConfig` 增 `geosite_db`（v2fly `.dat`，protobuf）；`geo.rs` 惰性加载 + 预编译索引（Plain=子串 / Domain=根域后缀 / Full=完全相等 / Regex=预编译，未知类型跳过），`GeoSite{category}` 条件按目标主机查询。
  - **domain full**：`MatchCondition::DomainFull{values}`（rillane-config/src/lib.rs:1860），完全相等（ASCII 大小写不敏感），不含子域；`rule_source` 的 `full:` 不再并入 suffix 联合（独立 `-full` 规则，rule_source.rs:53），Clash `DOMAIN` 规则不再转 suffix（clash.rs:1159）。
  - **domain regex**：`MatchCondition::DomainRegex{patterns}` 路由匹配经引擎级缓存（`cached_regex`，lib.rs:26）；`regexp:` 文本规则源入 `regexps` 并产出 `-regexp` 规则；Clash `DOMAIN-REGEX`/Rillane DSL `domain-regex` 导入；构建期 `RoutingConfig::validate` 逐条编译校验非法 pattern。
  - **OR/NOT**：`MatchCondition::Any{conditions}`/`Not{condition}` 递归（rillane-routing/src/lib.rs:834），顶层仍 AND；`clash_export` 对 Any/Not 跳过并登记。
  - **Clash 导出**：`DomainFull`→`DOMAIN`、`GeoSite`→`GEOSITE`（clash_export.rs:580/602），roundtrip 经导入侧重解析。
  - **配置加载**：`load_from_path` 相对数据库路径按配置文件目录解析并归一化（`..`/`.` 消解，rillane-config/src/lib.rs:1085）；`RoutingConfig` 增 `Default`。
  - **测试**：`geo.rs` 合成 mmdb（maxminddb-writer）与 `.dat`（geosite-rs encode）——`geosite_matches_v2fly_semantics`/`geosite_missing_and_invalid_db_never_match`/`geoip_country_lookup`/`geoip_missing_db_never_matches`；路由集成 `geoip_geosite_routes_through_databases`/`geo_conditions_never_match_without_db`/`reload_swaps_geo_database_path`；config `routing_geo_db_fields_parse_and_serialize`/`routing_geo_db_absent_defaults_to_none`/`load_from_path_resolves_relative_geo_db`；clash_export `domain_full_and_geosite_roundtrip`；rule_source `routing_rules_split_by_condition_type`（full 独立）。
  **证据**：`cargo test --workspace` 全绿（45 二进制全部 `test result: ok`，0 failed）；本次 commit sha 见 `ae8da20`。
- [x] **G0-3 协议嗅探层（sniff）**——TLS SNI/HTTP Host/QUIC SNI 覆写路由域名；TUN 场景 IP 直连流量无它即无法按域名分流。
  **已实现（2026-11-06）**：`sniff.rs` 增 `sniff_quic_sni`（RFC 9000 §17.2 + RFC 9001 §5.2/§5.4 密钥派生+header protection+AEAD 解密+CRYPTO 帧解析）与统一入口 `sniff_host`；TUN TCP 集成（`spawn_tcp_forward`）非阻塞 `peek_socket` 读首包 → TLS/HTTP SNI/Host 覆写 target.host → 按域名重路由（覆盖 SYN 面 IP 粘滞决策，peek 不消费数据）；TUN UDP 集成（`handle_udp_packet`）首包 QUIC Initial 解密提取 SNI 覆写路由域名。回归：`sniff` 6 测（QUIC 合成包回环含密钥派生/保护/AEAD/帧解析）、`peek_socket_returns_data_without_consuming`、`tcp_sniff_reroutes_on_tls_sni`、`udp_sniff_reroutes_on_quic_sni`；rillane-runtime 164 测 + `cargo test --workspace` 全绿。evidence：`crates/rillane-runtime/src/sniff.rs:99-290` / `crates/rillane-runtime/src/tun_ingress.rs:671-746`（TCP）/ `:455-472`（UDP）/ `crates/rillane-runtime/src/tun_tcp.rs:456-473`。**验证边界**：真实 TUN+TLS/HTTP/QUIC 流量验证需特权 TUN 环境与真实端点（合成包+单测已覆盖解析与重路由逻辑），留待后续环境验证。
- [x] **G0-4 UDP over vmess/vless/trojan**——主流加密通道均不载 UDP（构建期报错），游戏加速场景非 direct/ss/wg 出口即退化。
  **已实现（2026-11-09 `f2fa63d`）**：三协议各增 UDP 数据面出站（rillane-protocols outbound）——vmess `VmessUdpConnector`/`VmessUdpRelay`（命令 0x02，xray `AuthenticationWriter.writePacket` 语义：每数据报一块，复用既有 write_chunk/read_chunk 分块加密帧；`build_request_header_bytes`/`build_session` 增 command 参数）；vless `VlessUdpConnector`/`VlessUdpRelay`（命令 0x02，xray `MultiLengthPacketWriter` 帧 `[2B BE len][payload]`；头构建抽 `build_vless_request_bytes` TCP/UDP 共用；flow 配置构建期拒）；trojan `TrojanUdpConnector`/`TrojanUdpRelay`（UDP ASSOCIATE 命令 0x03，trojan-gfw protocol.md：恒叠 TLS、无应答头、逐报 `[ATYP][ADDR][PORT][LEN 2BE][CRLF][payload]`）。`build_udp_connectors` 增三臂（runtime_builder.rs：仅 network=tcp 注册，vmess 复用 TCP 面 security/alter_id 构建期校验，vless flow 拒，trojan network=tcp+tls），`scan_udp_capability` 错误信息同步。UDP 面与 TCP 面同一份节点配置（`from_connector`）。回归：`udp_loopback_command_02`（vmess mock 服务端按规格断言命令 0x02 + 分块 echo）、`udp_loopback_command_02`（vless，断言头/UUID/命令 0x02 + 帧回环）、`udp_loopback_command_03_tls`（trojan，rcgen 自签 TLS + 密码 SHA224 hash + 命令 0x03 + 逐报回环）；runtime `udp_build_connectors_skips_unsupported_kinds`（tcp 三协议注册、ws 跳过）、`udp_capability_scan_passes_when_all_reachable_are_capable`（5 连接器）、`udp_capability_scan_fails_listing_offending_nodes_and_sources`（vmess-ws/hy2 判负点名）。`cargo test --workspace` 全绿（45 二进制全部 `test result: ok`，0 failed）。**验证边界**：帧语义按 xray/trojan-gfw 规格实现并以规格保真 mock 服务端回环验证；真实 vmess/vless/trojan UDP 节点互通（连接复用/多目标、MTU 分片）需真机端点，留待真实环境验证。
- [x] **G0-5 reject/block 目标**——极小成本，断连/广告拦截基本表达。
  **已实现（2026-11-04 `43b731a`）**：`EgressConfig` 增 `Reject` 变体（rillane-config/src/lib.rs:1286），`build_egress_outputs` 为其装配 `RejectFlowOutput`（runtime_builder.rs:2604），`FlowOutput::forward` 直接返回拒绝错误断流（无网络 I/O）；`egress_kind`/`egress_server_host` 处理 Reject；`clash_export` 跳过并登记。路由 `target: block-ads` 指向 `type: reject` 出口即拦截。回归 `build_egress_outputs_reject_blocks_forward`（构建产出 + forward 拒绝）。`cargo test --workspace` 全绿（44 二进制）。
- [ ] **G1-6 REALITY + XTLS-Vision 出站**——主流机场节点形态；可复用 VMess xray 向量互操作经验。（更正：原「含 reality-opts/flow 即构建失败」不确——事实是 serde 静默丢弃两键，节点降级为普通 TLS VLESS：REALITY 服务端回落伪装站点、流量不走向代理且无任何报错，比构建失败更隐蔽）
  **M1 已落地（2026-11-10 `50170ef`）**：三个导入面捕获并显式拒绝——`ClashProxy` 增 `flow`/`reality_opts`（别名 reality-opts/reality_opts），VLESS 转换臂硬 Err 点名节点（clash.rs）；`RillaneNode` 增 `flow`/`reality` 同口径拒绝（rillane_dsl.rs）；`parse_vless` 捕获链接 pbk/sid/security=reality/flow（converter.rs），`convert_v2ray` 按批量路径既有约定对命中节点 warning+跳过（其余行照常导入）。回归测试 5 项：clash/DSL 拒绝路径（含普通 VLESS 不受影响）、serde 捕获证明（kebab+snake 别名）、链接参数捕获、批量导入 warning+跳过——`cargo test -p rillane-subscription` 68 passed 0 failed。设计文档 docs/design/reality-vision-outbound.md（+zh 镜像：协议分析/行为矩阵/里程碑 M1–M4）。
  **M1.5 已落地（2026-11-10，拍板改 M1 拒绝策略：配置保留 + 拨号期点名门）**：`rillane-config` 增 `RealityConfig{public_key, short_id}`（内层 kebab 别名）+ `EgressConfig::Vless.reality` 字段（serde 不再静默丢键，缺省 None 零差异，往返保真 6 测 reality_config.rs）；三个导入面（clash.rs/rillane_dsl.rs/converter.rs）改为转换成功且字段完整保留（仅缺 public-key 点名报错），批量 v2ray REALITY 行照常导入无跳过告警；clash_export.rs 导出 `reality-opts` 往返；runtime 构建不再拒绝 flow/reality（节点级失败不拖垮整份订阅，url-test 探活标不健康）；拨号期门 `gate_reality_flow` 在 TCP forward（pooled/inline）与 UDP associate 任何网络 I/O 前点名拒绝（REALITY：rustls 无 ClientHello 字节级控制防静默回落伪装站；flow：Vision 分帧未实现防静默降级）3 测。设计文档 reality-vision-outbound.md 更新至 M1.5 口径。**M2–M4 BLOCKED**：缺① ClientHello 字节级控制的栈决策（rustls 不暴露 session_id/扩展序/套件控制，无维护中的 Rust uTLS 等价物；候选手写最小 TLS1.3 握手 / 分叉 BoringSSL 级栈 / rustls shim——需用户拍板，见设计文档 §4.3）②真实 xray REALITY 节点凭据（地址/public-key/short-id/伪装 SNI）③真实 Vision 节点。（2026-11-06 复核的 BLOCKED 范围相应收窄至 M2–M4；M1 不依赖外部条件）（2026-11-12 复核：M1.5 已落地 `4aca4b5`；M2–M4 外部条件未变——栈决策未拍板、真机凭据未给，保留 BLOCKED）
- [ ] **G1-7 hysteria2 UDP 面（quinn 载具）+ salamander/端口跳跃**——现归 V2，游戏定位下建议提前。
  **BLOCKED**：现 connector 基于 `hysteria2` crate 0.1.6 TCP 面，该 crate 无 UDP API（仅 `UdpNotSupported` 错误，未暴露任何 UDP/QUIC stream），`build_udp_connectors` 亦未接入 hy2（runtime_builder.rs:2230）。需自研 hy2 UDP 帧格式或更换/扩展 QUIC 载具、实现 salamander 混淆与端口跳跃，并需真实 hysteria2 UDP 服务端（含 salamander/端口跳跃配置）互通验证；现缺此类端点与测试环境。（2026-11-06 复核：hysteria2 connector 仍基于 TCP 面 crate、`build_udp_connectors` 仍未接入 hy2，外部条件未变，保留 BLOCKED）（2026-11-12 复核：hysteria2 0.1.6 公开面仍仅 `tcp_connect`（hysteria_client.rs:16），`UdpNotSupported` 仍在 error.rs:20，未暴露 QUIC stream；外部条件未变，保留 BLOCKED）
- [ ] **G1-8 DNS 加密上游 DoH/DoT**——现仅裸 UDP 53；cross_check 在深水区才可靠。
  **M1 已落地（2026-11-10 `fbcac5f`，协议面 + 回环测试）**：引擎 `DnsUpstream` 三形态（`ip:port` UDP / `tls://host[:port]`、`dot://` 别名 DoT RFC 7858 缺省 853 / `https://url` DoH RFC 8484），`ResolverConfig.domestic/trusted` → `Vec<DnsUpstream>`；wire 格式三态共用（RFC 1035 手写编解码复用）；DoT = TCP+TLS 逐消息 2 字节大端长度前缀（host 允许域名，连接期系统解析器落地）；DoH = GET `?dns=` base64url 无填充、载荷 id=0（RFC 8484 §4.1），content-type 非 dns-message 仅 warn；UDP/DoT 保留随机 id + 应答 id 校验。证书校验缺省 webpki 根（进程级 ring provider 显式安装——双 provider 歧义同 rillane-protocols 裁决），`network.dns.tls_skip_verify` 兜底（rillane-config 新字段，serde 缺省 false）。配置 schema 不变：`network.dns.domestic/trusted` 串列表逐条解析（rillane-config validate 三形态校验 + rillane-runtime 转换层解析）。回环测试：`dot_loopback_roundtrip`/`doh_loopback_roundtrip`（rcgen 自签 + skip-verify，全链路 resolve 断言）、`upstream_parse_forms`、`encrypted_upstream_forms_convert`（runtime）、`dns_block_encrypted_upstream_forms`（config）、`doh_payload_uses_zero_id`——rillane-platform 54、rillane-config dns_block 9、rillane-runtime dns_config 6 全绿。文档 dns-partition.md §9-1/§10-O-dns2 落地注记（en+zh）。**残余边界（M2）BLOCKED**：缺① 真实 DoT/DoH 上游互操作验收（公网证书链、EDNS 行为差异、压缩点；需用户指定加密 DNS 上游部署/凭据）② DoQ 不做维持原判。（2026-11-12 复核：M2 外部条件未变，保留 BLOCKED）
- [ ] **G1-9 rule-set 远程规则提供者 + 订阅级 url-test 常驻测速**。
  **url-test 常驻测速 M1 已落地（2026-11-10 `3491661`，注入式探测句柄）**：rillane-core `probe_via_output`——duplex 流作 ingress 侧、探测目标为 Flow.target 走节点出口 forward 管道（与真实流量同管道），HEAD 请求收首字节判健康、RTT=发起到首字节耗时，timeout 覆盖连接+握手+往返全程（回环健康 + 黑洞超时 2 测）；rillane-config `PolicyGroup.url_test: Option<UrlTestConfig>`（probe `host:port` / path 缺省 `/generate_204` / interval_secs 缺省 300 / timeout_ms 缺省 5000）+ validate 矩阵（缺 host/缺端口/端口 0/非数字端口/path 无 `/`/interval<1/timeout<1 全拒，`RoutingConfig::validate` 逐组调用）+ serde 缺省面与存量零差异 4 测；rillane-routing 删随机 mock（`check_node_health`/`measure_node_latency`——随机假数据比无数据更害选路），`set_probe_handler` 注入句柄（None = 探测循环 no-op 零假数据），`perform_health_checks` 只探 url_test 组、组级 interval 门控（探测任务 10s tick 粒度）、逐成员串行（并发探测互抢带宽失真 RTT），Ok(rtt)→健康表+延迟表、Err→标不健康（不动旧延迟值）；rillane-runtime build 期出口表就绪后接线探测句柄（按节点名取出口，节点无出口 Err）；Clash 订阅 url-test 组的 `url`/`interval`（毫秒）自动映射为 UrlTestConfig（url 缺席或非 http(s) 宁缺不造；select 组即便带 url 不注入）3 测；split_probe_target 拆分（IPv6 方括号剥除）1 测。门禁 `cargo test --workspace` 46 二进制全绿。**url-test 残余**：真实出口节点互操作验收需真实节点凭据（回环已验管道语义）。**rule-set 远程提供者 M2 BLOCKED**：无远程 URL 拉取/热更路径，缺用户指定远程规则源（URL + 更新节奏 + 信任边界）。（2026-11-12 复核：远程规则源仍缺，保留 BLOCKED——注意 Clash RULE-SET 规则当前转换会 warn+跳过（clash.rs:1377 转换臂），不阻塞导入）
- [ ] **G1-10 fake-ip + DNS 回填路由**（配合 G0-3）。
  **fake-ip M1 已落地（2026-11-10 `a036a01`，池 + DNS 应答 + 入口回填）**：rillane-core `FakeIpTable`——CIDR 池（缺省 198.18.0.0/15）按域名稳定分配假 IPv4（forward/reverse 双表同锁不漂移，游标耗尽回绕为已登记语义）、`reverse` 反查、`in_range` 判定、`reverse_host` 入站改写助手（3 测：构建边界/稳定与反查/回绕）；rillane-config `network.dns.fake_ip` 块（enabled 缺省 true、range 缺省基准段，validate 矩阵：缺前缀/非 IPv4/非数字/前缀越界/主机位未清零全拒，enabled=false 容忍半配置；块缺席 None 存量零差异，2 测）；rillane-platform `LocalDnsServer`——池表在场时客户端 A 查询直接按池段假地址应答（不触上游、TTL 1、同域名恒同地址），AAAA 及其余类型照常真实解析（E2E 测：假地址落池段且非上游真值、反查还原、上游计数证 A 不触/AAAA 触）；rillane-protocols socks5/http/mixed 入口——target 为池段假 IPv4 时反查原域名改写进路由（原域名记 `dns.fakeip` 注解），socks5 CONNECT 假地址 E2E 测证路由面见原域名；rillane-runtime 一张表两侧共享（DNS 服务 + 入口装配，build 期接线）。门禁 `cargo test --workspace` 46 二进制全绿。**TUN 组合守卫（`1c49c20`）**：fake_ip 启用 + TUN 模式构建期显式拒绝（TUN 入口回填未接线，假地址无反查改写则出口不可达——拒绝而非静默断流；非 TUN 下同配置照常装配，测试双路钉住）。**M2 残项② 已落地（2026-11-10 `37887f1`，socks5 UDP 面 fake-ip 回填）**：`UdpAssociateService` 增持池表句柄（5 参 new），uplink 逐报文 target 解析后反查改写（`reverse_host` 池段假 IPv4→原域名，域名/池外 IP 原样；改写先于粘滞键建立——会话按域名绑定同域名复用）；runtime_builder 装配传 DNS 服务池表（None=未启用存量零差异）。回环测 `fake_ip_datagram_target_backfills_domain`（捕获路由器断言：池段假地址→路由见原域名、池外 IP→原样直达、假地址不直达路由）。`cargo test --workspace` 46 二进制全绿。**M2 残余**：①TUN 入口（tcp/udp_target）接回填后解除守卫（BLOCKED：需特权 TUN 环境）（2026-11-12 复核：三项残余 ①③④ 外部条件均未变，保留 BLOCKED）③AAAA 直通（应用走 IPv6 即回 IP 直连路由语义；BLOCKED：需拍板 IPv6 假池/AAAA 过滤/维持直通三选一）④真实 DNS/TUN 流量验收（BLOCKED：需真实环境）⑤G0-3 sniff 集成（独立面，fake-ip 不依赖，G0-3 已落地）。
- [ ] **G2-11 redir/tproxy 透明代理入站**（Linux）。
  **BLOCKED**：`NetworkBlockConfig::validate` 显式拒绝 `transparent`/`tap`/`hybrid`（config/lib.rs:287-290，E1「仅 tun」），无 redir/tproxy 入口、iptables/nftables 重定向或 `SO_ORIGINAL_DST` 处理。需实现透明代理入站（REDIRECT/TPROXY 链 + 原始目标读取 + 协议解析）并需 root/CAP_NET_ADMIN 真实机器与防火墙验证；现缺特权测试环境。（2026-11-06 复核：`validate` 仍显式拒绝 transparent/tap/hybrid，无 redir/tproxy 入口，外部条件未变，保留 BLOCKED）（2026-11-12 复核：config/lib.rs:289 仍显式拒绝 transparent/tap/hybrid，无 SO_ORIGINAL_DST 读取，缺特权防火墙环境，保留 BLOCKED）
- [ ] **G2-12 服务端入站协议**（trojan/vless/ss 至少一种）——若坚持纯客户端内核定位则显式决策不做并登记。
  **BLOCKED**：入站仅 socks5/http/mixed（rillane-config `IngressConfig`，无 trojan/vless/ss 服务端变体），协议服务端实现为零。需用户显式决策「是否坚持纯客户端内核定位」；若做则需实现服务端认证/数据面并需真实客户端互通（trojan/vless/ss 各至少一个）验证。现缺产品定位决策与互操作端点。（2026-11-06 复核：`IngressConfig` 仍仅 Socks5/Http/Mixed，无服务端变体；产品定位决策仍缺，保留 BLOCKED）（2026-11-12 复核：IngressConfig 仍仅 Socks5/Http/Mixed（config/lib.rs:1399/1407/1417），产品定位决策仍未登记，保留 BLOCKED——「显式决策不做」属用户产品决策，非工程可自决）
- [ ] **G2-13 tuic/anytls/shadowtls 出站**。
  **BLOCKED**：全仓无 tuic/anytls/shadowtls 代码或依赖（Cargo.toml 无对应 crate），`EgressConfig` 无变体。需新增三类出站连接器（tuic=QUIC、anytls=自定义 TLS 分帧、shadowtls=shadow-tls 协议）并需真实节点互通验证；现缺实现与端点。（2026-11-06 复核：Cargo.toml 仍无 tuic/anytls/shadowtls 依赖，`EgressConfig` 仍无变体，外部条件未变，保留 BLOCKED）（2026-11-12 复核：Cargo.lock 仍无 tuic/anytls/shadowtls 任何依赖，EgressConfig 仍无变体，保留 BLOCKED）
- [x] **G2-14 Clash API 兼容层（只读子集 + 面板直连）**——现控制面不兼容 /proxies /connections /traffic，metacubexd/yacd 无法直连。
  **已实现（2026-11-04 `f03424b`）**：`control_plane` 增只读端点 `/proxies`（出口名→ClashProxyDto{type,now,udp,history}）、`/connections`（flow stats 派生 ClashConnectionDto + downloadTotal/uploadTotal）、`/traffic`（runtime up/down）——metacubexd/yacd 可直连读。回归 `clash_api_readonly_endpoints_shape`。`cargo test --workspace` 全绿（44 二进制）。只读子集完成；写操作（/proxies/{name} 切换、/connections/{id} 断开）与 WebSocket 订阅面（/traffic 实时推送）未做，留作后续。
- [ ] **G2-15 httpupgrade/xhttp 传输；G3-16 macOS/Windows TUN + auto_route 全局接管；ICMP 代理、UoT、hosts 映射**。
  **部分完成（2026-11-10 httpupgrade `86bb735`）**：httpupgrade 传输落地 vless/vmess——rillane-protocols `outbound/httpupgrade.rs`（upgrade 握手：101 状态门、Sec-WebSocket-Accept 带则校验缺则容忍（xray 形）、101 后裸字节流 `HttpUpgradeStream` 直读直写无帧、握手残余回放保序）；vless/vmess 池+内联双路径接线（池借出→upgrade 握手→stale 一次性重拨 D-11 同口径；协议段与 tcp/h2 同序）；runtime_builder VMess 构建期白名单纳 httpupgrade + ws/httpupgrade 借出键预热第二键（host 首值 SNI 链）；clash.rs 导入读 `httpupgrade-opts` 块（vmess/vless，平铺键优先，块缺省回落 `/`），vless:// URI 面通用透传无需改。回环测试：vmess `echo_loopback_httpupgrade`、vless `echo_loopback_httpupgrade`（请求头/响应头直写直读+双向泵+EOF 半关收敛）、握手矩阵（accept 带/缺/错、非 101 拒、`stream_replays_leftover_before_inner`）。`cargo test --workspace` 全绿。UDP 面维持 network=tcp 口径（httpupgrade 节点无 UDP 连接器，scan_udp_capability 判负与 ws 同）。
  **部分完成（2026-11-10 hosts 映射 `aac6db2`）**：`network.dns.hosts` 静态映射落地——rillane-core `hosts.rs` `DnsHosts`（键小写精确归一、值须 IPv4/IPv6 字面量、按族过滤查询）；rillane-config `DnsBlockConfig.hosts` 构建期校验（空白键/键为 IP/坏值拒）；rillane-platform `LocalDnsServer` A/AAAA 命中直答真实映射地址（TTL 1，不触上游、优先于 fake-ip；名命中族不符给空 NOERROR 不泄上游；表外回落既有路径 A→fake-ip、AAAA→上游）；`DnsService`/runtime_builder 接线（非空映射建表、非法值构建期拒绝）。测试：表单元矩阵、config schema 矩阵、dns 引擎回环（A/AAAA 命中、族不符空应答、表外回落）、runtime 装配断言（`hosts_mapping_wired_into_dns_service`）。`cargo test --workspace` 全绿（46 二进制）。M1 口径：精确匹配（通配符不做）、DNS 监听面直答（出站拨号侧不消费 hosts，后续需要再扩）。
  **BLOCKED（余项）**：xhttp 传输——需真实 xhttp 端点验证其 HTTP/2/3 分帧语义，现缺端点；macOS/Windows TUN——仅 Linux 实现（rillane-platform `linux.rs`），需真实 macOS/Windows 机器；ICMP 代理/UoT——需特权环境与真实链路验证。（2026-11-12 复核：余项外部条件均未变，保留 BLOCKED）

---

## 审核发现（5ddd48417fab..HEAD；只审不改，2026-11-03）

覆盖：rillane-protocols（host_has_injection_chars 扩围 + socks5/http 回归测试）、rillane-runtime（config_apply_lock 热交换串行、hot_reload config_mutex、mesh send_existing_flow + 防重放窗口语义、chain fmt）、rillane-subscription（cache 锁外磁盘删除 + 热盘容量回填、fetcher 终态错误分类）、README/文档。

- [x] 审核发现：cache 三个 cleanup（cleanup_expired/cleanup_lru/cleanup_lru_by_count）把磁盘 `fs::remove_file` 移到 `memory_cache` 锁外（cache.rs:417/485/547），与并发 `set_with_ttl`→`save_to_disk`（cache.rs:253）同键竞态——清理线程在内存移除后、删盘前，set 可重插该键并落盘，随后清理删掉 set 刚写的新盘文件，留下「内存有、磁盘无」的副本；重启/后续 LRU 再逐即丢失。提交注释只声明了 get()→load_from_disk 复生窗口（自愈），未覆盖此 set 写删窗口（不白愈、持久化丢失）。P3。
  **已修（2026-11-03）**：`SubscriptionCache` 增 `disk_io_lock`（std Mutex），cleanup 删盘与 set 落盘串行；删盘前复查 `memory_cache` 已无该键（`cache.rs`），有活跃副本则跳过删盘。回归 `cleanup_expired_skips_delete_when_key_reinserted`（模拟 set 重插后 cleanup 不误删），rillane-subscription 54 测全绿。
- [x] 审核发现：`FetcherError` 文档声明「HTTP 状态错」为终态（fetcher.rs:8-10），但非 2xx 状态（4xx/5xx，如 404/429/5xx）经 `anyhow!` 返回（fetcher.rs:254-260），未包装成 FetcherError——`fetch()` 的终态短路（fetcher.rs:172 `downcast_ref::<FetcherError>`）对状态错不生效，仍按瞬时错误重试 `max_retries` 次；文档与实现语义不符，且 4xx（404/403/429）语义上应属终态。P3。
  **已修（2026-11-03）**：`FetcherError` 增 `HttpStatus(u16)` 变体；非成功状态中 4xx（400..500）包装成 `FetcherError::HttpStatus`（终态短路生效），5xx 保持瞬时 `anyhow`（可重试）。回归 `fetch_classifies_4xx_terminal_5xx_transient`（404 终态/500 瞬时），rillane-subscription 56 测全绿。
- [x] 审核发现：`apply_config_inner`/订阅循环的写序改「先装 egress 面、再 reload 路由、最后落 config」（runtime_builder.rs:1158-1163/1427-1434）消除了「新规则引用未就绪名」窗口，但引入反向窗口：outputs/connectors 整体替换后、`router.reload` 前，旧路由规则可解析到已被新 egress 集删除的名字 → 该窗口内命中已删 egress 的在途流报「未知 egress」失败（瞬时微秒级，多状态非原子交换固有残余）。注释「不再引用未就绪名」方向正确但未提此逆向窗口。P3（低）。
  **已文档化（2026-11-03）**：`apply_config_inner` 与订阅循环两处注释补「反向残余」说明（`runtime_builder.rs`）——多状态非原子交换固有残余，在途流已按旧路由解析、窗口仅影响并发新流；彻底消除需单状态原子交换或先 reload 再换 egress（会重引入「新规则引用未就绪名」窗口），接受并登记。P3（低）性质判定为可接受残余，无需代码改动。
- [x] 审核发现：测试缺口——① fetcher 终态错误仅 Content-Length 超限被回归（chunked 分块超限 ChunkOverLimit 与非 UTF-8 NotUtf8 两终态分支无测试，fetcher.rs:298-305）；② cache cleanup 锁外删盘 vs set 同键竞态无回归测试（cache.rs:417 窗口）；③ 订阅刷新循环持 config_apply_lock 路径（runtime_builder.rs:1132）无独立回归（仅 update_config/merge_config_delta 两路径被覆盖）。
  **已补（2026-11-03）**：① 增 `fetch_terminal_chunk_overlimit_and_not_utf8`（chunked 超限 ChunkOverLimit + 非 UTF-8 NotUtf8 两终态分支）；② 增 `cleanup_expired_skips_delete_when_key_reinserted`（cache.rs:417 窗口）。③ 订阅刷新循环持 config_apply_lock 路径无独立回归——**该项保留未修**（属 config_apply_lock 语义覆盖面，update_config/merge_config_delta 两路径已有回归，订阅循环复用同锁语义；如需独立回归需构造订阅热更时序，成本高）。

---

## 审核发现（f9cb1f3bf1066c0034f05fe87e0362dcbdd876ba..HEAD；只审不改，2026-11-03）

覆盖：rillane-core（constant_time_eq / 质量评分 NaN / net_mark 竞速 abort / udp 帧长守卫）、rillane-platform（DNS singleflight + start/stop 锁序）、rillane-protocols（认证恒时 / padding span / hysteria2 超时 / pong 有界 / trojan 帧长守卫）、rillane-runtime（mesh TLS 重载出写锁 / 后台循环 stop 标志）、rillane-subscription（cache disk_io_lock / fetcher 4xx 终态）、rillaned（非回环无 token 拒启）、rillane-ffi（共享引用消除别名）。

- [x] 审核发现：`encode_udp_header` 返回类型改 `Result<Vec<u8>>`（associate.rs:82）但未传播到 rillanectl——`apps/rillanectl/src/udp_probe.rs:221-227` 与 `:282` 仍按 `Vec<u8>` 调用（`.extend_from_slice`/`&frame`/`.len()`），`cargo check -p rillanectl` 编译失败（E0599×2、E0308，3 错）；rillanectl 为 workspace 成员，构建链中断。P1。
  **已修（2026-11-03 `513e3b1`）**：两调用点传播 `Result`——发送路径 `?` 映射 `ProbeError::Connect`，echo 桩解码失败 `continue` 跳过畸形帧；`cargo check -p rillanectl` 恢复，rillanectl 19 测 + `cargo test --workspace` 全绿。evidence：`apps/rillanectl/src/udp_probe.rs:221` / `:282`。
- [x] 审核发现：DNS singleflight inflight 槽位仅在正常完成路径移除（dns_engine.rs:779）；若首查任务在 `cross_check`/`query_group`（:763-765）中被取消（resolve future 被 drop），槽位残留且 map 持 `tx.clone()` 使 watch 通道保持开放，等待者 `rx.changed()`（:743）永久挂起（无超时/清理），该键后续查询全部阻塞。当前树内调用方无显式取消，属潜在；另 `saw_dead_leader` break 路径（:749-751）未插入自身却仍执行 `remove(&key)`（:779），可能误删他首查者槽位（该路径实际难达）。P3。
  **已修（2026-11-03 `fe931ce`）**：`InflightMap` 值改持 `watch::Receiver`（不再持 sender 使通道保持开放）+ 每代 `Arc<()>` token；等待者见通道关闭即按 token 清理同代槽位并重新抢占（死首查自愈），首查者完成后仅当 token 仍属自己才移除（防误删他代）。回归 `resolver_recovers_when_singleflight_leader_is_cancelled`。evidence：`crates/rillane-platform/src/network/dns_engine.rs:630-635` / `:748-770` / `:783-787`；rillane-platform 19+50 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`racing_winner_aborts_in_flight_losers`（net_mark.rs:423-448）未真正回归 abort——改前 `connect_racing` 胜出即 `return Ok(s)`（落选为 detached task，不等待），改后同样胜出即 return；测试断言「5s 内返回」在改前改后均通过，无法区分 abort 与否，注释「若未 abort，connect_racing 返回后仍需等次选超时」前提错误（connect_racing 从不等待落选）。回归失效。P3。
  **已修（2026-11-03 `ce5f3bd`）**：测试加 `cfg(test)` 连接门 + 在途计数：两候选均先确认挂起在途，再放行 echo 胜出；断言返回后、放行落选前 `ACTIVE_CONNECTS=0`。临时移除 `abort()` 验证该断言变红（left=1），证明可区分。evidence：`crates/rillane-core/src/net_mark.rs:16-22` / `:183-217` / `:506-521`；net_mark 8 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`disk_io_lock` 未覆盖 `remove()` 与 `clear()`——`cache.rs:290`（remove）与 `:336`（clear）仍持 `memory_cache` 写锁跨同步 `fs::remove_file`，且不持 `disk_io_lock`；cleanup 同类的「删盘 vs set 落盘」同键竞态仍经 `remove()` 可达（cleanup 已移出写锁并串行化，此两处未修），磁盘 IO 下写锁模式亦未消除。P3。
  **已实现（工作树待提交，非本人 WIP）**：`cache.rs` `remove()`/`clear()` 已按 cleanup 同型重构——内存突变（memory_cache→current_size）与磁盘删除分离，先释放写锁，再持 `disk_io_lock` 删盘；`remove()` 删前复查 `memory_cache` 活跃副本（并发 set 重插则跳过删盘）。evidence：`crates/rillane-subscription/src/cache.rs:273`（remove）/`:332`（clear）；`cargo test -p rillane-subscription` 57 测全绿。该改动为工作树既有未提交变更（非本人），未混入本批 commit，待其属主提交。
- [x] 审核发现：fetcher 将 408/429 一并判为终态——`fetcher.rs:261` `(400..500).contains(&status_code)` 把 408（Request Timeout）与 429（Too Many Requests）包装为 `FetcherError::HttpStatus` 短路重试；但 408/429 语义可重试（429 带 Retry-After 背压、408 瞬时超时），短路导致限流/瞬时超时的订阅获取永久放弃，与「5xx 瞬时可重试」的区分意图及 HTTP 重试语义不符。P3。
  **已修（2026-11-04）**：`fetcher.rs:264` 改为 `(400..500).contains(&status_code) && !matches!(status_code, 408 | 429)`——408/429 与 5xx 一样保持瞬时 `anyhow`（可重试至 `max_retries`），其余 4xx 仍终态 `FetcherError::HttpStatus`。回归 `fetch_classifies_4xx_terminal_5xx_transient` 扩展：404 请求 1 次即止；408/429/500 各重试 3 次。evidence：`crates/rillane-subscription/src/fetcher.rs:264` / `:650`；旧逻辑（408/429 判终态）时测试红（「408 应为瞬时错误」），修复后 `cargo test --workspace` 全绿（44 二进制）。

---

## 审核发现（e5029a2f9cde..4afe25b；只审不改，2026-11-04）

覆盖：rillane-core（net_mark 回归可观测化）、rillane-platform（dns singleflight 死首查自愈）、rillane-protocols（shaping 取模溢 / tls 回退 ring / pool 回归）、rillane-runtime（mesh 服务循环瞬态错误 / DNS 有界解析 / 下行序号续接 / UDP expiry 续期 / 单遍驱逐 / 进程归因单flight / 组环守卫 / sniff 解析器）、rillane-subscription（cache disk_io_lock / fetcher 408/429 / 转换器 admin_token / 订阅复活 / serde_yaml_ng）、rillaned（Clash 只读 API / reject 出口 / OR-NOT 规则 / IP-CIDR 匹配）、rillane-ffi（毒化锁恢复）、rillanectl（udp 头错误传播）。

- [x] 审核发现：ProcessAttributor 单flight（6499b63）用 `OnceCell + Notify` 存在 lost-wakeup/首领挂起——tokio `notify_waiters` 在无等待者时不存 permit（notify.rs:749-754），等待者 `cell.cell.get().is_none()` 检查（tun_process.rs:230）与 `notified()` 创建（:231）之间首领完成 `cell.set`+`notify_waiters`（:217-218）则等待者捕获的是已递增的 notify_waiters_calls、永不唤醒（多线程 runtime 下可发生）；且首领任务若在 `cell.set`/`notify_waiters` 前 panic/取消（如 `cache.lock().unwrap()` 毒化 panic）则所有等待者永久挂起。建议改用 `tokio::sync::OnceCell::get_or_init` 或循环复检。（crates/rillane-runtime/src/tun_process.rs:230-233、218）
  **已修（2026-11-04，证据=测试命令+结果：`cargo test --workspace` 全绿 44 二进制）**：`InflightState`（OnceCell+Notify）改为 `Arc<tokio::sync::OnceCell<Option<ProcessInfo>>>`，`attribute()` 用 `get_or_init`（tun_process.rs:180-227）——无 lost-wakeup（tokio 内部 watch 通道），init future 被取消/panic 时自愈（下次 get_or_init 重跑）。占位移除仍持 `Arc::ptr_eq` 守卫（防他代误删）。回归 `cancelled_leader_self_heals_and_waiters_complete`（首领取消后下次 miss 重扫且返回结果）。evidence：`crates/rillane-runtime/src/tun_process.rs:134` / `:180-227` / `:426-441`。

- [x] 审核发现：reject 出口（G0-5，43b731a）未接入 UDP 能力面——`build_udp_connectors` 对 `EgressConfig::Reject` 走 `_ => None`（runtime_builder.rs:2295），`scan_udp_capability` 遂把 reachable 的 reject 节点当「已知出站但无 UDP 能力」违规（:2349）；`udp.enabled=true` 且任一规则目标/组员为 reject 时整机构建失败，reject 无法拦截 UDP 流（广告拦截 + UDP 组合不可用），报错文案「节点 X（reject）不支持 UDP 转发」语义亦不符——reject 应直接丢弃 UDP 而非报错。（crates/rillane-runtime/src/runtime_builder.rs:2349）
  **已修（2026-11-04，证据=测试命令+结果：`cargo test --workspace` 全绿 44 二进制）**：`rillane-core::udp` 增 `RejectUdpConnector`/`RejectUdpRelay`（relay.rs:167-208）——关联成功返回 drop-only relay（`send_to` 吞包 Ok、`recv_from` 永久 pending，与 TCP `RejectFlowOutput` 断流对齐）；`build_udp_connectors` 对 `EgressConfig::Reject` 注册该连接器（runtime_builder.rs:2294），`scan_udp_capability` 不再把 reachable 的 reject 判负（构建不失败），能力表报错文案补 `reject`（:2366）。回归 `reject_udp_connector_drops_sends_and_never_recvs`（rillane-core:312）、`udp_capability_scan_passes_with_reject_reachable`（rillane-runtime:4643）。evidence：`crates/rillane-core/src/udp/relay.rs:167-208` / `crates/rillane-runtime/src/runtime_builder.rs:2294` / `:2366`。
- [x] 审核发现：非法或 Rust regex 不支持的正则未在导入或配置构建时校验，匹配时直接吞掉编译错误并回落默认路由，可能使拦截或代理规则静默失效（crates/rillane-routing/src/lib.rs:756）。
  **已修（2026-11-05）**：`RoutingConfig::validate` 逐条编译校验 `DomainRegex` pattern（递归进 Any/Not），非法正则构建期即 Err（含规则名与 pattern），不再落到匹配面吞错回落默认路由。evidence：`crates/rillane-config/src/lib.rs:1499-1532`（validate + `validate_condition_regex`）；回归 `crates/rillane-config/tests/routing_regex_validate.rs`（`valid_regex_passes_validate`/`invalid_regex_fails_validate_with_rule_name`/`nested_any_not_regex_validated_recursively`，3 测）；`cargo test --workspace` 全绿。
- [x] 审核发现：regexp 分支先于属性检查处理整行，`regexp:^example\.com$ @cn` 会被当作正则导入而非报告跳过，属性文本进入表达式后导致预期域名不命中（crates/rillane-subscription/src/rule_source.rs:129）。
  **已修（2026-11-05）**：`@` 属性检查前置于 `regexp:` 分支——含属性正则行整行 skipped（不进入表达式），纯正则仍入 regexps。evidence：`crates/rillane-subscription/src/rule_source.rs:133-152`；回归 `regexp_with_attribute_is_skipped_whole_line`（1 测）；`cargo test --workspace` 全绿。
- [x] 审核发现：含逗号的合法正则（如 `^ad{1,3}\.com$`）导出为逗号分隔规则后被导入侧拆成多个字段，导致正则截断且目标变成 `3}\.com$`，规则无法正确往返（crates/rillane-subscription/src/clash_export.rs:568）。
  **已修（2026-11-05）**：`condition_to_rules` 对含逗号的 `DomainRegex` pattern 不产出损坏规则串，整条登记 `skipped`（调用方可呈现），无 `DOMAIN-REGEX` 行被导入侧拆坏。evidence：`crates/rillane-subscription/src/clash_export.rs:565-590`；回归 `domain_regex_containing_comma_is_reported_not_corrupted`（1 测）；`cargo test --workspace` 全绿。
- [x] 审核发现：进程归因的最后一个调用者在初始化等待期间被取消时无法执行 inflight 移除，且映射持有强引用，未再次访问的键会永久残留并随不同源地址累积（crates/rillane-runtime/src/tun_process.rs:194）。
  **已修（2026-11-05）**：`attribute` 由首领安装 `InflightRemoveGuard`（Drop 守卫），正常完成与 future 被取消两路径都移除占位——不再依赖 await 后代码；等待者不安装守卫不承担移除。evidence：`crates/rillane-runtime/src/tun_process.rs:196-211` / `:235-257`；回归 `cancelled_last_caller_removes_inflight_placeholder`（1 测，断言取消后 inflight 空）；`cargo test --workspace` 全绿。
- [x] 审核发现：域名正则在每次流路由时逐条同步重新编译，较大的规则源或复杂表达式会反复占用 Tokio 工作线程并显著增加连接建立延迟（crates/rillane-routing/src/lib.rs:756）。
  **已修（2026-11-05）**：新增进程级 `REGEX_CACHE`（`LazyLock<DashMap<String, Arc<regex::Regex>>>`）——同一 pattern 只编译一次，命中 O(1)；`matches_condition` 经 `cached_regex` 取用。evidence：`crates/rillane-routing/src/lib.rs:21-35` / `:768-774`；回归 `domain_regex_cached_across_flows`（1 测）；`cargo test --workspace` 全绿。

- [x] 审核发现：含逗号正则被整条跳过时，clash_export 仍走 `rules.len()==before` 分支再补一条误导性的「Any/Not 逻辑条件暂不导出 Clash」，同一规则被登记两次且第二条原因不实（crates/rillane-subscription/src/clash_export.rs:121）。
  **已修（2026-11-05）**：`produced==0 && local_skipped.is_empty()` 才补 Any/Not 原因——含逗号正则已有具体 skipped 说明，不再二次登记误导性文案。evidence：`crates/rillane-subscription/src/clash_export.rs:118-130`；回归 `comma_regex_rule_not_also_reported_as_any_not`（`:1004`，断言单条 comma 原因且无 Any/Not 补登）；`cargo test --workspace` 全绿。
- [x] 审核发现：`REGEX_CACHE` 进程级缓存永不淘汰，配置热更新/订阅刷新后失效 pattern 仍占内存，随历史规则集差异缓慢累积（crates/rillane-routing/src/lib.rs:25）。
  **已修（2026-11-05）**：缓存从进程级 static 下沉为引擎字段 `regex_cache`，`reload` 后 `prune_regex_cache` 递归收集新配置仍用 pattern 并 retain，失效 pattern 即删。evidence：`crates/rillane-routing/src/lib.rs:165` / `:188` / `:194-201`；回归 `reload_prunes_stale_domain_regex_cache`（`:1550`，先路由入缓存再 reload 断言旧 pattern 被剔除、新 pattern 路由正常）；`cargo test --workspace` 全绿。
- [x] 审核发现：`cached_regex` 并发 miss 时两线程同时编译并各自 insert，后者覆盖前者，返回的 Arc 可能非 map 内实例——与注释「insert 后返回值与 map 内一致」不符（功能等价，仅多余编译）（crates/rillane-routing/src/lib.rs:27-33）。
  **已修（2026-11-05）**：miss 改 `entry` API——并发 vacant 单例写入，后者阻塞拿 `Occupied`，返回恒为 map 内 Arc，不重复编译；同步修正注释为引擎级缓存 + reload prune 口径。evidence：`crates/rillane-routing/src/lib.rs:26-41`；回归 `cached_regex_concurrent_miss_is_single_instance_semantics`（`:1612`，8 线程 64 并发 miss 后缓存恰一条 + 结果一致）；`cargo test --workspace` 全绿。
- [x] 审核发现：`MatchCondition::DomainRegex` 文档注释仍称「路由面惰性编译、校验面应在构建期拦截」，与本次改为构建期校验 + 进程级缓存的实际行为不同步，易误导后续维护（crates/rillane-config/src/lib.rs:1829-1830）。
  **已修（2026-11-05）**：注释同步为构建期 `validate` 编译拦截 + 路由面引擎级缓存（reload prune）实际行为。evidence：`crates/rillane-config/src/lib.rs:1829-1832`。
- [x] 审核发现：`DomainRegex` 分支注释仍称「编译结果走进程级缓存，同一 pattern 只编译一次」，与本次 diff 将缓存从进程级 static 下沉为引擎字段 `regex_cache` 的实际行为不同步——同文件 todo 声称已「同步修正注释为引擎级缓存口径」，但此处于本轮改动中漏改，易误导后续维护（crates/rillane-routing/src/lib.rs:828）。
  不属实：`:828` 是 `matches_rule` 签名参数行，实际注释在 `:862-863`，且该注释已写为「编译结果走引擎级缓存（`regex_cache`）」，所指漏改不存在。
- [x] 审核发现：回归测试 `cached_regex_concurrent_miss_is_single_instance_semantics` 仅断言 `regex_cache.len()==1` 与并发路由结果一致，但两者对原始并发双编译缺陷均为不变量（旧代码两线程各自编译后 insert 覆盖，len 恒为 1、路由结果等价），故该测试无法在缺陷复现时失败，为被守卫的回归提供虚假信心（crates/rillane-routing/src/lib.rs:1645）。
  **已修（2026-11-05）**：新增 `cached_regex_concurrent_miss_compiles_once`——`cached_regex_with` 注入原子计数编译器，64 线程并发同一 miss 后断言实际编译次数恰为 1 且 cache len=1；旧「get 后无条件 insert」实现会双编译并使计数断言红。evidence：`crates/rillane-routing/src/lib.rs:28-49` / `:1794-1817`；rillane-routing 25+9 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`resolve_geo_db` 归一化在相对路径越出配置目录深度时会弹出 `RootDir` 组件并把绝对路径退化为相对路径——如 `/etc/rillane` 下 `../../../geoip.mmdb` 应得 `/geoip.mmdb`，实际得 `../geoip.mmdb`（根被弹出、前导 `..` 残留，运行期路径错位，fail-open 下 geoip 条件静默恒不命中），`parts.last()!=".."` 判据未排除根组件（crates/rillane-config/src/lib.rs:1206）。
  **已修（2026-11-05）**：`resolve_geo_db` 改用 `Vec<Component>` 归一化，`ParentDir` 在栈顶为 `RootDir` 时钳制（不弹出根、不累积 `..`）；`/etc/rillane` + `../../../geoip.mmdb` 现得 `/geoip.mmdb`。回归 `resolve_geo_db_clamps_relative_paths_at_root`（根钳制 + 中途越界两例）。evidence：`crates/rillane-config/src/lib.rs:1198-1217` / `:1605-1615`；rillane-config 4 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`GeoSiteDb::matches` 四类匹配语义大小写口径不一致——Plain/Domain/Full 三臂对 `host_lower`（ASCII 小写化，geo.rs:193）匹配，而 Regex 臂用原始大小写 `host`（`re.is_match(host)`，geo.rs:200）；同一 geosite 类别内 `full:`/`domain:`/`plain:` 大小写不敏感、`regexp:` 大小写敏感，且预编译后未对 pattern 与 host 统一规范化，易造成同类别内条件命中结果与用户直觉相悖（crates/rillane-routing/src/geo.rs:200）。
  **已修（2026-11-05）**：四类统一 ASCII 小写口径——Plain/Domain/Full 加载期预小写（`to_ascii_lowercase`），Regex 用 `RegexBuilder::case_insensitive(true)` 预编译，匹配一律对 `host_lower`；正则不再对原始大小写 host 判命中。回归 `geosite_matching_is_case_insensitive_across_entry_types`（四类大写条目 vs 混合大小写 host 全命中）。evidence：`crates/rillane-routing/src/geo.rs:162-176` / `:199-222`；rillane-routing 25+9 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`DomainFull` 新条件用 ASCII 小写化后比较（lib.rs:853-857），而既有 `DomainSuffix`（`ends_with`，lib.rs:847-849）与 `DomainKeyword`（`contains`，lib.rs:850-852）均大小写敏感——同一 diff 引入的三类域名匹配大小写口径不一致，`full:` 规则将命中大写域名而 `suffix:`/`keyword:` 不命中，语义分裂易误导规则作者（crates/rillane-routing/src/lib.rs:853）。
  **已修（2026-11-05）**：`DomainSuffix`/`DomainKeyword`/`DomainFull`/`DomainRegex` 四类统一 ASCII 小写匹配——host 与 values 均小写化后比较/匹配（正则同样对 `host.to_ascii_lowercase()` 判 `is_match`）。回归 `domain_match_conditions_are_case_insensitive`（Suffix/Keyword/Full/Regex 对大写 host 均命中）。evidence：`crates/rillane-routing/src/lib.rs:853-882` / `:1623-1684`；rillane-routing 25+9 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`GeoSiteDb::matches` 热路径每流每次查询对每条域条目重复分配——`group.to_ascii_lowercase()`（geo.rs:190）、`d.to_ascii_lowercase()`（geo.rs:196）与 `format!(".{d}")`（geo.rs:197）均在查询时分配；域名/完全域条目可于加载期预小写并缓存后缀串，避免匹配热路径逐条分配（crates/rillane-routing/src/geo.rs:196-197）。
  **已修（2026-11-05）**：`GeoSiteGroup.domains` 改 `Vec<GeoSiteDomain>`（`value` 预小写 + `dotted` 预缓存 `.` + 值后缀串），`fulls`/`plains` 加载期预小写，`matches` 热路径仅对 host 小写一次、查询不再逐条 `to_ascii_lowercase`/`format!` 分配；类别键已小写存储，常见小写类别直查免分配。evidence：`crates/rillane-routing/src/geo.rs:46-58` / `:155-176` / `:199-222`；`cargo test --workspace` 全绿。
- [x] 审核发现：相对配置目录中的上级路径被错误丢弃，例如配置 `conf/config.yaml` 引用 `../../geoip.mmdb` 时解析成 `geoip.mmdb` 而非 `../geoip.mmdb`，导致数据库加载失败和 GeoIP 规则静默不命中（crates/rillane-config/src/lib.rs:1209）。
  **已修（2026-11-06）**：`resolve_geo_db` 的 `ParentDir` 分支在栈顶为 `RootDir` 时钳制（不弹出根），栈空或栈顶为相对普通段时保留前导 `..`（不再静默丢弃上级路径）；`conf` + `../../geoip.mmdb` 现得 `../geoip.mmdb`。回归 `resolve_geo_db_clamps_relative_paths_at_root` 增第三断言（相对越界保留 `..`）。evidence：`crates/rillane-config/src/lib.rs:1200-1214` / `:1614-1617`；rillane-config 4 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：域名正则仅将目标主机转为小写而保留原表达式的大小写敏感语义，合法规则 `^AD\d+\.example\.com$` 原本匹配 `AD123.example.com`，现在不再匹配，可能使代理或拦截规则失效（crates/rillane-routing/src/lib.rs:881）。
  **已修（2026-11-06）**：`DomainRegex` 改用 `RegexBuilder::case_insensitive(true)` 预编译（`cached_regex`），匹配对原始 host（不再 `to_ascii_lowercase`）判 `is_match`——pattern 含大写 `^AD` 仍命中 `AD123.example.com`，且保留 `\D`/`\S` 等大小写敏感转义语义；构建期 `validate_condition_regex` 同步用 `case_insensitive(true)` 编译（构建面与路由面一致）。回归 `domain_match_conditions_are_case_insensitive` 改 pattern 为 `^AD\d+\.`（旧实现仅小写 host 会红）。evidence：`crates/rillane-routing/src/lib.rs:30-35` / `:875-879` / `:1633-1676`；`crates/rillane-config/src/lib.rs:1628-1632`；rillane-routing 25+9 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：QUIC AEAD nonce 构造错误——`iv[0..4]` 未拷入 `nonce[0..4]`（恒为 0），仅 `iv[4..]` 写 `nonce[4..]`，违反 RFC 9001 §5.3「nonce = IV XOR 左填充 packet number」；真实 QUIC 包 AEAD 解密必失败，而合成回环测试加密端/解密端共用同一错误实现（同口径），故 `cargo test --workspace` 全绿不能证明正确（crates/rillane-runtime/src/sniff.rs:166-167、:420-421）。
  **已修（2026-11-06）**：`quic_aead_nonce` 先完整拷入 IV 再对最低 8 字节异或 PN（原错误仅写 `nonce[4..]`，`iv[0..4]` 恒 0），符合 RFC 9001 §5.3。回归 `quic_aead_nonce_xors_packet_number_into_full_iv` 验证 `nonce(0)==iv`、`nonce(1)` 末字节翻转。evidence：`crates/rillane-runtime/src/sniff.rs:278-285`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：HKDF-Expand-Label 编码错误——length 用 1 字节、label/context 长度用 2 字节写，而 RFC 8446 §7.1 规定 uint16 length + 单字节 label/context 长度（RFC 9001 A.1 向量 `00200f746c73313320636c69656e7420696e00`）；推导密钥与规范不符，真实流量解密失败，同样被回环测试掩盖（crates/rillane-runtime/src/sniff.rs:196-202）。
  **已修（2026-11-06）**：`hkdf_expand_label` 改为 `uint16 length` + `u8 label 长度` + `u8 context 长度`（原 1 字节 length / 2 字节 label·context），符合 RFC 8446 §7.1。回归 `quic_initial_keys_match_rfc9001_vector` 用 RFC 9001 A.1 向量（client initial secret `c00cf151...`）验证密钥派生。evidence：`crates/rillane-runtime/src/sniff.rs:310-325`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：QUIC CRYPTO 载荷误按 TLS 记录解析——QUIC 的 CRYPTO 帧携带裸 TLS 握手消息（无记录层，RFC 9001 §4），但 `parse_crypto_frames_sni` 将帧数据直接交给 `sniff_tls_sni`，后者要求首字节 0x16 的 5 字节记录头；真实 ClientHello（0x01 开头）恒返回 None，而测试端 `build_client_hello` 错误地包了记录层（:401-403），掩盖此缺陷（crates/rillane-runtime/src/sniff.rs:260、:17、:348-376、:401-403）。
  **已修（2026-11-06）**：新增 `sniff_tls_handshake_sni` 解析裸 TLS 握手消息（无记录层），`parse_crypto_frames` 直接对其返回的帧数据调用；测试 `build_client_hello` 不再包 5 字节记录头（原 `build_quic_initial` 错误包裹掩盖缺陷）。QUIC CRYPTO 载荷符合 RFC 9001 §4。evidence：`crates/rillane-runtime/src/sniff.rs:89-145` / `:198-201` / `:376+`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：TCP 嗅探交接竞态——`spawn_tcp_forward` 在 Established 检出时即 peek，而真实 TLS ClientHello 通常在三次握手完成后的独立分段才到达，peek 常为空导致嗅探静默跳过；测试仅覆盖 ClientHello 与最终 ACK 同段捎带场景（`tcp_sniff_reroutes_on_tls_sni`）。另 peek 上限 4096 字节而 `sniff_tls_sni` 要求整条记录，超长 ClientHello 永不命中（crates/rillane-runtime/src/tun_ingress.rs:707、sniff.rs:19-21）。
  **已修（2026-11-06）**：`spawn_tcp_forward` 交接改独立 spawn 任务，用 `peek_socket_with_wait` 短暂轮询等待 ClientHello 独立分段到达（120ms 窗口、上限 16389 字节容纳整条 TLS 记录），不再单次 peek 空即静默跳过；重路由后 forward。回归 `tcp_sniff_reroutes_when_client_hello_arrives_late`（纯 ACK 触发 Established、ClientHello 稍后到达仍重路由）。evidence：`crates/rillane-runtime/src/tun_ingress.rs:705-780` / `crates/rillane-runtime/src/tun_tcp.rs:477-495`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：UDP 流目标不一致——首包以 SNI 域名 target 发送（:539），后续同流包重新用 `udp_target(dst)` 以 IP 发送（:442），relay 每包 target_host 语义不一致（crates/rillane-runtime/src/tun_ingress.rs:539、:442）。
  **已修（2026-11-06）**：`TunFlowEntry` 增 `target: FlowTarget` 字段，首包 QUIC SNI 覆写后固化进条目，后续同流包复用该 target（原 `:442` 每包重新 `udp_target(dst)` 以 IP 发送），relay 每包 target_host 语义一致。evidence：`crates/rillane-runtime/src/tun_ingress.rs:107-113` / `:436-447` / `:550-556`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：32 位目标上 `token_len`（u32）累加 `i += 4 + token_len` 可溢出 panic/回绕——`length` 路径已用 `checked_add` 而 token 路径没有，仓库 Cross.toml/.cargo/config.toml 含 32 位 target（低危）（crates/rillane-runtime/src/sniff.rs:131-134）。
  **已修（2026-11-06）**：`token_len` 累加改用 `i.checked_add(n)?.checked_add(usize::try_from(token_len).ok()?)`（原 `i += 4 + token_len` 无溢出保护），32 位 target 上不再回绕/panic。evidence：`crates/rillane-runtime/src/sniff.rs:231-233`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：QUIC 长头 `token_len`/`length` 用固定 4 字节 `u32::from_be_bytes` 读取，而 RFC 9000 §17.2 规定为变长整数——RFC 9001 A.2 向量中 token_len 为 1 字节、length 为 2 字节，固定 4 字节读会错位偏移、得错误长度并使真实包解析失败（与 :396 的 32 位累加溢出是不同缺陷）（crates/rillane-runtime/src/sniff.rs:131、:136）。
  **已修（2026-11-06）**：`token_len`/`length` 改用 `read_varint` 变长整数解码（原固定 4 字节 `u32::from_be_bytes` 会错位偏移），符合 RFC 9000 §17.2；回归 `write_varint_roundtrips_all_widths` 覆盖 1/2/4/8 字节宽度。evidence：`crates/rillane-runtime/src/sniff.rs:230-240` / `:512-530`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：`sniff_http_host` 返回 Host 头原值（未剥端口，如 `example.com:443`）直接赋给 `target.host`，后续连接以 `lookup_host(("example.com:443", 443))` 把端口当主机名 DNS 解析而失败——HTTP 带端口 Host 头使 TCP 嗅探重路由后无法建连（crates/rillane-runtime/src/sniff.rs:87、crates/rillane-runtime/src/tun_ingress.rs:711）。
  **已修（2026-11-06）**：`sniff_http_host` 增 `strip_host_port` 剥离 Host 头端口（`example.com:443`→`example.com`，`[v6]:443`→`v6`），后续 `lookup_host` 不再把端口当主机名。回归 `http_host_extracts_host_header_without_port` 三断言。evidence：`crates/rillane-runtime/src/sniff.rs:147-181`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：测试辅助 `write_varint` 第三分支先 push 4 字节 `[0x80,0,0,0]` 再 `buf[last..].copy_from_slice(&value.to_be_bytes())`，将 8 字节 `u64` 拷入 4 字节切片，`value∈[16384,2^30)` 时 `copy_from_slice` 长度不匹配必然 panic——该值域覆盖 QUIC 长头 length 常见范围，构造真实长度包会崩（crates/rillane-runtime/src/sniff.rs:383-386）。
  **已修（2026-11-06）**：`write_varint` 测试辅助 4/8 字节分支改为首字节写前缀位 + 余字节 `extend_from_slice`（原 `copy_from_slice` 把 8 字节 `u64` 拷入 4 字节切片必 panic）。回归 `write_varint_roundtrips_all_widths` 覆盖 `16384`/`1<<20`/`1<<29`/`1<<30`。evidence：`crates/rillane-runtime/src/sniff.rs:653-668`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：QUIC CRYPTO 帧的 offset 是握手流偏移而非当前数据在包内的偏移，且解析器只处理第一帧、不重组跨帧或跨包的 ClientHello，导致分片握手无法提取 SNI 并按域名分流（crates/rillane-runtime/src/sniff.rs:253）。
  **已修（2026-11-06）**：新增 `QuicCryptoReassembler` 按握手流 offset 跨包拼接 CRYPTO 帧（`append_crypto_frames` 处理空洞/超限），`parse_crypto_frames` 收集全部帧（跳过合法 PADDING/PING/ACK 等）而非只取第一帧。回归 `quic_crypto_reassembles_split_client_hello`（半包首片不命中、次片命中 SNI）。evidence：`crates/rillane-runtime/src/sniff.rs:37-68` / `:355-374`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：HTTP 嗅探将整个 peek 缓冲区按 UTF-8 解码，合法请求头之后若已包含二进制请求体则解码失败，导致该连接无法按 Host 域名分流（crates/rillane-runtime/src/tun_ingress.rs:709）。
  **已修（2026-11-06）**：`sniff_http_host` 只解码 `\r\n\r\n` 之前的头部（`windows(4).position`），二进制请求体不再导致 UTF-8 解码失败。回归 `http_host_ignores_binary_body_and_requires_complete_headers`（含 `[0xff,0x00,0xfe]` 请求体仍提取 Host）。evidence：`crates/rillane-runtime/src/sniff.rs:147-158`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：HTTP 嗅探无需等待 Host 头的行结束就接受当前缓冲内容，若首段在域名中途截断便会将不完整域名用于路由和连接，造成错误分流或连接失败（crates/rillane-runtime/src/tun_ingress.rs:709）。
  **已修（2026-11-06）**：`sniff_http_host` 未见到 `\r\n\r\n` 头部结束标记即返回 None（不把截断域名用于路由）。回归 `http_host_ignores_binary_body_and_requires_complete_headers`（`Host: partial.exa` 与缺空行均返回 None）。evidence：`crates/rillane-runtime/src/sniff.rs:147-158`；rillane-runtime 170 测 + `cargo test --workspace` 全绿；commit evidence: `25a7d16..HEAD`。
- [x] 审核发现：url-test 周期探测任务已实现但从未在运行时启动——`RoutingEngine::start_health_check_task`（`crates/rillane-routing/src/lib.rs:437-443`）在 `crates/rillane-runtime/src/runtime_builder.rs` 的 `start()` 任务区（`:1048-1320`）无任何调用点，仅 `ChainManager::start_health_check_task`（`chain.rs:979`，`runtime_builder.rs:1268`）与 mesh→routing 质量桥（`:1302-1314`）被 spawn；探测句柄虽在 `runtime_builder.rs:199-211` 注入，配置了 `url_test` 的策略组运行时也不会周期探活，健康/延迟表恒空，url-test 组退化为默认健康兜底。
  **已修（2026-11-10）**：`start()` 任务区补唯一启动点（detached 内层探活任务 + 外层 running 门控随停止信号退出——同 ChainManager 健康任务模式，任务不驻 `tasks` 防 `run()` 挂死）。回归 `urltest_health_task_wired_into_start`（移除修复后该测必失败：健康表恒空 (0,0)，修复后无出口成员被探活标不健康 (0,1)）。evidence：`crates/rillane-runtime/src/runtime_builder.rs:1298-1317`（spawn 块）+ `:4795`（回归测）；`cargo test --workspace` 46 二进制全绿；commit evidence: `196cfc1`。
