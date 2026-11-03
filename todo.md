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
  **已修（2026-11-03）**：`maybe_reload` 增 `reload_lock` 串行门（tokio Mutex），磁盘载入移出 `inner` 写锁并经 `spawn_blocking`（`mesh_transport.rs:2155-2192`）；写锁仅覆盖内存交换短临界，三处双检保留；回归 `maybe_reload_reloards_only_on_fingerprint_change`（真实 rcgen 证书夹具，指纹不变不重载/触摸触发重载），seep-runtime 138+2 测全绿。
- [ ] **DNS 解析缓存未命中 stampede**——`dns_engine.rs:695-738`：N 并发冷名全部 miss 全部上游 `query_group`/`cross_check` 再各自插入，无 singleflight；突发时击穿上游解析器。
  evidence：`dns_engine.rs:695` check-then-act，`724/726` await 上游后 `728` insert。
- [ ] **control-plane 无 token 时鉴权门整体跳过**——`control_plane.rs:129-140`：`admin_token=None`（serde 缺省）+ 非回环 `api_bind` 时 mutating 端点与 `/runtime/config`、`/events`、`/logs` 全开放。建议非回环绑定无 token 时启动告警/拒启。
  evidence：`control_plane.rs:135-137` `(is_mutating||is_sensitive_read) && admin_token.is_some() && !is_authorized`——None 即短路放行。注释 "if token configured" 示有意设计，故 P2。

P3（收尾）：
- [ ] **hysteria2 连接器持 client mutex 跨 QUIC/HTTP3 握手**——`hysteria2.rs:119-124`：cache-miss 持锁跨 `connect_client()`（秒级或挂起拨号）；有意的 single-flight（防连接风暴），但握手无显式超时则永久钉住全部该出站流。建议 connect 超时。
  evidence：`hysteria2.rs:119` `client.lock().await` 持至 `:124` `connect_client().await?` 完成。
- [ ] **无界 pong/keepalive 通道**——`vless.rs:630` / `trojan.rs:473` / `vmess.rs:1349` `mpsc::unbounded_channel`：对端洪泛 PONG 时队列无界内存增长（流量生命周期有界）。
- [ ] **mesh 信封 `as u8` 长度截断**——`mesh_transport.rs:379-386/616-631`（flow_id/target_host/path 长度）+ `trojan.rs:99` / `udp/associate.rs:96`（域名长度）：无 `>255` 守卫，超长静默截断长度字节产畸形帧；对照 `vless.rs:165` 有守卫。
- [ ] **padding.rs range span 下溢**——`middleware/padding.rs:71` `spec.max - spec.min + 1`：仅 config validate 保证 min≤max；绕过校验（或未来路径）即 usize wrap。
- [ ] **seep-core 链路质量 NaN**——`seep-core/lib.rs:744-745`：`hop_bandwidths` 空而 `hop_latencies` 非空时 `0.0/0.0=NaN` 传播进 `calculate_quality_score`；两 pub 向量常规同长（update_path），需外部独立变更。
- [ ] **非常量时间认证比对**——`inbound/http.rs:262/276` + `socks5.rs:253` + `control_plane.rs:266`：`String ==` 短路径；网络时序攻击对本地代理密码实际难利用，防御纵深。
- [ ] **runtime 无限循环任务无 stop 标志、JoinHandle 丢弃**——`runtime_builder.rs:1007-1225/2924-2954`（mesh stats/chain health/mesh quality/health checker/topology updater）+ `pool.rs:714-725`（sweeper）：重载路径每轮泄漏一组 loopers（各持 Arc）；单进程守护进程生命周期内良性，seepd 以进程退出掩盖。
- [ ] **DNS start() shutdown_tx mutex 跨 await**——`dns_engine.rs:1072-1086`：持 `shutdown_tx` tokio mutex 跨取 `task` 与 spawn；生命周期串行化，有界。
- [ ] **FFI raw-pointer 别名（UB 风险）**——`seep-ffi/lib.rs`：`seep_ffi_tun_start/stop` 取 `&mut *handle` 而 `is_running/stats_json` 取 `&*handle`；内嵌方并发调用即数据竞争 UB，无内部同步。
- [ ] **connect_racing 落选候选不中止**——`net_mark.rs:111-145`：胜出后落选拨号任务不自中止（channel drop 时自终止），慢候选短暂持套接字/TLS 握手。
- [ ] **订阅刷新 read-modify-write 复活已删订阅**——`subscription/lib.rs:380-455`：`refresh_subscription` 克隆后长 fetch，`update_subscription_in_map` 回写；fetch 期间热更删除的订阅被复活。
- [ ] **process 归因缓存重复工作**——`tun_process.rs:165-178`：并发 miss 重复扫 /proc 并插入等价值；幂等仅性能。
- [ ] **事件广播 fire-and-forget**——`runtime_builder.rs:538`：`broadcast::channel(1024)` 首 receiver 丢弃；生产 `ControlPlane::new` 立即订阅且 Lagged 已处理，订阅前事件静默丢失。
- [ ] **TUN 设备锁全生命周期持有**——`tun_ingress.rs:221-268`：`tun.lock()` 跨多 await 持进程生命周期；有意单主设计，正确性依赖该不变式。
- [ ] **poll_read/poll_write 内 std Mutex**——`tun_tcp.rs:502,538`：无 await 持锁（短临界），争用下可 stall tokio worker。
- [ ] **DefaultHasher 缓存文件名**——`cache.rs:584-595`：确定性哈希（跨进程稳定），非密码用途可接受；文件名碰撞极低。
- [ ] **wasmtime Engine 初始化 expect**——`plugins/loader.rs:26`：进程级全局 `LazyLock` init，平台不支持/feature 不匹配时首插件加载即 panic（罕见且致命）。
- [ ] **TLS CryptoProvider get_default().expect**——`protocols/tls.rs:57`：ring feature 缺失或竞争 provider 时首次 TLS 握手 panic；`let _ =` 忽略 install 失败致仅剩 expect。
- [ ] **HotReloadManager Default panic + reload_rx 一次性槽位**——`hot_reload.rs:623`（Default 恒 panic）/`:353`（`take().expect("reload_rx already taken")`）：现无双重调用，不变式仅由 expect 维持。
- [ ] **不变式 expect（结构上恒真，重构漂移即启动 panic）**——`tun_ingress.rs:214`（flow_router 未注入）/`runtime_builder.rs:479`（tun_enabled 蕴含 network_config）。
- [ ] **插件/FFI mutex poison 级联**——`plugins/plugin.rs:133`（std Mutex 跨 wasm 调用，宿主 panic 即毒化后续全插件流）/`ffi/lib.rs:302,328`（tun_thread lock）。
- [ ] **unmaintained 依赖**——`serde_yaml`/`unsafe-libyaml`（RUSTSEC-2024-0449）、`basic-toml`（RUSTSEC-2026-0374）：cargo audit 信息级；升级候选。

## 2026-11-02 代码深审补充（P2/P3，源自 docs/review/2026-11-01-code-review.md 第二轮补充节）

P2（下一步修）：
- [ ] **TUN UDP 下行只续 last_active 不续 expiry**——`tun_ingress.rs:812-813`：上行（:432-434）续两者、下行续一者，清扫（:714）按 `expiry<=now` 驱逐。纯下行推送流（客户端 udp_idle_secs 内无上行）被中途逐出。
  evidence：`tun_ingress.rs:812` `e.last_active = now`（无 `e.expiry` 续期）；`:714` `.filter(|e| e.expiry <= now)`。
- [ ] **scan_udp_capability BFS 无 visited 集（组环挂起 build）**——`runtime_builder.rs:2266-2280`：组环（g1→g2→g1）队列永不空，`udp.enabled` 时 build() 无限挂起；`RoutingConfig::validate`（seep-config:1489）仅查 SLO 无环守卫。
  evidence：`runtime_builder.rs:2266` `while let Some((name, source)) = queue.pop()` 无 visited；`continue` 在 `reachable.entry` 前。
- [ ] **chain 故障转移复用已消费 flow.io（协议流损坏）**——`runtime_builder.rs:1919/2025`：首 `dial_and_tunnel`（mesh_transport.rs:1569 copy_bidirectional 读 io）中途失败即部分消费；重试拼接尾流+新信封。正确恢复=中止应用连接（RST）非重接。
  evidence：`runtime_builder.rs:2025` `&mut *flow.io` 与 :1919 同一流复用。
- [ ] **串行 UDP serve 循环内联 lookup_host（头阻塞整面）**——`mesh_transport.rs:1852`：单任务无 per-packet spawn（§13-5），一个不可解析 `target_host`（线上可控）阻塞所有流。
  evidence：`mesh_transport.rs:1852` `lookup_host(...).await?` 在 serve 循环内。
- [ ] **瞬时 recv_from 错误终止 UDP serve 任务**——`mesh_transport.rs:1946`：`Ok(Err(e))=>return Err`（ENOBUFS/EINTR 瞬时亦毙）；应 continue 或按瞬时/致命分类。
- [ ] **瞬时 accept 错误终止 TCP mesh 监听任务**——`mesh_transport.rs:1330`：`listener.accept().await?`（ECONNABORTED/EMFILE/EINTR 瞬时亦毙）。

P3（收尾）：
- [ ] **active_chains.len()-1 下溢**——`chain.rs:907`：`drop(chain)`（:901）后读 len；并发 `terminate_chain`（:924 remove）移除 → 0-1 下溢（release 裹 usize::MAX 指标污染）；宜 `saturating_sub(1)` 或由 terminate 自减。
- [ ] **mesh UDP 下行序号归零瞬态丢包**——`mesh_transport.rs:1877`：exit 建流归零下行序号而客户端窗口仍在（last>63）→ 序号 0..36 判回退拒、≥37 自愈；瞬态 ~37 包突发丢包（非永久拒收）。
- [ ] **缓存满插入 O(n) 驱逐扫描**——`mesh_transport.rs:868-876`：满（65536）时每次插入全 `min_by_key` 扫描；文档化权衡（"O(n) 无新依赖"），需认证 peer + 6.5 万流触发。
- [ ] **订阅转换配置硬编码 admin_token="seep"**——`clash.rs:768-771`/`seep_dsl.rs:413-418`：回环绑定约束暴露面；建议省略或随机生成。
- [ ] **shaping 抖动 jitter_ms+1 裹 0（% 0 panic）**——`shaping.rs:45`：jitter_ms=interval_ms=u64::MAX 时裹 0；validate（seep-config:908-918）无上界；`wrapping_add(1).max(1)` 或上界校验。
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
- [x] 审核发现：`host_has_injection_chars` 仅拦截 CR/LF/控制字符/DEL（b<0x20 或 b==0x7F），允许空格(0x20)与 authority 元字符 `@`/`/`/`?`/`#`——空格产生畸形 CONNECT 请求行，`@` 可被上游按 `userinfo@host` 解析致目标混淆（请求走私/SSRF 变体），作为出口"最后防线"不完整（seep-protocols/src/lib.rs:44）。
- [x] 审核发现：ReplayWindow 段首注释仍述旧语义"1..=64 前进接受（越 64 位窗历史全丢）"，与新实现（1..=63 滑窗、≥64 跳变重置 bits=0）不符，属文档漂移易误导后续维护（mesh_transport.rs:757）。
- [x] 审核发现：订阅内容超限经 `bail!`（fetcher.rs:267/277）抛出后被 `fetch()`（fetcher.rs:144）视为可重试错误，对持续返回超大/分块超限端点会重复下载（chunked 路径每次至多 50MiB）`max_retries` 次；宜将终态错误与瞬时错误分类。
- [x] 审核发现：`merge_subscription_config` 仅语句级持 `current_config` 写锁克隆（hot_reload.rs:565-566）、末段重取写锁写回（hot_reload.rs:616），中途 `fs::write` await 让锁——若与 `apply_config`（hot_reload.rs:461）并发会丢失其更新（lost-update）；现调用方串行，属潜在竞态。
- [ ] 审核发现：测试缺口——本区间多项 P1/正确性修复无回归测试：pool.rs `maybe_refill` inflight 并发门（pool.rs:579-597，pool.rs 全文件 0 测试）；seep-mesh 健康检查写锁复检（seep-mesh/src/lib.rs:982-990）；chain.rs `handle_chain_failure` 分片守卫释放（chain.rs:860-890）；http.rs 出口注入守卫（http.rs:119/164，仅 socks5 入口被覆盖）；fetcher.rs 分块超限与非 UTF-8 拒绝（fetcher.rs:277/279）；mesh_transport.rs flow miss 丢弃路径（mesh_transport.rs:1905-1906）。

---

## 功能差距分析（2026-11-02，对照 sing-box/mihomo/xray-core）

> 完整报告：[docs/gap-analysis-2026-11-02.md](docs/gap-analysis-2026-11-02.md)。只审不改；未触碰工作树既有未提交改动。

**核心结论**：底座完成度高，差距集中在四块——① 路由规则引擎（无目的 IP-CIDR、无 GeoIP/GeoSite 数据库、无 rule-set、无 OR/NOT、无嗅探）；② QUIC 生态（tuic/REALITY/XTLS-Vision/hy2 UDP 全缺）；③ 服务端入站协议为零；④ 透明代理仅 TUN(Linux)（缺 redir/tproxy、macOS/Windows TUN）。seep 独有优势：mesh mTLS 多跳+SLO 打分、场景 profile、WASM 插件、移动端 FFI。

建议优先级（新条目，未编号入现有 P 序列）：
- [ ] **G0-1 目的 IP-CIDR 匹配器**——现 `MatchCondition::Network` 绑定 `client.cidr` 源注解（seep-routing/src/lib.rs:706），目标网段分流表达不了；三大项目最基本匹配器。
- [ ] **G0-2 GeoIP/GeoSite 数据库接入 + domain full/regex + OR/NOT 逻辑规则**——替换 `geoip.country` 注解等价物（无数据库）。
- [ ] **G0-3 协议嗅探层（sniff）**——TLS SNI/HTTP Host/QUIC SNI 覆写路由域名；TUN 场景 IP 直连流量无它即无法按域名分流。
- [ ] **G0-4 UDP over vmess/vless/trojan**——主流加密通道均不载 UDP（构建期报错），游戏加速场景非 direct/ss/wg 出口即退化。
- [ ] **G0-5 reject/block 目标**——极小成本，断连/广告拦截基本表达。
- [ ] **G1-6 REALITY + XTLS-Vision 出站**——主流机场节点形态，现订阅含 reality-opts/flow 即构建失败；可复用 VMess xray 向量互操作经验。
- [ ] **G1-7 hysteria2 UDP 面（quinn 载具）+ salamander/端口跳跃**——现归 V2，游戏定位下建议提前。
- [ ] **G1-8 DNS 加密上游 DoH/DoT**——现仅裸 UDP 53；cross_check 在深水区才可靠。
- [ ] **G1-9 rule-set 远程规则提供者 + 订阅级 url-test 常驻测速**。
- [ ] **G1-10 fake-ip + DNS 回填路由**（配合 G0-3）。
- [ ] **G2-11 redir/tproxy 透明代理入站**（Linux）。
- [ ] **G2-12 服务端入站协议**（trojan/vless/ss 至少一种）——若坚持纯客户端内核定位则显式决策不做并登记。
- [ ] **G2-13 tuic/anytls/shadowtls 出站**。
- [ ] **G2-14 Clash API 兼容层（只读子集 + 面板直连）**——现控制面不兼容 /proxies /connections /traffic，metacubexd/yacd 无法直连。
- [ ] **G2-15 httpupgrade/xhttp 传输；G3-16 macOS/Windows TUN + auto_route 全局接管；ICMP 代理、UoT、hosts 映射**。

---

## 审核发现（5ddd48417fab..HEAD；只审不改，2026-11-03）

覆盖：seep-protocols（host_has_injection_chars 扩围 + socks5/http 回归测试）、seep-runtime（config_apply_lock 热交换串行、hot_reload config_mutex、mesh send_existing_flow + 防重放窗口语义、chain fmt）、seep-subscription（cache 锁外磁盘删除 + 热盘容量回填、fetcher 终态错误分类）、README/文档。

- [x] 审核发现：cache 三个 cleanup（cleanup_expired/cleanup_lru/cleanup_lru_by_count）把磁盘 `fs::remove_file` 移到 `memory_cache` 锁外（cache.rs:417/485/547），与并发 `set_with_ttl`→`save_to_disk`（cache.rs:253）同键竞态——清理线程在内存移除后、删盘前，set 可重插该键并落盘，随后清理删掉 set 刚写的新盘文件，留下「内存有、磁盘无」的副本；重启/后续 LRU 再逐即丢失。提交注释只声明了 get()→load_from_disk 复生窗口（自愈），未覆盖此 set 写删窗口（不白愈、持久化丢失）。P3。
  **已修（2026-11-03）**：`SubscriptionCache` 增 `disk_io_lock`（std Mutex），cleanup 删盘与 set 落盘串行；删盘前复查 `memory_cache` 已无该键（`cache.rs`），有活跃副本则跳过删盘。回归 `cleanup_expired_skips_delete_when_key_reinserted`（模拟 set 重插后 cleanup 不误删），seep-subscription 54 测全绿。
- [x] 审核发现：`FetcherError` 文档声明「HTTP 状态错」为终态（fetcher.rs:8-10），但非 2xx 状态（4xx/5xx，如 404/429/5xx）经 `anyhow!` 返回（fetcher.rs:254-260），未包装成 FetcherError——`fetch()` 的终态短路（fetcher.rs:172 `downcast_ref::<FetcherError>`）对状态错不生效，仍按瞬时错误重试 `max_retries` 次；文档与实现语义不符，且 4xx（404/403/429）语义上应属终态。P3。
  **已修（2026-11-03）**：`FetcherError` 增 `HttpStatus(u16)` 变体；非成功状态中 4xx（400..500）包装成 `FetcherError::HttpStatus`（终态短路生效），5xx 保持瞬时 `anyhow`（可重试）。回归 `fetch_classifies_4xx_terminal_5xx_transient`（404 终态/500 瞬时），seep-subscription 56 测全绿。
- [x] 审核发现：`apply_config_inner`/订阅循环的写序改「先装 egress 面、再 reload 路由、最后落 config」（runtime_builder.rs:1158-1163/1427-1434）消除了「新规则引用未就绪名」窗口，但引入反向窗口：outputs/connectors 整体替换后、`router.reload` 前，旧路由规则可解析到已被新 egress 集删除的名字 → 该窗口内命中已删 egress 的在途流报「未知 egress」失败（瞬时微秒级，多状态非原子交换固有残余）。注释「不再引用未就绪名」方向正确但未提此逆向窗口。P3（低）。
  **已文档化（2026-11-03）**：`apply_config_inner` 与订阅循环两处注释补「反向残余」说明（`runtime_builder.rs`）——多状态非原子交换固有残余，在途流已按旧路由解析、窗口仅影响并发新流；彻底消除需单状态原子交换或先 reload 再换 egress（会重引入「新规则引用未就绪名」窗口），接受并登记。P3（低）性质判定为可接受残余，无需代码改动。
- [x] 审核发现：测试缺口——① fetcher 终态错误仅 Content-Length 超限被回归（chunked 分块超限 ChunkOverLimit 与非 UTF-8 NotUtf8 两终态分支无测试，fetcher.rs:298-305）；② cache cleanup 锁外删盘 vs set 同键竞态无回归测试（cache.rs:417 窗口）；③ 订阅刷新循环持 config_apply_lock 路径（runtime_builder.rs:1132）无独立回归（仅 update_config/merge_config_delta 两路径被覆盖）。
  **已补（2026-11-03）**：① 增 `fetch_terminal_chunk_overlimit_and_not_utf8`（chunked 超限 ChunkOverLimit + 非 UTF-8 NotUtf8 两终态分支）；② 增 `cleanup_expired_skips_delete_when_key_reinserted`（cache.rs:417 窗口）。③ 订阅刷新循环持 config_apply_lock 路径无独立回归——**该项保留未修**（属 config_apply_lock 语义覆盖面，update_config/merge_config_delta 两路径已有回归，订阅循环复用同锁语义；如需独立回归需构造订阅热更时序，成本高）。
