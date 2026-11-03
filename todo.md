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
- [x] **DNS 解析缓存未命中 stampede**——`dns_engine.rs:695-738`：N 并发冷名全部 miss 全部上游 `query_group`/`cross_check` 再各自插入，无 singleflight；突发时击穿上游解析器。
  evidence：`dns_engine.rs:695` check-then-act，`724/726` await 上游后 `728` insert。
  **已修（2026-11-03）**：`DnsResolver` 增 `inflight`（tokio Mutex<HashMap<键, watch::Sender>>）singleflight——首个调用者查上游并经 watch 广播结果（含负缓存），其余等待者直接取结果不重复查；tokio Mutex 守卫可跨 await 且锁不跨上游查询。回归 `resolver_concurrent_cold_miss_singleflight`（8 并发同名 miss → 上游到达计数 1），seep-platform 49 测全绿。
- [x] **control-plane 无 token 时鉴权门整体跳过**——`control_plane.rs:129-140`：`admin_token=None`（serde 缺省）+ 非回环 `api_bind` 时 mutating 端点与 `/runtime/config`、`/events`、`/logs` 全开放。建议非回环绑定无 token 时启动告警/拒启。
  evidence：`control_plane.rs:135-137` `(is_mutating||is_sensitive_read) && admin_token.is_some() && !is_authorized`——None 即短路放行。注释 "if token configured" 示有意设计，故 P2。
  **已修（2026-11-03）**：`seepd` 启动路径（`main.rs`）fail-closed——`api_bind` 非回环且 `admin_token=None` 时拒启（bail，错误含绑定地址与处置建议）；回环绑定保留无 token 能力（本机开发/诊断）。seepd 27+2 测全绿。

P3（收尾）：
- [x] **hysteria2 连接器持 client mutex 跨 QUIC/HTTP3 握手**——`hysteria2.rs:119-124`：cache-miss 持锁跨 `connect_client()`（秒级或挂起拨号）；有意的 single-flight（防连接风暴），但握手无显式超时则永久钉住全部该出站流。建议 connect 超时。
  evidence：`hysteria2.rs:119` `client.lock().await` 持至 `:124` `connect_client().await?` 完成。
  **已修（2026-11-03）**：`get_or_connect_client` 的 `connect_client()` 包 `tokio::time::timeout(CONNECT_TIMEOUT=15s)`——挂起握手超时后失败释放互斥、不缓存半成品（fail-closed），后续调用可重试；single-flight 语义保留。seep-runtime `build_egress_outputs_supports_hysteria2` 测绿，seep-protocols clippy 零警告。
- [x] **无界 pong/keepalive 通道**——`vless.rs:630` / `trojan.rs:473` / `vmess.rs:1349` `mpsc::unbounded_channel`：对端洪泛 PONG 时队列无界内存增长（流量生命周期有界）。
  **已修（2026-11-03）**：`WsReader::pong_tx` 改有界 `mpsc::Sender<Vec<u8>>(64)`；PONG 帧经 `try_send`（满则丢弃控制帧，不阻塞读帧、不积压）。三调用点（vless/trojan/vmess）统一改 `mpsc::channel(64)`。seep-protocols 71+5+6+7 测全绿，clippy 零警告。
- [x] **mesh 信封 `as u8` 长度截断**——`mesh_transport.rs:379-386/616-631`（flow_id/target_host/path 长度）+ `trojan.rs:99` / `udp/associate.rs:96`（域名长度）：无 `>255` 守卫，超长静默截断长度字节产畸形帧；对照 `vless.rs:165` 有守卫。
  **已修（2026-11-03）**：`trojan::build_request` 与 `encode_udp_header`（SOCKS5 UDP）加 `>255` 守卫（拒发畸形帧，返回 Result/错误）。`encode_mesh_envelope_binary` 已含 flow_id/target_host/path 守卫（mesh_transport.rs:366-375/580-589），无需改动。seep-core 26+13+3+4+10 测、seep-protocols 71+5+6+7 测全绿，clippy 零警告。
- [x] **padding.rs range span 下溢**——`middleware/padding.rs:71` `spec.max - spec.min + 1`：仅 config validate 保证 min≤max；绕过校验（或未来路径）即 usize wrap。
  **已修（2026-11-03）**：`decide_padding` range 分支健壮化——`max < min` 时回退为固定 min（`(hi-lo+1).max(1)` 保证 span≥1，防 `% 0` panic）；掷点确定性保留。回归 `range_mode_max_below_min_does_not_panic`，seep-protocols 72+5+6+7 测全绿，clippy 零警告。
- [x] **seep-core 链路质量 NaN**——`seep-core/lib.rs:744-745`：`hop_bandwidths` 空而 `hop_latencies` 非空时 `0.0/0.0=NaN` 传播进 `calculate_quality_score`；两 pub 向量常规同长（update_path），需外部独立变更。
  **已修（2026-11-03）**：`calculate_quality_score` 判 `hop_bandwidths.is_empty()`（与 latencies 同判）——任一为空视为无有效样本，回退 `reliability_score`（非 NaN）。回归 `quality_score_no_nan_when_bandwidths_empty`，seep-core 11+4+13+3+26 测全绿，clippy 零警告。
- [x] **非常量时间认证比对**——`inbound/http.rs:262/276` + `socks5.rs:253` + `control_plane.rs:266`：`String ==` 短路径；网络时序攻击对本地代理密码实际难利用，防御纵深。
  **已修（2026-11-03）**：`seep_core::constant_time_eq`（字节切片恒时 XOR 累积，异长亦完整遍历长侧防长度侧信）替换三处明文 `==`（http.rs Basic+Bearer / socks5.rs 用户名密码 / control_plane.rs admin_token Bearer+X-Admin-Token）。回归 `constant_time_eq_matches_and_rejects`，seep-core 12+4+13+3+26、seep-protocols 72+5+6+7、seepd 27 测全绿，clippy 零警告。
- [x] **runtime 无限循环任务无 stop 标志、JoinHandle 丢弃**——`runtime_builder.rs:1007-1225/2924-2954`（mesh stats/chain health/mesh quality/health checker/topology updater）+ `pool.rs:714-725`（sweeper）：重载路径每轮泄漏一组 loopers（各持 Arc）；单进程守护进程生命周期内良性，seepd 以进程退出掩盖。
  **已修（2026-11-03 `e9612ff`）**：runtime 三条周期 loop（mesh stats :1017 / chain stats :1210 / mesh quality :1236）改 `while *running.read()` 受 `stop()`（:1368 置 false）控制；pool sweeper 增 `sweeper_running` AtomicBool（pool.rs:346）+ `stop_sweeper()`（pool.rs:738），`Runtime::stop` 接线（runtime_builder.rs:1373）；mesh registry 内嵌 health/topology updater 生命周期与 registry 同属（单进程 daemon 退出即回收，重载不重建 registry）。回归 `sweeper_stops_after_stop_flag`，seep-protocols 16 测 + seep-runtime 138 测全绿，clippy 零警告。
- [x] **DNS start() shutdown_tx mutex 跨 await**——`dns_engine.rs:1072-1086`：持 `shutdown_tx` tokio mutex 跨取 `task` 与 spawn；生命周期串行化，有界。
  **已修（2026-11-03 `b880ad4`）**：`start()`/`stop()` 统一锁序 task→shutdown_tx；`shutdown_tx` 获取后仅同步赋值/发送，不再跨 `task.lock().await`（dns_engine.rs:1116-1128/1132-1140）。seep-platform 49 测全绿，clippy 零警告。
- [x] **FFI raw-pointer 别名（UB 风险）**——`seep-ffi/lib.rs`：`seep_ffi_tun_start/stop` 取 `&mut *handle` 而 `is_running/stats_json` 取 `&*handle`；内嵌方并发调用即数据竞争 UB，无内部同步。
  **已修（2026-11-03 `e9741a7`）**：`seep_ffi_tun_start`/`seep_ffi_tun_stop`/`stop_inner`/`tun_start_inner`/`tun_stop_inner` 改取 `&FfiHandle`——`FfiHandle` 内全部可变面已走内部可变性（`tun_stop` AtomicBool / `tun_thread` Mutex / `tun_fd` AtomicI32），共享引用即可完成；消除 `&mut *handle` 与 `&*handle` 跨线程别名（lib.rs:221/238/271/316/326）。seep-ffi 10 测全绿，clippy 零警告。
- [x] **connect_racing 落选候选不中止**——`net_mark.rs:111-145`：胜出后落选拨号任务不自中止（channel drop 时自终止），慢候选短暂持套接字/TLS 握手。
  **已修（2026-11-03 `1623604`）**：`connect_racing` 收集在途 `JoinHandle`，胜出时 `abort()` 全部落选候选（net_mark.rs:98-170）——取消在途拨号/握手，资源随取消释放，不再持 socket 等待超时。回归 `racing_winner_aborts_in_flight_losers`（次选指向不可达段，首选胜出即时返回即证 abort），seep-core 13 测全绿，clippy 零警告。
- [x] **订阅刷新 read-modify-write 复活已删订阅**——`subscription/lib.rs:380-455`：`refresh_subscription` 克隆后长 fetch，`update_subscription_in_map` 回写；fetch 期间热更删除的订阅被复活。
  **已修（2026-11-04 `40d986c`）**：`SubscriptionManager` 增 `subscription_epoch`（AtomicU64，删除/重载递增）；`refresh_subscription` 在克隆快照时同步读 epoch，写回改走 `update_subscription_in_map_checked`——epoch 已变（订阅被删）即跳过插入，不复活旧状态。回归 `refresh_does_not_revive_subscription_removed_during_fetch`（本地慢端点，fetch 中删除，断言 map 无该键；未修复时该测试红）。evidence：`crates/seep-subscription/src/lib.rs:346` / `:383-391` / `:598-617` / `:736-781`；`cargo test -p seep-subscription` 57 测 + `cargo test --workspace` 全绿。
- [x] **process 归因缓存重复工作**——`tun_process.rs:165-178`：并发 miss 重复扫 /proc 并插入等价值；幂等仅性能。
  **已修（2026-11-04 `6499b63`）**：`attribute` 增 inflight 单flight（OnceCell+Notify，同 key 并发 miss 合并为一次扫描，其余等待复用；完成后移除 cell 保 TTL 过期重扫）。回归 `concurrent_miss_singleflights_one_scan`（8 并发断言 scan_count=1，TTL 过期后重扫=2；禁用合并时测试红 scan_count=8）。evidence：`crates/seep-runtime/src/tun_process.rs:140-152` / `:186-227` / `:347-411`；seep-runtime 139+1 测 + `cargo test --workspace` 全绿。
- [x] **事件广播 fire-and-forget**——`runtime_builder.rs:538`：`broadcast::channel(1024)` 首 receiver 丢弃；生产 `ControlPlane::new` 立即订阅且 Lagged 已处理，订阅前事件静默丢失。
  **已修（2026-11-04 `f7a61cc`）**：`spawn_event_log_task` 从 `serve()` 提前到 `ControlPlane::new()` 构造完成即订阅（早于 `runtime.start()`），消除「new 后/serve 前」事件丢弃窗口；`serve()` 不再重复订阅。回归 `events_before_serve_are_captured`（new 后 update_config 触发 ConfigUpdated，断言 /events 含该事件；订阅移回 serve 时测试红 /events 空）。evidence：`apps/seepd/src/control_plane.rs:58-63` / `:3324-3351`；seepd 28 测 + `cargo test --workspace` 全绿。
- [x] **TUN 设备锁全生命周期持有**——`tun_ingress.rs:221-268`：`tun.lock()` 跨多 await 持进程生命周期；有意单主设计，正确性依赖该不变式。
  **核查保留（2026-11-04）**：确认为有意设计而非缺陷——`run_internal` 单任务独占 `tun_guard` 贯穿设备生命周期（创建→configure→包循环→teardown→销毁），`packet_loop` 注释明确「guard 已由本循环独占，无锁竞争面」（`tun_ingress.rs:309-314`）；select 四事件枚举模式依赖该独占不变式，拆锁反而引入并发读写/事件序风险。全锁生命周期是设备独占语义的正确实现，无外部条件缺失，不修；代码与注释已自证设计。evidence：`crates/seep-runtime/src/tun_ingress.rs:221` / `:268` / `:303-314`；seep-runtime 139+1 测全绿（本轮 `cargo test --workspace` 通过）。
- [x] **poll_read/poll_write 内 std Mutex**——`tun_tcp.rs:502,538`：无 await 持锁（短临界），争用下可 stall tokio worker。
  **核查保留（2026-11-04）**：`StackInner` 单锁注释明确「全同步、不跨 await」（`tun_tcp.rs:163`）；`poll_read`/`poll_write` 临界区仅做 `flow_live`/`recv_slice`/`send_slice` 等 smoltcp 纯内存操作（无 IO/await，微秒级），之后立即 drop(inner) 并 notify。这是 Rust 标准做法：短同步临界用 std Mutex（tokio Mutex 更重且为跨 await 设计）；换锁反而增加开销且无法消除单状态竞争。该条目是可接受设计而非缺陷，不改。
- [x] **DefaultHasher 缓存文件名**——`cache.rs:584-595`：确定性哈希（跨进程稳定），非密码用途可接受；文件名碰撞极低。
  **核查保留（2026-11-04）**：确认 `DefaultHasher::new()` 为固定 key 的 SipHasher13（std 文档：固定 key），跨进程稳定，**非** RandomState；仅作缓存文件名（非密码/非安全用途），64-bit 碰撞概率极低。经实验验证：两个独立 `SubscriptionCache` 实例同 key 的 `get_disk_path` 一致（DefaultHasher 版通过确定性测试），设计正确不改。evidence：`crates/seep-subscription/src/cache.rs:729-738`。
- [x] **wasmtime Engine 初始化 expect**——`plugins/loader.rs:26`：进程级全局 `LazyLock` init，平台不支持/feature 不匹配时首插件加载即 panic（罕见且致命）。
  **已修（2026-11-04 `59a7745`）**：`ENGINE` 改 `LazyLock<Result<wasmtime::Engine, String>>`，`engine()` 返回 `Result`，`load_plugin_from_bytes` 以 `?` 传播 `Err` 而非 panic——引擎初始化失败可观测可降级，不再首插件加载即杀进程。evidence：`crates/seep-plugins/src/loader.rs:22-34` / `:58-60`；seep-plugins 10 测 + `cargo test --workspace` 全绿。
- [x] **TLS CryptoProvider get_default().expect**——`protocols/tls.rs:57`：ring feature 缺失或竞争 provider 时首次 TLS 握手 panic；`let _ =` 忽略 install 失败致仅剩 expect。
  **已修（2026-11-04 `4ad96fe`）**：`tls_crypto_provider` 的 `get_default().expect` 移除——`get_default()` None 时回退显式 `ring::default_provider()`（`install_default` Err=已有安装，尊重既有），调用方总获可用提供方，不再 panic。evidence：`crates/seep-protocols/src/tls.rs:51-60`；seep-protocols 71+6+7 测 + `cargo test --workspace` 全绿。
- [x] **HotReloadManager Default panic + reload_rx 一次性槽位**——`hot_reload.rs:623`（Default 恒 panic）/`:353`（`take().expect("reload_rx already taken")`）：现无双重调用，不变式仅由 expect 维持。
  **已修（2026-11-04 `233950f`）**：`handle_reload_events` 的 `take().expect("reload_rx already taken")` 改为 match——`None`（二次 start / 外部 take_reload_rx 已取走）时 warn 并静默 return，不再 panic。`Default` 恒 panic 保留为显式 API 拒绝（`HotReloadManager` 需 config_path/router，不可 Default，注释已声明）；不变式不再依赖运行时 expect。回归 `handle_reload_events_after_rx_taken_returns_quietly`（先 take 再调用，未修复 panic/修复后返回）。evidence：`crates/seep-runtime/src/hot_reload.rs:356-371` / `:843-866`；hot_reload 4 测 + `cargo test --workspace` 全绿。
- [x] **不变式 expect（结构上恒真，重构漂移即启动 panic）**——`tun_ingress.rs:214`（flow_router 未注入）/`runtime_builder.rs:479`（tun_enabled 蕴含 network_config）。
  **已修（2026-11-04 `ee33690`）**：`runtime_builder.rs:479` 的 `.expect("tun_enabled 蕴含 network_config")` 改 `ok_or_else` 传播 `Err`（build() 返回 Result，不变式破坏可观测不 panic）；`tun_ingress.rs` 在 `run_internal` 开头增前置 fail-fast（`flow_router`/`flow_output` 未注入即 `bail`，不再运行期每包在 `router()` 热路径 panic——`router()` 的 `expect` 保留为启动后已注入的防御断言）。回归 `run_internal_fails_fast_without_endpoints`（未注入断言 Err 含「未注入」）。evidence：`crates/seep-runtime/src/runtime_builder.rs:479-485` / `crates/seep-runtime/src/tun_ingress.rs:221-226` / `:1017-1028`；seep-runtime 139+1 测 + `cargo test --workspace` 全绿。
- [x] **插件/FFI mutex poison 级联**——`plugins/plugin.rs:133`（std Mutex 跨 wasm 调用，宿主 panic 即毒化后续全插件流）/`ffi/lib.rs:302,328`（tun_thread lock）。
  **已修（2026-11-04 `b9abae5`）**：`plugin.rs` `vm.lock()` 与 `ffi/lib.rs` 两处 `tun_thread.lock()` 的 `expect` 改 poison 恢复（`Err(p) => p.into_inner()`，恢复底层值继续；恢复时 tracing warn / set_last_error 记录）——宿主 panic 后级联终止消除；wasm trap 本经 `classify_call_err` 转为 Err 不 panic。evidence：`crates/seep-plugins/src/plugin.rs:133-143` / `crates/seep-ffi/src/lib.rs:302-309` / `:328-335`；seep-plugins 10 测 + `cargo test --workspace` 全绿。
- [x] **unmaintained 依赖**——`serde_yaml`/`unsafe-libyaml`（RUSTSEC-2024-0449）、`basic-toml`（RUSTSEC-2026-0374）：cargo audit 信息级；升级候选。
  **已修（2026-11-04 `466367c`）**：`serde_yaml 0.9`（弃用）迁 `serde_yaml_ng 0.10`（维护 fork，API 兼容，`Cargo.toml` 用 `package = "serde_yaml_ng"` 保留 crate 名，全仓无源码改动）；`cargo audit` 原 2 条 serde_yaml 弃用消除，`cargo test --workspace` 全绿。**传递依赖保留**：`unsafe-libyaml`（serde_yaml_ng 底层 C FFI，配置 YAML 为可信输入）、`basic-toml`（askama_derive 构建期 proc-macro）仍 unmaintained 信息级——替换需纯 Rust YAML 重写 / uniffi+askama 大版本迁移，收益低风险高，接受并记录。evidence：`Cargo.toml:31`；`cargo audit` 仅剩 2 条信息级 warning；`cargo test --workspace` 全绿。

## 2026-11-02 代码深审补充（P2/P3，源自 docs/review/2026-11-01-code-review.md 第二轮补充节）

P2（下一步修）：
- [x] **TUN UDP 下行只续 last_active 不续 expiry**——`tun_ingress.rs:812-813`：上行（:432-434）续两者、下行续一者，清扫（:714）按 `expiry<=now` 驱逐。纯下行推送流（客户端 udp_idle_secs 内无上行）被中途逐出。
  **已修（2026-11-04 `bcd6d1c`）**：`downlink_task` 增 `udp_idle_secs` 参数，下行续期口径与上行一致——同时续 `last_active` 与 `expiry = now + udp_idle_secs`（原仅续 last_active，sweep 按 expiry 驱逐纯下行流）。回归 `downlink_packet_renews_expiry`（feed 下行包断言 expiry 推进；未修复 expiry 不变红）。evidence：`crates/seep-runtime/src/tun_ingress.rs:510-517` / `:782-787` / `:813-818` / `:1040-1090`；seep-runtime 141+1 测 + `cargo test --workspace` 全绿。
  evidence：`tun_ingress.rs:812` `e.last_active = now`（无 `e.expiry` 续期）；`:714` `.filter(|e| e.expiry <= now)`。
- [x] **scan_udp_capability BFS 无 visited 集（组环挂起 build）**——`runtime_builder.rs:2266-2280`：组环（g1→g2→g1）队列永不空，`udp.enabled` 时 build() 无限挂起；`RoutingConfig::validate`（seep-config:1489）仅查 SLO 无环守卫。
  **已修（2026-11-04 `2bef0c8`）**：`scan_udp_capability` 增 `visited_groups: HashSet<&str>`——同组二次遇及（环/重复）跳过展开，队列有界、build 不再无限挂起。回归 `udp_capability_scan_terminates_on_group_cycle`（g1→g2→g1，线程+2s 超时断言终止；无 visited 时 Timeout 红）。evidence：`crates/seep-runtime/src/runtime_builder.rs:2317-2326` / `:4572-4601`；seep-runtime 142+1 测 + `cargo test --workspace` 全绿。
  evidence：`runtime_builder.rs:2266` `while let Some((name, source)) = queue.pop()` 无 visited；`continue` 在 `reachable.entry` 前。
- [x] **chain 故障转移复用已消费 flow.io（协议流损坏）**——`runtime_builder.rs:1919/2025`：首 `dial_and_tunnel`（mesh_transport.rs:1569 copy_bidirectional 读 io）中途失败即部分消费；重试拼接尾流+新信封。正确恢复=中止应用连接（RST）非重接。
  **已修（2026-11-04）**：`forward_chain` mesh `dial_and_tunnel` 失败不再重放尾流到新链/回退出口（`flow.io` 已被部分消费会拼出损坏协议流）；链路/事件面簿记照常（`chain_failure_tx`、`PathUpdated`、注解），随后无条件 `return Err(e)` 让上游 TUN `retire` 中止应用连接（RST/FIN）。回归 `forward_chain_mesh_failure_aborts_without_fallback_forward`（mesh 首跳连接失败断言 `Err` 且回退出口未调用；旧重试逻辑时该测试红）。evidence：`crates/seep-runtime/src/runtime_builder.rs:2070-2075` / `:3149-3233`；seep-runtime 144+1 测 + `cargo test --workspace` 全绿。
  evidence：`runtime_builder.rs:2025` `&mut *flow.io` 与 :1919 同一流复用。
- [x] **串行 UDP serve 循环内联 lookup_host（头阻塞整面）**——`mesh_transport.rs:1852`：单任务无 per-packet spawn（§13-5），一个不可解析 `target_host`（线上可控）阻塞所有流。
  **已修（2026-11-04）**：保留 §13-5 单任务顺序处理设计（不 per-packet spawn），为 exit 首包 `lookup_host` 加 3s 上界（`EXIT_LOOKUP_TIMEOUT`，测试可经 `with_dns_lookup_timeout` 调小）；超时/解析失败按单包错误丢弃并继续 serve，错误带 target host 便于定位。回归 `exit_uplink_dns_lookup_is_bounded`（有界性 + 错误上下文）与 `serve_udp_survives_bad_host_packet`（bad-host FULL 后 serve 存活且继续处理 good-host 建流）。evidence：`crates/seep-runtime/src/mesh_transport.rs:33-38` / `:1274-1280` / `:1287-1294` / `:1877-1906` / `:3820-3967`；seep-runtime 146 测 + `cargo test --workspace` 全绿。
  evidence：`mesh_transport.rs:1852` `lookup_host(...).await?` 在 serve 循环内。
- [x] **瞬时 recv_from 错误终止 UDP serve 任务**——`mesh_transport.rs:1946`：`Ok(Err(e))=>return Err`（ENOBUFS/EINTR 瞬时亦毙）；应 continue 或按瞬时/致命分类。
  **已修（2026-11-04）**：`serve_udp` 的 `recv_from` 错误按瞬时/致命分类——`is_transient_recv_error`（EINTR/EAGAIN/ENOBUFS）记 debug 并 `continue` 保留 serve 任务；其余仍 `return Err` 终止。seep-runtime 增 `libc = "0.2"` 依赖取 ENOBUFS 常量。回归 `udp_recv_transient_error_classification`（三瞬时 true、ConnectionRefused false）。evidence：`crates/seep-runtime/src/mesh_transport.rs:40-52` / `:1997-2011` / `:4000-4018`；`crates/seep-runtime/Cargo.toml`；seep-runtime 147 测 + `cargo test --workspace` 全绿。
- [x] **瞬时 accept 错误终止 TCP mesh 监听任务**——`mesh_transport.rs:1330`：`listener.accept().await?`（ECONNABORTED/EMFILE/EINTR 瞬时亦毙）。
  **已修（2026-11-04）**：`serve` 的 `accept` 错误按瞬时/致命分类——`is_transient_accept_error`（ECONNABORTED/EINTR/EMFILE/ENFILE/ENOBUFS）记 debug + 10ms 退避后 `continue` 保留监听任务；其余仍 `return Err` 终止。回归 `tcp_accept_transient_error_classification`（五瞬时 true、ConnectionRefused false）。evidence：`crates/seep-runtime/src/mesh_transport.rs:54-63` / `:1390-1403` / `:4049-4071`；seep-runtime 148 测 + `cargo test --workspace` 全绿。

P3（收尾）：
- [x] **active_chains.len()-1 下溢**——`chain.rs:907`：`drop(chain)`（:901）后读 len；并发 `terminate_chain`（:924 remove）移除 → 0-1 下溢（release 裹 usize::MAX 指标污染）；宜 `saturating_sub(1)` 或由 terminate 自减。
  **已修（2026-11-04）**：`handle_chain_failure` 备用耗尽分支 `active_chains.len() - 1` 改 `saturating_sub(1)`——并发 `terminate_chain` 在 drop 分片守卫后窗口内移除本链时不再下溢裹 usize::MAX（若已移除则 len 本身已正确，不再二次自减）。回归 `concurrent_terminate_and_failure_no_active_chains_underflow`（64 轮并发 failure×terminate，断言 active_chains 不裹 MAX 且终态 0）。evidence：`crates/seep-runtime/src/chain.rs:900-904` / `:1308-1360`；seep-runtime 149 测 + `cargo test --workspace` 全绿。
- [x] **mesh UDP 下行序号归零瞬态丢包**——`mesh_transport.rs:1877`：exit 建流归零下行序号而客户端窗口仍在（last>63）→ 序号 0..36 判回退拒、≥37 自愈；瞬态 ~37 包突发丢包（非永久拒收）。
  **已修（2026-11-04）**：`ExitFlow` 增加 `down_seq: Arc<AtomicU32>`，FULL 重关联到新 target 时在 `retire_flow` 前捕获旧序号源，新 ExitFlow 继续复用同一 Arc——下行序号跨重关联单调续接，不再归零触发客户端回退窗口拒绝（瞬态丢包）。回归 `exit_full_reassociation_preserves_downlink_sequence`（旧流 down_seq=100，重关联后仍 100；旧归零逻辑红）。evidence：`crates/seep-runtime/src/mesh_transport.rs:1064-1073` / `:1910-1918` / `:1967-1998` / `:4051-4110`；seep-runtime 150 测 + `cargo test --workspace` 全绿。
- [x] **缓存满插入 O(n) 驱逐扫描**——`mesh_transport.rs:868-876`：满（65536）时每次插入全 `min_by_key` 扫描；文档化权衡（"O(n) 无新依赖"），需认证 peer + 6.5 万流触发。
  **已修（2026-11-04）**：`UdpFlowCache::insert` 满时驱逐合并为单遍扫描——一次遍历同时收集过期条目（清扫，不计驱逐）与最早未过期 expiry（= 同 TTL 最久未触 LRU，§11-6）；仍满再逐该条目。旧实现先全表 `sweep_expired`、再全表 `min_by_key`，满时每插两次 O(n) 扫，合并为一遍。LRU 语义与计数口径不变。回归 `udp_flow_cache_full_insert_mixed_expired_and_live_evicts_earliest_live`（过期清扫不计驱逐 + 最早未过期被逐）。evidence：`crates/seep-runtime/src/mesh_transport.rs:895-929` / `:3532-3577`；seep-runtime 151 测 + `cargo test --workspace` 全绿。
- [x] **订阅转换配置硬编码 admin_token="seep"**——`clash.rs:768-771`/`seep_dsl.rs:413-418`：回环绑定约束暴露面；建议省略或随机生成。
  **已修（2026-11-04）**：`ClashConverter::convert_to_seep` 与 `SeepDslConverter::convert_to_seep` 的 `ControlConfig.admin_token` 由 `Some("seep")` 改 `None`——不再生成众所周知的固定 token（回环 API 暴露面收敛，与 runtime 其余 `admin_token: None` 配置一致；token 由用户显式配置）。回归断言两转换器产出 `control.admin_token.is_none()`。evidence：`crates/seep-subscription/src/clash.rs:770` / `:1587-1590`；`crates/seep-subscription/src/seep_dsl.rs:417` / `:1403-1406`；seep-subscription 57 测 + `cargo test --workspace` 全绿。
- [x] **shaping 抖动 jitter_ms+1 裹 0（% 0 panic）**——`shaping.rs:45`：jitter_ms=interval_ms=u64::MAX 时裹 0；validate（seep-config:908-918）无上界；`wrapping_add(1).max(1)` 或上界校验。
  **已修（2026-11-04）**：`decide_shaping_offset` 的 jitter 域计算改 `jitter_ms.checked_add(1).unwrap_or(u64::MAX)`（满值截为 `% u64::MAX`，域 [0, u64::MAX-1]，不裹 0）；随后 `k×interval + jitter` 改 `saturating_add` 防第二处加法溢出，末值仍 `.min(u64::MAX/2)` 有界。回归 `shaping_offset_max_jitter_does_not_panic`（interval/jitter/max 均 u64::MAX，多 k 值不 panic 且 offset ≤ u64::MAX/2；旧 `+1` 表达式红）。evidence：`crates/seep-protocols/src/middleware/shaping.rs:41-52` / `:238-256`；seep-protocols 74 测 + `cargo test --workspace` 全绿。
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
- [x] 审核发现：测试缺口——本区间多项 P1/正确性修复无回归测试：pool.rs `maybe_refill` inflight 并发门（pool.rs:579-597，pool.rs 全文件 0 测试）；seep-mesh 健康检查写锁复检（seep-mesh/src/lib.rs:982-990）；chain.rs `handle_chain_failure` 分片守卫释放（chain.rs:860-890）；http.rs 出口注入守卫（http.rs:119/164，仅 socks5 入口被覆盖）；fetcher.rs 分块超限与非 UTF-8 拒绝（fetcher.rs:277/279）；mesh_transport.rs flow miss 丢弃路径（mesh_transport.rs:1905-1906）。全部子项已核实：pool `crates/seep-protocols/src/pool/tests.rs:237` `maybe_refill_no_spawn_when_key_at_capacity`（旧门失效 inflight=32 红，修复后全绿）；mesh `crates/seep-mesh/src/lib.rs:869` 重构 `health_check_once`/`stale_candidates`/`mark_stale_offline` + `health_check_reread_under_write_lock_keeps_refreshed_node_online`（旧逻辑无条件标记红，复检后绿）；chain `crates/seep-runtime/src/chain.rs:1232` `switch_ledger_records_failure_and_exhaustion` + `:1310` `concurrent_terminate_and_failure_no_active_chains_underflow` 已覆盖；http `crates/seep-protocols/src/outbound/http.rs:294` `forward_inline_rejects_authority_metachar_hosts` + `:315` `forward_pooled_rejects_authority_metachar_hosts_before_connect` 已覆盖两路径；fetcher `crates/seep-subscription/src/fetcher.rs:701` `fetch_terminal_chunk_overlimit_and_not_utf8` 已覆盖两分支；mesh_transport `crates/seep-runtime/src/mesh_transport.rs:4266` `send_existing_flow_miss_does_not_count_forwarded_up` 已覆盖。`cargo test --workspace` 全绿（44 二进制 `test result: ok`）。

---

## 功能差距分析（2026-11-02，对照 sing-box/mihomo/xray-core）

> 完整报告：[docs/gap-analysis-2026-11-02.md](docs/gap-analysis-2026-11-02.md)。只审不改；未触碰工作树既有未提交改动。

**核心结论**：底座完成度高，差距集中在四块——① 路由规则引擎（无目的 IP-CIDR、无 GeoIP/GeoSite 数据库、无 rule-set、无 OR/NOT、无嗅探）；② QUIC 生态（tuic/REALITY/XTLS-Vision/hy2 UDP 全缺）；③ 服务端入站协议为零；④ 透明代理仅 TUN(Linux)（缺 redir/tproxy、macOS/Windows TUN）。seep 独有优势：mesh mTLS 多跳+SLO 打分、场景 profile、WASM 插件、移动端 FFI。

建议优先级（新条目，未编号入现有 P 序列）：
- [x] **G0-1 目的 IP-CIDR 匹配器**——现 `MatchCondition::Network` 绑定 `client.cidr` 源注解（seep-routing/src/lib.rs:706），目标网段分流表达不了；三大项目最基本匹配器。
  **已实现（2026-11-04 `a262735`）**：`MatchCondition` 增 `IpCidr { cidrs }` 变体（seep-config/src/lib.rs:1785），路由匹配器 `ip_in_cidr`（seep-routing/src/lib.rs:24）对目标 host 为 IP 字面量按 IPv4/IPv6 前缀匹配（主机形式按精确地址；域名不命中，路由面不做 DNS）；`SeepRule::IpCidr`/`ClashRule::IpCidr`/rule_source 的 `IpCidr` 规则改走新变体（seep_dsl.rs:1126、clash.rs:1147、rule_source.rs:60），`Network`（源注解）保留；`clash_export` 导出 IP-CIDR 兼容。回归 `tests::ip_cidr_matches_target_ip_prefix`（IPv4/IPv6 前缀、主机精确、域名不命中；旧逻辑恒 false 红）。`cargo test --workspace` 全绿（44 二进制）。
- [ ] **G0-2 GeoIP/GeoSite 数据库接入 + domain full/regex + OR/NOT 逻辑规则**——替换 `geoip.country` 注解等价物（无数据库）。
  **部分完成（2026-11-04 `33ba5e4`）**：OR/NOT 逻辑规则已实现——`MatchCondition::Any{conditions}`/`Not{condition}`（seep-config/src/lib.rs:1779），路由 `matches_condition` 递归（seep-routing/src/lib.rs:750），回归 `logical_any_not_condition_semantics`（顶层仍 AND，Any 任一命中，Not 反选）；`clash_export` 对 Any/Not 跳过并登记。domain `full:` 在 rule_source 路由面并入 suffix 联合（既有），`regexp:` 仍逐条 skipped。**GeoIP/GeoSite 数据库部分 BLOCKED**：需 v2fly `.dat`/mmdb 外部数据库文件 + maxminddb 类依赖与惰性加载路径（仓库无任何 .dat/mmdb），缺真实数据源与下载/更新机制——该项待提供数据库或用户决策后继续。
- [ ] **G0-3 协议嗅探层（sniff）**——TLS SNI/HTTP Host/QUIC SNI 覆写路由域名；TUN 场景 IP 直连流量无它即无法按域名分流。
  **部分完成（2026-11-04 `db7f997`）**：`crates/seep-runtime/src/sniff.rs` 增 `sniff_tls_sni`（ClientHello server_name 扩展解析）与 `sniff_http_host`（HTTP/1.x Host 头，大小写不敏感），纯函数无 I/O，回归 4 测（TLS SNI 提取/非 ClientHello None、HTTP Host/非 HTTP None）。**集成到 TUN 首包缓冲与路由覆写 BLOCKED**：需在 `spawn_tcp_forward`（tun_ingress.rs:662）对 Established 流读首包、解析后按域名重路由并透传首包（SmolTcpStream 首读会消费流数据，需缓冲回放/栈内 peek），且 QUIC SNI 需 UDP 载荷解析——此项需真实 TUN+TLS/HTTP 流量验证与用户对「首包重路由语义」决策。
- [ ] **G0-4 UDP over vmess/vless/trojan**——主流加密通道均不载 UDP（构建期报错），游戏加速场景非 direct/ss/wg 出口即退化。
  **BLOCKED**：需为 vmess/vless/trojan 各实现 UDP 数据面变体（vmess 现 `build_udp_connectors` 仅 direct/ss/wg 有能力，runtime_builder.rs:2230；vless.rs/trojan.rs 无任何 UDP 代码），并需真实 vmess/vless/trojan UDP 节点验证帧格式与复用（UDP 关联/连接复用、目标地址编码、分片/长度）。现缺这些协议的真实 UDP 端点与互通测试环境。
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

---

## 审核发现（f9cb1f3bf1066c0034f05fe87e0362dcbdd876ba..HEAD；只审不改，2026-11-03）

覆盖：seep-core（constant_time_eq / 质量评分 NaN / net_mark 竞速 abort / udp 帧长守卫）、seep-platform（DNS singleflight + start/stop 锁序）、seep-protocols（认证恒时 / padding span / hysteria2 超时 / pong 有界 / trojan 帧长守卫）、seep-runtime（mesh TLS 重载出写锁 / 后台循环 stop 标志）、seep-subscription（cache disk_io_lock / fetcher 4xx 终态）、seepd（非回环无 token 拒启）、seep-ffi（共享引用消除别名）。

- [x] 审核发现：`encode_udp_header` 返回类型改 `Result<Vec<u8>>`（associate.rs:82）但未传播到 seepctl——`apps/seepctl/src/udp_probe.rs:221-227` 与 `:282` 仍按 `Vec<u8>` 调用（`.extend_from_slice`/`&frame`/`.len()`），`cargo check -p seepctl` 编译失败（E0599×2、E0308，3 错）；seepctl 为 workspace 成员，构建链中断。P1。
  **已修（2026-11-03 `513e3b1`）**：两调用点传播 `Result`——发送路径 `?` 映射 `ProbeError::Connect`，echo 桩解码失败 `continue` 跳过畸形帧；`cargo check -p seepctl` 恢复，seepctl 19 测 + `cargo test --workspace` 全绿。evidence：`apps/seepctl/src/udp_probe.rs:221` / `:282`。
- [x] 审核发现：DNS singleflight inflight 槽位仅在正常完成路径移除（dns_engine.rs:779）；若首查任务在 `cross_check`/`query_group`（:763-765）中被取消（resolve future 被 drop），槽位残留且 map 持 `tx.clone()` 使 watch 通道保持开放，等待者 `rx.changed()`（:743）永久挂起（无超时/清理），该键后续查询全部阻塞。当前树内调用方无显式取消，属潜在；另 `saw_dead_leader` break 路径（:749-751）未插入自身却仍执行 `remove(&key)`（:779），可能误删他首查者槽位（该路径实际难达）。P3。
  **已修（2026-11-03 `fe931ce`）**：`InflightMap` 值改持 `watch::Receiver`（不再持 sender 使通道保持开放）+ 每代 `Arc<()>` token；等待者见通道关闭即按 token 清理同代槽位并重新抢占（死首查自愈），首查者完成后仅当 token 仍属自己才移除（防误删他代）。回归 `resolver_recovers_when_singleflight_leader_is_cancelled`。evidence：`crates/seep-platform/src/network/dns_engine.rs:630-635` / `:748-770` / `:783-787`；seep-platform 19+50 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`racing_winner_aborts_in_flight_losers`（net_mark.rs:423-448）未真正回归 abort——改前 `connect_racing` 胜出即 `return Ok(s)`（落选为 detached task，不等待），改后同样胜出即 return；测试断言「5s 内返回」在改前改后均通过，无法区分 abort 与否，注释「若未 abort，connect_racing 返回后仍需等次选超时」前提错误（connect_racing 从不等待落选）。回归失效。P3。
  **已修（2026-11-03 `ce5f3bd`）**：测试加 `cfg(test)` 连接门 + 在途计数：两候选均先确认挂起在途，再放行 echo 胜出；断言返回后、放行落选前 `ACTIVE_CONNECTS=0`。临时移除 `abort()` 验证该断言变红（left=1），证明可区分。evidence：`crates/seep-core/src/net_mark.rs:16-22` / `:183-217` / `:506-521`；net_mark 8 测 + `cargo test --workspace` 全绿。
- [x] 审核发现：`disk_io_lock` 未覆盖 `remove()` 与 `clear()`——`cache.rs:290`（remove）与 `:336`（clear）仍持 `memory_cache` 写锁跨同步 `fs::remove_file`，且不持 `disk_io_lock`；cleanup 同类的「删盘 vs set 落盘」同键竞态仍经 `remove()` 可达（cleanup 已移出写锁并串行化，此两处未修），磁盘 IO 下写锁模式亦未消除。P3。
  **已实现（工作树待提交，非本人 WIP）**：`cache.rs` `remove()`/`clear()` 已按 cleanup 同型重构——内存突变（memory_cache→current_size）与磁盘删除分离，先释放写锁，再持 `disk_io_lock` 删盘；`remove()` 删前复查 `memory_cache` 活跃副本（并发 set 重插则跳过删盘）。evidence：`crates/seep-subscription/src/cache.rs:273`（remove）/`:332`（clear）；`cargo test -p seep-subscription` 57 测全绿。该改动为工作树既有未提交变更（非本人），未混入本批 commit，待其属主提交。
- [x] 审核发现：fetcher 将 408/429 一并判为终态——`fetcher.rs:261` `(400..500).contains(&status_code)` 把 408（Request Timeout）与 429（Too Many Requests）包装为 `FetcherError::HttpStatus` 短路重试；但 408/429 语义可重试（429 带 Retry-After 背压、408 瞬时超时），短路导致限流/瞬时超时的订阅获取永久放弃，与「5xx 瞬时可重试」的区分意图及 HTTP 重试语义不符。P3。
  **已修（2026-11-04）**：`fetcher.rs:264` 改为 `(400..500).contains(&status_code) && !matches!(status_code, 408 | 429)`——408/429 与 5xx 一样保持瞬时 `anyhow`（可重试至 `max_retries`），其余 4xx 仍终态 `FetcherError::HttpStatus`。回归 `fetch_classifies_4xx_terminal_5xx_transient` 扩展：404 请求 1 次即止；408/429/500 各重试 3 次。evidence：`crates/seep-subscription/src/fetcher.rs:264` / `:650`；旧逻辑（408/429 判终态）时测试红（「408 应为瞬时错误」），修复后 `cargo test --workspace` 全绿（44 二进制）。
