# 2026-11-01 代码深审报告（rillane 全仓）

> 依据：审计任务书 `/tmp/brief-audit.txt` 第二段「代码深审」+ `requesting-code-review` / `code-review` 技能流程。
> 范围：`crates/*`（11 crate）+ `apps/*`（rillaned/rillanectl）+ `plugins/*`，全部非测试源码（`#[cfg(test)]`/`tests/`/`benches/`/`examples`/`target` 排除）。
> 方法：安全静态扫描 + 隐藏 bug 猎捕（panics/越界/资源泄漏/off-by-one/竞态/并发锁序）+ 质量门（lint/类型检查/测试基线）。每条发现经本人复核（技能要求：先验证后报告，不通过即驳回）。

---

## 总账

| 面 | 发现数 | 已修 | 剩余（todo） | 说明 |
|---|---|---|---|---|
| 安全静态扫描 | 0 | 0 | 0 | 六类（硬编码密钥/shell 注入/SQL 拼接/eval/反序列化/路径穿越）全净；crypto 与规范一致 |
| P0 | 1 | 1 | 0 | 订阅缓存自锁死锁（cache.rs:208→470 同锁重入，单线程必触） |
| P1 | 5 | 5 | 0 | tokio bump、ReplayWindow 前进滑窗、fetcher 无界读、chain 锁序反转、pool inflight 门、hot_reload 写回 |
| P2 | 6 | 1 | 5 | mesh 健康检查 TOCTOU 已顺手修；余 5 记 todo |
| P3 | 24 | 0 | 24 | 防御纵深/设计权衡/罕见路径，全记 todo |
| 质量门 | 1 | 1 | 0 | docs build + 全仓测试 + clippy 绿（见 §4） |

**发现 36 · 已修 8 · 剩余 29（todo.md「2026-11-01 代码深审发现」节）。**

> 第二轮补充（2026-11-02）再增 15 项（P1×3 已修 / P2×6 / P3×6），累计 **51 · 已修 11 · 剩余 40**——见文末「第二轮补充」节。

## P0/P1 修复清单（一问题一 commit，测试绿）

| # | 严重度 | 问题 | file:line 证据 | commit |
|---|---|---|---|---|
| 1 | P0 | 订阅缓存 `set_with_ttl` 自锁死锁：已持 `memory_cache` 写锁调 `cleanup_lru_by_count`（同锁重入，std::sync::RwLock 不可重入，cache 满时单线程必死锁）；另有 ABBA：持 `current_size` 写锁跨 `cleanup_expired`（取 `memory_cache`）与插入路径 `memory_cache→current_size` 成环 | `cache.rs:208,210` + `cache.rs:470`；`cache.rs:190-204` | `7e57710` |
| 2 | P1 | 订阅 fetcher 无界读体：`response.text()` 无上限，50MiB 守卫仅在未被生产调用的 `validate_content`；不可信订阅端点可流式灌爆内存 | `fetcher.rs:261`（旧） | `aab4b86` |
| 3 | P1 | mesh 反放窗口前进超窗永久卡死：`diff>64` 即拒且不滑窗，窗口永久 stall（TTL 60s 自愈，故 P1 非 P0） | `mesh_transport.rs` `check_and_advance` | `90c9f48` |
| 4 | P1 | chain 失败切换持 DashMap 分片写锁（RefMut）跨 `stats.write().await`，与 `get_or_create_chain` 的 `stats→len()` 锁序反转 → 死锁 | `chain.rs:840-878` vs `chain.rs:823-827` | `91a93b0` |
| 5 | P1 | pool 水位补充 `inflight_refill` 只减不加，防风暴门失效；并发 release 各自见满余量都补拨，超出 `max_idle_per_key` 拨号风暴 | `pool.rs:575-591,652` | `5bc8dad` |
| 6 | P1 | 订阅合并从不写回 `current_config`（router/磁盘已合并而内存仍旧），陈旧副本 + `routing.rules` 无条件追加 → 每次订阅刷新重复累积节点/规则，配置无界增长 | `hot_reload.rs:564-606` | `362bb75` |
| 7 | P2（顺手修） | mesh 健康检查 TOCTOU：读锁快照后写锁无条件标离线，快照间到达的心跳被误杀致拓扑抖动 | `rillane-mesh/lib.rs:957-980` | `7527fd0` |
| 8 | P1 | tokio 依赖过旧（RUSTSEC-2026-0386 AsyncFd unsound）→ 1.54.1 | `Cargo.toml`/`Cargo.lock`/README 徽章 | `16c7c13` |

**P0/P1 合计 8 项，全部落地；每项对应独立 commit，测试/裁剪全绿。**

## P2 剩余（记 todo）

| 问题 | file:line 证据 |
|---|---|
| 订阅缓存持 `memory_cache` 写锁跨同步磁盘 IO（get→load_from_disk、cleanup→remove_file） | `cache.rs:150-176,360,411,470` |
| 配置热交换非原子（check-then-act：读 config→长 await 拨号→四次独立写） | `runtime_builder.rs:1120-1146`、`update_config:1384-1408` |
| mesh TLS 重载在 write 锁下同步读 CA/私钥/吊销列表 | `mesh_transport.rs:2136-2153` |
| DNS 解析缓存 miss stampede（无 singleflight） | `dns_engine.rs:695-738` |
| control-plane 无 token 时鉴权门整体跳过（非回环绑定即开放） | `control_plane.rs:129-140` |

## P3 剩余（记 todo）

防御纵深 / 设计权衡 / 罕见路径，共 24 项，逐条列于 `todo.md`「2026-11-01 代码深审发现」P3 节，含：hysteria2 持锁跨握手（有意 single-flight，建议超时）、无界 pong 通道、mesh/域名 `as u8` 长度截断（对照 vless.rs:165 有守卫）、padding span 下溢、链路质量 NaN、非常量时间认证比对、无 stop 标志的 loop 任务、FFI 裸指针别名、connect_racing 落选不中止、订阅刷新复活已删订阅、process 归因重复工作、事件广播 fire-and-forget、TUN 锁生命周期、poll 内 std Mutex、DefaultHasher 文件名、若干不变式 `expect`（wasmtime/tls/CryptoProvider/HotReloadManager/reload_rx/flow_router/network_config）、插件与 FFI mutex poison、unmaintained 依赖（serde_yaml/unsafe-libyaml/basic-toml）。

## 驳回（经核实不成立）

| 主张 | 理由 |
|---|---|
| `percent_decode` 尾随转义 off-by-one（converter.rs:1267） | 尾部完整 `%XX` 在 i=len-3 时 `i+2=len-1 < len` 为真，可正确解码；守卫无误 |

## 质量门（§3 检查项）

- **lint**：`cargo clippy --workspace --all-targets` 零警告（各修改 crate 单独 + workspace 复核）。
- **类型检查/编译**：`cargo test --workspace --all-targets` 编译全绿；`cargo check --workspace` 绿。
- **测试基线**：全仓测试通过（fetcher 新增 1、cache 新增 2、hot_reload 新增 2，均过；既有 failover/水位/健康检查用例回归绿）。
- **docs build**：`pnpm vitepress build` 绿（任务书要求先本地 build 后落库）。
- **依赖审计**：`cargo audit` 3 条信息级（basic-toml/unsafe-libyaml unmaintained；tokio 已随 1.54.1 清除）。

## 安全静态扫描结论

六类（硬编码密钥 / shell 注入 / SQL 拼接 / eval / 反序列化 / 路径穿越）全仓扫描无命中：
- shell 注入：无 `Command::new(...).arg(shell)` 拼接——命令均为 args 数组直传（无 `sh -c` 字符串拼装）。
- 反序列化：`serde_yaml/json/toml` 用于配置/订阅解析，均为白名单结构体，无 `unsafe` 反序列化、无 `#[serde(deny_unknown_fields)]` 缺失面的任意类型实例化。
- 路径穿越：缓存路径由 `DefaultHasher` 哈希文件名（`{:016x}.cache`）派生，非用户输入直拼；插件路径经配置校验。
- 硬编码密钥：config 样例仅 demo/占位值；无仓库内真实凭据。
- crypto 与规范一致：vmess v2ray KDF/AES-GCM、shadowsocks crate、mesh mTLS（rustls 验证默认开启，`NoVerifier` 仅 `skip_cert_verify` 显式 opt-in）。
- FFI：`rillane_ffi_start` `from_raw_parts` 契约 + 文档化 `#Safety`；wasmtime 插件 fuel + zero-import 沙箱。

## 四段式总账（对齐 docs 审计惯例）

1. **发现面**：安全扫描 0 + bug 猎捕 36（P0×1 / P1×5 / P2×6 / P3×24）。
2. **修复面**：P0/P1 全清（6 commit），P2 顺手 1，共 8 项落地。
3. **剩余面**：P2×5 + P3×24 = 29 项，全记 `todo.md`，含 file:line 证据。
4. **质量面**：clippy 零警告 / 全仓测试绿 / docs build 绿 / audit 仅信息级。

## commit 清单

- `16c7c13` fix(deps): bump tokio to 1.54.1 (RUSTSEC-2026-0386)
- `90c9f48` fix(mesh): advance replay window on forward jump
- `aab4b86` fix(subscription): bound subscription body read to 50MiB
- `7e57710` fix(subscription): fix cache deadlocks in set_with_ttl
- `91a93b0` fix(runtime): drop chain shard guard before stats in failover
- `5bc8dad` fix(protocols): gate pool refill dials with inflight counter
- `7527fd0` fix(mesh): recheck last_seen before marking node offline
- `362bb75` fix(runtime): write back merged subscription config and dedup rules

（另：docs 审计任务 `f0db1b6`/`9b564bf`/`a130556` 属前段文档面，不重复计入。）

---

## 第二轮补充（2026-11-02，独立会话语料补齐）

首轮报告（36 项）由并行会话语料产出；本段由另一会话语料补充其漏检面，逐条经复核（先验证后报告）。
**新增 15 项：P1×3（已修）/ P2×6（记 todo）/ P3×6（记 todo）。累计 51 项 · 已修 11 · 剩余 40。**

### 新增 P1（本轮已修，一问题一 commit）

| # | 问题 | file:line 证据 | 严重度定级 | commit |
|---|---|---|---|---|
| 9 | UDP mesh 出口 `exit_uplink` 两次 `flows.get` 间被下行 task 并发 `forget_flow`（独立 worker 真并行），`.expect("need_create=false 即 flow 必在表")` panic 杀掉整条 `serve_udp`——全节点 UDP 面停摆。客户端 ≤30s/64 包重发 FULL（udp_chain.rs:26-29）可重建，改为 miss 丢弃本包 | `mesh_transport.rs:1898-1906`（旧 :1904 expect） | P1（远程可触、面级停摆） | `b8b7636` |
| 10 | 订阅缓存 `get()` 持 `memory_cache` 写锁跨 `load_from_disk`（:557 重取同锁，std::sync::RwLock 不可重入）→ 重启带热盘缓存 / 内存条目过期两路径**必自锁死锁**。首轮 P2#1 判为「持锁跨同步磁盘 IO（阻塞）」属实但低估——实为死锁；`set_with_ttl`（7e57710）已修但漏 `get()` 路径。修复：守卫先行释放再交 `load_from_disk`，2 个回归测试 | `cache.rs:149-176`（load_from_disk :557） | P1（正常重启路径必触） | `bec9785` |
| 11 | SOCKS5 域名字符串未校验（CR/LF/控制字符直入 `FlowTarget.host`）；HTTP CONNECT 出口把 host 内插进请求行与 `Host` 头 → 客户端可向上游代理注入任意头（请求走私/头伪造）。修复：crate 辅助 `host_has_injection_chars`（空/控制字符），SOCKS5 入口（第一道闸）+ HTTP CONNECT 出口（最后防线）双闸，2 个回归测试 | `socks5.rs:291` + `http.rs:81`（出口 :122/:166） | P1（远程可利用安全漏洞） | `fefa6d5` |

（注：`bec9785` 同时使首轮 P2#1 的 get() 死锁半落地——该条目剩余面仅 cleanup→`fs::remove_file` 持锁同步 IO 一项，仍记 todo。）

### 新增 P2（记 todo，本轮未改）

| 问题 | file:line 证据 |
|---|---|
| TUN UDP 下行只续 `last_active` 不续 `expiry`——上行（:432-434）续两者、下行（:812-813）续一者，清扫（:714）按 `expiry<=now` 驱逐。纯下行推送流（客户端 udp_idle_secs 内无上行）被中途逐出 | `tun_ingress.rs:812-813` |
| `scan_udp_capability` BFS 无 visited 集，组环（g1→g2→g1）队列永不空 → `build()` 无限挂起（udp.enabled 时）；`RoutingConfig::validate`（:1489）仅查 SLO 无环守卫 | `runtime_builder.rs:2266-2280` |
| chain 故障转移复用已消费 `flow.io`：首 `dial_and_tunnel`（mesh_transport.rs:1569 `copy_bidirectional` 读 io）中途失败即部分消费；重试（:2025）拼接尾流+新信封 → 协议流损坏。正确恢复=中止应用连接 | `runtime_builder.rs:1919/2025` |
| 串行 UDP serve 循环内联 `lookup_host`（单任务无 per-packet spawn，§13-5）——一个不可解析 `target_host`（线上可控）阻塞整面所有流 | `mesh_transport.rs:1852` |
| 任意 `recv_from` 错误（ENOBUFS/EINTR 瞬时）经 `Ok(Err(e))=>return Err` 终止 UDP serve 任务 | `mesh_transport.rs:1946` |
| 瞬时 `accept` 错误（ECONNABORTED/EMFILE/EINTR）经 `?` 终止 TCP mesh 监听任务 | `mesh_transport.rs:1330` |

### 新增 P3（记 todo，本轮未改）

| 问题 | file:line 证据 |
|---|---|
| `stats.active_chains = active_chains.len() - 1` 在 `drop(chain)` 后；并发 `terminate_chain` 移除 → 0-1 下溢（release 裹成 usize::MAX 指标污染） | `chain.rs:907` |
| exit 建流归零下行序号而客户端窗口仍在（last>63）→ 序号 0..36 判回退拒、≥37 自愈。**瞬态 ~37 包突发丢包，非「永久静默拒收」**（首轮转述修正） | `mesh_transport.rs:1877` |
| 缓存满（65536）时每次插入全 O(n) `min_by_key` 驱逐扫描；文档化权衡（"O(n) 无新依赖"），需认证 peer + 6.5 万流触发 | `mesh_transport.rs:868-876` |
| 订阅转换配置硬编码 `admin_token: "rillane"`（回环绑定约束暴露面） | `clash.rs:768-771` / `rillane_dsl.rs:413-418` |
| shaping 抖动 `jitter_ms + 1` 在 jitter_ms=interval_ms=u64::MAX 时裹 0 → `% 0` panic；validate 无上界 | `shaping.rs:45` / `rillane-config:908-918` |
| `save_to_disk` 固定 `{hash}.tmp` 路径，并发 `set()` 同键交错写 → 损坏缓存条目（重取可恢复） | `cache.rs:588-601` |

（首轮 P3 已含 `trojan.rs:99` `as u8` 截断、padding range span 下溢、loop 任务无 stop、lock-poison 级联、非常量时间比对、FFI 裸指针——本会话复核一致，不重复列。）

### 复核修正 / 排除项

- `interval(ttl/4)` 零周期 panic：ttl/4==0 仅 ttl<4ns，YAML Duration ≥1ms → 不可达，**排除**。
- mesh UDP 下行序号重启「永久拒收」：经 `ReplayWindow::check_and_advance` 逐档推演为**瞬态**（回退>63 拒、63 内按历史位收、追平后前进），降级 P3 并修正转述。
- `rillane-routing` 一致哈希 `% len` 与空表守卫、`rillane-telemetry/plugins/config` 生产路径（unwrap 均测试面）、`rillaned/main.rs` `?` 传播、`udp_associate.rs`（tests 面）——**净**。

### 本会话复核净检面（首轮未覆盖或补强）

- `rillane-protocols` outbound/inbound 全量、`rillane-core/udp`、`rillane-subscription`（fetcher 50MiB 上限+重定向 10 界、clash `parse_ports` 4096 上限、converter/rillane_dsl 无界分配）——净。
- `shadowsocks` SIP003：`Command::new(plugin)` + `args(opts.split_whitespace())` 为 argv 直传，**无 shell 注入**（复核确认）。
- `inbound/http.rs` httparse 按 CRLF 切分，authority 结构上不能携带 CRLF——净（与 SOCKS5 域名字符串不同源）。
