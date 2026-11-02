# P3-5 零拷贝/批量收发（实现级设计）

> 上游：[todo.md](../../../todo.md) P3-5（2026-09-30 自 PROTOCOLS.md「性能优化」降级登记）·
> [PROTOCOLS.md](../PROTOCOLS.md) 性能节。
> 本文是落地定稿：**范围裁决（splice/recvmmsg 出界）、进程级 relay 缓冲参数、
> 帧写 vectored 化、基准方案、分步清单**。落地后偏差回填 §7。
> **状态：R0–R4 已全部落地**（2026-10-05。R1：seep-core `performance`
> 模块 + seep-config `performance:` 块 + RuntimeBuilder 接线 + 16 处
> relay 点 `copy_bidirectional_with_sizes`；R2：`write_frame` vectored
> 化 + 短写推进 + ShortWriter 专项测试；R3：criterion benches 实跑，
> 数字见 §5 结果表；R4：PROTOCOLS.md 性能节「已实现（范围）」回填 +
> todo.md P3-5 勾选）。

## 0. 范围与验收口径

**todo 原文**：PROTOCOLS.md「性能优化」节的零拷贝与批量处理描述超前于实现且无近期
落地计划，自"设计口径"降级为本登记项。
**验收原文**：落地时以基准测试佐证吞吐/延迟收益，并回填 PROTOCOLS.md 性能节状态
（异步 I/O 已实现一行保留）。

**可测口径（显式改写）**：

1. **relay 缓冲可配**：TCP relay 双向缓冲大小可经 `performance.relay_buffer`
   配置（进程级，启动期设定）；缺省 None = 8192×2 维持现行为，存量零差异；
2. **帧写合一**：mesh `[len][payload]` 帧写由两次 `write_all` 改为
   `write_vectored` 两段一次提交 + 短写推进循环——明文 TcpStream 段一次 syscall；TLS 段
   rustls 无 vectored 实现，自动回落逐段（行为不劣于现状）；
3. **基准佐证**：criterion benches——回环 TCP relay 在 8K/32K/64K/256K
   缓冲下的吞吐对照（模拟 BDP 场景），与帧写两段/vectored 对照；结果
   数字回填本文 §6 并同步 PROTOCOLS.md 性能节（「已实现（范围）」口径，
   范围外项如实登记未做）。

## 1. 现状与结构约束

- TCP relay 全部经 `tokio::io::copy_bidirectional`：seep-protocols 出站
  12 处（direct/socks5/http×3/trojan×2/ss/hysteria2/vless×2/wireguard）+
  seep-runtime mesh 面 3 处（`mesh_transport.rs:1419/1481` 与
  dial_and_tunnel）——tokio 内部固定 8192 字节 × 双向用户态拷贝循环；
- **connector 无 config 通道**：`EgressConnector::forward(&self, Flow)`
  签名无运行参数（seep-core lib.rs:766）——逐 connector 传参需动 12+
  实现与 trait；`IngressEndpoint` 同理；
- mesh 帧写 `write_frame`（mesh_transport.rs:1961）= `write_u32(len)` +
  `write_all(payload)` 两次写——明文段两次 syscall，TLS 段两次 record 封装；
- `MAX_HEADER_BYTES = 64 KiB`（含 pad 上界）——帧体最大 64 KiB+pad，
  逐帧预拼接整体 buf 的方案会引入最高 64 KiB 的额外 memcpy，不取
  （两段 vectored 零拷贝提交，见 D-2）；
- **TLS 段无真 vectored**：rustls 0.23 `TlsStream` 未实现
  `poll_write_vectored`（`is_write_vectored()=false`）；落地实现为
  `write_vectored` + 短写推进循环，对 false 流自动回落逐段 `write_all`——行为等价现状；
- 生产 mesh 数据面强制 mTLS（dev 才可 `SEEP_MESH_ALLOW_PLAINTEXT=1`），
  出站 TLS 系协议占比高——**明文直连段（socks5/http 入 → direct/socks5
  出）是 vectored 与大缓冲的主要收益面**。

## 2. 设计决策

- **D-1 进程级 relay 缓冲参数（AtomicUsize）**：`seep-core` 新增
  `performance` 模块——`set_relay_buffer(usize)`（启动期一次，仅允许
  从缺省改出；测试可 reset）+ `relay_buffer() -> usize`（缺省
  `DEFAULT_RELAY_BUFFER = 8192`）。15 处 relay 点改用
  `tokio::io::copy_bidirectional_with_sizes(io_a, io_b, n, n)`。进程级
  而非 per-connector 参数的理由：trait 无 config 通道（§1），且 relay
  缓冲无逐出口差异化需求（BDP 由路径决定，非出口类型）；先例同 P1-5
  池/工厂进程级单例（egress-connection-pool.md D-10）。
- **D-2 帧写 vectored 化**：`write_frame` 改
  `stream.write_vectored(&mut [IoSlice::new(&len_be),
  IoSlice::new(payload)])` + 短写推进——`is_write_vectored()` 为真的流（TcpStream）
  一次 syscall；为假（rustls）回落逐段，零回退损失。`write_u32` 的
  4 字节头部以栈数组 `len_be` 承载，无堆分配。
- **D-3 splice 出界**：内核态零拷贝（splice/tee）仅适用于
  「plaintext↔plaintext 且两端皆为真实 fd」段——本仓 flow.io 经
  FlowMiddleware 链包装（P1-4 padding/timing/shaping 为
  AsyncRead/Write wrapper，splice 语义破坏）、TLS 段占多数，tokio 亦
  不暴露 splice（需 nix + 自管 fd 与 tokio 注册机制冲突）。收益面窄、
  工程风险高——出界，登记 §7。
- **D-4 UDP recvmmsg/sendmmsg 出界**：UDP 面逐包 `recv_from`/`send_to`
  每 datagram 一次 syscall，批量批量收发需 recvmmsg/sendmmsg（libc 直调
  + tokio 托管 fd 兼容复杂）；现网验收包率（AVD 模拟器 ping 级）距
  syscall 瓶颈多个数量级，无证据支撑引入复杂度——出界，登记 §7；
  待真机高包率场景出现时以基准驱动重评。
- **D-5 缺省零差异**：`performance` 块缺省缺省（`Option`），relay
  缓冲缺省 8192=现行为；无配置时全链路字节行为不变。
- **D-6 观测**：不加新指标族——relay 缓冲是静态配置形态；基准结果
  落本文 §6（静态数字）。

## 3. 数据结构与接线点

```rust
// seep-core/src/performance.rs（新）
pub const DEFAULT_RELAY_BUFFER: usize = 8192;
static RELAY_BUFFER: AtomicUsize = AtomicUsize::new(DEFAULT_RELAY_BUFFER);
pub fn set_relay_buffer(n: usize) -> Result<()>;   // 非法值(0/超上界)报错
pub fn relay_buffer() -> usize;                    // 全部 relay 点读取
```

```rust
// seep-config：顶层新块（deny_unknown_fields，Option 缺省）
pub struct PerformanceBlock {
    pub relay_buffer: Option<u32>,   // 字节；8192..=1 MiB 校验
}
```

| # | 点 | 动作 |
|---|----|------|
| 1 | seep-protocols 出站 12 处 + mesh_transport 3 处 | `copy_bidirectional` → `copy_bidirectional_with_sizes(n, n)`（D-1） |
| 2 | `mesh_transport::write_frame` | vectored 两段合一（D-2） |
| 3 | `runtime_builder` | `performance:` 块读取 → `set_relay_buffer`（构建期一次） |
| 4 | seepd config schema 透传 | `PerformanceBlock` 进 `SeepConfig` 顶层 |

## 4. 错误与边界

- E1 `relay_buffer` 非法值（0 或 > 1 MiB）：seep-config validate 报错
  带原值（network/obfs 先例）；`set_relay_buffer` 二次防御同样报错；
- E2 vectored 回落：rustls 段行为 = 现状两段写（§1），无回归面；
- E3 缓冲上调的内存代价：每流 2×n 字节——1 MiB 上界 × 千流 = 2 GiB
  极端上界，文档注明按并发量估算（缺省 8192 不变）；
- E4 帧写头 4 字节 `payload.len() as u32` 溢出：`MAX_HEADER_BYTES`
  64 KiB 上界检查先行（现状已有），vectored 化不改检查位置。

## 5. 基准方案（criterion，`benches/`）

- `relay_throughput`：本地回环 TCP 对打——`tokio::spawn` 一端灌
  N MiB，relay task 以指定缓冲中继，计吞吐；对照组 8K/32K/64K/256K；
  另加「模拟 BDP」组（两 tokio task 间串 64 KiB 延迟
  `tokio::time::sleep` 注入? 否——延迟注入会使基准失真，改用
  大 payload 单向灌包测摊薄效果），结果取 MiB/s；
- `write_frame`：两段写 vs vectored 对比（明文 TcpStream 回环），
  4 KiB/64 KiB payload 两组；
- 产出：criterion 输出截图式数字回填 §6 表格；基准不入 CI 门禁
  （本地跑，噪声大环境不稳定不判 CI）。

**结果（2026-10-05 实跑，多轮取中位）**。实跑落点：
`seep-core/benches/{relay_throughput,write_frame}.rs`；relay 组单迭代
= 32 MiB 单向灌包经 `copy_bidirectional_with_sizes` 中继收毕；帧写组
单迭代 = 2048 帧连续写、读端读满总量收敛。环境为多会话共用开发机
（bench 期间 load avg 19–45），run-to-run 波动显著，故每配置跑
3–4 轮取中位数；数字仅代表同轮相对对照，非绝对吞吐承诺（§7.4）。

relay 吞吐（32 MiB 单向，多轮中位）：

| 缓冲 | 8192 | 32768 | 65536 | 262144 |
|------|------|-------|-------|--------|
| 迭代耗时 | 149 ms | 122 ms | 112 ms | 96 ms |
| 吞吐 | 214 MiB/s | 263 MiB/s | 286 MiB/s | 357 MiB/s |

8K→256K 中位吞吐 +67%，缓冲上调摊薄 syscall 的方向与幅度稳定复现。

帧写对照（2048 帧/迭代，多轮中位）：

| 写法 | 4 KiB payload | 64 KiB payload |
|------|---------------|----------------|
| 两段 `write_all` | 33.8 ms / 243 MiB/s | 206.9 ms / 620 MiB/s |
| vectored 合一 | 25.3 ms / 318 MiB/s | 217.4 ms / 589 MiB/s |

4 KiB 帧 vectored 中位快约 26%（安静轮次最高 2.2×，4 轮中 3 轮占优）；
64 KiB 帧两者同量级（差约 5%，置信区间重叠，判无回归）——大帧下
syscall 次数占比趋零，与 §2-D2「明文段收益、TLS 段等价回落」的
预期一致；TLS 段等价性由既有帧测试与 ShortWriter 短写专项测试保证。

## 6. 分步实施清单

| 步 | 内容与落点 | 验收 |
|----|-----------|------|
| R0 | 本设计稿 | — |
| R1 | seep-core `performance` 模块 + seep-config `performance:` 块（validate E1）+ runtime_builder/seepd 接线 + 15 处 relay 点换 `copy_bidirectional_with_sizes` + 单测（set/get、非法值、缺省零差异） | 门禁全绿；无配置时行为与现状逐字节一致 |
| R2 | `write_frame` vectored 化 + 既有帧测试零回归 | mesh 帧测试全绿 |
| R3 | criterion benches（§5 两组）+ 实跑 + 数字回填本文 §5 结果表 | 基准产出真实数字（已落地，见 §5 结果表） |
| R4 | PROTOCOLS.md 性能节回填（「已实现（范围）」+ 范围外项登记）+ todo.md P3-5 勾选 + 本文状态行 | 文档与实现对齐（已落地） |

## 7. 偏差与假设

1. **「零拷贝」降档为「减少拷贝/减少 syscall」**：用户态代理的流式中继
   无法消除用户态拷贝（TLS 终结、middleware 链语义）；本条目交付
   syscall 摊薄（大缓冲）与 vectored 合一提交，splice 判出界（D-3）；
2. **「批量处理」降档为「UDP 批量收发出界」**（D-4）：无高包率场景
   证据，不引入 libc 直调复杂度；
3. relay 缓冲为进程级单值（D-1）——per-出口差异化留待真实需求；
4. 基准在开发机回环跑，数字代表本机相对对照而非绝对吞吐承诺；
5. criterion 入 dev-dependencies，`benches/` 不进 CI 门禁（§5）。
