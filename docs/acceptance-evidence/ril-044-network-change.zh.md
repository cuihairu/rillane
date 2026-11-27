# RIL-044 移动宿主网络变化面（本地可核验段，2026-11-27）

## 交付内容

`crates/rillane-ffi/tests/network_changed_contract.rs`（3/3 绿）把 RIL-044
验收条款「网络变化」钉在其核心半边。`rillane_ffi_network_changed`（新增 C
导出，同提交更新头文件 + JNI 桥 `networkChanged` + Kotlin 声明与
`onAvailable` 接线）通知核心宿主底层网络已变化：

- **冲刷真实生效（真实 DNS 解析往返）**：runtime 以 `network.dns` 块启动，
  trusted 上游是测试本地 mock——复用平台 crate 自己的线格式编解码（与解析
  器同方言，零失配面）。同域名二次查询走缓存（上游命中数不动，
  `dns_stats` cache_hits ≥ 1）；`network_changed` 后第三次查询重回上游
  （命中数 +1）——缓存若未失效则停在基线，对账器自证证明缺席可检出。
- **幂等可重复**：再次 `network_changed` 后下一次查询再度回上游（命中数
  继续前进）；调用无状态。
- **DNS 块缺席 = 诚实 no-op**：无 `network.dns` 的 runtime 返回 0（冲刷空
  即成功），`dns_stats` 面如实读出 `enabled:false`。
- **NULL 句柄具名**：NULL → -1 + 稳定 `last_error`，绝不与成功 0 混同。
- **桥接面同步**：JNI 符号恰等门升到 16 方法（两侧同加 `networkChanged`），
  C 头 ↔ Rust 导出恰等门过，RIL-082 诊断账本登记新导出
  （`contracts/mobile_diagnostic_bridge_v1.json` 账本事务）。

## 如实边界

本门钉核心半边（缓存冲刷行为 + 句柄面）。会话排空是具名边界不是宣称：
在途转发流不主动斩断——排空归 RIL-022/023 消费侧边界，网络变化沿同一
边界（旧网流自然失败，宿主不得依赖本调用斩流）。Kotlin
`onAvailable → networkChanged` 接线是文本纪律门钉的结构面；真机活切网
（Wi-Fi ↔ 蜂窝）归 RIL-046 真机批次开放，有界诊断 IPC（RIL-044 其余交付）
同样未开工。主勾选保持关闭。
