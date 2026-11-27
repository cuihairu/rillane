# RIL-043 移动 FFI — 缓冲所有权与并发面（本地可核验段，2026-11-27）

## 交付内容

`crates/rillane-ffi/tests/ownership_concurrency_contract.rs`（2/2 绿，
连续 5 次稳定通过）钉住验收条款「缓冲所有权、线程、取消、ABI 版本」在
拉模型 FFI 上的半边。本 FFI 按构造即拉模型——无回调、无共享队列——
宿主侧残余风险就是缓冲所有权、并发查询与 ABI 版本漂移。三者全部对
真实运行时（真实 SOCKS5 入站、真实传输）钉死：

- **堆族 vs 静态族**：活句柄上两次 `rillane_ffi_stats_json` 返回不同的
  非 NULL 指针（每次调用独立 `CString` 堆分配——若两次归还同一静态缓冲，
  宿主第一次 free 即毁掉第二份读），各自解析为合法 JSON 且对冻结 stats
  子集面（`uptime_seconds`、`total_connections`、`is_running`、
  `tun_fd`；`is_running == true`）。`rillane_ffi_version()` 是相反族：
  两次调用返回**同一**指针（进程级静态，文档写明永不归还），且串文本
  必须与根 `Cargo.toml` `[workspace.package].version` 逐字一致
  （`version.workspace = true` 继承链）——升版本不过门即失败。
- **缺席编码**：NULL 句柄查询应答 NULL（非垃圾指针）；
  `rillane_ffi_free_string(NULL)` 容忍。
- **last_error 读后即清**：启动失败（坏 YAML）后错误串恰交出一次——
  第二次读为 NULL——交出的缓冲由宿主归还。
- **并发查询不阻塞数据面**：4 线程 × 25 轮在同一共享句柄上跑
  stats/flows/nodes 查询，同时一条真实传输（手写 SOCKS5 无鉴权协商、
  IPv4 CONNECT、8192 字节载荷）经入站 → direct 出站 → echo 服务。
  字节逐位精确回声（查询面零干扰），并发 flows/nodes 应答全部携带
  `schema_version == 1`（无撕裂/无串代际），echo 侧确认收满载荷长度。
  两测试经端口守卫串行（cargo 默认并行跑测试，两者共用固定端口）。

## 诚实边界

- 取消作为设备侧概念归宿主生命周期门（RIL-044 停止面）；本 FFI 除
  `rillane_ffi_stop` 外无取消动词。
- 公开 `packetFlow` 批次（iOS NE）与真机 ABI 批次归 RIL-094 设备面，
  本门不冒充。
- 悬空句柄解引用是 UB、不可测；宿主侧「stop 后清引用」纪律由
  host_lifecycle 的 Kotlin 文本门钉，本门不重复声明覆盖。
