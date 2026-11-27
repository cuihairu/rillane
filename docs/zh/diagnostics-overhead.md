# 诊断开销与留存（RIL-064）

诊断采集面（有界事件采集器 + 逐连接查询服务）在默认上限与关闭/采样/全量三档下的对照，及留存契约。

**诚实范围**：生产 trace 准入已接线（`TracedFlowOutput` 包装运行时输出，RIL-083 活面证据记录了经该路径的 TCP 入口轨迹）；本报告仍经开销量测工具隔离量测采集器 + 查询面，不是转发路径之后的端到端逐连接开销。以下数字为 debug 构建在开销量测工具（`cargo test -p rillane-core --test collector_overhead -- --nocapture`）下的实测；release 构建更快。端到端数据路径开销是具名缺口，这些数字不得读作该量测结果。

## 三档对照（守护进程默认形：容量 1024 / 活动上限 256 / 每流 256 / TTL 1h；只变开关与采样分母）

| 档 | 8 000 条新流 admit 均值 | 建迹数 | 说明 |
|------|------|------|------|
| 关闭（`enabled: false`） | 0.28 µs | 0 | 整体 no-op——写路径只付一次布尔检查 |
| 采样（`sample: 10`） | 0.80 µs | 256 | 确定性 1/10 入选；其余答显式墓碑；活动上限把滞留量钉在 256 |
| 全量（`sample: 1`，默认档） | 4.77 µs | 8 000 | 环形容量逐出最旧，逐出计数可见 |

查询面（命中路径，1024 迹线性扫描，2 000 次取样）：p50 53 µs / p95 72 µs / p99 82 µs（debug 构建）。

全量档运行期间量测进程 RSS 增量：约 0.5 MiB——由环形容量钉界，不随流量增长。

## 留存契约（历史可过期 / 可删除）

- **过期**：TTL 清扫在 runtime 内每 60 s 一轮（`Runtime::start` 装配；错过 tick 跳过——尽力而为的维护面）。过期迹留 `collector.flow.expired` 墓碑；`traces_expired` 在每份缺席答复可见。
- **删除**：`DELETE /trace/history`（操作员动作；配置 `admin_token` 后走鉴权门）立即清除全部已关闭迹——活动流绝不拆。被清除流此后答 `collector.flow.purged`，与「从未见过」分立。端点答版本化信封 `{schema_version: 1, purged: N}`；空采集器答 `0`，绝不造数。
- **有界是构造事实**：环形容量钉滞留量；墓碑同界；每流事件上限钉单迹。没有任何量随流量无界增长。

## 指标标签卫生

- `/metrics` 标签键全集是固定审查名单（`direction`、`egress`、`from`、`ingress`、`mode`、`name`、`origin`、`quantile`、`reason`、`result`、`source`、`subscription`、`to`、`type`）——契约测未登记键一律拒绝，新键必须先进名单。
- 逐连接身份绝不作为标签值：值只来自配置定义的名字（ingress/egress）、mesh 节点 ID 或固定枚举——由配置钉界，从不由流量决定。
- 断言标签值永不为地址形态（`ip:port` 或裸 IP）——高基数身份无法以标签形式混入。
- 秘密（`control.admin_token`、订阅 URL 凭据）绝不出现在 `/metrics` 输出（同测断言）。

## 量测工具

`crates/rillane-core/tests/collector_overhead.rs` 打印上表并钉保守上界（关闭档亚微秒 admit、全量档微秒级 p99 admit、查询命中十微秒级 p99）——采集器若出现二次方退化，任何机器上都会挂测。
