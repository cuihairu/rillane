# 订阅指南（现状）

> 状态：全链路已实现（`crates/seep-subscription`）· 相关：[architecture.md](architecture.md) · [mesh.md](mesh.md) · Seep DSL schema 定义于 `crates/seep-subscription/src/seep_dsl.rs`

## 执行摘要

Seep 订阅链路覆盖：拉取（条件请求/代理/自定义头）→ 类型自动识别（Clash YAML / 分享链接 / base64）→ 转换为 `SeepConfig` → TTL+LRU 缓存 → 两级定时刷新（内容哈希无变化跳过重载）→ 控制面 CRUD 与热更新。本文按代码实况描述各环节与边界。

另有离线转换面：`rule_source.rs`（O-dns1，2026-10-10）把 geosite/chnroutes 文本规则源解析为路由/DNS 分流规则片段（`seepctl import-rules` 取数），不经订阅缓存链路。

## 1. 订阅源与类型识别

- 支持源类型：**Clash YAML**（proxies/proxy-groups/rules）与**分享链接列表**（`vmess://`、`vless://`、`trojan://`、`hysteria2://`/`hy2://`、`ss://` 等，见 `converter.rs`）；整体为 base64 编码的链接列表会自动解码（`try_decode_base64`）。
- 类型自动识别：`Subscription::detect_type` 按内容特征判定，无需手工指定。
- 内容校验：拉取后经 `validate_content` 检查非空与基本形态，防止空响应覆盖现有配置。

## 2. 拉取（`fetcher.rs`）

- 基于 `reqwest`（rustls）；可配置：超时、User-Agent、自定义请求头、出站代理（`with_proxy`）、重定向策略。
- **条件请求**：记录并回传 `ETag` / `Last-Modified`，服务端返回 304 时命中缓存、不重复转换。
- 拉取结果 `FetchResult` 携带响应头元数据与最终内容。

## 3. 转换为 SeepConfig（`clash.rs` + `converter.rs`）

| Clash 概念 | Seep 映射 |
|-----------|----------|
| `proxies` | `egress`（`EgressConfig` 各变体） |
| `proxy-groups` | `routing.groups`（`PolicyGroup`，保留策略；成员支持嵌套组与权重） |
| `rules` | `routing.rules` |

- 转换产出**当前未实现的出站类型**（如 hysteria v1——schema/订阅转换已支持，出站连接器缺）时不会静默丢弃：运行时构建（`RuntimeBuilder`）阶段报错提示。协议实现边界见 [PROTOCOLS.md](PROTOCOLS.md) 状态标注。
- **传输层字段**（`network` + 各 `*-opts` 块，2026-10 随协议批补齐）：导入识别 `network: tcp | ws | grpc | h2` 与 `ws-opts`（path / `headers.host`，Host 头键大小写三形兼容；平铺 `path`/`host` 优先兜底）、`grpc-opts`（`grpc-service-name` 规范键 + 变体别名）、`h2-opts`（path/host，host 标量或数组皆收）；SS 的 `plugin`/`plugin-opts` 按换算表转 SIP003（obfs 族→`obfs-local`、v2ray-plugin 原名键值透传、其余插件名拒导宁缺毋滥）。导出侧对称产出：ws/h2 按 `network` 出块（trojan 不产 h2——seep 侧 trojan 白名单无 h2 口径）、`grpc-opts` 仅 `network=grpc`；SS 插件无 Clash 等价表达，导出降级提示不产出。seep 白名单外的 `network` 值在 RuntimeBuilder 构建期报错。
- 亦支持导出为 Seep 自有 DSL 并回导入（`seep_dsl.rs`）：`version/meta/nodes（auth/transport/tls/location）/groups（strategy、嵌套成员）/rulesets`，附带校验器。
- **Seep → Clash 回导出**（`clash_export.rs`，2026-10-07）：`ClashExporter::export(&SeepConfig)` 产出 Clash YAML + 报告（导出/降级清单）。proxies 覆盖 ss/vmess/vless/trojan/http(s)/socks5/hysteria2/hysteria/wireguard（direct 映射内置 `DIRECT`，不产出 proxy）；规则仅单条件可线性化（seep 多条件 AND ≠ Clash 首中即停，多条件跳过并登记）；组策略 Fixed→select、Latency→url-test（generate_204/300s）、Random/Weighted/Bandwidth/RoundRobin→load-balance(round-robin)、ConsistentHash→load-balance(consistent-hashing)；字段级无对应项（如 `tls_fingerprint`）逐条入 `skipped` 不阻塞导出。

## 4. 缓存与刷新（`cache.rs` + `lib.rs`）

- `SubscriptionCache`：TTL + LRU 双维度清理，默认清理间隔 1 小时；暴露命中命中率等统计（`CacheStats`）。
- 两级刷新节奏：单订阅 `refresh_interval`（分钟）与全局刷新循环（默认 300 秒一轮，`needs_refresh` 判定是否到期）。
- **变更检测**：内容哈希（`has_content_changed`）不变时跳过转换与 runtime 重载，避免无效热更新。

## 5. 控制面与热更新

控制面（`control.api_bind`，认证方式见 [mesh.md](mesh.md) Auth 小节）：

| 端点 | 行为 |
|------|------|
| `GET /subscriptions` | 列出订阅与状态（最近刷新/错误） |
| `POST /subscriptions` | 添加订阅 |
| `POST /subscriptions/refresh` | 全量刷新 |
| `POST /subscriptions/{name}/refresh` | 单订阅刷新 |
| `DELETE /subscriptions/{name}` | 删除订阅 |

- 刷新成功且内容变化时触发 runtime 热更新（路由/组/出站重建），订阅事件计入指标（`inc_subscription_event`）。
- 配置文件本身的变更**当前无自动监视**：seepd 启动一次性读配置，`seep-runtime::HotReloadManager`（`watch_config_file`）为导出能力但 seepd 未接线——改配置需重启进程或经订阅/控制面路径触发热更新。

## 6. CLI

```bash
seepctl import-clash <url|file> --output seep.yaml   # 离线转换预览（不经守护进程；-o 同义，缺省 config/clash_import.yaml）
seepctl export-clash <seep配置> -o clash.yaml        # Seep → Clash 回导出（离线；缺省 config/clash_export.yaml，末尾打印降级/跳过清单）
seepctl import-rules <url|file> --target <组或出口> [--face routing|dns]  # geosite/chnroutes 文本规则源批量导入（O-dns1；缺省 stdout，--out 写文件；跳过清单走 stderr）
seepctl subscription list|add|remove|refresh      # 经控制面管理
```

完整 `seepctl` 旗标（含 `--header`/`--refresh-interval`/`--timeout` 单位）与控制面端点语义见 [cli.md](cli.md)。

## 7. 边界与未落地

- 订阅拉取暂无内建定时重试退避（失败依赖下一轮全局刷新周期重试）；
- 「Clash → Seep」导入与「Seep → Clash」回导出双向已实现（`clash.rs` / `clash_export.rs`）；Seep 自有 DSL（`seep_dsl.rs`）→ Clash 未实现；
- 订阅规则集（rulesets）转换粒度受 Clash 规则类型覆盖面限制，未覆盖类型在转换期提示。
