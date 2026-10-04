# 订阅指南（现状）

> 状态：全链路已实现（`crates/seep-subscription`）· 相关：[architecture.md](architecture.md) · [mesh.md](mesh.md) · Seep DSL schema 定义于 `crates/seep-subscription/src/seep_dsl.rs`

## 执行摘要

Seep 订阅链路覆盖：拉取（条件请求/代理/自定义头）→ 类型自动识别（Clash YAML / 分享链接 / base64）→ 转换为 `SeepConfig` → TTL+LRU 缓存 → 两级定时刷新（内容哈希无变化跳过重载）→ 控制面 CRUD 与热更新。本文按代码实况描述各环节与边界。

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
- 亦支持导出为 Seep 自有 DSL 并回导入（`seep_dsl.rs`）：`version/meta/nodes（auth/transport/tls/location）/groups（strategy、嵌套成员）/rulesets`，附带校验器。

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
- 配置文件本身的变更由 `seep-runtime::HotReloadManager` 监视（`notify` crate，`watch_config_file` 可关），走同一热更新路径。

## 6. CLI

```bash
seepctl import-clash <url|file> --out seep.yaml   # 离线转换预览（不经守护进程）
seepctl subscription list|add|remove|refresh      # 经控制面管理
```

## 7. 边界与未落地

- 订阅拉取暂无内建定时重试退避（失败依赖下一轮全局刷新周期重试）；
- DSL 与 Clash 双向转换以「Clash → Seep」为主，DSL → Clash 回导出未实现；
- 订阅规则集（rulesets）转换粒度受 Clash 规则类型覆盖面限制，未覆盖类型在转换期提示。
