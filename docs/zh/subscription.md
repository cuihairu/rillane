# 订阅指南（当前实现）

Clash/Mihomo 为**部分兼容**。当前拉取、转换、缓存、刷新与控制面链路存在；目标的来源快照、完整 provider 与保真规则/组见 [v1 订阅设计](design/architecture-v1.md#subscription-compatibility)。

## 输入和转换

支持 Clash YAML、分享链接列表及其 base64 表达，以及 Rillane 自有 DSL。具体类型与协议字段以 `crates/rillane-subscription` 的转换器和运行时校验为准。当前 ClashConfig 要求的结构不能被理解为已支持任意 provider-only 输入。

| 输入 | 当前映射 | 限制 |
|---|---|---|
| proxies | egress | 导入字段存在不代表对应平台/协议可运行 |
| proxy-groups | routing.groups | fallback → Random、relay → ConsistentHash 存在语义损失 |
| rules | routing.rules | PROCESS-NAME、RULE-SET 等关键规则可能被告警后跳过 |
| url-test interval | 探活秒数 | 当前错误按毫秒除以 1000；显式 300 被算成 1 秒，缺省仍为 300 秒 |

因此不能只看“转换成功”判断安全可用。先核查关键规则、组和单位；修复任务为根目录 `todo.md` 的 RIL-092/RIL-093，完整保真实现见 RIL-007～RIL-016。源码依据见[研究缺口](research/proxy-architectures-2026-11-14.md#verified-gaps)。

## 拉取、缓存与更新

拉取器支持超时、请求头、代理和条件请求；缓存提供 TTL/LRU。Subscription 已有 SHA-256 内容摘要和变更检测。摘要不是签名，也不证明来源可信。

当前 runtime 按名字追加节点/组并 extend 规则，不能正确传播更新/删除。控制面删除来源不等于 v1 所承诺的来源对象与存活会话事务。订阅刷新后的有效配置必须检查；新代际实现前不能假定本地策略、旧流与 OS 状态已原子切换。

## 命令与接口

```bash
rillanectl subscription --help
rillanectl import-clash --help
rillanectl export-clash --help
rillanectl import-rules --help
```

`import-rules` 是 geosite/chnroutes 文本规则到配置片段的离线转换，不等于订阅 RULE-SET 运行时支持。具体参数见 [CLI](cli.md)。

| 接口 | 操作 |
|---|---|
| GET /subscriptions | 状态列表 |
| POST /subscriptions | 添加 |
| POST /subscriptions/refresh | 刷新全部 |
| POST /subscriptions/{name}/refresh | 刷新单个 |
| DELETE /subscriptions/{name} | 删除来源 |

管理鉴权见 [配置](config.md)的 `control.admin_token`；当前普通只读与敏感读/写端点的门控不同，不等于 v1 的细粒度 MCP 权限。配置文件本身没有通用 watch 或 SIGHUP 重载，修改后需要按当前支持方式生效。

订阅 URL、头、节点秘密及原始运行配置不应发送给模型；现有 diagnose 不自动满足 v1 DiagnosticView 的脱敏契约。参见 [Debug 与 MCP](design/debug-and-mcp.md)。
