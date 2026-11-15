# 订阅字段/单位支持表

本表范围：当前 Clash/Mihomo 导入器（`crates/rillane-subscription`）的字段级
兼容口径，按目标架构四层兼容分级（§4.2）组织。状态标记：

- ✅ 保真：导入后语义保持
- ⚠️ 降级：显式有损映射——宽松模式进损失清单，严格模式整体拒绝
- ❌ 拒绝：不支持的关键语义——宽松模式点名丢弃+报告，严格模式拒绝导入；
  绝不静默丢弃
- ⏳ 待接入：暂不吸收，随引用的 backlog 项落地

支撑本表的脱敏样本在 `crates/rillane-subscription/tests/samples/`（凭据只用
占位值，URL 不带 token——RIL-007 脱敏红线）；每份样本的预期对象/诊断在
`tests/subscription_samples.rs` 逐条断言。

## L1 节点

| 类型 | 字段 | 状态 | 说明 |
|---|---|---|---|
| ss | server/port/cipher/password，`plugin`/`plugin-opts` | ✅ | SIP003 仅换算 obfs/v2ray-plugin 两族键名，其余插件名拒导该节点 |
| vmess | uuid/alterId/cipher/tls/servername | ✅ | |
| vless | uuid，`reality` 块 | ✅ | reality 缺 `public-key` 保持节点级硬错误（G1-6 拒绝策略） |
| trojan | password/sni | ✅ | |
| http/https/socks5 | username/password | ✅ | |
| hysteria / hysteria2 | password，`mport`（别名 ports/ports-range/port-range），obfs 字段 | ✅ | 带宽字段不解释 |
| wireguard | private-key/public-key/ip 或 ipv6 | ✅ | 三者齐备才有效，否则按无效节点处理 |
| snell | — | ❌ | 类型级不支持：宽松丢弃+报告 / 严格拒绝导入 |

有效性门：`server` 为空或 `port: 0` 判无效节点；无效节点点名进损失清单
（RIL-093），不炸掉整个导入。

## L2 策略组

| 组类型 | 状态 | 说明 |
|---|---|---|
| select | ✅ | 成员顺序保持；用户选择跨更新持久（`routing.selections`，RIL-011）：仍存在的点选即使不健康也生效，已被删除的点选回落首健康成员且恢复原因进决策原因，reload 保留新配置未携带的选择。嵌套组引用构建期校验——循环与悬空引用点名拒绝 |
| url-test | ✅ | `url` 映射；**`interval` 单位是秒**（官方缺省 300；`0`/缺省→300，RIL-092）；导出侧同样按秒产出 |
| fallback | ✅ | RIL-012 起保真：映射 `Strategy::Fallback`——恒取声明序里首个健康成员（故障沿顺序回退，恢复即回首首位，绝不随机替代）。组上的 `url`/`interval` 随行注入探测参数（`UrlTestConfig`，interval 单位秒），导入后按原节奏探活成员 |
| relay | ❌ | RIL-013 起两种模式都明确拒绝：relay 是链式转发（流量依次经成员链），rillane v1 无同语义配置面——映射 ConsistentHash 只会伪装成功（成员被当链终点，流量根本不过链）。导入报错点名组 |
| load-balance | ✅ | RIL-013 审计：`strategy` 子键分派——`consistent-hashing`（及缺省，Clash 口径）→ `consistent_hash`（同目标恒落同成员，会话可重现）、`round-robin` → `round_robin`；旧实现一律映射加权随机（不可重现）属伪装。`sticky-sessions` 以 `consistent_hash` 近似并点名登记（粘滞键不同：源会话 vs 目标）；未知子键按缺省处理并在报告里留原文 |
| 嵌套组引用 / `use:` | ✅ | provider 引用在求值期按 `routing.provider_nodes` 展开（引用策略，RIL-009）；库为空或缺省时成员集为空，失效 provider 不提供任何新流候选——不伪装成有成员。无载荷的声明按引擎降级报告 |

## L3 规则

| 规则 | 状态 | 说明 |
|---|---|---|
| DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX | ✅ | 首匹配顺序保持 |
| IP-CIDR / IP-CIDR-6 | ✅ | 源/目的区分按换算表 |
| GEOIP / GEOSITE | ✅ | |
| SRC-PORT / DST-PORT | ✅ | 源/目标端口分立条件（源走 `net.src_port` 注解面，目标走目的端口）；区间展开 |
| NETWORK（逻辑规则内） | ✅ | → `proto` 条件 |
| MATCH（兜底） | ✅ | 必须保持最后 |
| PROCESS-NAME / PROCESS-PATH | ✅ | → `process`（comm 口径短名）/ `process_path`（完整可执行路径）条件（RIL-015）；比较精确且区分大小写。按引擎降级显式报告：命中依赖 TUN 进程归因（`process.name` / `process.path` 注解），其它入口流与归因不可得平台恒不命中；不以短名冒充路径 |
| RULE-SET / rule-providers | ✅ | 引用策略（RIL-014）：provider 声明落 `routing.rule_providers`（interval 秒口径原样），RULE-SET 匹配期按 `routing.rule_sets` 库解析；未声明引用拒绝+报告；载荷下载共用 RIL-010 生命周期（条件缓存、退避、预置摘要），控制面装配归 RIL-019 |
| 逻辑表达式（AND/OR/NOT） | ✅ | AND 平铺进规则条件列表；OR → `any`、NOT → `not`；OR/NOT 内嵌套 AND 拒绝+报告（需单条件表达）；未知子条件整条拒绝 |

## L4 其他配置

| 块 | 状态 | 说明 |
|---|---|---|
| `proxy-providers` | ✅ | 声明落入 `routing.proxy_providers`（type/url/path/interval/health-check；**`interval` 单位为秒**，原样带入，RIL-092）；组内 `use:` 引用成为 provider 成员；未声明引用被拒并报告。下载生命周期已随 RIL-010 落地（大小/并发上限、超时、取消、304 条件缓存、指数退避、可选预置摘要比对）；把下载接进 provider 节点库的控制面装配归 RIL-019，在此之前声明仍按引擎降级报告 |
| `dns` | 捕获不导入 | DNS 分流归本地策略层（RIL-020） |
| mixed-port / allow-lan / external-controller | 捕获不导入 | 入口所有权归用户主配置（RIL-016） |

## 单位

| 字段 | 单位 | 说明 |
|---|---|---|
| url-test `interval` | 秒 | 原样透传；`0`/缺省→300（RIL-092） |
| provider `interval` | 秒 | provider 落地时强制（RIL-009） |
| health-check `interval` | 秒 | |

## 端到端接管验收（RIL-095，Linux 候选）

范围：既有 Linux 转发链路上的订阅接管闭环
（`crates/rillane-runtime/tests/linux_takeover_acceptance.rs`）：

- **订阅样例真实接管/转发**：Clash 订阅样例（trojan + ss 节点、select +
  url-test 组）→ 导入 IR → 与本地兜底面合并（订阅 catch-all 不进运行面，
  `default_node` 归本地——RIL-016）→ 守护加载面（serde 往返 +
  `RillaneConfig::from_str`，守护进程同款解析入口）→ 运行时消费：
  SOCKS5 入口 CONNECT → 路由 → Direct 出口 → 回环回显逐字节一致
  （RIL-087 全链一致性的运行面延伸）。
- **interval 秒口径全链**：显式 `interval: 300` 逐面保持 300 秒——转换面
  （`UrlTestConfig.interval_secs`）→ 守护加载面（serde 往返不变）→ 运行时
  探测门（`Duration::from_secs` 消费）。不变 1 秒（RIL-092 的运行面回归锚）。
- **有损配置拒绝**：未知规则类型样本严格导入整体拒绝（拒绝信息即完整损失
  清单，绝不产出半份伪装成功的配置——RIL-093）；宽松模式损失显式可见
  （清单非空、被丢规则留名），合法节点照常产出；显式未知配置版本在守护
  加载面稳定拒绝（错误信息携带 `config.version.unknown` 稳定原因码，
  不猜语义）。
- **启停恢复**：运行时停止 → 同配置重建 → 转发恢复（第二组会话照常真实
  往返）；发布 journal 现役代际跨启停保留——守护状态面由发布协调器权威
  承载（RIL-019）。

不宣称：新 provider、完整 fallback、新 ScenarioPolicy 已交付（随各自
backlog 项落地）。
