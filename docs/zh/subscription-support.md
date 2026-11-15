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
| select | ✅ | 成员顺序保持 |
| url-test | ✅ | `url` 映射；**`interval` 单位是秒**（官方缺省 300；`0`/缺省→300，RIL-092）；导出侧同样按秒产出 |
| fallback | ⚠️ | 降级 Random，点名进损失清单；按序回退保真随 RIL-012 |
| relay | ⚠️ | 降级 ConsistentHash，点名进损失清单；链式保真归 RIL-013 决策 |
| load-balance | ✅ | 分配算法审计归 RIL-013 |
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
