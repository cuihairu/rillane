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
| 嵌套组引用 / `use:` | ⏳ | RIL-009（proxy-providers/use） |

## L3 规则

| 规则 | 状态 | 说明 |
|---|---|---|
| DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX | ✅ | 首匹配顺序保持 |
| IP-CIDR / IP-CIDR-6 | ✅ | 源/目的区分按换算表 |
| GEOIP / GEOSITE | ✅ | |
| MATCH（兜底） | ✅ | 必须保持最后 |
| PROCESS-NAME / 进程字段 | ❌ | 拒绝+报告；规范映射随 RIL-015 |
| RULE-SET / rule-providers | ❌ | 拒绝+报告；随 RIL-014 |
| 逻辑表达式（AND/OR/NOT） | ❌ | 拒绝+报告 |

## L4 其他配置

| 块 | 状态 | 说明 |
|---|---|---|
| `proxy-providers` | ❌（整块） | 解析期捕获并按未支持块报告（RIL-007）；provider 生命周期随 RIL-009/RIL-010 |
| `dns` | 捕获不导入 | DNS 分流归本地策略层（RIL-020） |
| mixed-port / allow-lan / external-controller | 捕获不导入 | 入口所有权归用户主配置（RIL-016） |

## 单位

| 字段 | 单位 | 说明 |
|---|---|---|
| url-test `interval` | 秒 | 原样透传；`0`/缺省→300（RIL-092） |
| provider `interval` | 秒 | provider 落地时强制（RIL-009） |
| health-check `interval` | 秒 | |
