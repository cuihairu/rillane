# rillanectl CLI 参考

本页只描述现有 CLI；旗标、默认值和可用命令以 `rillanectl <命令> --help` 为准。[订阅](subscription.md)、[Mesh](mesh.md)、[网络接管](networking.md)为现状参考。v1 的 Explain/Trace/Probe/MCP 仍是[目标设计](design/debug-and-mcp.md)，不能当成当前命令执行。

## 全局选项

| 选项 | 说明 |
|------|------|
| `-c, --config <CONFIG>` | 配置文件路径（缺省 `config/rillane.yaml`）；控制面命令用它读 `control.api_bind` / `control.admin_token` |
| `-V, --version` | 打印版本 |

## 取数口径

- **控制面命令**（`stats` / `group` / `switches` / `nodes` / `chain` / `pool` / `subscription` / `route` / `diagnose` / `mtls revoke status`）：HTTP 取 `rillaned` 控制面；`control.admin_token` 非空时附 `x-admin-token` 头，未配置即匿名请求。
  - `--endpoint` 语义分两型（易混）：
    - **完整 URL 型**（替换整个目标 URL，须含路径）：`stats`（缺省 `http://{api_bind}/flows`）、`group`（`/routing/stats`）、`switches`（`/mesh/switches`）、`pool status`（`/egress/pool/stats`）、`nodes`（`/nodes`）；
    - **base URL 型**（仅替换 base，路径内部拼接）：`chain`、`subscription`、`route`、`diagnose`、`trace`、`mtls revoke status`。
- **离线命令**（`check` / `show` / `profile` / `tls-fingerprint` / `import-rules` / `udp-probe` / `import-clash` / `export-clash` / `mtls` 证书工具）：不经控制面，只读本地文件（`udp-probe` 例外——直接连 SOCKS5 入口实测）。
- 无 `rillanectl reload` 子命令：rillaned 启动一次性读配置，运行期热更新仅由订阅刷新与控制面端点驱动（见 [architecture.md](architecture.md) 热更新口径）。

## 控制面 REST 端点总表

按 `apps/rillaned/src/control_plane.rs` 路由表对账（2026-10-11）。除注明外均需 `x-admin-token` 头（配置 `control.admin_token` 非空时）。

| 方法 | 路径 | 说明 | rillanectl 对应 |
|------|------|------|--------------|
| GET | `/health` | 存活探针 | — |
| GET | `/nodes` | mesh 节点快照 | `nodes` |
| GET | `/flows` | 入口→出口累计流量统计 | `stats` |
| GET | `/udp/stats` | UDP 会话/中继统计快照 | `stats`（UDP 段同取） |
| GET | `/routing/stats` | 组实时质量（成员数据源/p95/质量 ratio（按来源解释）/SLO 门/当前选点） | `group` |
| GET | `/mesh/switches` | 链路切换账本（最近 100 次） | `switches` |
| GET | `/egress/pool/stats` | 出站连接池快照 | `pool status` |
| GET | `/dns/stats` | DNS 服务统计快照 | —（仅 REST） |
| GET | `/plugins/stats` | 插件统计 | —（仅 REST） |
| GET | `/runtime/stats` | runtime 统计 | —（仅 REST） |
| GET | `/runtime/config` | 当前生效配置快照 | —（仅 REST） |
| GET | `/events` | 事件日志（最近 N 行） | —（仅 REST） |
| GET | `/logs` | 最近日志（需 `RILLANE_CAPTURE_LOGS=1`） | `diagnose`（采集） |
| GET | `/metrics` | Prometheus 文本 | —（Prometheus 抓取） |
| GET | `/mtls/revoked` | 撤销列表生效面（mtime/条目/加载错误） | `mtls revoke status` |
| GET | `/chains/stats` | 链路统计 | `chain stats` |
| GET | `/chains/{chain_id}` | 链路详情 | `chain get` |
| POST | `/chains/dry-run` | 链路预检 | `chain dry-run` |
| POST | `/chains` | 创建链路（同 session_id 复用） | `chain create` |
| DELETE | `/chains/{chain_id}` | 终止链路 | `chain terminate` |
| GET | `/subscriptions` | 订阅列表与状态 | `subscription list` |
| POST | `/subscriptions` | 添加订阅 | `subscription add` |
| POST | `/subscriptions/refresh` | 全量刷新 | `subscription refresh` |
| POST | `/subscriptions/{name}/refresh` | 单订阅刷新 | `subscription refresh <NAME>` |
| DELETE | `/subscriptions/{name}` | 删除订阅 | `subscription remove` |
| POST | `/network/route/apply` | 应用路由规则（幂等） | `route apply` |
| POST | `/network/route/clear` | 撤销已应用规则 | `route clear` |
| GET | `/network/route/status` | 路由应用状态 | `route status` |
| POST | `/mesh/nodes/register` | 节点注册（mesh 面内部） | —（节点间） |
| POST | `/mesh/link-states` | 链路状态上报（mesh 面内部） | —（节点间） |
| GET | `/trace/flows` | 逐连接轨迹分页列表（可过滤；版本化信封 `schema_version=1`） | `trace list` |
| GET | `/trace/flow?id=` | 单流完整轨迹或显式缺席答复（`found:false` + 稳定码） | `trace flow` |
| GET | `/trace/events?id=&from_seq=&limit=` | 事件增量读取（未知/缺席 ID → 404 + 稳定码） | `trace events` |

## 命令总览

| 命令 | 说明 | 面 |
|------|------|----|
| `check` | 校验配置文件 | 离线 |
| `show` | 打印配置摘要 | 离线 |
| `stats` | 查看流量统计（尾部附 UDP 段：会话/中继字节/丢弃/过期/mesh 面） | 控制面 `/flows` |
| `group` | 查看组实时质量：成员数据源、p95/质量 ratio（按来源解释）、SLO 门判定、latency 组当前选点 | 控制面 `/routing/stats` |
| `switches` | 查看链路切换账本（最近 100 次事件，含前后路径与原因） | 控制面 `/mesh/switches` |
| `profile` | 生成场景骨架配置（`proxy\|game\|web`） | 离线 |
| `tls-fingerprint` | TLS 指纹形态预设对照表（none/chrome/ios/safari 的 shape_material 四维导出） | 离线 |
| `import-rules` | 批量导入 geosite/chnroutes 文本规则源为路由/DNS 规则 YAML | 离线 |
| `udp-probe` | UDP ASSOCIATE 联调探测（最小 RFC 1928 客户端；退出码 0-4） | 直连 SOCKS5 入口 |
| `nodes` | 查看 mesh 节点注册信息 | 控制面 `/nodes` |
| `chain` | 链路管理（dry-run/create/get/terminate/stats） | 控制面 |
| `pool` | 出站连接池快照（status） | 控制面 `/egress/pool/stats` |
| `import-clash` | Clash YAML → Rillane 配置（离线预览） | 离线 |
| `export-clash` | Rillane 配置 → Clash YAML 回导出（离线） | 离线 |
| `subscription` | 订阅管理（list/add/remove/refresh） | 控制面 |
| `route` | 系统路由管理（apply/clear/status） | 控制面 + 本机 ip 命令 |
| `diagnose` | 一键诊断信息收集（生成诊断目录） | 控制面 + 本机快照 |
| `trace` | 逐连接轨迹查询（list / 单流详情 / 事件增量；显式缺席 = 退出码 2） | 控制面 `/trace/*` |
| `mtls` | Mesh mTLS 证书工具（init-ca/issue/rotate/bundle-ca/rotate-ca/revoke） | 离线（revoke status 例外走控制面） |

## 各命令旗标

### 控制面取数

```bash
rillanectl stats   [--endpoint <完整URL，含 /flows>]
rillanectl group   [--endpoint <完整URL，含 /routing/stats>]
rillanectl switches [--endpoint <完整URL，含 /mesh/switches>]
rillanectl nodes   [--endpoint <完整URL，含 /nodes>]
rillanectl pool status [--endpoint <完整URL，含 /egress/pool/stats>]
```

`stats` 的 UDP 段与 `/flows` 同 base 推导：`--endpoint` 覆盖仅作用于 `/flows` 一侧。

### check / show

无旗标；配置经全局 `-c` 指定。`show` 打印摘要（控制面监听地址 + 入口/出口计数）；`check` 输出「配置有效」。

### profile

```bash
rillanectl profile <proxy|game|web> [--out <路径>]   # 缺省打印 stdout
```

### tls-fingerprint

无旗标；打印四预设的 `shape_material` 形态串对照表（版本|套件|群|签名方案）。

### import-rules

```bash
rillanectl import-rules <SOURCE> --target <TARGET> [--face routing|dns] [--name <NAME>] [--out <路径>]
```

- `<SOURCE>`：文件路径或 http(s) URL（v2fly 文本清单行集）；
- `--target`：routing 面 = 组/出口名；dns 面 = `domestic | trusted`；
- `--face`：缺省 `routing`；
- `--name`：规则名，缺省取源文件名去扩展名；
- `--out`：缺省 stdout（可管道）；跳过清单走 **stderr**。

### udp-probe

```bash
rillanectl udp-probe --socks5 <地址> --host <主机> --port <端口> --payload-hex <hex>
                  [--timeout <3s>] [--user <U>] [--pass <P>]
```

`--timeout` 支持 `s/ms/m` 单位；退出码 0-4 语义见 `--help`。

### chain

```bash
rillanectl chain dry-run   --source <S> --target <T>
rillanectl chain create    --source <S> --target <T> [--session-id <UUID>]   # 同 session_id 复用链路
rillanectl chain get       <CHAIN_ID>
rillanectl chain terminate <CHAIN_ID>
rillanectl chain stats
```

`chain` 组的 `--endpoint` 为 **base URL 型**。

### import-clash / export-clash

```bash
rillanectl import-clash <url|file> [-o config/clash_import.yaml]   # -o 同义 --output
rillanectl export-clash <rillane配置> [-o config/clash_export.yaml]   # 末尾打印降级/跳过清单
```

### subscription

```bash
rillanectl subscription list
rillanectl subscription add <NAME> <URL> [--type <T>] [--enabled true|false]
                       [--refresh-interval <分>] [--timeout <秒>]
                       [--header k=v]... [--user-agent <UA>]
rillanectl subscription remove <NAME>
rillanectl subscription refresh [NAME]    # 不指定则刷新全部
```

`--header` 可多次传入。`--endpoint` 为 base URL 型。

### route

```bash
rillanectl route apply   [--dry-run]   # 幂等重放配置中的 include 目标；--dry-run 仅打印 ip 命令
rillanectl route clear               # 逆序清理所有已应用规则
rillanectl route status              # 设备态 + 已应用步骤表
```

`--endpoint` 为 base URL 型。apply/clear 需 root 或 `CAP_NET_ADMIN`。

### diagnose

```bash
rillanectl diagnose [--endpoint <base URL>] [--output <目录>] [--scope safe|full|raw] [--no-redact] [--no-local]
```

按范围选择包内容（默认 `safe`）：`safe` 不采集订阅列表/运行配置/完整日志并对配置脱敏；`full` 全量采集但每个出口都剥除秘密（配置秘密键、订阅 URL 凭证、日志 key=value 秘密对与 PEM 块）；`raw` 不脱敏落盘——清单标注 `ai_upload_policy: do-not-upload`（仅供本地人工排查）。`--no-redact` 等价 `--scope raw`；`--no-local` 跳过本机快照（路由/DNS/接口）。`meta.json` 恒记录范围、需人工复核文件清单与上传政策——rillanectl 不做任何自动上传；诊断包不自动构成可安全上传 AI 的材料，分享前先复核。

### trace

```bash
rillanectl trace list   [--state active|closed] [--origin stream|association] [--generation <G>] [--offset N] [--limit N] [--json]
rillanectl trace flow   <id> [--json]
rillanectl trace events <id> [--from-seq N] [--limit N] [--json]
```

逐连接轨迹查询（RIL-060，走内核逐连接查询服务）。`--endpoint` 为 base URL 型（默认 `http://{api_bind}`）。以真实 flow ID 锚定——`stats`/`/flows` 展示的 ingress/egress 聚合键在本面不作为流 ID 命中。缺席显式分码（`query.flow.unknown` / `query.tracing.disabled` / `collector.flow.evicted|expired|active_limit|sampled_out|drained`）；缺席答复恒携带采集计数快照与固定说明「无记录 ≠ 应用未发包」——绝不把缺席报告为「未发包」。默认文本输出；`--json` 原样打印版本化信封（`schema_version=1`）。

退出码：`0` 查询有答；`1` 连接或用法错误；`2` 显式缺席（`trace flow` 答复 `found:false`，或 `trace events` 收到 404 错误信封）。

### mtls

```bash
rillanectl mtls init-ca    --out-dir <目录> [--common-name rillane-mesh-ca] [--valid-days 3650]
rillanectl mtls issue      --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <目录>
                        [--server-name rillane] [--valid-days 365]
rillanectl mtls rotate     --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <目录>
                        [--no-backup] [--valid-days 365]    # 默认备份 *.bak.<epoch>；新连接自动生效
rillanectl mtls bundle-ca  --ca-cert <pem>... --out-path <bundle.pem>
rillanectl mtls rotate-ca  --old-ca-cert <pem> --out-dir <目录>
                        [--common-name rillane-mesh-ca-next] [--valid-days 3650]   # 输出旧+新双信任 bundle
rillanectl mtls revoke list   [--file <路径>]
rillanectl mtls revoke add    --file <路径> --node-id <ID>
rillanectl mtls revoke remove --file <路径> --node-id <ID>
rillanectl mtls revoke status [--endpoint <base URL>]   # GET /mtls/revoked：分发—生效—校验闭环的「生效」观测
```

撤销列表文件逐行 `node_id`（忽略空行/`#` 注释/逗号分隔）；推荐路径与 `RILLANE_MESH_MTLS_REVOKED_NODES_FILE` 一致。
