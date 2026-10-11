# seepctl CLI 参考

> 状态：按 `apps/seepctl/src/main.rs` clap 定义对账（2026-10-11，18 个顶层子命令）· 本文只描述已实现行为；旗标/缺省值以 `seepctl <命令> --help` 实际输出为准 · 相关：[订阅指南](subscription.md) · [Mesh & Chain](mesh.md) · [系统路由与网络接管](networking.md)

## 全局选项

| 选项 | 说明 |
|------|------|
| `-c, --config <CONFIG>` | 配置文件路径（缺省 `config/seep.yaml`）；控制面命令用它读 `control.api_bind` / `control.admin_token` |
| `-V, --version` | 打印版本 |

## 取数口径

- **控制面命令**（`stats` / `group` / `switches` / `nodes` / `chain` / `pool` / `subscription` / `route` / `diagnose` / `mtls revoke status`）：HTTP 取 `seepd` 控制面；`control.admin_token` 非空时附 `x-admin-token` 头，未配置即匿名请求。
  - `--endpoint` 语义分两型（易混）：
    - **完整 URL 型**（替换整个目标 URL，须含路径）：`stats`（缺省 `http://{api_bind}/flows`）、`group`（`/routing/stats`）、`switches`（`/mesh/switches`）、`pool status`（`/egress/pool/stats`）、`nodes`（`/nodes`）；
    - **base URL 型**（仅替换 base，路径内部拼接）：`chain`、`subscription`、`route`、`diagnose`、`mtls revoke status`。
- **离线命令**（`check` / `show` / `profile` / `tls-fingerprint` / `import-rules` / `udp-probe` / `import-clash` / `export-clash` / `mtls` 证书工具）：不经控制面，只读本地文件（`udp-probe` 例外——直接连 SOCKS5 入口实测）。
- 无 `seepctl reload` 子命令：seepd 启动一次性读配置，运行期热更新仅由订阅刷新与控制面端点驱动（见 [architecture.md](architecture.md) 热更新口径）。

## 控制面 REST 端点总表

按 `apps/seepd/src/control_plane.rs` 路由表对账（2026-10-11）。除注明外均需 `x-admin-token` 头（配置 `control.admin_token` 非空时）。

| 方法 | 路径 | 说明 | seepctl 对应 |
|------|------|------|--------------|
| GET | `/health` | 存活探针 | — |
| GET | `/nodes` | mesh 节点快照 | `nodes` |
| GET | `/flows` | 入口→出口累计流量统计 | `stats` |
| GET | `/udp/stats` | UDP 会话/中继统计快照 | `stats`（UDP 段同取） |
| GET | `/routing/stats` | 组实时质量（成员数据源/p95/丢包/SLO 门/当前选点） | `group` |
| GET | `/mesh/switches` | 链路切换账本（最近 100 次） | `switches` |
| GET | `/egress/pool/stats` | 出站连接池快照 | `pool status` |
| GET | `/dns/stats` | DNS 服务统计快照 | —（仅 REST） |
| GET | `/plugins/stats` | 插件统计 | —（仅 REST） |
| GET | `/runtime/stats` | runtime 统计 | —（仅 REST） |
| GET | `/runtime/config` | 当前生效配置快照 | —（仅 REST） |
| GET | `/events` | 事件日志（最近 N 行） | —（仅 REST） |
| GET | `/logs` | 最近日志（需 `SEEP_CAPTURE_LOGS=1`） | `diagnose`（采集） |
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

## 命令总览

| 命令 | 说明 | 面 |
|------|------|----|
| `check` | 校验配置文件 | 离线 |
| `show` | 打印配置摘要 | 离线 |
| `stats` | 查看流量统计（尾部附 UDP 段：会话/中继字节/丢弃/过期/mesh 面） | 控制面 `/flows` |
| `group` | 查看组实时质量：成员数据源、p95/丢包、SLO 门判定、latency 组当前选点 | 控制面 `/routing/stats` |
| `switches` | 查看链路切换账本（最近 100 次事件，含前后路径与原因） | 控制面 `/mesh/switches` |
| `profile` | 生成场景骨架配置（`proxy\|game\|web`） | 离线 |
| `tls-fingerprint` | TLS 指纹形态预设对照表（none/chrome/ios/safari 的 shape_material 四维导出） | 离线 |
| `import-rules` | 批量导入 geosite/chnroutes 文本规则源为路由/DNS 规则 YAML | 离线 |
| `udp-probe` | UDP ASSOCIATE 联调探测（最小 RFC 1928 客户端；退出码 0-4） | 直连 SOCKS5 入口 |
| `nodes` | 查看 mesh 节点注册信息 | 控制面 `/nodes` |
| `chain` | 链路管理（dry-run/create/get/terminate/stats） | 控制面 |
| `pool` | 出站连接池快照（status） | 控制面 `/egress/pool/stats` |
| `import-clash` | Clash YAML → Seep 配置（离线预览） | 离线 |
| `export-clash` | Seep 配置 → Clash YAML 回导出（离线） | 离线 |
| `subscription` | 订阅管理（list/add/remove/refresh） | 控制面 |
| `route` | 系统路由管理（apply/clear/status） | 控制面 + 本机 ip 命令 |
| `diagnose` | 一键诊断信息收集（生成诊断目录） | 控制面 + 本机快照 |
| `mtls` | Mesh mTLS 证书工具（init-ca/issue/rotate/bundle-ca/rotate-ca/revoke） | 离线（revoke status 例外走控制面） |

## 各命令旗标

### 控制面取数

```bash
seepctl stats   [--endpoint <完整URL，含 /flows>]
seepctl group   [--endpoint <完整URL，含 /routing/stats>]
seepctl switches [--endpoint <完整URL，含 /mesh/switches>]
seepctl nodes   [--endpoint <完整URL，含 /nodes>]
seepctl pool status [--endpoint <完整URL，含 /egress/pool/stats>]
```

`stats` 的 UDP 段与 `/flows` 同 base 推导：`--endpoint` 覆盖仅作用于 `/flows` 一侧。

### check / show

无旗标；配置经全局 `-c` 指定。`show` 打印监听口、控制面、路由/组/出站摘要。

### profile

```bash
seepctl profile <proxy|game|web> [--out <路径>]   # 缺省打印 stdout
```

### tls-fingerprint

无旗标；打印四预设的 `shape_material` 形态串对照表（版本|套件|群|签名方案）。

### import-rules

```bash
seepctl import-rules <SOURCE> --target <TARGET> [--face routing|dns] [--name <NAME>] [--out <路径>]
```

- `<SOURCE>`：文件路径或 http(s) URL（v2fly 文本清单行集）；
- `--target`：routing 面 = 组/出口名；dns 面 = `domestic | trusted`；
- `--face`：缺省 `routing`；
- `--name`：规则名，缺省取源文件名去扩展名；
- `--out`：缺省 stdout（可管道）；跳过清单走 **stderr**。

### udp-probe

```bash
seepctl udp-probe --socks5 <地址> --host <主机> --port <端口> --payload-hex <hex>
                  [--timeout <3s>] [--user <U>] [--pass <P>]
```

`--timeout` 支持 `s/ms/m` 单位；退出码 0-4 语义见 `--help`。

### chain

```bash
seepctl chain dry-run   --source <S> --target <T>
seepctl chain create    --source <S> --target <T> [--session-id <UUID>]   # 同 session_id 复用链路
seepctl chain get       <CHAIN_ID>
seepctl chain terminate <CHAIN_ID>
seepctl chain stats
```

`chain` 组的 `--endpoint` 为 **base URL 型**。

### import-clash / export-clash

```bash
seepctl import-clash <url|file> [-o config/clash_import.yaml]   # -o 同义 --output
seepctl export-clash <seep配置> [-o config/clash_export.yaml]   # 末尾打印降级/跳过清单
```

### subscription

```bash
seepctl subscription list
seepctl subscription add <NAME> <URL> [--type <T>] [--enabled true|false]
                       [--refresh-interval <分>] [--timeout <秒>]
                       [--header k=v]... [--user-agent <UA>]
seepctl subscription remove <NAME>
seepctl subscription refresh [NAME]    # 不指定则刷新全部
```

`--header` 可多次传入。`--endpoint` 为 base URL 型。

### route

```bash
seepctl route apply   [--dry-run]   # 幂等重放配置中的 include 目标；--dry-run 仅打印 ip 命令
seepctl route clear               # 逆序清理所有已应用规则
seepctl route status              # 设备态 + 已应用步骤表
```

`--endpoint` 为 base URL 型。apply/clear 需 root 或 `CAP_NET_ADMIN`。

### diagnose

```bash
seepctl diagnose [--endpoint <base URL>] [--output <目录>] [--no-redact] [--no-local]
```

缺省对配置做脱敏（token/password/private_key 等）；`--no-local` 跳过本机快照（路由/DNS/接口）。

### mtls

```bash
seepctl mtls init-ca    --out-dir <目录> [--common-name seep-mesh-ca] [--valid-days 3650]
seepctl mtls issue      --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <目录>
                        [--server-name seep] [--valid-days 365]
seepctl mtls rotate     --node-id <ID> --ca-cert <pem> --ca-key <pem> --out-dir <目录>
                        [--no-backup] [--valid-days 365]    # 默认备份 *.bak.<epoch>；新连接自动生效
seepctl mtls bundle-ca  --ca-cert <pem>... --out-path <bundle.pem>
seepctl mtls rotate-ca  --old-ca-cert <pem> --out-dir <目录>
                        [--common-name seep-mesh-ca-next] [--valid-days 3650]   # 输出旧+新双信任 bundle
seepctl mtls revoke list   [--file <路径>]
seepctl mtls revoke add    --file <路径> --node-id <ID>
seepctl mtls revoke remove --file <路径> --node-id <ID>
seepctl mtls revoke status [--endpoint <base URL>]   # GET /mtls/revoked：分发—生效—校验闭环的「生效」观测
```

撤销列表文件逐行 `node_id`（忽略空行/`#` 注释/逗号分隔）；推荐路径与 `SEEP_MESH_MTLS_REVOKED_NODES_FILE` 一致。
