# 配置参考

本页描述当前代码的配置 schema，不代表 v1 目标字段已经实现。定义以 `crates/rillane-config/src/lib.rs` 与各块校验为准，示例见仓库 `config/rillane.yaml`。[协议支持](PROTOCOLS.md)、[网络接管](networking.md)描述现有边界；[v1 设计](design/architecture-v1.md)描述下一阶段。必填表示没有 serde 缺省。

## 格式与加载

- 路径：`RILLANE_CONFIG` 环境变量（缺省 `config/rillane.yaml`）；rillaned 无 `--config` 旗标。
- 格式：按扩展名 hint 解析（`.yaml`/`.yml`/`.json`/`.toml`）；无 hint 依次尝试 YAML → JSON → TOML。
- `profile:` 场景预设**仅在文件加载入口展开**（缺省填充语义，见下节）；订阅转换等程序化构造不触发。
- 新增块（`udp:`/`network:`/`obfuscation:`/`egress_pool:`/`performance:`）均为 `deny_unknown_fields`：拼错子字段立刻报错；块缺席 = 整块关闭、行为零差异（`network.dns` 例外：块在场缺省启用）。

## 顶层块

| 块 | 类型 | 说明 |
|----|------|------|
| `control` | 必填 | 控制面 |
| `telemetry` | 必填 | 日志/指标/追踪 |
| `ingress` | 必填（可为空表） | 入站列表 |
| `egress` | 必填（可为空表） | 出站列表 |
| `routing` | 必填 | 默认节点/组/规则 |
| `udp` | 可选 | UDP 数据面（缺省关） |
| `network` | 可选 | TUN/系统路由/DNS 分流（缺省关） |
| `obfuscation` | 可选 | 混淆横切层（缺省关） |
| `egress_pool` | 可选 | 出站连接池（缺省关） |
| `probe` | 可选 | 主动探测授权（缺省 None = 整面关） |
| `profile` | 可选 | 场景预设 `proxy\|game\|web` |
| `performance` | 可选 | relay 缓冲参数 |

## control / telemetry

| 字段 | 必填 | 说明 |
|------|------|------|
| `control.api_bind` | ✓ | 控制面监听地址（如 `127.0.0.1:9090`）；rillanectl 缺省从它推导取数 URL |
| `control.uds_path` |  | Unix domain socket 路径（可选） |
| `control.admin_token` |  | 非空时控制面要求 `x-admin-token` 头；rillanectl 读取配置后自动附带 |
| `telemetry.log_level` | ✓ | 日志级别（如 `info`） |
| `telemetry.enable_metrics` | ✓ | `true` 时暴露 `GET /metrics`（Prometheus 文本） |
| `telemetry.enable_tracing` | ✓ | `true` 且环境 `RILLANE_CAPTURE_LOGS=1` 时提供 `GET /logs` |

## ingress[]（`type` 标签）

| type | 字段 |
|------|------|
| `socks5` | `bind`（必填）、`auth`?、`udp_enabled`? |
| `http` | `bind`（必填）、`auth`?、`bearer_tokens`? |
| `mixed` | `bind`（必填）、`auth`?、`udp_enabled`?、`bearer_tokens`?（仅 http 分支） |
| `shadowsocks` | `bind`（必填）、`method`（必填）、`password`（必填）、`udp_enabled`? |
| `trojan` | `bind`（必填）、`password`（必填）、`cert`（必填）、`cert_key`（必填）、`udp_enabled`? |
| `vless` | `bind`（必填）、`uuid`（必填）、`cert`（必填）、`cert_key`（必填）、`udp_enabled`? |
| `vmess` | `bind`（必填）、`uuid`（必填）、`udp_enabled`? |
| `hysteria2` | `bind`（必填）、`password`（必填）、`cert`（必填）、`cert_key`（必填）、`udp_enabled`? |
| `hysteria` | `bind`（必填）、`password`（必填）、`cert`（必填）、`cert_key`（必填）、`up_mbps`?、`down_mbps`?、`udp_enabled`? |
| `shadow_tls` | `bind`（必填）、`password`（必填）、`handshake_addr`（必填）、`target_addr`（必填） |

- `auth`：`[{username, password}]` 凭据表**非空即强制**（socks5 走 RFC 1929、http 走 `Proxy-Authorization: Basic` 407 挑战）；缺省/空表 = 匿名放行。
- `bearer_tokens`：`[token]` 明文比对（`Proxy-Authorization: Bearer`），与 `auth` 并列任一通过即放行；缺省不启用。
- `udp_enabled`：入口级 UDP 覆盖（SOCKS5 ASSOCIATE / mixed socks5 分支 / Shadowsocks 数据报面 / Trojan、VLESS、VMess、Hysteria2 UDP 关联）；缺省继承 `udp.enabled`，显式 `true/false` 覆盖该入口（显式 true 且全局关时构建期 WARN）。
- `trojan` `cert`/`cert_key`：证书与私钥为内联 PEM 字符串，装配期解析（垃圾材料在监听前报错）；口令为明文字符串，线上以 SHA224 十六进制哈希呈现。
- `vless` `uuid`：标准形 UUID，装配期解析（垃圾在监听前报错），线上以 16 字节恒时比对认证；`cert`/`cert_key` 同 trojan（内联 PEM 装配期解析）。服务端面仅普通 TLS + UUID 认证——Vision/REALITY 服务端组合另验，不设配置字段。
- `vmess` `uuid`：标准形 UUID，装配期解析（垃圾在监听前报错）；线上认证键为 `cmdKey = MD5(uuid ‖ 常量)` 派生，AEAD 封头即认证面——服务端不设 TLS 字段（裸 TCP 承载）也不设 security 旋钮（客户端逐连接自选 AES-128-GCM / ChaCha20-Poly1305；仅 AEAD 口径，`alter_id: 0`）。
- `hysteria2` `password`：HTTP/3 `/auth` 认证门恒时比对（233 放行 + `Hysteria-UDP` 声明）；QUIC 端点即监听面——`cert`/`cert_key` 为内联 PEM 装配期解析，ALPN 恒 `h3`。obfs/masquerade/ACME/Brutal 不交付不留字段。
- `hysteria`（v1）`password`/`up_mbps`/`down_mbps`：口令在控制流上恒时比对（版本字节 `0x03` 握手）；QUIC 端点即监听面——`cert`/`cert_key` 为内联 PEM 装配期解析，ALPN 恒 `hysteria`、TLS 最低 1.3。`up_mbps`/`down_mbps` 为服务端速率上限（分别封客户端下行/上行向；`None` = 不设上限——官方「>0 才施加」口径；`0` 装配期具名拒绝，不设上限用 `None` 表达）。obfs/wechat/faketcp 包层传输、ACL 路由、ACME、流量统计 API 不交付不留字段。
- `shadow_tls`（v2 载具，RIL-110）：`handshake_addr` 为伪装/握手站点（纯 TLS 中继 + 挑战应答），`target_addr` 为切换后流原样交付的内层协议入口 bind（通常 Shadowsocks 入口）。无 `udp_enabled` 字段——载具无 UDP 面。空口令与畸形地址装配期报错。

## egress[]（`type` 标签，13 变体）

| type | 字段（✓=必填） | 缺省 |
|------|----------------|------|
| `direct` | — | — |
| `socks5` | `server`✓ `port`✓ `username`? `password`? | — |
| `http` | `server`✓ `port`✓ `username`? `password`? `tls` `skip_cert_verify` `sni`? `tls_fingerprint`? | `tls: false` |
| `shadowsocks` | `server`✓ `port`✓ `method`✓ `password`✓ `plugin`? `plugin_opts`? | — |
| `shadowsocks-shadow-tls` | `server`✓ `port`✓ `method`✓ `password`✓ `shadow_tls`✓（`host`✓ `password`✓ `version`? `skip_cert_verify`?） | `shadow_tls.version`: 2 |
| `vmess` | `server`✓ `port`✓ `uuid`✓ `alter_id` `security` `network` `path`? `host`? `grpc_service_name`? `grpc_reuse`? `tls` `skip_cert_verify` `sni`? `alpn`? `tls_fingerprint`? | `alter_id: 0`、`security: auto`、`network: tcp`、`tls: false` |
| `vless` | 同 vmess 基础 + `flow`? `xhttp_mode`? `packet_encoding`? | `network: tcp`、`tls: false` |
| `trojan` | `server`✓ `port`✓ `password`✓ `network` `path`? `host`? `grpc_service_name`? `grpc_reuse`? `tls` `skip_cert_verify` `sni`? `alpn`? `tls_fingerprint`? | `network: tcp`、**`tls: true`** |
| `hysteria` | `server`✓ `port`✓ `password`✓ `protocol` `up_mbps`? `down_mbps`? `auth`? `auth_str`? `obfs`? `obfs_param`? `server_name`? `skip_cert_verify` `alpn`? | `protocol: udp` |
| `hysteria2` | `server`✓ `port`✓ `password`✓ `mport`? `obfs`? `obfs_param`? `server_name`? `skip_cert_verify` `alpn`? | — |
| `anytls` | `server`✓ `port`✓ `password`✓ `sni`? `skip_cert_verify` | — |
| `tuic` | `server`✓ `port`✓ `uuid`✓ `password`✓ `congestion_controller`? `server_name`? `skip_cert_verify` `alpn`? | `congestion_controller`：cubic |
| `wireguard` | `endpoint`✓ `private_key`✓ `public_key`✓ `address`✓ `allowed_ips`? `preshared_key`? `persistent_keepalive`? `listen_port`? `mtu`? `dns`? | — |

传输与构建期约束：

- `network` 取值：vless = `tcp | ws | httpupgrade | grpc | h2 | xhttp`，vmess = `tcp | ws | httpupgrade | grpc | h2`；trojan = `tcp | ws | grpc`（**无 h2/httpupgrade 口径**，白名单外构建期报错）。`grpc` 须配 `grpc_service_name`（线上路径 `/{name}/Tun`），grpc/h2 恒叠 TLS（`tls: false` 构建期拒绝）；`ws`/`httpupgrade`/`h2` 用 `path`/`host`（host 为字符串数组；订阅侧 `httpupgrade` 读 `httpupgrade-opts` 块，与 `ws-opts` 同形）；`xhttp`（仅 vless，RIL-129）恒叠 TLS（`tls: false` 构建期拒绝），`path`/`host` 同 ws 口径，`xhttp_mode` 限 `auto | packet-up | stream-one`（缺省 auto；白名单外构建期拒绝，未交付载具拨号期点名拒绝）。
- `grpc_reuse`（vmess/vless/trojan，RIL-130）：gRPC gun 流复用旋钮，仅 `network: grpc` 可携带——其余传输面携带构建期点名拒绝。字段 `max_connections`/`min_streams`/`max_streams`（均可选）对应订阅键 `grpc-opts.max-connections/min-streams/max-streams`；三键全缺 = 单连接全流复用（mihomo 客户端缺省）。`max_streams` 限单连接并发现役流数；多路复用连接租借随连接全生命周期持有（共享资源——不还池），对端死连接在下次获取时逐出并重拨。
- `packet_encoding`（仅 vless，RIL-130）：UDP 包编码 `raw | xudp | packetaddr`，缺省 `raw`；白名单外构建期拒绝。订阅侧平铺 `packet-encoding` 键双向转换。VMess 接受订阅键但仅 `raw` 可交付（xudp/packetaddr 载具未交付——转换期点名拒绝）。
- `security`（vmess）：`auto | aes-128-gcm | chacha20-poly1305`；`alter_id > 0` 与非 AEAD security 构建期拒绝。
- `flow`（vless）：拨号期校验——精确接受 `xtls-rprx-vision`（Vision 分帧；须 `network: tcp` + `tls: true`/REALITY，UDP 拒绝），其余取值拨号期拒绝（报错含节点名）。
- `method`（shadowsocks）：自由字符串，非法值构建期报错（以 shadowsocks crate 1.25 AEAD 方法集为准）；`plugin` 走 SIP003 桥（TCP 面经插件进程，UDP 面 plugin 模式判负）。
- `shadowsocks-shadow-tls`（RIL-110）：SS TCP 面架于 ShadowTLS v2 载具——SS `password` 与载具 `shadow_tls.password` 两侧独立；`shadow_tls.version` 仅接受缺席/2（v1/v3 构建期点名拒绝，不静默降级）；`skip_cert_verify` 与 vless/vmess 的 TLS 语义一致。载具无 UDP 面——组合节点在 `udp.enabled` 下被构建期能力扫描判负。订阅侧按 mihomo 插件形（`plugin: shadow-tls` + `plugin-opts`）双向转换。
- `hysteria`（v1）：TCP 请求流与 UDP 数据报面可用（自写面，RIL-109；官方 v1.3.5 core/cs 线镜像）——`protocol: udp` 以外的载具（wechat/faketcp）与 `obfs` 包层传输拨号期点名拒绝；节点在 UDP 可达集内时 UDP 面构建期同样判负；`up_mbps`/`down_mbps` 为 `0` 拨号期点名拒绝。`hysteria2` TCP 与 UDP 数据报面可用（UDP 限无 obfs 组合，服务端未声明 UDP 支持时点名拒绝）。
- `tuic`（v5）：TCP 流与 UDP 数据报面可用——仅 v5（v4 无代码路径，v4 线格式按名拒绝）；`congestion_controller` 非 `cubic` 拨号期点名拒绝（不静默降级）；认证无响应面——拒绝以流/QUIC 收束呈现。
- `tls_fingerprint`：`none | chrome | ios | safari`（对照表：`rillanectl tls-fingerprint`）；缺省不模拟。
- `address`（wireguard）：逗号分隔多 CIDR（如 `10.0.0.2/32,fd00::2/128`）；`listen_port: 0` = 自动。

## routing

```yaml
routing:
  default_node: direct-main        # 必填
  groups:                          # 必填（可为空表）
    - name: auto
      strategy: latency
      members:                     # 字符串简写 = 节点引用
        - direct-main
        - type: weighted_node      # 或 node | group | weighted_group
          name: trojan-node
          weight: 3
      slo:                        # 可选；质量值需核查来源
        p95_ms: 80
        loss_ratio: 0.02
        loss_penalty_ms: 1000     # 缺省 1000.0（ratio 增加 0.01 ≈ +10ms 罚分）
  rules:                           # 必填（可为空表）；先到先得
    - name: cn
      target: auto
      matches:                     # 同规则内多条件 = AND
        - type: geoip
          country: CN
```

- `strategy` 七种：`fixed | latency | random | bandwidth | weighted | consistent_hash | round_robin`。
- 路由条件 `type` 标签：`any{conditions}` / `not{condition}` / `domain_suffix{values}` / `domain_keyword{values}` / `domain_regex{patterns}` / `domain_full{values}` / `geoip{country}` / `geo_site{category}` / `ip_cidr{cidrs}` / `network{cidrs}` / `port{values}` / `process{values}`。进程名口径 `/proc/<pid>/comm` 截断 15 字节；**仅 TUN 入口有该注解**，其它 ingress 恒不命中。`geoip` 读 `routing.geoip_db`（MaxMind DB Country `.mmdb`，仅目标 IP 字面量）；`geo_site` 读 `routing.geosite_db`（v2fly `.dat`）。数据库路径缺席或加载失败时对应条件恒不命中。数据库相对路径按配置文件所在目录解析。
- `slo` 校验：`loss_ratio ∈ [0,1]`、`loss_penalty_ms ≥ 0`；`latency` 策略在 `slo:` 门内取最低分，chain 侧 `slo_watch` 劣化自动切换。

注意：现有 `loss_ratio` 字段保留兼容名称，部分链路来源实际为连接错误率；配置目标不能当成真实游戏丢包测量。需要连同来源/样本解释，v1 将区分指标类型。

## udp（缺省整块关；变更重启生效——会话状态不可热迁移）

| 字段 | 缺省 | 约束 |
|------|------|------|
| `enabled` | `false` | false 时入口对 ASSOCIATE 回 0x07 |
| `strict_udp_source` | `true` | 数据报源 IP 校验（防中继借用） |
| `session_idle_secs` | `180` | 会话空闲上限（秒） |
| `mapping_idle_secs` | `60` | 目标映射空闲上限（秒） |
| `max_sessions` | `4096` | 全局并发会话上界（满员拒新） |
| `sweep_interval_secs` | `15` | 回收扫描间隔（秒） |
| `max_mappings` | `256` | 会话内映射上界（溢出逐最久空闲） |
| `session_lifetime_secs` | 不限 | 设值须 ≥ `session_idle_secs` |
| `downlink_queue_depth` | `64` | 下行队列深度（满即丢 + 计数） |
| `max_associates` | `256` | 并发 ASSOCIATE 上限（超限回 0x01） |

`sweep_interval_secs`/`max_mappings`/`downlink_queue_depth`/`max_associates` 须 ≥ 1（构建期报错）。

## network（缺省 None = 整块关）

```yaml
network:
  mode: tun                      # 仅 tun（transparent/tap/hybrid 构建期拒）
  tun:
    name: rillane0                  # 缺省自动命名（tun%d）
    mtu: 1500                    # 须 ≥ 68
    ipv4: 10.255.0.1/24          # CIDR；进 auto-bypass
    ipv6: fd00::1/128            # 可选
    dns_servers: [1.1.1.1]       # 可选；network.dns.domestic 缺省回落此列表 +53
  routing:
    include: ["10.111.0.0/16"]   # 纳入 tun 的前缀（include 语义；负向即 bypass）
  dns:                           # 见下表；字段见本节
    enabled: true                # 块在场缺省 true
    domestic: ["223.5.5.5:53"]   # 空 = 回落 tun.dns_servers +53
    trusted: ["8.8.8.8:53"]      # ip:port；可信性由部署者保证
    rules:                       # 前导点 = suffix（.cn 收 x.cn 不收 cn），先到先得；pattern 重复报错
      - pattern: ".cn"
        group: domestic          # domestic | trusted
    default_group: domestic      # 未命中兜底
    anti_poison: off             # off | cross_check（须 trusted 非空）
    timeout_ms: 5000             # ≥1
    retries: 2
    cache:                       # 可选；None = 不缓存
      max_entries: 10000
      min_ttl: 60                # ≤ max_ttl
      max_ttl: 86400
      enable_negative_cache: true
      negative_ttl: 300          # ≥1
    listen_address: 127.0.0.1
    listen_port: 15353           # ≠0
  egress_fwmark: 0               # 0/缺省 = 不打 SO_MARK；非 0 须 root/CAP_NET_ADMIN（降级直连 WARN）
```

- `routing.include` CIDR 须显式 `addr/prefix` 形式（裸 IP 不收，主机路由写 `/32`）。
- 出站 fwmark 逃逸面（`egress_fwmark` ≠ 0）：planner 追加 `ip rule fwmark` + escape 表 100 默认路由，`rillanectl route apply/clear` 账目内管理。

## obfuscation（缺省 None = 整块关、零开销）

| 字段 | 缺省 | 说明 |
|------|------|------|
| `enabled` | `false` | false 容忍半成品配置 |
| `default_padding` / `default_timing` / `default_shaping` | — | 引用 `profiles` 中的名字；与同名内联**互斥** |
| `apply_to` | `chain` | `chain \| single \| all \| "egress:<name>"` |
| `middleware` | `[padding]` | 声明链顺序；可用名 `padding \| latency_probe \| timing \| shaping` |
| `profiles` | `{}` | 命名策略集 `{padding?, timing?, shaping?}`（未选中的坏 profile 也构建期拦） |
| `padding` / `timing` / `shaping` | — | 内联策略 |
| `plugins` | `[]` | WASM 插件 `{path, fuel?}`（fuel 缺省 1e8；enabled 时 path 必须存在） |

策略块校验：

- `padding`：`mode: fixed|bucket|range`——fixed 须 `target ≠ 0`；bucket 须 `buckets` 严格升序非空；range 须 `min ≤ max`；`max_overhead_ratio` 缺省 0.5、须 ≥ 0。
- `timing`：`mode: fixed|uniform`——fixed 须 `fixed_ms ≥ 1`；uniform 须 `min_ms ≤ max_ms ≤ max_delay_ms`；`max_delay_ms ≥ 1` 必填。
- `shaping`：`mode: interval`（唯一值）——`interval_ms ≥ 1`、`jitter_ms ≤ interval_ms`、`max_delay_ms ≥ interval_ms`。

`enabled: true` 时至少配一维策略（default_*/内联/plugins 任选），否则构建期报错。

## egress_pool（缺省 None = 整块关；`tls_resumption` 块存在即生效、独立于 enabled）

| 字段 | 缺省 | 约束 |
|------|------|------|
| `enabled` | `false` | 池总开关 |
| `tls_resumption` | `true` | 共享 ClientConfig + 会话缓存 |
| `max_idle_per_key` | `2` | ≥ 1 |
| `max_idle_global` | 取 runtime `connection_pool_size` | — |
| `low_watermark` | `1` | ≤ `max_idle_per_key` |
| `idle_timeout_secs` | `30` | 自入池起算 |
| `dial_timeout_secs` | `5` | TCP+TLS 全程 |
| `session_cache_size` | `256` | TLS 恢复开启时 ≥ 1 |
| `pre_dial_direct` | `false` | 须搭配 `enabled: true` |

快照观测：`GET /egress/pool/stats` 或 `rillanectl pool status`。

## probe（缺省 None = 整面关；targets 是闭合登记表，本版无 handshake 种类）

| 字段 | 缺省 | 约束 |
|------|------|------|
| `targets` | `[]` | 闭合目标登记表（空 = 无目标可探测）；逐条 `kind: dns`（`host`）、`kind: connect`（`addr`）、`kind: udp_echo`（`addr`）；`addr` 为 `ip:port`，装载期校验 |
| `limits.max_active` | `4` | ≥ 1；超额作业排队不丢弃 |
| `limits.job_timeout_ms` | `5000` | ≥ 1，单作业 deadline |
| `limits.udp_payload_max_bytes` | `512` | ≥ 1；超上限提交被拒 |
| `limits.byte_budget` | `65536` | ≥ 1；提交预留、完成按实发字节双向结算（退还 + 超耗） |

本块只存在于操作员本地配置：来源合并面是对象登记（`SourceSnapshot.objects`），顶层 `probe` 块结构上进不了合并面——不可信订阅文本永远无法扩探测范围。无 `probe` 块 = 探测面整体关闭：端点答 `503 probe.disabled`，无网络副作用。测量只含执行器实际观测（`failure` / `rtt_ms` / UDP 回显 `sent`/`replies`/`loss_ratio`/`payload_len`），不含任何机场内部路径推断（debug-and-mcp.md §3）。代理握手目标本版刻意不在配置面——egress connector 是流级 forward 面，无「拨号并测握手」形态。

端点/CLI 面：`GET /probe`、`POST /probe`、`GET /probe/result?id=`、`POST /probe/cancel?id=` 与 `rillanectl probe submit|cancel|result|list`（见 [cli.md](cli.md) § probe）。

## profile / performance

- `profile: proxy|game|web`：**缺省填充**展开——groups 空则建组（proxy=`auto`、game=`game-auto`(slo p95 80ms/loss 2%)、web=`web-auto`），rules 空则填模板（game=8 个游戏平台域 suffix、proxy/web=geoip CN），game 补 padding(bucket)+timing(10ms) 混淆、web 补 `egress_pool.enabled=true`；显式配置恒优先、再展开幂等。三选一即运行见 `examples/profile-*.yaml`。
- `performance.relay_buffer`：TCP relay 双向缓冲字节数，`1..=1048576`（缺省 8192）；进程级启动期一次，变更需重启。

## 环境变量

| 变量 | 缺省 | 说明 |
|------|------|------|
| `RILLANE_CONFIG` | `config/rillane.yaml` | rillaned 配置路径 |
| `RILLANE_CAPTURE_LOGS` | 关 | 配合 `telemetry.enable_tracing=true` 捕获进程日志供 `GET /logs`（`rillanectl diagnose`） |
| `RILLANE_MESH_ALLOW_PLAINTEXT` | 关 | TCP mesh 数据面明文放行（仅开发） |
| `RILLANE_MESH_UDP_ALLOW_PLAINTEXT` | 关 | UDP mesh 数据面明文放行（仅开发；与上门独立取或） |
| `RILLANE_MESH_MTLS` | `false` | mTLS 环境配置总开关（false/缺省 = 不从环境装配 mTLS） |
| `RILLANE_MESH_MTLS_CA/_CERT/_KEY` | — | 证书三件套路径 |
| `RILLANE_MESH_MTLS_SERVER_NAME` | `rillane` | rustls 验证 server_name |
| `RILLANE_MESH_MTLS_REQUIRE_CLIENT_AUTH` | `true` | 强制客户端证书校验（生产保持开启；绕过须 `RILLANE_MESH_ALLOW_NO_CLIENT_AUTH=1`） |
| `RILLANE_MESH_ALLOW_NO_CLIENT_AUTH` | 关 | 开发环境绕过客户端证书校验（与上门互斥的逃生门） |
| `RILLANE_MESH_MTLS_VERIFY_PEER_NODE_ID` | `true` | 校验对端证书 CN 与节点 ID 一致 |
| `RILLANE_MESH_MTLS_ALLOW_UNKNOWN_PEERS` | `false` | 允许未知节点证书 |
| `RILLANE_MESH_MTLS_REVOKED_NODES` | — | 内联撤销清单（CSV） |
| `RILLANE_MESH_MTLS_REVOKED_NODES_FILE` | — | 撤销清单文件路径（mtime 热加载；`GET /mtls/revoked` 可查生效面） |

SIP003 插件桥内部约定（`SS_LOCAL_*`/`SS_REMOTE_*`）不属配置面。mesh 证书工具链见 [mesh.md](mesh.md) 与 `rillanectl mtls --help`。
