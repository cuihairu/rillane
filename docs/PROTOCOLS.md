# 协议支持

Seep 是一个网络路由代理系统，支持多种主流的网络协议。

> **实现状态标注（2026-09 对照代码核实；2026-09-30 回填 P0-1..P0-4 落地状态；2026-10-02 回填 P1-4/P1-5/P2-1..P2-6 落地状态；2026-10-04 回填 P2-7 落地状态；2026-10-10 回填 gRPC/h2 传输落地状态）**：本文协议语义描述为设计口径；每节开头的「状态」标注为代码实况。总体对照：
>
> | 能力 | 状态 | 落地去向 |
> |------|------|---------|
> | 入站 socks5 (CONNECT) / http (CONNECT) / mixed | 已实现（TCP） | — |
> | 入站 socks5 UDP ASSOCIATE | **已实现（2026-09，P0-2）**：RFC 1928 ASSOCIATE + 数据报中继；`udp:` 块缺省关闭 | — |
> | 出站 direct/socks5/http/shadowsocks/trojan/hysteria2/vless/wireguard（TCP） | 已实现 | — |
> | 出站 UDP 承载（direct/ss/wg） | **已实现（2026-09，P0-3）**；联调工具 = `seepctl udp-probe`（P0-5，退出码 0-4） | — |
> | mesh TCP/UDP envelope 二进制化（TCP 面 JSON→二进制 v2，接收侧嗅探兼容旧 JSON） | **已实现（2026-10，P2-6）**：UDP 面 P0-4 即二进制；TCP 面 `MeshEnvelope` 本步切换 | [mesh-envelope-binary.md](design/mesh-envelope-binary.md) |
> | mesh UDP 多跳转发（UdpEnvelope over UDP 数据报） | **已实现（2026-09，P0-4）**：FULL/CACHED 跳缓存、exit per-flow socket、同端口双栈、明文门（chain+udp 未配加密构建期拒绝） | — |
> | UDP 观测与联调（`seep_udp_*` 指标族 / `/udp/stats` / `seepctl stats` UDP 段 / `udp-probe`） | **已实现（2026-09，P0-5）**：`/metrics` 恒渲染（开关关闭全零、端点不消失）+ 入口级 `udp_enabled` 覆盖 + `udp:` 配置全字段 | — |
> | 出站 UDP 承载（hy2） | 未实现（`hysteria2` 0.1.6 公开 API 无 UDP 出口；P0-4 已完成且**维持改判**） | V2（quinn 载具，未决） |
> | 出站 vmess 连接器 | **已实现（2026-10）**：VMess AEAD 认证头（authID 时间窗+防重放）+ AES-128-GCM/ChaCha20-Poly1305 分块流数据面，tcp（可叠 TLS）/ws（可叠 TLS）/gRPC（恒叠 TLS）/h2（恒叠 TLS）；`alter_id=0` 限定，UDP 承载未实现 | todo「VMess 出站」条目 |
> | hysteria v1 | **出站连接器未实现**（配置 schema 与订阅转换已支持，构建期报错） | 无计划（仅 hy2） |
> | 出站连接池 / TLS 会话恢复 | **已实现（2026-10，P1-5）**：`egress_pool:` 配置块 + 预建立/借出即消费池（trojan/http/vless/vmess + direct 选通）+ TLS 会话恢复（进程级共享 ClientConfig）+ `seep_pool_*`/`seep_tls_*` 指标 + `GET /egress/pool/stats` | — |
> | 包长填充混淆横切层（`FlowMiddleware` + chain `MeshEnvelope` 帧填充 + `seep_obfs_*` 指标族 + 分布检查脚本） | **已实现（2026-10，P1-4）**：fixed/bucket/range 三形态；单跳 TCP 无自有帧 no-op，UDP 数据报填充随 `UdpEnvelope` 预留钩子（V2） | [obfuscation-middleware.md](design/obfuscation-middleware.md) |
> | mesh 链路可观测（per-link RTT 分位 / 观测形丢包 / 切换原因账本） | **已实现（2026-10，P2-1）**：`seep_mesh_link_rtt_ms{from,to,quantile}` + `seep_mesh_link_loss_ratio{from,to}` + `seep_mesh_switch_total{reason}`（chain 启用时恒渲染）+ `GET /mesh/switches` 最近 100 事件；mesh 未启用三族与端点均缺席 | [mesh-link-observability.md](design/mesh-link-observability.md) |
> | mesh UDP 防重放 + 撤销可见性 | **已实现（2026-10-04，P2-7）**：UDP 面 v2 帧流序号 + per-(flow,dir) 64 位滑窗（`replay_dropped` 计数进 `/udp/stats` 与 `/metrics`）+ 撤销文件载体 mtime 热加载 + 运行期观测（`GET /mtls/revoked`、`seepctl mtls revoke status`）；OCSP/CA 直连撤销查询与端到端 MAC 归 V2 | [mesh-advanced-security.md](design/mesh-advanced-security.md) |
> | timing/shaping 扰动（启动抖动 + 写网格归一） | **已实现（2026-10，P2-4）**：`TimingMiddleware` handle 内 sleep（fixed/uniform，max_delay_ms 闸门）、`ShapingMiddleware` 包装 `flow.io` 为 `PacedIo`（interval 网格 + jitter，读侧不包装）；注解可观测 `seep.obfs.timing`/`seep.obfs.shaping`；game 预设接线演示 | [obfuscation-timing-shaping.md](design/obfuscation-timing-shaping.md) |
> | SLO 打分选路（组策略 `slo:` 门 + penalty 评分 + chain 侧 `slo_watch` 劣化切换） | **已实现（2026-10，P2-2）**：`latency` 策略真数据在场时 = 门内最低分（score = p95 + loss × penalty）；chain watcher 越门即切换，账本 `reason="slo_degraded"`；无真数据部署行为不变；`slo_watch` YAML 面归 P2-3 | [slo-scoring.md](design/slo-scoring.md) |
> | 场景 profile 预设（`profile: proxy\|game\|web` 配置期展开） | **已实现（2026-10，P2-3）**：缺省填充语义（显式恒优先，运行期零分支）；game = SLO 目标 + 域名模板 + bucket 混淆；web = 连接池；`examples/profile-*.yaml` 三选一即运行 | [scenario-profiles.md](design/scenario-profiles.md) |
> | obfs/salamander 插件 | 未实现（salamander 伪态不在本仓路线） | V2 备选 |
> | timing/shaping 扰动 | **已实现（2026-10，P2-4）** | [obfuscation-timing-shaping.md](design/obfuscation-timing-shaping.md) |
> | 客户端 TLS 指纹形态（none/chrome/ios/safari 预设 + 池键/工厂键扩展） | **已实现（2026-10，P2-5）**：按 egress `tls_fingerprint` 配置选择，QUIC 面不在内 | [tls-fingerprint.md](design/tls-fingerprint.md) |
>
> 各节标注中的「超前」指：本文保留了设计目标描述，但当前代码不包含对应实现。

## 入口协议 (Ingress Protocols)

### SOCKS5 代理
> 状态：已实现 CONNECT（含用户名/密码认证，`IngressConfig::Socks5`）与 **UDP ASSOCIATE（2026-09，P0-2）**——cmd 0x01/0x03 分派（`seep-protocols/src/inbound/socks5.rs`），ASSOCIATE 服务/数据报头编解码/准入在 `seep-core/src/udp/associate.rs`，认证用户名进粘滞键，mixed 入口同享；`udp:` 配置块缺省关闭（关闭时 0x03 回 0x07）。详见 [udp-dataplane.md](design/udp-dataplane.md) §2 与 [udp-relay-path.md](design/udp-relay-path.md) §2。

- **协议版本**: SOCKS5 (RFC 1928)
- **认证方式**:
  - 无认证
  - 用户名/密码认证 (RFC 1929)
- **支持命令**:
  - CONNECT (TCP 连接)
  - UDP ASSOCIATE (UDP 代理)
- **TLS 支持**: 支持通过 SOCKS5 建立 TLS 连接

### HTTP 代理
> 状态：已实现 CONNECT 隧道（非 CONNECT 请求返回 405）+ 入站 Basic 认证（`IngressConfig::Http.auth` 凭据表非空即强制：缺 `Proxy-Authorization` 头或凭据不符统一应 `407 Proxy Authentication Required` + `Proxy-Authenticate: Basic`，空表/缺省 = 匿名放行；仅 CONNECT 面校验，非 CONNECT 请求先过认证再应 405）+ **Bearer Token 认证（2026-10-10：`IngressConfig::Http.bearer_tokens` 令牌表——`Proxy-Authorization: Bearer <token>` 明文比对，与 Basic 并列任一通过即放行，407 挑战按已配置 scheme 通告；Mixed 入口 http 分支同语义）**。下列「支持方法」矩阵、请求/响应头修改、压缩仍为**超前描述**（CONNECT 隧道数据面为裸字节流，无 HTTP 头/压缩可改）。

- **协议版本**: HTTP/1.1
- **支持方法**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **认证方式**:
  - Basic 认证（已实现，`auth` 字段 + `Proxy-Authorization` 校验）
  - Bearer Token 认证（已实现，`bearer_tokens` 字段 + `Proxy-Authorization: Bearer` 校验）
- **特性**:
  - 支持 HTTP CONNECT 方法用于 HTTPS 代理
  - 支持请求/响应头修改（未实现，超前描述——需全量转发代理数据面，本入口仅 CONNECT 隧道）
  - 支持压缩 (gzip, deflate)（未实现，超前描述——同上）

### 混合代理 (Mixed)
> 状态：已实现协议自动识别与端口共享；`IngressConfig::Mixed.auth` 已接线——socks5 分支强制 RFC 1929（仅提供无认证法时回 0xFF）、http 分支 Basic 认证（407 拒绝），空表/缺省 = 两分支均匿名放行，语义同 Socks5/Http；`bearer_tokens` 同 Http（仅 http 分支）。

- **描述**: 同时支持 SOCKS5 和 HTTP 协议
- **自动检测**: 根据请求特征自动识别协议类型
- **端口共享**: 在同一端口提供多种协议支持

## 出口协议 (Egress Protocols)

### 直连 (Direct)
> 状态：已实现 TCP 直连（多候选 **RFC 8305 Happy Eyeballs 竞速，2026-10-07**：IPv6 优先双栈交错、250ms 错峰补位、失败即刻补位、首个成功胜出）与 **UDP 承载（2026-09，P0-3，direct 载体）**——「自动 IP 版本选择 / Happy Eyeballs」超前描述已清账。

- **描述**: 直接连接目标服务器，不经过代理
- **支持协议**: TCP, UDP
- **特性**:
  - 最小延迟
  - 自动 IP 版本选择 (IPv4/IPv6)
  - 支持 Happy Eyeballs 算法

### SOCKS5 出口
> 状态：已实现 TCP 转发与用户名/密码认证；「UDP 中继」**未实现**且不在 S1 范围（见 [udp-dataplane.md](design/udp-dataplane.md) §3.5）——超前描述。

- **用途**: 通过外部 SOCKS5 代理转发流量
- **支持认证**:
  - 无认证
  - 用户名/密码认证
- **特性**:
  - 支持 IPv4/IPv6
  - 支持 UDP 中继

### HTTP 代理出口
> 状态：已实现 CONNECT 隧道、Basic 认证、TLS+SNI（`EgressConfig::Http`）；「代理链」未作为 egress 参数实现——多跳经 mesh chain 表达（见 [mesh.md](mesh.md)）。

- **用途**: 通过外部 HTTP 代理转发流量
- **支持版本**: HTTP/1.1, HTTP/1.0
- **认证方式**:
  - Basic 认证
  - ~~Bearer Token 认证~~（Bearer 为入站能力——见 HTTP 入站节，出口不支持）
- **特性**:
  - ~~支持代理链~~（未实现——多跳经 mesh chain 表达，见状态注记）
  - 自动处理隧道 (CONNECT)

### Shadowsocks
> 状态：已实现 TCP（AEAD 加密由 `shadowsocks` crate 承载，可用方法以 crate 1.25 为准，`method` 为自由字符串、非法值构建期报错）与 **UDP（2026-09，P0-3：`ShadowsocksUdpConnector`，方法校验提前至构建期、目标地址固定 R7 语义；完整解密往返需 shadowsocks-service 服务端联调，归 P0-5）**与 **SIP003 插件桥（2026-10-07：`plugin`/`plugin_opts` 字段——TCP 数据面经插件进程桥接，SS_LOCAL_*/SS_REMOTE_* 环境变量约定 + 本地端口就绪探测 + 子进程随连接收尾 kill_on_drop；UDP 面不经插件（SIP003 仅定义 TCP），plugin 模式下 UDP 能力判负由 scan_udp_capability 构建期报错；订阅面 clash 导入按换算表转 SIP003（obfs→`obfs-local` mode/host→`obfs=`/`obfs-host=`、v2ray-plugin 原名键值透传 bool true→裸 flag，其余插件名拒导宁缺毋滥）、导出侧无 Clash 等价表达仅 degrade 提示；插件端到端需真实插件二进制环境，单测覆盖 spawn 失败/端口探测两态）**；动态端口分配**未实现**——超前描述。

- **加密算法**:
  - AES-256-GCM
  - AES-128-GCM
  - ChaCha20-IETF-Poly1305
  - XChaCha20-IETF-Poly1305
- **支持协议**: TCP, UDP
- **特性**:
  - 插件系统支持 (v2ray-plugin, obfs)
  - 动态端口分配（未实现，超前描述——SIP004 服务端特性，本仓 Shadowsocks 仅出站客户端）
  - 混淆和伪装

### VMess (V2Ray)
> 状态：**已实现出站连接器（2026-10）**——VMess AEAD 认证头（authID = AES-ECB(unix 秒‖随机‖CRC32)，服务端 ±120s 时间窗 + 防重放）+ 分块流数据面（chunk-stream|chunk-masking|global-padding；SHAKE128(方向 IV) 出掩码与 padding 长度，**每块先抽 padding 再抽 mask**，块 nonce = 计数器‖IV[2..12] 递增）；KDF/请求头/封套/SHAKE 抽取序以 Xray-core kdf.go 原文实跑真值向量逐字节钉死（Go 1.27.1 对拍，V0–V16）。security 支持 `auto`/`aes-128-gcm`/`chacha20-poly1305`（xray AEAD 口径，legacy `alter_id>0` 与 none/zero 构建期拒绝）；传输 tcp（可叠 TLS/SNI/ALPN/指纹）、ws（可叠 TLS，upgrade 失败 stale 一次性重拨）与 gRPC（2026-10：`network: grpc` + `grpc_service_name`，恒叠 TLS + ALPN h2，POST `/{service}/Tun` 单流隧道，请求头‖首块合入首条 gRPC 消息，5 字节长度前缀帧，16MiB 消息上限；池键携带 ALPN h2，隧道握手失败 stale 一次性重拨；订阅侧 clash `grpc-opts` 导入导出）。h2 传输已实现（2026-10：`network: h2` + `path`/`host`，恒叠 TLS + ALPN h2，POST `{path}` 单流隧道，`:authority` = host 首值 → sni → server，请求体/响应体即双方向裸字节流；请求头写入流后 `tokio::io::split` 复用既有分块流 relay；池键携带 ALPN h2，SNI 链 sni → host 首值 → server，隧道握手失败 stale 一次性重拨；订阅侧 clash `h2-opts` 导入导出）；UDP 承载未实现（构建期扫描即报错）。

- **版本**: VMess (V2Ray Protocol)——AEAD 认证头（Xray-core 同源线形 authID‖sealedLen‖connNonce‖sealedHeader）
- **安全**: auto / AES-128-GCM / ChaCha20-Poly1305（legacy MD5 认证与 none/zero 已随 xray 删除）
- **传输层**:
  - TCP（可叠 TLS）
  - WebSocket (WS)（可叠 TLS）
  - gRPC（恒叠 TLS，`grpc_service_name`）
  - HTTP/2 (h2)（恒叠 TLS，`path`/`host`，裸字节流单流隧道）
- **路径配置**:
  - 自定义路径（ws path，自动补 `/` 前缀）
  - Host 头部伪装（`host` 首值优先，回落 sni/server）
- **TLS 支持**:
  - TLS 1.2/1.3
  - SNI 伪装
  - ALPN 协商
  - 客户端 TLS 指纹形态（`tls_fingerprint`，P2-5）

### VLESS
> 状态：部分实现——uuid 认证 + TCP 直连 / WebSocket / gRPC 传输（tcp/ws 可叠 TLS/SNI/ALPN，`network: ws`；gRPC 2026-10：`network: grpc` + `grpc_service_name`，恒叠 TLS + ALPN h2，POST `/{service}/Tun` 单流隧道，请求头作为首条 gRPC 消息，应答头 `[ver][opt_len][opt]` 跨消息抽取，客户端 EOF → 零长 DATA + END_STREAM 收尾；池键携带 ALPN h2，隧道握手失败 stale 一次性重拨；订阅侧 clash `grpc-opts` 导入导出）；h2 传输已实现（2026-10：`network: h2` + `path`/`host`，恒叠 TLS + ALPN h2，POST `{path}` 单流隧道，请求/响应体即双方向裸字节流，隧道建好后与 tcp 臂同构 `copy_bidirectional`；池键携带 ALPN h2，SNI 链 sni → host 首值 → server，隧道握手失败 stale 一次性重拨；订阅侧 clash `h2-opts` 导入导出）；**flow（如 xtls-rprx-vision）显式拒绝**（构建期即拦，RuntimeBuilder 装配报错并列节点名，与 `forward()` 口径同为 `is_some()` 即拒）。「QoS 集成」「VLESS-Vision」系列为**超前描述**。

- **特点**: 轻量级协议，无内建加密（明文承载，机密性由 TLS 传输层负责）
- **Flow 控制**:
  - VLESS-Vision-Stream (实时流)
  - VLESS-Vision-UDP (UDP 支持)
- **传输层**: 同 VMess
- **特性**:
  - 更低的性能开销（相比 VMess 少一层协议内加密）

### Trojan
> 状态：部分实现——TCP 原生 + 完整 TLS（SNI/证书校验/`skip_cert_verify`/指纹），「流量看起来像标准 HTTPS」的目标由 TLS 形态达成；WebSocket 传输已实现（trojan-go 惯例：ws 恒叠 TLS，请求头作为首个 binary 帧，无独立应答头；池路径 upgrade 失败 stale 一次性重拨）；gRPC 传输已实现（2026-10：`network: grpc` + `grpc_service_name`，恒叠 TLS + ALPN h2，POST `/{service}/Tun` 单流隧道，请求头作为首条 gRPC 消息，5 字节长度前缀帧，16MiB 消息上限；池键携带 ALPN h2，握手失败 stale 一次性重拨；订阅侧 clash `grpc-opts` 导入导出）；h2 传输不实现（trojan 白名单仅 tcp/ws/grpc，`network: h2` 构建期拒绝）。

- **协议**: 基于 TLS 伪装的代理协议
- **TLS 特性**:
  - 完整 TLS 1.3 握手
  - 证书验证
  - SNI 伪装
- **传输层**:
  - TCP (原生)
  - WebSocket
  - gRPC
- **安全性**:
  - 流量看起来像标准 HTTPS
  - DPI 抗审查能力强

### Hysteria
> 状态：**v1 出站连接器未实现**（配置 schema 与订阅转换已支持，构建期报错「暂不支持的出口类型」），本节保留为背景资料。

- **协议**: 基于 QUIC 的高性能代理
- **版本**: Hysteria v1/v2
- **拥塞控制**:
  - BBR (Bottleneck Bandwidth and RTT)
  - Cubic
  - 自定义算法
- **认证**:
  - 密码认证
  - Base64/Str 字符串
- **特性**:
  - UDP 首包优化
  - 自适应速率控制
  - 低延迟传输

### Hysteria2
> 状态：部分实现——TCP over QUIC、密码认证、`mport`/`server_name`/`alpn`/`skip_cert_verify` 配置生效（`hysteria2` crate 承载）；拥塞控制算法选择、**UDP 中继/首包优化未实现**——V1 核查结论（2026-09）：`hysteria2` 0.1.6 公开 API 仅 connect/tcp_connect、`quic_connection` 为 pub(crate)，无 UDP 出口，非静默缩水，移 P0-4 的改判在 **P0-4 完成时维持**（2026-09，todo P0-4 §0.1-③——hy2 UDP 终态 = V2，载具 quinn 未决，见 todo.md P0-3/P0-4 条目与 [udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)）；salamander 混淆未实现（配置无该字段；包长填充横切层已落 P1-4，timing/shaping 扰动已落 P2-4，salamander 归 V2 备选）。

- **协议**: Hysteria 的改进版本
- **改进**:
  - 更简单的协议设计
  - 更好的移动网络支持
  - 降低 CPU 使用率
- **加密**:
  - AES-128-GCM
  - ChaCha20-Poly1305
- **认证**:
  - 密码或字符串
  - 支持混淆 (salamander)

### WireGuard
> 状态：部分实现——TCP 流量经系统 WireGuard 接口转发（`address`/`allowed_ips`/`preshared_key`/`persistent_keepalive`/`mtu`/`dns` 配置生效，需系统 WG 接口与相应权限）；「内核级实现」指依赖系统 WG，seep 自身不做加解密；**UDP 承载已实现（2026-09，P0-3：`WireguardUdpConnector`——`allowed_ips` 解析后预检（不在集合 → 拆映射重路由）+ MTU 上限 `mtu-80`，仍走系统 WG 接口路径）**，见 [udp-relay-path.md](design/udp-relay-path.md)。

- **协议**: 快速现代 VPN
- **加密**:
  - ChaCha20-Poly1305
  - AES-GCM
- **密钥交换**: Curve25519
- **特性**:
  - Layer 3 (IP) 隧道
  - 完整前向保密
  - 简化的配置
- **性能**:
  - 内核级实现
  - 极低的 CPU 开销

## 协议扩展

Seep 的模块化设计使新协议以 `EgressConnector` 实现挂入：

1. **实现协议 trait**: 创建新的协议处理器
2. **注册协议**: 在配置文件中声明新协议
3. **路由集成**: 协议自动参与路由决策

### 添加新协议示例

```rust
use async_trait::async_trait;
use seep_core::{Flow, FlowRouter};

pub struct MyProtocol;

#[async_trait]
impl EgressConnector for MyProtocol {
    fn name(&self) -> &'static str {
        "my-protocol"
    }

    async fn forward(&self, flow: Flow) -> Result<FlowReport> {
        // 实现协议转发逻辑
        todo!()
    }
}
```

## 性能优化

> 状态：异步 I/O（tokio）已实现；**零拷贝/批量收发已按范围落地**（2026-10，P3-5：relay 缓冲参数化 `performance.relay_buffer`（缺省 8192 零差异）+ 16 处 relay 点 `copy_bidirectional_with_sizes` + mesh 帧写 vectored 合一；基准与范围裁决见 [performance-io.md](design/performance-io.md)——内核态 splice 与 UDP recvmmsg/sendmmsg 为范围外，如实登记）；**连接池已实现**（2026-10，P1-5：预建立/借出即消费池 + TLS 会话恢复，`egress_pool:` 块，`seep_pool_reuse_ratio` 等指标可见——总拨号 ≈ 流数不降系每流消耗一条连接的结构约束，降总连接数归 V2 多路复用）；「智能选择/故障转移」部分成立——组策略选路（7 种策略）与 mesh chain 故障回退已实现；「会话保持」在 UDP 侧已成立（2026-09，P0-1 会话表：进程/五元组粘滞键 + 空闲/生命周期回收，`seep-core/src/udp/`），TCP 侧连接复用以池形态成立（2026-10，P1-5）。

### 协议层优化
- **零拷贝**: 使用 Rust 的所有权系统避免不必要的内存拷贝（**已实现（范围）**，2026-10 P3-5——用户态中继无法全免拷贝（TLS 终结、middleware 链语义），落地形态为减少拷贝与 syscall：`performance.relay_buffer` 双向缓冲可配（8K→256K 基准中位吞吐 +67%）、16 处 relay 点 `copy_bidirectional_with_sizes`、mesh 帧写两段合一 vectored 提交（4 KiB 帧基准快约 26%，TLS 段 rustls 无 vectored 自动回落等价现状）；内核态 splice 判出界（middleware 链包装破坏 fd 语义），见 [performance-io.md](design/performance-io.md)）
- **连接池**: 复用 TCP 连接减少握手开销（**已实现**，2026-10 P1-5——池形态 = 预建立 + 借出即消费：命中借出的请求零拨号零握手，预热/补充拨号的握手被 TLS 会话恢复取代；总拨号 ≈ 流数不降为结构约束，降总连接数归 V2 多路复用）
- **异步 I/O**: 基于 Tokio 的非阻塞 I/O（已实现）
- **批量处理**: 支持批量发送和接收（**未实现**——UDP recvmmsg/sendmmsg 批量收发判出界：现网无高包率场景证据，libc 直调 + tokio 托管 fd 兼容复杂度不值；待真机高包率场景以基准驱动重评，见 [performance-io.md](design/performance-io.md) §2-D4）

### 路由优化
- **智能选择**: 根据延迟、带宽、负载自动选择最优路径
- **会话保持**: 保持同一连接的路由一致性
- **故障转移**: 自动检测故障并切换备用路径
- **链路可观测**: per-link RTT p50/p95 分位、观测形丢包比、切换原因账本与计数（2026-10，P2-1，`/metrics` 三族 + `GET /mesh/switches`）
- **SLO 打分选路**: `latency` 策略以 p95 RTT/丢包为目标打分（`slo:` 门 + penalty），chain 侧 `slo_watch` 劣化自动切换且原因入账本（2026-10，P2-2，见 [slo-scoring.md](design/slo-scoring.md)）
- **TLS 指纹形态**: egress 四 TLS 变体 `tls_fingerprint: none|chrome|ios|safari`，池键/工厂键扩展（2026-10，P2-5，`seepctl tls-fingerprint` 打印预设 shape_material 对照表，见 [tls-fingerprint.md](design/tls-fingerprint.md)）

## 安全特性

> 状态：mesh 层 CA 轮换/双信任窗口/最小撤销列表已实现（[mesh.md](mesh.md)）；「自动定期更新密钥」「多因素认证」「JWT/Token 管理」**未实现**——超前描述；「TLS 伪装」中 Trojan/VLESS+TLS 形态已实现，「协议混淆/域前置」：包长填充横切层已落 P1-4 + timing/shaping 扰动已落 P2-4（见 [positioning.md](design/positioning.md) §2.4 现状注记、todo P2-4/P2-5）。

### 加密支持
- **端到端加密**: 所有协议支持强加密
- **密钥轮换**: 自动定期更新密钥
- **前向安全**: 支持完全前向保密

### 认证机制
- **多因素认证**: 支持多种认证方式组合
- **证书验证**: 完整的证书链验证
- **Token 管理**: JWT 和其他 token 格式支持

### 流量伪装
- **TLS 伪装**: 让流量看起来像正常 HTTPS
- **协议混淆**: 使用插件隐藏协议特征
- **域前置**: 通过 CDN 隐藏真实服务器

## 配置示例

```yaml
ingress:
  - name: socks5-proxy
    type: socks5
    bind: "0.0.0.0:1080"
    auth:
      - username: user1
        password: pass1

egress:
  - name: vmess-server
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789abc"
    alter_id: 0
    security: auto
    network: ws
    path: /path
    host: ["vmess.example.com"]
    tls: true
    sni: vmess.example.com
```

## 兼容性

### 客户端兼容性
Seep 入口与主流代理客户端互通（SOCKS5/HTTP CONNECT 口径；入口不支持的方法返回 405）：

- **Windows**: Shadowsocks-windows, Clash, v2rayN, Qv2ray
- **macOS**: ShadowsocksX-NG, ClashX, V2RayU
- **Linux**: shadowsocks-libev, clash, v2ray-core
- **Android**: v2rayNG, Clash for Android, Shadowsocks Android
- **iOS**: Shadowrocket, Quantumult X, Surge, Stash

### 服务端互操作
- **V2Ray**: 核心 VMess/VLESS 面互通（tcp/ws/gRPC/h2；VLESS flow 不支持，见各节状态行）
- **Xray**: VMess AEAD（tcp/ws/gRPC/h2）+ VLESS（tcp/ws/gRPC/h2，无 flow）互通；flow 不支持
- **Shadowsocks**: AEAD 方法互通（方法集以 `shadowsocks` crate 1.25 为准，非法 `method` 构建期报错）
- **Trojan**: 标准 Trojan 协议实现（TCP 原生 + TLS；ws/gRPC 传输已实现）

## 路线图

### 即将支持
- [ ] QUIC v2 支持
- [ ] HTTP/3 代理
- [ ] WireGuard v2
- [x] 自定义协议插件系统（WASM 加载器已落地，2026-10-04 P3-2——[plugin-loader.md](design/plugin-loader.md)）
- [x] 协议性能基准测试工具（已落地，2026-10 P3-5——criterion 基准：relay 8K–256K 缓冲对照中位吞吐与帧写 vectored 两段合一对照，数字与噪声口径见 [performance-io.md](design/performance-io.md) §5）

### 未来计划
- [ ] QUIC 协议原生代理（未排期——hy2 出站 UDP 承载随 V2 quinn 载具裁决，见 [design/udp-mesh-dataplane.md](design/udp-mesh-dataplane.md)）
- [x] gRPC 协议支持（2026-10：trojan/vless/vmess 出站 `network: grpc` 单流隧道）
- [ ] eBPF 加速 (XDP)
- [x] WebAssembly 协议插件（wasmtime 动态加载 + 示例插件，同 P3-2——[plugin-loader.md](design/plugin-loader.md)）
- [ ] 自适应协议选择

更多信息请参考 [架构总览](architecture.md)、[订阅指南](subscription.md)、[系统路由](networking.md)、[Mesh 指南](mesh.md) 与 [设计文档](design/positioning.md)。