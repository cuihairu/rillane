# 协议支持

Seep 是一个高性能的网络路由代理系统，支持多种主流的网络协议。

> **实现状态标注（2026-09 对照代码核实；2026-09-30 回填 P0-1..P0-4 落地状态；2026-10-02 回填 P1-4/P1-5/P2-1..P2-6 落地状态）**：本文协议语义描述为设计口径；每节开头的「状态」标注为代码实况。总体对照：
>
> | 能力 | 状态 | 落地去向 |
> |------|------|---------|
> | 入站 socks5 (CONNECT) / http (CONNECT) / mixed | 已实现（TCP） | — |
> | 入站 socks5 UDP ASSOCIATE | **已实现（2026-09，P0-2）**：RFC 1928 ASSOCIATE + 数据报中继；`udp:` 块缺省关闭 | — |
> | 出站 direct/socks5/http/shadowsocks/trojan/hysteria2/vless/wireguard（TCP） | 已实现 | — |
> | 出站 UDP 承载（direct/ss/wg） | **已实现（2026-09，P0-3）**；联调工具 = `seepctl udp-probe`（P0-5，退出码 0-4） | — |
> | mesh TCP/UDP envelope 二进制化（TCP 面 JSON→二进制 v2，接收侧嗅探兼容旧 JSON） | **已实现（2026-10，P2-6）**：UDP 面 P0-4 即二进制；TCP 面 `MeshEnvelope` 本步切换 | [mesh-envelope-binary.md](design/mesh-envelope-binary.md) |
| mesh UDP 多跳转发（UdpEnvelope over UDP 数据报） | **已实现（2026-09，P0-4）**：FULL/CACHED 跳缓存、exit per-flow socket、同端口双栈、明文门（chain+udp 未配加密构建期拒绝） | — |
> | UDP 观测与联调（`seep_udp_*` 指标族 / `/udp/stats` / `seepctl stats` UDP 段 / `udp-probe`） | **已实现（2026-09，P0-5）**：`/metrics` 恒渲染（开关关闭全零、端点不消失）+ 入口级 `udp_enabled` 覆盖 + `udp:` 配置全字段 | — |
> | 出站 UDP 承载（hy2） | 未实现（`hysteria2` 0.1.6 公开 API 无 UDP 出口；P0-4 已完成且**维持改判**） | V2（quinn 载具，未决） |
> | 出站 vmess 连接器 | 未实现（配置 schema 与订阅转换已支持，运行时构建期报错） | todo「VMess 出站」条目 |
> | hysteria v1 | 未实现 | 无计划（仅 hy2） |
> | 出站连接池 / TLS 会话恢复 | **已实现（2026-10，P1-5）**：`egress_pool:` 配置块 + 预建立/借出即消费池（trojan/http/vless + direct 选通）+ TLS 会话恢复（进程级共享 ClientConfig）+ `seep_pool_*`/`seep_tls_*` 指标 + `GET /egress/pool/stats` | — |
> | 包长填充混淆横切层（`FlowMiddleware` + chain `MeshEnvelope` 帧填充 + `seep_obfs_*` 指标族 + 分布检查脚本） | **已实现（2026-10，P1-4）**：fixed/bucket/range 三形态；单跳 TCP 无自有帧 no-op，UDP 数据报填充随 `UdpEnvelope` 预留钩子（V2） | [obfuscation-middleware.md](design/obfuscation-middleware.md) |
> | mesh 链路可观测（per-link RTT 分位 / 观测形丢包 / 切换原因账本） | **已实现（2026-10，P2-1）**：`seep_mesh_link_rtt_ms{from,to,quantile}` + `seep_mesh_link_loss_ratio{from,to}` + `seep_mesh_switch_total{reason}`（chain 启用时恒渲染）+ `GET /mesh/switches` 最近 100 事件；mesh 未启用三族与端点均缺席 | [mesh-link-observability.md](design/mesh-link-observability.md) |
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
> 状态：已实现 CONNECT 隧道（非 CONNECT 请求返回 405）。下列「支持方法」矩阵、Basic/Bearer 认证、请求/响应头修改、压缩均为**超前描述**——`IngressConfig::Http` 仅有 `bind` 字段，无认证与头处理逻辑。

- **协议版本**: HTTP/1.1
- **支持方法**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **认证方式**:
  - Basic 认证
  - Bearer Token 认证
- **特性**:
  - 支持 HTTP CONNECT 方法用于 HTTPS 代理
  - 支持请求/响应头修改
  - 支持压缩 (gzip, deflate)

### 混合代理 (Mixed)
> 状态：已实现协议自动识别与端口共享；认证未接入（`IngressConfig::Mixed` 无 auth 字段，认证列表为超前描述）。

- **描述**: 同时支持 SOCKS5 和 HTTP 协议
- **自动检测**: 根据请求特征自动识别协议类型
- **端口共享**: 在同一端口提供多种协议支持

## 出口协议 (Egress Protocols)

### 直连 (Direct)
> 状态：已实现 TCP 直连与 **UDP 承载（2026-09，P0-3，direct 载体）**；「自动 IP 版本选择 / Happy Eyeballs」未实现（现状为直接 `TcpStream::connect`）——超前描述。

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
  - Bearer Token 认证
- **特性**:
  - 支持代理链
  - 自动处理隧道 (CONNECT)

### Shadowsocks
> 状态：已实现 TCP（AEAD 加密由 `shadowsocks` crate 承载，可用方法以 crate 1.21 为准，`method` 为自由字符串、非法值在运行时报错）与 **UDP（2026-09，P0-3：`ShadowsocksUdpConnector`，方法校验提前至构建期、目标地址固定 R7 语义；完整解密往返需 shadowsocks-service 服务端联调，归 P0-5）**；插件系统（v2ray-plugin/obfs）与动态端口分配**未实现**——超前描述。

- **加密算法**:
  - AES-256-GCM
  - AES-128-GCM
  - ChaCha20-IETF-Poly1305
  - XChaCha20-IETF-Poly1305
- **支持协议**: TCP, UDP
- **特性**:
  - 插件系统支持 (v2ray-plugin, obfs)
  - 动态端口分配
  - 混淆和伪装

### VMess (V2Ray)
> 状态：**未实现出站连接器**。配置 schema（`EgressConfig::Vmess`）与订阅转换已支持，运行时构建期报错提示（见 todo「P2/P3 原遗留——VMess 出站」条目）；下列传输层细节（ws/h2/gRPC、SNI、ALPN）为规划口径，随该条目落地后更新。

- **版本**: VMess (V2Ray Protocol)
- **安全**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **传输层**:
  - TCP
  - WebSocket (WS)
  - HTTP/2
  - gRPC
- **路径配置**:
  - 自定义路径
  - Host 头部伪装
- **TLS 支持**:
  - TLS 1.2/1.3
  - SNI 伪装
  - ALPN 协商

### VLESS
> 状态：部分实现——uuid 认证 + TCP 直连 / WebSocket 传输（可叠 TLS/SNI/ALPN，`network: ws`）；**flow（如 xtls-rprx-vision）显式拒绝**（配置携带 flow 即报错）。「自动选择最优加密算法」「QoS 集成」「VLESS-Vision」系列与 H2/gRPC 传输为**超前描述**。

- **特点**: 轻量级协议，无状态加密
- **加密**: 自动选择最优加密算法
- **Flow 控制:
  - VLESS-Vision-Stream (实时流)
  - VLESS-Vision-UDP (UDP 支持)
- **传输层**: 同 VMess
- **特性**:
  - 更低的性能开销
  - 更好的 QoS 集成

### Trojan
> 状态：部分实现——TCP 原生 + 完整 TLS（SNI/证书校验/`skip_cert_verify`），「流量看起来像标准 HTTPS」的目标由 TLS 形态达成；WebSocket/gRPC 传输**未实现**——超前描述。

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
> 状态：**v1 未实现**（配置 schema、订阅转换与出站连接器均不支持），本节保留为背景资料。

- **协议**: 基于 QUIC 的高性能代理
- **版本**: Hysteria v1/v2
- **拥塞控制:
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
- **加密:
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

Seep 的模块化设计使得添加新协议变得简单：

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

> 状态：异步 I/O（tokio）已实现；**零拷贝与批量处理未实现**（描述为设计口径，无近期落地计划，降级登记 todo **P3-5**）；**连接池已实现**（2026-10，P1-5：预建立/借出即消费池 + TLS 会话恢复，`egress_pool:` 块，`seep_pool_reuse_ratio` 等指标可见——总拨号 ≈ 流数不降系每流消耗一条连接的结构约束，降总连接数归 V2 多路复用）；「智能选择/故障转移」部分成立——组策略选路（7 种策略）与 mesh chain 故障回退已实现；「会话保持」在 UDP 侧已成立（2026-09，P0-1 会话表：进程/五元组粘滞键 + 空闲/生命周期回收，`seep-core/src/udp/`），TCP 侧连接复用以池形态成立（2026-10，P1-5）。

### 协议层优化
- **零拷贝**: 使用 Rust 的所有权系统避免不必要的内存拷贝
- **连接池**: 复用 TCP 连接减少握手开销（**已实现**，2026-10 P1-5——池形态 = 预建立 + 借出即消费：命中借出的请求零拨号零握手，预热/补充拨号的握手被 TLS 会话恢复取代；总拨号 ≈ 流数不降为结构约束，降总连接数归 V2 多路复用）
- **异步 I/O**: 基于 Tokio 的非阻塞 I/O
- **批量处理**: 支持批量发送和接收

### 路由优化
- **智能选择**: 根据延迟、带宽、负载自动选择最优路径
- **会话保持**: 保持同一连接的路由一致性
- **故障转移**: 自动检测故障并切换备用路径
- **链路可观测**: per-link RTT p50/p95 分位、观测形丢包比、切换原因账本与计数（2026-10，P2-1，`/metrics` 三族 + `GET /mesh/switches`）
- **SLO 打分选路**: `latency` 策略以 p95 RTT/丢包为目标打分（`slo:` 门 + penalty），chain 侧 `slo_watch` 劣化自动切换且原因入账本（2026-10，P2-2，见 [slo-scoring.md](design/slo-scoring.md)）
- **TLS 指纹形态**: egress 四 TLS 变体 `tls_fingerprint: none|chrome|ios|safari`，池键/工厂键扩展（2026-10，P2-5，见 [tls-fingerprint.md](design/tls-fingerprint.md)）

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
Seep 与主流代理客户端完全兼容：

- **Windows**: Shadowsocks-windows, Clash, v2rayN, Qv2ray
- **macOS**: ShadowsocksX-NG, ClashX, V2RayU
- **Linux**: shadowsocks-libev, clash, v2ray-core
- **Android**: v2rayNG, Clash for Android, Shadowsocks Android
- **iOS**: Shadowrocket, Quantumult X, Surge, Stash

### 服务端互操作
- **V2Ray**: 完全兼容 VMess/VLESS 协议
- **Xray**: 支持所有 Xray 扩展功能
- **Shadowsocks**: 兼容所有标准 SS 实现
- **Trojan**: 标准 Trojan 协议实现

## 路线图

### 即将支持
- [ ] QUIC v2 支持
- [ ] HTTP/3 代理
- [ ] WireGuard v2
- [ ] 自定义协议插件系统
- [ ] 协议性能基准测试工具

### 未来计划
- [ ] QUIC 协议原生代理
- [ ] gRPC 协议支持
- [ ] eBPF 加速 (XDP)
- [ ] WebAssembly 协议插件
- [ ] 自适应协议选择

更多信息请参考 [架构总览](architecture.md)、[订阅指南](subscription.md)、[系统路由](networking.md)、[Mesh 指南](mesh.md) 与 [设计文档](design/positioning.md)。