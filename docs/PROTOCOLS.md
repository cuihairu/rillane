# 协议支持

Seep 是一个高性能的网络路由代理系统，支持多种主流的网络协议。

## 入口协议 (Ingress Protocols)

### SOCKS5 代理
- **协议版本**: SOCKS5 (RFC 1928)
- **认证方式**:
  - 无认证
  - 用户名/密码认证 (RFC 1929)
- **支持命令**:
  - CONNECT (TCP 连接)
  - UDP ASSOCIATE (UDP 代理)
- **TLS 支持**: 支持通过 SOCKS5 建立 TLS 连接

### HTTP 代理
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
- **描述**: 同时支持 SOCKS5 和 HTTP 协议
- **自动检测**: 根据请求特征自动识别协议类型
- **端口共享**: 在同一端口提供多种协议支持

## 出口协议 (Egress Protocols)

### 直连 (Direct)
- **描述**: 直接连接目标服务器，不经过代理
- **支持协议**: TCP, UDP
- **特性**:
  - 最小延迟
  - 自动 IP 版本选择 (IPv4/IPv6)
  - 支持 Happy Eyeballs 算法

### SOCKS5 出口
- **用途**: 通过外部 SOCKS5 代理转发流量
- **支持认证**:
  - 无认证
  - 用户名/密码认证
- **特性**:
  - 支持 IPv4/IPv6
  - 支持 UDP 中继

### HTTP 代理出口
- **用途**: 通过外部 HTTP 代理转发流量
- **支持版本**: HTTP/1.1, HTTP/1.0
- **认证方式**:
  - Basic 认证
  - Bearer Token 认证
- **特性**:
  - 支持代理链
  - 自动处理隧道 (CONNECT)

### Shadowsocks
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

### 协议层优化
- **零拷贝**: 使用 Rust 的所有权系统避免不必要的内存拷贝
- **连接池**: 复用 TCP 连接减少握手开销
- **异步 I/O**: 基于 Tokio 的非阻塞 I/O
- **批量处理**: 支持批量发送和接收

### 路由优化
- **智能选择**: 根据延迟、带宽、负载自动选择最优路径
- **会话保持**: 保持同一连接的路由一致性
- **故障转移**: 自动检测故障并切换备用路径

## 安全特性

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

更多信息请参考 [配置文档](CONFIGURATION.md) 和 [开发指南](DEVELOPMENT.md)。