# 协议支持（当前实现）

本页记录现有协议边界。未来协议与兼容工作以 [v1 设计](design/architecture-v1.md)和根目录 `todo.md` 为准；未列为可用的能力不能由配置模型或脚手架推断。

## 入站

| 类型 | 当前支持 | 限制 |
|---|---|---|
| SOCKS5 | CONNECT、用户名/密码、UDP ASSOCIATE | UDP 需启用 `udp.enabled`；入口还可单独关闭 UDP |
| HTTP | CONNECT、Basic / Bearer 认证 | 普通非 CONNECT 请求不提供完整 HTTP 转发；不是缓存或 MITM |
| mixed | 同端口识别 SOCKS5 / HTTP | 继承对应协议的限制 |
| Shadowsocks | TCP 流 + 同端口 UDP 数据报；method/password 构建期校验（与出站同口径） | SIP003 插件服务端面未交付；UDP 需启用 `udp.enabled`；入口还可单独关闭 UDP |
| Trojan | TLS 上的 TCP 流，SHA224 恒时口令哈希认证；UDP 关联复用同一 TLS 流（无独立 UDP socket） | 证书/私钥内联 PEM 装配期解析；UDP 需启用 `udp.enabled`；入口还可单独关闭 UDP |
| TUN | Linux TCP/UDP 共享数据面 | 其他平台完整接管仍需实现/验收 |

## 出站

| 类型 | 当前承载 | 重要限制 |
|---|---|---|
| direct | TCP、UDP | 需正确设置旁路；TCP socket 的 fwmark 不代表所有 UDP 拨号都已防环 |
| SOCKS5 | TCP 隧道 + 出站 UDP ASSOCIATE（RFC 1928 §6/§7，来源验证 + FRAG≠0 丢弃） | HTTP CONNECT 仅 TCP 隧道 |
| AnyTLS | TCP（TLS 承载，会话复用）；UDP-over-TCP（UoT） | 订阅 alpn/client-fingerprint 不入 IR（转换报告点名） |
| Shadowsocks | TCP、UDP；TCP 可用 SIP003 插件桥 | 插件模式不承载 UDP；算法以实际依赖/校验为准 |
| Trojan | TCP/TLS，可叠加支持的传输；gRPC gun 连接复用（复用旋钮） | 不据此承诺 UDP 或所有上游扩展 |
| VLESS / VMess | TCP、WebSocket、HTTPUpgrade、gRPC（gun 连接复用，镜像对端验收）、HTTP/2 传输；XHTTP 传输（**仅 VLESS**，TLS1.3/H2 承载，packet-up/stream-one 两模式，镜像对端验收）；REALITY（TCP 承载，客户端面）；XTLS Vision 分帧（tcp+TLS/REALITY 承载，镜像对端验收）；UDP（**VLESS**：raw/xudp/packetaddr 包编码，镜像对端验收；**VMess**：raw 单目标面） | 传输/加密配置需通过构建校验；XHTTP 须 `network: xhttp` 且恒叠 TLS，`xhttp_mode` 限 `auto | packet-up | stream-one`（其余拨号期点名拒绝，stream-up/H3/H1.1 载具未交付）；REALITY 须 `network: tcp` 并按其口径处置 TLS；Vision 须 `flow: xtls-rprx-vision`、`network: tcp` 且外层为 TLS1.3，其余 flow 取值拨号期点名拒绝；`grpc_reuse` gun 旋钮仅 `network: grpc` 可携带（其余传输面构建期拒绝；三键全缺 = 单连接全流复用）；`packet_encoding`（仅 VLESS）限 `raw | xudp | packetaddr`（缺省 raw，构建期白名单），VMess 订阅 `packet-encoding` 仅 `raw` 可交付（xudp/packetaddr 点名拒绝）；VMess 限 AEAD/alter_id=0 |
| Hysteria2 | QUIC 上的 TCP stream；UDP 数据报面（官方 UDPMessage over QUIC 不可靠数据报，镜像对端验收） | obfs（salamander）不支持——TCP/UDP 面均判负；服务端未声明 UDP 支持时点名拒绝（Hysteria-UDP 声明校验）；不等价于网页 QUIC 透传 |
| TUIC | QUIC 上的 TCP stream（v5 Connect 走双向流，token 认证经 TLS keying-material exporter）；UDP 数据报面（v5 Packet over QUIC 不可靠数据报，按 assoc 独立服务端 socket，客户端分片/重组，镜像对端验收） | 仅 v5——v4 线格式无代码路径，按名拒绝；`congestion-controller` 非 `cubic` 拨号期点名拒绝（不静默降级）；无错误响应面——拒绝以流/QUIC 收束呈现 |
| WireGuard | TCP、UDP 的用户态承载 | 部分平台目标是拒绝桩，交叉编译不能证明可用 |
| Hysteria v1 等 | 不列为当前可用 | 存在 schema、订阅字段或研究方向不代表已有连接器 |

## 可选扩展与边界

Mesh 是自己管理的节点网，普通订阅节点不理解其封装。Mesh TCP 使用版本化 envelope 和逐跳 mTLS；没有完整安全承载的 UDP Mesh 路径仍拒绝运行。防重放序号不替代完整性或来源认证。参见 [Mesh 使用参考](mesh.md)。

现有连接池、TLS 恢复、包长/timing/shaping 中间件、WASM 插件是独立配置能力。代理连接预热不等于缓存网站；TLS shape 预设不证明与某浏览器指纹完全一致；给游戏增加等待也不证明加速收益。配置见 [config](config.md)，测量与资源约束见 [v1 设计](design/architecture-v1.md)。

Clash/Mihomo 导入为部分兼容。节点、组、规则和传输字段分别验收；当前 fallback/relay/interval 与规则跳过问题见[研究证据](research/proxy-architectures-2026-11-14.md#verified-gaps)。不能把导入成功当成语义完整保留。
