# P2-5 客户端 TLS 指纹模拟（设计稿）

> 2026-10-02 就绪。uTLS 类能力挂载到出站 TLS 公共层（tls.rs）。
> 定位依据：positioning.md §2.4「指纹模拟」行（uTLS/客户端 TLS 指纹
> chrome/ios/safari，对标 sing-box `utls`）。

## 0. 范围与验收口径

**todo 原文**：uTLS 类能力挂载到出站 TLS 公共层（`tls.rs`）。
**验收原文**：对外握手指纹可按配置选择（chrome/ios 等），指纹检测工具可区分。

**可测口径（显式改写，非缩水；含对「模拟」一词的诚实降档，见 §9-1）**：

1. **公共层挂载**：`tls.rs::build_client_config` 增指纹形态参数——所有
   出站 TLS（每流路径 + P1-5 工厂路径）经同一漏斗变形，无旁路；
2. **按配置选择**：指纹形态是配置值（预设枚举 none/chrome/ios/safari），
   缺省 none = 存量零差异；
3. **指纹可区分**：本地 ClientHello 捕获（测内 TCP 服务端直读首记录
   解析 hello 五元组：version / cipher_suites / extensions /
   supported_groups / signature_algorithms）断言各预设两两互异——
   JA3 五元组输入层面可区分即「指纹检测工具可区分」的可复现形。

## 1. 现状与结构约束

- 出站 TLS 全走 rustls 0.23（`build_client_config` 单漏斗：每流路径
  `create_tls_connector*` + 工厂路径 `TlsConnectorFactory::shared_config`）；
- rustls 暴露的 hello 可变形面（0.23.21 源码核对，client/hs.rs）：
  - `cipher_suites`：CryptoProvider 套件表按序全量发出（hs.rs:424），
    尾追 renegotiation SCSV——**子集 + 排序可控**；
  - `kx_groups`：supported_groups 扩展按 provider 序（首个 = TLS1.3
    key_share 默认群）——**子集 + 排序可控**；
  - `signature_algorithms`：= `config.verifier.supported_verify_schemes()`
    （hs.rs:258-260）——**验证器包装即子集 + 排序可控**（NoVerifier 已
    有先例，webpki 路径可包装 `WebPkiServerVerifier` 委托校验仅改清单）；
  - 协议版本面：`with_protocol_versions` 决定 supported_versions 内容，
    1.2/1.3 取舍连带 hello 扩展集形变（1.3 独有 key_share /
    psk_key_exchange_modes）；
  - ALPN 有无改变扩展集（既有配置面，不归指纹预设管——语义字段）。
- **rustls 不可变面**：扩展集成员固定（无 GREASE / padding /
  compress_certificate 等 Chrome 特有扩展）——hello 五元组中 extensions
  维度只能在「rustls 形态集」内变化，见 §9-1；**0.23.4x 起 rustls 每
  握手随机化扩展序**（hs.rs `extension_order_seed`）——扩展维稳定判据
  是集合非序列（测试 §7-5 同律），上游反指纹行为同时弱化静态 JA3 的
  意义（§9-5）。

## 2. 设计决策

- **D-1 预设 = 参数表非新栈**：每个预设是一张
  `{protocol_versions, cipher_suites 序, kx_groups 序, sig_schemes 序}`
  表——从 rustls/ring 支持集内取子集重排，全部可协商成功（不引入
  服务器必然拒出的组合）；不打包 BoringSSL/自组 ClientHello（§9-1）。
- **D-2 单漏斗挂载**：`build_client_config(skip_cert_verify, alpn,
  profile)` 增参；两个调用方（每流/工厂）同参数传递；工厂缓存键扩展
  为 `(skip, alpn, profile)`（异指纹异配置——同键共享会话缓存的
  P1-5 语义按键保持）。
- **D-3 验证器包装**：sig_schemes 变形 = 包装既有验证器
  （委托 verify_* 仅改 `supported_verify_schemes`）——skip 与 webpki
  两路径同构，验证语义零变化（清单是 hello 广告面非校验面）。
- **D-4 池键入身份**：指纹进 `TransportKey`（pool D-2 传输身份）——
  hello 形态不同的连接不可互借；热更新键自失效同既有键字段语义。
- **D-5 预设集**：`none`（rustls 缺省 = 存量零差异）/ `chrome` /
  `ios` / `safari`——chrome 走双版本 + AES 优先长链；ios 单 1.3 +
  P256 优先；safari 单 1.3 + ChaCha 优先——预设间在版本/套件/群三维度
  各至少一处差异（§7-3 两两互异的构造保证）。
- **D-6 观测**：不做新指标族——指纹是静态配置形态非运行期动态量；
  `shape_material()` 形态串（版本/套件/群/方案四维，纯函数从预设表
  导出）供调试/测试比对——命名刻意避开 JA3：extensions 维度运行期
  由 rustls 决定，静态表不谎称完整 JA3（§9-1 同律）。

## 3. 数据结构

```rust
// seep-protocols/src/fingerprint.rs
pub enum TlsFingerprint { None, Chrome, Ios, Safari }

impl TlsFingerprint {
    pub fn parse(s: &str) -> Result<Self>;   // M1 转换层用（E1 带原值报错）
}

struct FingerprintSpec {
    protocol_versions: &'static [&'static SupportedProtocolVersion],
    cipher_suites: &'static [SupportedCipherSuite],   // ring 集内子集排序
    kx_groups: &'static [&'static dyn SupportedKxGroup],
    sig_schemes: &'static [SignatureScheme],
}

impl TlsFingerprint {
    fn spec(&self) -> Option<FingerprintSpec>; // None = rustls 缺省（零差异）
    pub fn shape_material(&self) -> String;    // 形态串（D-6）
}
```

seep-config 面（M1）：四个 TLS 承载 egress 变体（http/vmess/vless/trojan）
增 `tls_fingerprint: Option<String>`（none 缺省；转换层校验合法值）。

## 4. 接线点

| # | 点 | 动作 |
|---|----|------|
| 1 | `tls.rs::build_client_config` | 增 profile 参——按预设装 provider/版本/验证器 |
| 2 | `create_tls_connector*` / `TlsConnectorFactory` | 透传 + 缓存键扩展（D-2） |
| 3 | trojan/vless/http 连接器构造 | 透传（M1，含 pool `TransportKey` 字段 D-4） |
| 4 | seep-config egress 变体 + 转换 | 配置面（M1） |

## 5. 错误与边界

- E1 未知指纹值：配置转换层报错带原值（network/obfs 先例）；
- E2 none 缺省：零差异——不装变形 provider、不包验证器；
- E3 池命中键含指纹：异指纹不互借（D-4）；warm keys 派生同键含指纹；
- E4 指纹与 TLS1.2-only 服务器：chrome 预设含 1.2 套件可协商；ios/
  safari 单 1.3 对 1.2-only 服务器握手指明失败路径（用户选预设自担，
  文档注明）；
- E5 sig_schemes 子集不诚实广告的兼容风险：预设只收主流五scheme
  （RSA_PKCS1_SHA256/384、ECDSA_NISTP256_SHA256、RSA_PSS_SHA256/384…），
  全部为验证器真实支持——广告面收缩不引入验证盲区（D-3 委托语义）。

## 6. 控制面

无新端点/指标族（D-6）。`seep_obfs_*`/`seep_tls_handshakes_total` 不受
影响（工厂观测面同键计数）。

## 7. 测试策略

1. 预设表纯函数：none = rustls 缺省形（零差异）；各预设套件/群/方案
   均为 ring 支持集子集（防构造期 panic）；
2. hello 捕获解析：测内 TCP 服务端收首记录，按 TLS ClientHello 结构
   解析五元组——chrome/ios/safari/none 各拨本地空回服务器（握手可在
   ServerHello 后即断，无需完成握手）；
3. 两两互异：四形态五元组（version/suites/groups/sigalgs/extensions）
   任意两形至少两维不同（§7-2 数据上断言）；
4. 缓存键：工厂同指纹同 Arc、异指纹异 Arc（`Arc::ptr_eq`，§8.1 先例）；
5. 既有 TLS 测试零回归（none 路径逐字节不动）。

## 8. 分步实施清单

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M0 | 设计稿 + seep-protocols fingerprint.rs（预设表/shape_material/单漏斗挂载）+ §7-1..3/5 测 | — | §7 全绿；none 零差异 |
| M1 | seep-config 四变体配置面 + 转换校验（E1）+ 连接器/pool 键/工厂接线（§4-2/3）+ §7-4 + 文档回填 | M0 | §7-4 绿；池不互借异指纹 |

## 9. 偏差与假设

1. **「模拟」降档为「形态变异」**：真·浏览器 JA3 等值模拟需要
   rustls 不提供的 hello 自由度（GREASE、扩展重排、Chrome 专有扩展、
   精确随机/会话 ID 形态）——本步在 rustls 约束内交付**指纹可变且
   预设间可区分**（验收「可区分」的可复现形 = §0-3），「对检测工具
   呈现为真 Chrome」不承诺、明示不达成；uTLS 级拟真归 V2（需换栈
   BoringSSL 或自研 ClientHello 组包器，positioning §2.4 同注）。
   预设名 chrome/ios/safari 表达「形态取向」非「等值伪装」；
2. **可区分的判定面 = JA3 输入五元组**（本地解析），非三方检测服务
   在线比对——离线可复现优先；
3. 预设表值随 ring 支持集漂移：ring 升级增删套件时预设表需对表修订
   （纯常量变更）；
4. hysteria2/wireguard 等非 rustls 出站不在本能力面（QUIC hello 归
   quicotls 栈，另议）；
5. **上游行为发现（实施期核对 0.23.45 源码）**：rustls 已内置每握手
   ClientHello 扩展序随机化——「可区分性」的稳定承载维 = 版本/套件序/
   群/签名方案四个我们可控的维；extensions 维在测试中按集合比较。这
   同时意味着静态 JA3 对 rustls 客户端本已弱化，本步价值重心进一步
   落在「形态可变可分」而非「拟真」。

## 10. 风险与未决

- **R-tfp1**：指纹形态本身成为新特征（「会变形的 rustls」）——MVP
  面向「同形多实例打散」，拟真对抗归 V2 换栈后重评；
- **O-tfp1**：`seepctl` 调试子命令输出各预设 shape_material 对照表；
- **O-tfp2**：自定义预设（配置直写套件/群清单）——预设表开放为配置
  形按需再做。
