# Seep 示例插件（P3-2）

WASM `FlowMiddleware` 插件（ABI：[docs/design/plugin-loader.md](../docs/design/plugin-loader.md) §1.2/§1.3）。
本目录**不随宿主 workspace 编译**（wasm 专属 crate，独立 `[workspace]`，plugin-loader.md §7 P-load）。

| 插件 | wants_payload | 语义 |
|------|---------------|------|
| `rate-limit/` | 0 | 令牌桶限速（容量 3、每秒回 1；桶态存活于实例，时钟取宿主 `now_ms`） |
| `content-filter/` | 1 | 首块关键词过滤（内置禁词表，命中 deny；探测字节 allow 后回放） |

## 构建

```bash
rustup target add wasm32-unknown-unknown
plugins/build.sh            # 产物 → plugins/output/{rate_limit,content_filter}.wasm
```

## 启用（seepd 配置）

```yaml
obfuscation:
  enabled: true
  plugins:
    - path: plugins/output/rate_limit.wasm
    - path: plugins/output/content_filter.wasm
      fuel: 100000000       # 每调用指令预算（缺省 1e8）
```

- 链序：内置 `middleware` 声明序在前，`plugins` 声明序在后；
- 相对路径按进程 CWD 解析（validate E1：enabled 时路径必须存在）；
- 配置热更新重建链 = 插件实例状态（令牌桶）清零（plugin-loader.md §7 R-state）。

## 宿主侧验收实况

```bash
plugins/build.sh
cargo run -p seep-plugins --example plugins_smoke
```

预期：限速插件容量内放行、桶空后 deny（note 可见）；内容过滤命中禁词 deny、
干净载荷 allow 且首块回放完好；trap/fuel 隔离由 seep-plugins 内联 WAT 单测钉死
（§4.1，同一 ABI 面）。

## 插件单测（宿主纯逻辑面）

```bash
(cd plugins/rate-limit && cargo test)
(cd plugins/content-filter && cargo test)
```
