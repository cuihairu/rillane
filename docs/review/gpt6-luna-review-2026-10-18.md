[0m
> build · gpt-6-luna
[0m→ [0mSkill "code-review" 
> build · gpt-6-luna
[0m$ [0mgit status --short && git log -1 --oneline
M .gitignore
a56fe4d fix(deps): bump quinn-proto rustls wasmtime for rustsec advisories
[0m✱ [0mGlob "**/*" [90m2000 matches[0m
[0m✱ [0mGrep "TODO|FIXME|XXX|HACK" [90min . · 123 matches[0m
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[limit=280][0m
[0m→ [0mRead README.zh.md [90m[limit=220][0m
[0m→ [0mRead Cargo.toml [90m[limit=240][0m
[0m→ [0mRead docs/architecture.md [90m[limit=180][0m
[0m$ [0mgit ls-files | grep -vE '(^|/)(target|build)/' | wc -l && git ls-files | grep -E '(^|/)(\.github/workflows|tests|benches)/|^(README|docs/|todo)' | head -200
239
.github/workflows/ci.yml
README.md
README.zh.md
apps/seepd/tests/samples.rs
crates/seep-config/tests/dns_block.rs
crates/seep-config/tests/egress_pool_block.rs
crates/seep-config/tests/group_member_roundtrip.rs
crates/seep-config/tests/network_block.rs
crates/seep-config/tests/obfuscation_block.rs
crates/seep-config/tests/profile_examples.rs
crates/seep-config/tests/profile_presets.rs
crates/seep-config/tests/tls_fingerprint_field.rs
crates/seep-config/tests/udp_config.rs
crates/seep-core/benches/relay_throughput.rs
crates/seep-core/benches/write_frame.rs
crates/seep-core/tests/middleware_chain.rs
crates/seep-core/tests/udp_associate.rs
crates/seep-core/tests/udp_egress_selection.rs
crates/seep-core/tests/udp_session_table.rs
crates/seep-protocols/tests/pool_connectors.rs
crates/seep-protocols/tests/pool_tls_integration.rs
crates/seep-protocols/tests/udp_egress.rs
crates/seep-routing/tests/routing_tests.rs
crates/seep-runtime/tests/mesh_chain_routing.rs
crates/seep-runtime/tests/tun_ingress.rs
docs/.vitepress/config.mts
docs/.vitepress/theme/custom.css
docs/.vitepress/theme/index.ts
docs/PROTOCOLS.md
docs/architecture.md
docs/cli.md
docs/config.md
docs/design/dns-partition.md
docs/design/egress-connection-pool.md
docs/design/mesh-advanced-security.md
docs/design/mesh-envelope-binary.md
docs/design/mesh-link-observability.md
docs/design/network-route.md
docs/design/obfuscation-middleware.md
docs/design/obfuscation-timing-shaping.md
docs/design/performance-io.md
docs/design/platform-packaging.md
docs/design/plugin-loader.md
docs/design/positioning.md
docs/design/roadmap.md
docs/design/scenario-profiles.md
docs/design/slo-scoring.md
docs/design/status-audit-tun-network-middleware.md
docs/design/tls-fingerprint.md
docs/design/tun-dataplane.md
docs/design/tun-linux-impl.md
docs/design/udp-dataplane.md
docs/design/udp-mesh-dataplane.md
docs/design/udp-observability.md
docs/design/udp-relay-path.md
docs/design/udp-session-table-api.md
docs/design/udp-session-table.md
docs/grafana/README.md
docs/grafana/seep-dashboard.json
docs/index.md
docs/mesh.md
docs/networking.md
docs/package-lock.json
docs/package.json
docs/public/logo.svg
docs/subscription.md
todo.md
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[offset=140, limit=90][0m
[0m→ [0mRead apps/seepd/src/control_plane.rs [90m[limit=240][0m
[0m→ [0mRead crates/seep-plugins/src/loader.rs [90m[limit=300][0m
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[limit=260][0m
[0m→ [0mRead docs/design/mesh-advanced-security.md [90m[offset=1, limit=230][0m
[0m→ [0mRead docs/design/roadmap.md [90m[limit=130][0m
> build · gpt-6-luna
[0m✱ [0mGrep "api_bind|admin_token|ControlPlane::new|control_plane.serve" [90min . · 100 matches[0m
[0m→ [0mRead crates/seep-runtime/src/udp_chain.rs [90m[limit=280][0m
[0m→ [0mRead crates/seep-plugins/src/plugin.rs [90m[limit=260][0m
[0m→ [0mRead crates/seep-config/src/lib.rs [90m[limit=300][0m
[0m→ [0mRead config/seep.yaml [90m[limit=260][0m
[0m✱ [0mGrep "TODO|FIXME|todo!\(|unimplemented!\(|return Err\(.*未实现|恒 Err|暂未实现" [90min . · 19 matches[0m
> build · gpt-6-luna
[0m→ [0mRead crates/seep-config/src/lib.rs [90m[offset=1180, limit=130][0m
[0m→ [0mRead docs/design/plugin-loader.md [90m[limit=170][0m
[0m→ [0mRead crates/seep-runtime/src/runtime_builder.rs [90m[offset=450, limit=105][0m
[0m→ [0mRead apps/seepd/src/main.rs [90m[offset=45, limit=70][0m
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[offset=1140, limit=160][0m
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[offset=740, limit=260][0m
[0m→ [0mRead crates/seep-runtime/src/tun_ingress.rs [90m[limit=280][0m
> build · gpt-6-luna
[0m✱ [0mGrep "handle_udp_datagram|serve_udp|udp_listener|recv_from\(&mut" [90min crates/seep-runtime/src/mesh_transport.rs · 29 matches[0m
[0m→ [0mRead docs/architecture.md [90m[offset=82, limit=40][0m
[0m→ [0mRead docs/config.md [90m[limit=220][0m
[0m→ [0mRead docs/networking.md [90m[limit=130][0m
[0m→ [0mRead docs/design/tls-fingerprint.md [90m[limit=125][0m
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[offset=1370, limit=240][0m
> build · gpt-6-luna
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[offset=1609, limit=145][0m
> build · gpt-6-luna
[0m✱ [0mGrep "tls.is_none|明文门|UDP.*加密|UDP.*明文|udp.*plaintext|allow_plaintext" [90min docs · 35 matches[0m
> build · gpt-6-luna
[0m→ [0mRead docs/design/udp-mesh-dataplane.md [90m[offset=1, limit=70][0m
[0m→ [0mRead docs/design/udp-mesh-dataplane.md [90m[offset=172, limit=28][0m
[0m→ [0mRead docs/design/positioning.md [90m[offset=1, limit=160][0m
[0m→ [0mRead docs/design/roadmap.md [90m[offset=79, limit=28][0m
[0m→ [0mRead apps/seepd/src/control_plane.rs [90m[offset=250, limit=35][0m
[0m✱ [0mGrep "18 个子命令|18 commands|HotReloadManager|reload|LuCI|SCM 1053|TUN.*TCP.*UDP" [90min docs · 17 matches[0m
> build · gpt-6-luna
[0m→ [0mRead todo.md [90m[offset=227, limit=24][0m
> build · gpt-6-luna
[0m→ [0mRead crates/seep-runtime/src/mesh_transport.rs [90m[offset=1905, limit=40][0m
> build · gpt-6-luna
## 1）最薄弱的 3 处（按风险排序）

1. **Mesh UDP 明文门可能让人误以为已有加密保护｜高风险**  
   `crates/seep-runtime/src/mesh_transport.rs:963-969,1291-1296,1915-1928`；客户端发送路径见 `crates/seep-runtime/src/udp_chain.rs:152-155,244-245`。  
   `MeshUdpGate` 只检查是否配置了 `MeshTlsConfig`，有配置就放行；但 UDP 面直接收发原始数据报，没有 TLS/mTLS 封装。也就是说，配置 TCP mTLS 后，UDP 仍可能在未设置 `SEEP_MESH_UDP_ALLOW_PLAINTEXT` 时以明文启动。UDP 重放窗口也没有 MAC/认证，网络可达的攻击者可伪造新序号注入报文。应先修正 gate，使“有 TCP mTLS”不能被当成“UDP 已加密”。

2. **控制面认证可被配置成完全关闭，且没有非本机监听保护｜高风险**  
   `apps/seepd/src/control_plane.rs:129-139,258-261`；绑定点 `apps/seepd/src/main.rs:74-81`；配置说明 `docs/config.md:32-34`。  
   `admin_token` 为空时 `is_authorized()` 直接返回 `true`，而 `api_bind` 可配置为非回环地址；此时路由应用/清除、订阅变更等管理操作均无认证。配置文档只说 token 是可选项，没有提示“非本机监听必须配置认证”，代码也没有拒绝危险组合。

3. **WASM 插件载入期调用没有有效的时间上限｜中高风险**  
   `crates/seep-plugins/src/loader.rs:64-70,86-105`。  
   载入期把 fuel 设为 `u64::MAX`，随后直接调用插件导出的 `wants_payload`、`plugin_name`；插件若在这些函数中死循环，可能卡住启动。文档所述 fuel 隔离实际只覆盖每次 `on_flow` 调用（`crates/seep-plugins/src/plugin.rs:130-144`），并未覆盖载入期探测。应给初始化导出单独的有限预算，并为线性内存设置明确上限。

## 2）最值得补的 3 项新能力

1. **Mesh UDP 端到端加密与认证**  
   当前 UDP mesh 缺少加密和 MAC，防重放不能防伪造。现在没有，是因为 UDP 加密被明确划到 V2，QUIC 载具尚未选定，也没有端到端密钥分发/协商机制（`docs/architecture.md:59`、`docs/design/mesh-advanced-security.md:11-13,176`）。

2. **控制面安全边界：默认强制鉴权，并限制远程暴露**  
   补上非回环监听时的启动校验，提供 TLS/mTLS 或 UDS 管理入口；后续再按只读、运维等权限拆分。现在没有，是因为控制面按本机 HTTP/REST 最小管理面实现，token 只是可选配置，尚无远程管理的威胁模型和权限体系。

3. **事务式配置热加载**  
   实现校验后原子切换，并协调路由、TUN、连接池和中间件生命周期。现在没有，是因为当前采用启动时一次性读配置；`HotReloadManager` 虽导出但未接入，且动态重建会话和系统路由需要明确回滚/迁移语义（`docs/architecture.md:50`）。

## 3）文档与实现可能对不上的地方

- `docs/architecture.md:85` 仍写“S1…→S2…→S4…”为“进行中/规划”，但 `docs/design/roadmap.md:4` 已宣称 S1–S4 和 P3 全部完成。
- `docs/design/roadmap.md:89-91` 仍把高级安全与平台打包列为新增项；实际 P2-7 仅交付撤销状态可观测和 UDP 防重放，OCSP、端到端 MAC 明确未实现；平台打包也有 Windows SCM 真启动、macOS 真机等未验证边界（`todo.md:126-127,147`）。应把已交付子集与延期项分开标注。
- UDP 加密门的口径与实现有风险性偏差：`docs/architecture.md:59` 说 UDP 加密未实现；但实现用“是否配置 TCP 的 `MeshTlsConfig`”决定是否放行 UDP（`mesh_transport.rs:963-969,1291-1296`），而 UDP 监听仍是原始 `recv_from`（`mesh_transport.rs:1915-1928`）。应明确 gate 不等于 UDP 加密，并避免 mTLS 配置让明文 UDP 静默放行。
- `docs/config.md:32-34` 将 `control.uds_path` 描述为可选 UDS 配置；当前 `ControlConfig` 虽定义该字段（`crates/seep-config/src/lib.rs:1211-1216`），`seepd` 启动只使用 `api_bind` 建 TCP 控制面（`apps/seepd/src/main.rs:74-81`）。该字段目前看是未消费配置。
- `docs/networking.md:43-47` 的目标数据流图把 `PacketFilter` 画成实际处理环节，但同文 `:15` 明确无独立包过滤实现，当前分流由 routing 条件承担；图应标成概念模型或改为实际路径。
