# 验收证据索引

支撑 `todo.md` 验收条目的证据文档。这里只有两种诚实类型：

- **真机证据**——在真实硬件上执行的命令，输出带时间戳留档；未跑的内容在文档内以具名缺口记录。
- **本地可核验账本**——机器可读矩阵（`contracts/*.json`），由 `cargo test --workspace` 内的契约门钉住，只覆盖本机可核验的条款；真机/签名依赖未决的验收主项保持关闭。

| 条目 | 证据 | 类型 | 状态 |
|---|---|---|---|
| RIL-032 Windows 技术探针 | [ril-032-windows-probe](../../acceptance-evidence/ril-032-windows-probe) | 真机 | `imac` 实机已验 |
| RIL-033 Windows 接管/旁路 | [ril-033-windows-takeover](../../acceptance-evidence/ril-033-windows-takeover) | 真机 | `imac` 机批次已验；浏览器/游戏流与 DNS 劫持端到端为具名缺口 |
| RIL-034 Windows 进程归属 | [ril-034-windows-owner](../../acceptance-evidence/ril-034-windows-owner) | 真机 | `imac` 实机已验 |
| RIL-035 Windows 服务与退出恢复 | [ril-035-windows-service-recovery](../../acceptance-evidence/ril-035-windows-service-recovery) | 真机 | 已验；休眠恢复为具名缺口 |
| RIL-042 OpenWrt ipk 包结构 | [ril-042-openwrt-ipk](../../acceptance-evidence/ril-042-openwrt-ipk) · [中文](../../acceptance-evidence/ril-042-openwrt-ipk.zh) | 本地账本 | 真包拆解（ar 成员、control/conffiles/postinst、procd init 形状）**并已真跑运维脚本**（升级保留运维配置、enabled=0/缺配置拒绝、reload=先停后起）；small 档守护进程冒烟（控制面 + 真 SOCKS5）本机已跑；opkg/procd 真机批次开放 |
| RIL-043 移动 FFI JNI 符号面 | [ril-043-jni-symbol-face](../../acceptance-evidence/ril-043-jni-symbol-face) · [中文](../../acceptance-evidence/ril-043-jni-symbol-face.zh) | 本地账本 | Kotlin↔Rust 符号恰等已钉；真机批次未勾 |
| RIL-043 移动 FFI TUN fd 注入面 | [ril-043-tun-fd-injection](../../acceptance-evidence/ril-043-tun-fd-injection) · [中文](../../acceptance-evidence/ril-043-tun-fd-injection.zh) | 本地账本 | 坏 fd 具名拒绝 + 句柄不被污染（已修整进程 abort 缺陷）；真 TUN 通路归真机批次 |
| RIL-043 移动 FFI 缓冲所有权与并发面 | [ril-043-ownership-concurrency](../../acceptance-evidence/ril-043-ownership-concurrency) · [中文](../../acceptance-evidence/ril-043-ownership-concurrency.zh) | 本地账本 | 堆/静态缓冲两族钉死、last_error 读后即清、ABI 版本对齐 workspace 版本；4 线程并发查询不阻塞真实 SOCKS5 传输已真跑；packetFlow/真机批次开放（RIL-094） |
| RIL-044 移动宿主生命周期停止面 | [ril-044-host-lifecycle](../../acceptance-evidence/ril-044-host-lifecycle) · [中文](../../acceptance-evidence/ril-044-host-lifecycle.zh) | 本地账本 | 重复停止两侧半边已钉；秘密注入/网络变化/IPC 已作为本地账本交付（见下行）；真机批次开放 |
| RIL-044 移动宿主秘密引用注入面 | [ril-044-secret-injection](../../acceptance-evidence/ril-044-secret-injection) · [中文](../../acceptance-evidence/ril-044-secret-injection.zh) | 本地账本 | `${secret:` 引用经真实 RFC1929 往返钉注入生效 + fail-closed 稳定码；网络变化/IPC 已作为本地账本交付（见下行）；Kotlin 宿主半边/真机批次开放 |
| RIL-044 移动宿主网络变化面 | [ril-044-network-change](../../acceptance-evidence/ril-044-network-change) · [中文](../../acceptance-evidence/ril-044-network-change.zh) | 本地账本 | `network_changed` 冲刷 DNS 缓存经真实解析往返钉生效，幂等，DNS 缺席诚实 no-op；真机活切网仍开放 |
| RIL-044 移动宿主有界诊断 IPC | [ril-044-diagnostic-ipc](../../acceptance-evidence/ril-044-diagnostic-ipc) · [中文](../../acceptance-evidence/ril-044-diagnostic-ipc.zh) | 本地账本 | 显式起桥 UDS 只读桥、有界帧与稳定码经真实往返钉死；宿主授权/真机批次开放 |
| RIL-082 移动/路由器诊断桥接 | [ril-082-mobile-diagnostic-bridge](../../acceptance-evidence/ril-082-mobile-diagnostic-bridge) · [中文](../../acceptance-evidence/ril-082-mobile-diagnostic-bridge.zh) | 本地账本 | 无默认 MCP/入站端口、脱敏导出范围与 OpenWrt 资源受限档已钉；脱敏助手由 CLI 门真调用钉死；x86_64/aarch64 small/mobile 跨编译产物已验（armv7 缺口含根因）；真机批次开放 |
| RIL-083 SessionTracer 活面接线 | [ril-083-live-trace-wiring](../../acceptance-evidence/ril-083-live-trace-wiring) · [中文](../../acceptance-evidence/ril-083-live-trace-wiring.zh) | 本地账本 | TCP 入口流活面轨迹（takeover/rule/plan/close）；UDP 关联与探测面见第四段条目；真机批次开放 |
| RIL-083 UDP 关联与探测流轨迹接线 | [ril-083-udp-association-trace](../../acceptance-evidence/ril-083-udp-association-trace) · [中文](../../acceptance-evidence/ril-083-udp-association-trace.zh) | 本地账本 | UDP 关联生命周期活面轨迹（mapped/reclaimed/closed）+ url-test 探测流轨迹；真机批次开放 |
| RIL-083 破坏兼容 bite 矩阵 | [ril-083-breaking-compat-bites](../../acceptance-evidence/ril-083-breaking-compat-bites) · [中文](../../acceptance-evidence/ril-083-breaking-compat-bites.zh) | 本地账本 | 五冻结面 + 结构门各有具名负向自证：丢键/加键/未走事务升版本被点名不放行；宿主桥接/MCP 协议面开放 |
| RIL-084 六平台构建产物矩阵 | [ril-084-artifact-matrix](../../acceptance-evidence/ril-084-artifact-matrix) · [中文](../../acceptance-evidence/ril-084-artifact-matrix.zh) | 本地账本 | 产物面对齐；OpenWrt 不支持架构具名含根因与重开条件；构建日志声称有脚本背书 + 依赖来源可复核（patch 申报 ↔ Cargo.lock ↔ checksum ↔ 成员版本）含自证；真机/签名验收未勾 |
| RIL-085 三桌面进程端到端条款矩阵 | [ril-085-desktop-e2e-matrix](../../acceptance-evidence/ril-085-desktop-e2e-matrix) · [中文](../../acceptance-evidence/ril-085-desktop-e2e-matrix.zh) | 本地账本 | 条款×平台账本；Linux 跨 uid 权限不足与端口复用已真实进程实测；浏览器/两款游戏分组轨迹未跑 |
| RIL-086 六平台并行场景矩阵 | [ril-086-parallel-scenario-matrix](../../acceptance-evidence/ril-086-parallel-scenario-matrix) · [中文](../../acceptance-evidence/ril-086-parallel-scenario-matrix.zh) | 本地账本 | 条款×平台账本；Linux 双栈与并行 DNS 回环已实测；真实网站/QUIC 与游戏并行矩阵未跑 |

账本的机器可读真源在 docs 树外：`contracts/build_matrix_v1.json`、
`contracts/desktop_e2e_matrix_v1.json`、`contracts/parallel_scenario_matrix_v1.json`、
`contracts/mobile_diagnostic_bridge_v1.json`；
契约门随 `cargo test --workspace` 在 `crates/rillane-platform/tests/` 下运行。

状态不夸大：`partial` 或 `needs_*` 格表示该场景未验证——单元测试、交叉编译
与构建产物都不是真机验收。
