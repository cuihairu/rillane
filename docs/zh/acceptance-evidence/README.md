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
| RIL-043 移动 FFI JNI 符号面 | [ril-043-jni-symbol-face](../../acceptance-evidence/ril-043-jni-symbol-face) · [中文](../../acceptance-evidence/ril-043-jni-symbol-face.zh) | 本地账本 | Kotlin↔Rust 符号恰等已钉；真机批次未勾 |
| RIL-043 移动 FFI TUN fd 注入面 | [ril-043-tun-fd-injection](../../acceptance-evidence/ril-043-tun-fd-injection) · [中文](../../acceptance-evidence/ril-043-tun-fd-injection.zh) | 本地账本 | 坏 fd 具名拒绝 + 句柄不被污染（已修整进程 abort 缺陷）；真 TUN 通路归真机批次 |
| RIL-044 移动宿主生命周期停止面 | [ril-044-host-lifecycle](../../acceptance-evidence/ril-044-host-lifecycle) · [中文](../../acceptance-evidence/ril-044-host-lifecycle.zh) | 本地账本 | 重复停止两侧半边已钉；秘密注入/网络变化/IPC 仍开放 |
| RIL-083 SessionTracer 活面接线 | [ril-083-live-trace-wiring](../../acceptance-evidence/ril-083-live-trace-wiring) · [中文](../../acceptance-evidence/ril-083-live-trace-wiring.zh) | 本地账本 | TCP 入口流活面轨迹（takeover/rule/plan/close）；UDP 关联面与真机批次开放 |
| RIL-084 六平台构建产物矩阵 | [ril-084-artifact-matrix](../../acceptance-evidence/ril-084-artifact-matrix) · [中文](../../acceptance-evidence/ril-084-artifact-matrix.zh) | 本地账本 | 产物面对齐；真机/签名验收未勾 |
| RIL-085 三桌面进程端到端条款矩阵 | [ril-085-desktop-e2e-matrix](../../acceptance-evidence/ril-085-desktop-e2e-matrix) · [中文](../../acceptance-evidence/ril-085-desktop-e2e-matrix.zh) | 本地账本 | 条款×平台账本；浏览器/两款游戏分组轨迹未跑 |
| RIL-086 六平台并行场景矩阵 | [ril-086-parallel-scenario-matrix](../../acceptance-evidence/ril-086-parallel-scenario-matrix) · [中文](../../acceptance-evidence/ril-086-parallel-scenario-matrix.zh) | 本地账本 | 条款×平台账本；真实网站/QUIC 与游戏并行矩阵未跑 |

账本的机器可读真源在 docs 树外：`contracts/build_matrix_v1.json`、
`contracts/desktop_e2e_matrix_v1.json`、`contracts/parallel_scenario_matrix_v1.json`；
契约门随 `cargo test --workspace` 在 `crates/rillane-platform/tests/` 下运行。

状态不夸大：`partial` 或 `needs_*` 格表示该场景未验证——单元测试、交叉编译
与构建产物都不是真机验收。
