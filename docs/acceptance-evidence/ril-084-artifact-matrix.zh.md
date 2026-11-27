# RIL-084 构建产物矩阵（第一段：本地可核验面，2026-11-26）

机器可读真源 `contracts/build_matrix_v1.json`，
契约门 `crates/rillane-platform/tests/artifact_matrix_contract.rs`
（4 测，CI 纳入 `cargo test --workspace`）。本段只交付**目标架构 / 最低系统 /
feature / 产物 / 签名 / 验证分层**的对齐面；六平台真机与签名产物验收未发生，
RIL-084 勾选保持关闭（依赖 RIL-036/039/041/042/046/049 真机批次未决）。

## 矩阵（摘要；完整字段见 JSON）

| 平台 | 目标（产物 / 仅检查） | 最低系统 | 产物形态 | 签名 | 运行验收 |
|---|---|---|---|---|---|
| Linux systemd | gnu ×2 产物 + armv7 仅检查 | 无发行版下限（glibc 随构建机） | deb ×2（amd64/arm64） | 无 | needs_os（enable/start 真机未验） |
| OpenWrt | musl ×3 产物 | 22.03+（fw4/nft） | ipk ×3 | 无 | needs_device（opkg/procd/TUN/nft 未验） |
| Windows | x86_64-gnu 产物 | 最低版本未验证 | zip（含服务脚本） | 无 Authenticode | needs_os（SCM 1053 缺口） |
| macOS launchd | darwin ×2 产物（universal2） | 未声明 | tar.gz（lipo 合并） | 未签名/notarize | needs_os（本机不产 Mach-O） |
| Android | arm64 + x86_64 产物 | API 24（target 33 / compile 35） | debug APK | **仅 debug key** | verified_emulator（AVD API33：安装/autostart/撤销/切网/onTrimMemory/字体放大/四 Tab 渲染已验；数据面仅 ICMP 回环） |
| iOS | device/sim ×3 产物（xcframework） | 需签名设备 + 付费账号 | xcframework | 无 entitlement | needs_signing（RIL-094 阻塞） |

## 契约门钉死的事实

1. CI `cross check`（ci.yml）与 nightly `cross build`（nightly.yml）矩阵里的每个
   三元组必须在矩阵中登记；每个目标唯一归属一平台，杜绝产线与清单分叉。
2. 平台目录 / build.sh / 证据文件必须存在；产物目标必须在脚本或 README 被点名。
3. `ci_check_only_triples` 与 `artifact_triples` 不交叠——**cross-check 只证明可
   编译，不冒充交付产物或运行通过**（Linux armv7 是明示的仅检查面）。
4. 签名状态：`release_signed` 恒 false；只有 Android 是 debug-key 面；iOS 需
   开发者账号。`run_verification` 只允许 `verified_emulator` / `needs_os` /
   `needs_device` / `needs_signing` 四值；除 Android AVD 外一律不得标实测。
5. 自证门：伪造 macOS `verified_emulator` 即刻点名失败。
6. **不支持架构具名入账（RIL-042 第四段）**：OpenWrt 条目
   `unsupported_architectures` 逐项列架构 + 根因 + 重开条件——32 位
   mips/mipsel（rust 1.99+ 无预编译 musl std + aws-lc-sys 不支持；重开须
   `-Z build-std` + ring）、armv7 musl 交叉（LuaJIT 32 位宿主阶段缺
   multilib 头文件，档位无关；重开须定制镜像或上游特性可选化）。契约门
   核对 build.sh/README 出处、禁止与 `run_verification` 升格冲突，并有
   删条目自证 panic。

## 验证边界（如实）

- 已验：矩阵与 CI/nightly 工作流、平台脚本/文档的结构对账；Android AVD API 33
  ICMP 回环（RIL-150 既有证据，非本次新增）。
- 未验：所有需要真机/签名/宿主 OS 的运行层——deb/systemd 安装、OpenWrt 设备安装
  与 nft 接管、Windows SCM 服务（当前 SCM 1053 缺口）、macOS Mach-O 实产与
  launchctl、iOS NE 真机生命周期。cross-check 绿不等于这些面通过。
- 不宣称：正式版本、发布签名、notarization 或任何版本 tag（发布红线见
  `CLAUDE.md`）；nightly 滚动构建是独立允许面，不由本矩阵授权。

## 复开条件

真机证据出现后，须显式更新 JSON 中对应平台的 `run_verification` 与 `run_note`
（附证据文件路径），契约门会拒绝静默升格；签名产物出现才允许改 `release_signed`。
