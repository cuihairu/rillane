# 平台适配计划

- `openwrt/`（P3-3，已落地）：musl 静态交叉编译 + ipk 组装 + procd init.d；
  `build.sh` 三目标（aarch64/armv7/x86_64）产线，mips 面边界见其 README。
- `systemd/`（P3-3，已落地）：deb 组装产线（amd64 native + arm64 cross）+
  `seep.service` unit（专用系统用户 + 硬化旗标组 + `SEEP_CONFIG` 环境注入）
  + 装机配置示例；真机 systemd 面边界见其 README。
- `windows/`（P3-3，已落地）：cross windows-gnu + zip 交付包 +
  `install/uninstall-service.ps1`（sc.exe 模板级，SCM 1053 边界与
  WinSW/NSSM 替代见其 README）。
- `launchd/`（P3-3，脚本级落地）：macOS 原生产线（universal2 tar.gz）+
  LaunchDaemon plist + 装卸脚本；Apple SDK 许可限制下本仓 Linux 侧只验
  脚本/plist 结构面，Mach-O 实产与实装待 macOS（边界见其 README）。
- `android/`（P3-4，已落地，模拟器一轮流量验收通过）：Rust 核心
  `crates/seep-ffi` cdylib（C ABI + Android JNI 双面）经 cross 容器交叉 →
  jniLibs → Kotlin VpnService demo APK；一轮流量验收路径与边界见其 README。
- `ios/`（P3-4，已落地脚手架）：Swift `NEPacketTunnelProvider` 源码 +
  macOS 侧 xcframework 构建脚本（本仓 Linux 环境无 Xcode，iOS 面仅源码
  级交付，边界见其 README）。
- `ohos/`（P3-4 填空，编译面落地：aarch64 2026-10-10、x86_64/armv7
  2026-10-11）：三个 `*-unknown-linux-ohos` 目标下 seep-ffi 编译 + cdylib
  链接 + ELF 静态核验（OHOS SDK native 工具链，`.cargo/config.toml`
  集中配置）；armv7 因上游 defguard_boringtun 阻塞走 wireguard 恒 Err 桩；
  ArkTS 宿主与真机面边界见其 README。

各目录均共享上层 `crates/` 与 `apps/`，只补充平台 glue 与打包脚本。
验证分层口径（L1 脚本结构 / L2 产物静态核验 / L3 运行冒烟 / L4 真平台面）
见 [docs/design/platform-packaging.md](../docs/design/platform-packaging.md) §5。
