# 平台适配计划

- `openwrt/`（P3-3，已落地）：musl 静态交叉编译 + ipk 组装 + procd init.d；
  `build.sh` 三目标（aarch64/armv7/x86_64）产线，mips 面边界见其 README。
- `android/`（P3-4，已落地，模拟器一轮流量验收通过）：Rust 核心
  `crates/seep-ffi` cdylib（C ABI + Android JNI 双面）经 cross 容器交叉 →
  jniLibs → Kotlin VpnService demo APK；一轮流量验收路径与边界见其 README。
- `ios/`（P3-4，已落地脚手架）：Swift `NEPacketTunnelProvider` 源码 +
  macOS 侧 xcframework 构建脚本（本仓 Linux 环境无 Xcode，iOS 面仅源码
  级交付，边界见其 README）。
- `desktop/` (后续)：存放 Windows Service installer、systemd unit、launchd plist 模板。

各目录均共享上层 `crates/` 与 `apps/`，只补充平台 glue 与打包脚本。
