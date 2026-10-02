# 平台适配计划

- `openwrt/`（P3-3，已落地）：musl 静态交叉编译 + ipk 组装 + procd init.d；
  `build.sh` 三目标（aarch64/armv7/x86_64）产线，mips 面边界见其 README。
- `android/`：Rust 核心编译为 `cdylib`，通过 `ffi/` 暴露 C ABI，Kotlin UI 通过 JNI 接入；保留 `cargo-apk` 配置与 AAR 打包脚本。
- `ios/`：同样输出 `cdylib` + Swift Package，接入 NEPacketTunnelProvider，支持 on-device VPN Profile。
- `desktop/` (后续)：存放 Windows Service installer、systemd unit、launchd plist 模板。

各目录均共享上层 `crates/` 与 `apps/`，只补充平台 glue 与打包脚本。
