# SEEP HarmonyOS（鸿蒙）适配（P3-4 填空，2026-10-10 编译面落地）

Rust 核心（`crates/seep-ffi` cdylib，C ABI 面）在三个
`*-unknown-linux-ohos` 目标下编译面打通：aarch64 与 x86_64 走真实
wireguard 面，armv7 因上游 `defguard_boringtun` 阻塞改走 wireguard 恒
Err 桩（其余出站/入口不受影响，见「依赖链要点」第 4 条）。与
Android/iOS 共享同一 C ABI 层（`lib.rs`/`tun.rs`，unix 家族零改动）；
鸿蒙侧宿主接入（ArkTS/ArkUI 侧 XComponent + fd 交接）未在本批——当前
交付为**编译面 + ELF 静态核验**，无 demo 工程。

## 环境前提（宿主一次性）

1. rust std：`rustup target add aarch64-unknown-linux-ohos`
2. OHOS SDK native 组件 → `/opt/ohos-sdk`（rust-lang CI 同布局，
   `src/ci/docker/scripts/ohos-sdk.sh` 同款流式取件，全量包数 GB、仅解 native）：

   ```sh
   curl https://repo.huaweicloud.com/openharmony/os/5.0.0-Release/ohos-sdk-windows_linux-public.tar.gz \
     | tar xz -C /tmp linux/native-linux-x64-5.0.0.71-Release.zip
   sudo unzip /tmp/linux/native-linux-x64-5.0.0.71-Release.zip -d /opt/ohos-sdk   # ~2.8G
   rm /tmp/linux/native-linux-x64-5.0.0.71-Release.zip
   ```

3. 仓库根 `.cargo/config.toml` 已提交 target 段（linker/ar + cc/cmake 的
   `CC_/CXX_/AR_aarch64_unknown_linux_ohos` + `OHOS_SDK_NATIVE`）。wrapper
   脚本自带 `--target`/`--sysroot`，无需手工 CFLAGS。

## 验收（aarch64 已实证 2026-10-10；x86_64/armv7 已实证 2026-10-11）

```sh
cargo check -p seep-ffi --target aarch64-unknown-linux-ohos   # 验收口径：编译过
cargo build  -p seep-ffi --target aarch64-unknown-linux-ohos  # 实测亦过：链接出 cdylib
cargo check -p seep-ffi --target x86_64-unknown-linux-ohos    # 2026-10-11 实测过（真实 wireguard 面）
cargo build  -p seep-ffi --target x86_64-unknown-linux-ohos   # 实测过：链接出 cdylib
cargo check -p seep-ffi --target armv7-unknown-linux-ohos     # 2026-10-11 实测过（wireguard 桩面）
cargo build  -p seep-ffi --target armv7-unknown-linux-ohos    # 实测过：链接出 cdylib
```

L2 静态核验：产物 `libseep_ffi.so` 经 SDK `llvm-readelf -h` 确认
DYN 共享对象——aarch64/x86_64 为 ELF64（AArch64/X86-64），armv7 为
ELF32（ARM）。cfg 门改写后的 android 复归核验：
`cargo check -p seep-ffi --target aarch64-linux-android`（NDK clang 在
PATH）实测仍过——stub 路径语义不变。

## 依赖链要点（踩坑实录）

- `aws-lc-sys` 0.45 自带 OpenHarmony 面（builder 检测 `OHOS_SDK_NATIVE` →
  `build/cmake/ohos.toolchain.cmake`）；不设该 env 时手拼 flags 的 configure
  会在陈旧 CMake cache 上炸出假错（`add_subdirectory(tool)`），清
  `target/<triple>/` 重跑即消。
- `ring`/`aws-lc-sys` 均需目标 C 编译器——**cargo check 也要 SDK**
  （build script 照跑），纯 rustup std 不够。
- `nix` 的 `_bad` ioctl 宏在 linux 面恒转 `as c_ulong`，而 ohos 的 musl 系
  `libc::ioctl` request 形参是 `c_int`——结构性冲突，`linux.rs` 的
  TUNSETIFF/TUNGETIFF 两包装按 `target_env = "ohos"` 手写同形函数
  （语义同 nix `convert_ioctl_res`），其余目标原样走宏。
- `defguard_boringtun` 0.6.2 在 **armv7-ohos** 编不过（2026-10-11 实测）：
  `src/device/epoll.rs:135` 以结构体字面量构造 `libc::timespec`，而 32 位
  ohos libc 的 timespec 多一个私有 `__pad0`（32 位 arm time64 padding）→
  E0451 private fields；aarch64/x86_64-ohos 的 timespec 无此字段、实测
  可编。处置：armv7-ohos 下 wireguard 出站整体剥离为恒 Err 桩（同
  android 先例——`seep-protocols` 的 Cargo.toml target cfg 门 +
  `outbound/mod.rs` 双分支），aarch64/x86_64-ohos 不回退。

## 边界（如实登记）

- **L4 真机面未验**：无 DevEco Studio/鸿蒙真机，无 ArkTS 宿主工程；cdylib
  装载、fd 交接与 ICMP 一轮流量（对齐 android demo 口径）待真平台批。
- `armv7-unknown-linux-ohos` 的 wireguard 出站为恒 Err 桩（上游
  defguard_boringtun 阻塞，见踩坑实录第 4 条），其余出站/入口在该目标
  不受影响；`x86_64-unknown-linux-ohos` 全量面（含真实 wireguard）已验。
- CI 未编排 ohos 腿（self-hosted runner 需同装 SDK 至 `/opt/ohos-sdk`，
  成本数 GB；待真平台批一并决）。
- `jni_bridge.rs` 仅 android 编译（既有 cfg 门），鸿蒙不走 JNI。
