# RILLANE Android demo

Rust 核心（`crates/rillane-ffi` cdylib）+ Kotlin VpnService。`build.sh` 一条命令
产 APK：rillane-ffi 交叉（NDK 工具链）→ `jniLibs` 预置 → gradle 只打包
（无 externalNativeBuild，不需要 gradle 侧 NDK）。

## 构建矩阵

| ABI | rust triple | 代表设备 |
|---|---|---|
| `arm64-v8a` | `aarch64-linux-android` | 现代手机/平板 |
| `x86_64` | `x86_64-linux-android` | 模拟器（AVD x86_64 镜像） |
| `armeabi-v7a` | `armv7-linux-androideabi` | 老 32 位 arm（可选项；除 `rustup target add` 外还需在 `Cross.toml` 补 `[target.armv7-linux-androideabi]` 段——该段现缺，cross 会走官方旧镜像并撞 libunwind 缺失） |

依赖：docker + cross（rillane-ffi 交叉编译；镜像自带 NDK 工具链——host 直配
NDK 需逐依赖喂 CC/AR/cmake 面，ring/aws-lc-sys 均探不到裸 clang 前缀，故
与 platforms/openwrt 同走 cross 约定）、Android SDK（compileSdk 35 +
licenses；buildToolsVersion 未显式声明，走 AGP 缺省）、java 17+、首次运行需网络（gradle 发行版 +
AGP/Kotlin 插件下载，gradle 8.10.2 由脚本按需落 `~/.rillane-tools/`，不依赖
系统 gradle 版本）。

```sh
platforms/android/build.sh
adb install -r platforms/android/app/build/outputs/apk/debug/app-debug.apk
```

## 一轮流量验收路径

1. 安装启动 →「启动 VPN」→ 系统 consent 弹窗放行一次
   （CI/自动化可免弹窗：`adb shell appops set com.rillane.rillane ACTIVATE_VPN allow`）；
2. `RillaneVpnService.establish()` 建 TUN（`10.111.0.2/24`，路由仅接管
   `10.111.0.0/24` 测试网段），fd `detachFd()` 后经 JNI 交 `rillane_ffi_tun_start`；
3. FFI 层持有 fd 跑 ICMP echo 轮转（`crates/rillane-ffi/src/tun.rs`）；
4. 验证：

   ```sh
   adb shell ping -c 3 10.111.0.1    # 经 VpnService TUN → Rust → 回包
   ```

   ping 通 = 内核 → tun fd → FFI → 内核 的一轮流量完成；`adb logcat -s RillaneVpn`
   看各交接点日志，界面文本框显示 FFI statsJson（一秒刷新）。

## 验证边界（如实说明）

- **已验（宿主面）**：rillane-ffi C ABI start/stop/stats/last_error 往返 +
  socketpair 模拟 TUN 的 echo 轮转（`cargo test -p rillane-ffi`）。
- **已验（模拟器，API 33 x86_64 AVD）**：cross 交叉 .so（NDK r27c，ELF
  `for Android 24`）→ APK 打包含双 ABI .so → 安装 → `appops ACTIVATE_VPN
  allow` 免弹窗 → autostart 起 VpnService → `establish()` 得 `tun0
  10.111.0.2/24` → fd 交接 `rillane_ffi_tun_start` → **`ping -c 3 10.111.0.1`
  3/3 收包 0 丢失**（内核 → tun fd → Rust echo → 内核 一轮流量）；全程
  logcat 无 AndroidRuntime 崩溃。交叉链路要点：cross 0.2.5 官方 android
  镜像 NDK 过老（缺 libunwind，rustc 1.99 链接失败）且镜像 ENV 的
  `CARGO_TARGET_*_LINKER` 压过 cargo config 文件——自定义镜像
  （`cross/Dockerfile.android`）装 NDK r27c 并在 PATH 前段落 `*-gcc/g++`
  转发脚本（NDK wrapper 按 dirname $0 定位本体，软链会断）。
- **未验（真机）**：arm64 真机全流程（.so 形态已验、真机 consent/UI 交互
  与性能未跑）；有真机时按上面验收路径即可。
- TCP/UDP 的真实代理路径（IP 流重组 → FlowRouter → egress）仍需移植
  共享数据面；当前 TUN 面仅 ICMP echo 轮转，全局路由（0.0.0.0/0）
  在此之前不开启（避免流量黑洞）。
- **wireguard 出站在 android 构建中剥离**：`defguard_boringtun` 0.6 无
  android 平台支撑（内部 `tun` crate 不识别目标 + cfg 面守卫类型错位，
  实测编译失败）。`rillane-protocols` 对 android 目标改出恒 Err 桩
  （`outbound/wireguard_stub.rs`），wireguard egress 在 android 配置下
  构建期即报错；其余出站/入口不受影响。宿主面零差异。同一桩现亦覆盖
  armv7-ohos（上游另一形态阻塞，见 `platforms/ohos/README.md` 踩坑实录）。
- demo 用 `targetSdk 33`：免 Android 14+ 前台服务类型/通知权限样板；服务在
  应用前台期间运行即可完成验收，后台常驻（FGS 声明 + 通知）归正式面。
- gradle 不走 wrapper：gradle 发行版由 `build.sh` 按需下载到 `~/.rillane-tools/`
  （系统 gradle 4.4.1 过老无法跑 AGP 8，wrapper 反而引入版本耦合）。
