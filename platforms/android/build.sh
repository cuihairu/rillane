#!/usr/bin/env bash
# platforms/android/build.sh —— RILLANE Android demo 产线（P3-4）
#
# 流程：rillane-ffi cdylib 交叉（cross 0.2.5 容器镜像自带 NDK 工具链——与
# platforms/openwrt 同一约定；host 直配 NDK 需逐依赖喂 CC/AR/cmake 面，
# ring/aws-lc-sys 均探不到裸 clang 前缀）→ jniLibs 预置 → gradle assembleDebug
# （gradle 只打包预置 .so，无需 NDK/externalNativeBuild）。
#
# 用法：
#   platforms/android/build.sh                     # arm64-v8a + x86_64 + APK
#   platforms/android/build.sh arm64-v8a           # 单 ABI（只出 .so + 打包）
#   APK_TASK=assembleRelease platforms/android/build.sh          # 换打包任务
#
# 环境依赖：
#   - docker + cross（交叉编译；镜像首次自动拉取）
#   - ANDROID_HOME（或 ~/Android/Sdk）：gradle 侧 SDK（compileSdk 35 +
#     build-tools 35；licenses 已接受）
#   - java 17+；网络（首次拉 gradle 发行版与 AGP/Kotlin 插件）
#   - unzip/ curl：gradle 引导与产物核验
set -euo pipefail
cd "$(dirname "$0")/../.."

ABIS=(${@:-arm64-v8a x86_64})
APK_TASK=${APK_TASK:-assembleDebug}
GRADLE_VER=8.10.2
TOOLS_DIR=${RILLANE_TOOLS_DIR:-$HOME/.rillane-tools}

# ---- ABI → rust triple（NDK API 面由 cross 镜像内定）----
triple_of() {
    case "$1" in
        arm64-v8a) echo aarch64-linux-android ;;
        armeabi-v7a) echo armv7-linux-androideabi ;;
        x86_64) echo x86_64-linux-android ;;
        *) echo "未映射 ABI：$1" >&2; return 1 ;;
    esac
}

# ---- rillane-ffi 交叉（cross 容器；产物统一落仓库 ./target 同 openwrt）----
# 移动宿主构建档（RIL-040/RIL-082）：--no-default-features --features mobile
# ——default 是 full 档（wasmtime/JIT），移动 cdylib 不带 WASM 插件面
# （rillane-ffi Cargo.toml 档位注记 + mobile_diagnostic_bridge_v1.json 钉死）。
FFI_FEATURE_ARGS=(--no-default-features --features mobile)
for abi in "${ABIS[@]}"; do
    triple="$(triple_of "$abi")"
    echo "=== [$abi → $triple] cross build --release -p rillane-ffi ${FFI_FEATURE_ARGS[*]}"
    env -u CARGO_TARGET_DIR cross build --release -p rillane-ffi \
        --target "$triple" "${FFI_FEATURE_ARGS[@]}"
    so="target/$triple/release/librillane_ffi.so"
    [ -f "$so" ] || { echo "缺产物 $so" >&2; exit 1; }
    file "$so" | grep -qE "ARM aarch64|Intel 80386|x86-64|ELF" \
        || { echo "产物 ELF 形态异常：$so" >&2; exit 1; }
    mkdir -p "platforms/android/app/src/main/jniLibs/$abi"
    cp "$so" "platforms/android/app/src/main/jniLibs/$abi/librillane_ffi.so"
done

# ---- gradle 引导（发行版按需下载；无 wrapper 依赖系统 gradle 版本面）----
GRADLE_BIN="$TOOLS_DIR/gradle-$GRADLE_VER/bin/gradle"
if [ ! -x "$GRADLE_BIN" ]; then
    echo "=== 下载 gradle $GRADLE_VER → $TOOLS_DIR"
    mkdir -p "$TOOLS_DIR"
    curl -fL --retry 3 -o "$TOOLS_DIR/gradle-$GRADLE_VER-bin.zip.part" \
        "https://services.gradle.org/distributions/gradle-$GRADLE_VER-bin.zip"
    mv "$TOOLS_DIR/gradle-$GRADLE_VER-bin.zip.part" "$TOOLS_DIR/gradle-$GRADLE_VER-bin.zip"
    unzip -q -o "$TOOLS_DIR/gradle-$GRADLE_VER-bin.zip" -d "$TOOLS_DIR"
fi

# ---- SDK 定位（gradle 侧）----
ANDROID_HOME=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
[ -d "$ANDROID_HOME" ] || { echo "未找到 Android SDK：设 ANDROID_HOME" >&2; exit 1; }

echo "=== gradle $APK_TASK（SDK: $ANDROID_HOME）"
(cd platforms/android && ANDROID_HOME="$ANDROID_HOME" "$GRADLE_BIN" "$APK_TASK")

APK="platforms/android/app/build/outputs/apk/debug/app-debug.apk"
[ "$APK_TASK" = "assembleDebug" ] || APK="platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk"
[ -f "$APK" ] || { echo "缺 APK：$APK" >&2; exit 1; }

# ---- 产物核验：.so 确入包（逐 ABI）----
# 先落盘再 grep：管道里 grep -q 早退配合 pipefail 会让上游 unzip 的退出码
# 参与判定（一次实测误报缺件，无法复现）——落盘列表使核验确定性，且失败
# 时可直接打印列表对账。
echo "=== APK: $APK ($(du -h "$APK" | cut -f1))"
APK_LIST=$(mktemp)
trap 'rm -f "$APK_LIST"' EXIT
unzip -l "$APK" > "$APK_LIST" || { echo "APK 列表读取失败：$APK" >&2; exit 1; }
for abi in "${ABIS[@]}"; do
    grep -q "lib/$abi/librillane_ffi.so" "$APK_LIST" \
        || { echo "APK 缺 lib/$abi/librillane_ffi.so，实际列表：" >&2; cat "$APK_LIST" >&2; exit 1; }
done
grep -E "lib/.*librillane_ffi|classes\.dex" "$APK_LIST"
echo "完成。安装：adb install -r $APK"
