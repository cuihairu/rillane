#!/usr/bin/env bash
# platforms/ios/build.sh —— seep-ffi 静态库 iOS 交叉（**需 macOS + Xcode**）
#
# 本仓库开发环境为 Linux：本脚本在 macOS 机器上运行（Xcode 命令行工具 +
# rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios），
# 产出 xcframework 供 Packet Tunnel Provider extension 链接。
#
# 用法（macOS）：
#   platforms/ios/build.sh            # ios + ios-sim + ios-x86_64 三面
set -euo pipefail
cd "$(dirname "$0")/../.."

OUT=platforms/ios/build
mkdir -p "$OUT"

build_one() { # triple, sysroot target name
    local triple="$1"
    echo "=== [$triple] cargo build --release -p seep-ffi"
    cargo build --release -p seep-ffi --target "$triple"
    # cdylib 面链接由 Xcode 工程负责；此处取静态 rlib 的目标码合成 .a——
    # 实际以 ar 合并 release deps 下本 crate 与依赖（简化：直接链接 dylib 亦可，
    # 但 Network Extension 进程内静态链接更贴合沙箱分发约束）
    ar crs "$OUT/libseep_ffi_${triple}.a" target/"$triple"/release/libseep_ffi.rlib
}

# 简化路径：直接以 rlib 打 .a 仅在依赖全静态时成立；更稳的做法是让 Xcode
# 链接全部 rlib。此处保留 cdylib 产物为主要交付面：
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build --release -p seep-ffi --target "$t"
done

echo "=== 合成 xcframework（cdylib 面）"
rm -rf "$OUT/seep_ffi.xcframework"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libseep_ffi.dylib -headers crates/seep-ffi/include \
    -library target/aarch64-apple-ios-sim/release/libseep_ffi.dylib -headers crates/seep-ffi/include \
    -library target/x86_64-apple-ios/release/libseep_ffi.dylib -headers crates/seep-ffi/include \
    -output "$OUT/seep_ffi.xcframework"

echo "完成：$OUT/seep_ffi.xcframework（拖入 Packet Tunnel Provider extension 的 Link Binary）"
