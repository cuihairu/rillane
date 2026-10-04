#!/usr/bin/env bash
# platforms/launchd/build.sh —— SEEP macOS universal2 tar.gz 产线（P3-3，platform-packaging.md §4）
#
# 用法（**须在 macOS 原生运行**——Apple SDK 再分发限制，Linux 不可交叉产出
# Mach-O，与 CI darwin 排除同一口径；本仓 Linux 侧验证仅 bash -n + plist
# 结构面，见 README「验证边界」）：
#   platforms/launchd/build.sh
#   OUT_DIR=/tmp/seep-mac platforms/launchd/build.sh
#
# 产物：$OUT_DIR/seep_<版本>_macos_universal2.tar.gz
#       （seepd + seepctl + com.seep.seepd.plist + install/uninstall.sh +
#       seep.yaml.example）

set -euo pipefail
cd "$(dirname "$0")/../.."

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
case "$HOST_TARGET" in
    *darwin*) ;;
    *) echo "本脚本须在 macOS 原生运行（当前 host=$HOST_TARGET；Apple SDK 许可限制，Linux 不可交叉产出 Mach-O）" >&2; exit 1 ;;
esac

OUT_DIR=${OUT_DIR:-dist/launchd}
PKG_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/seepd/Cargo.toml | head -1)"
TARBALL="$OUT_DIR/seep_${PKG_VERSION}_macos_universal2.tar.gz"
BUNDLE="seep-${PKG_VERSION}-macos-universal2"
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

mkdir -p "$OUT_DIR"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$BUNDLE"

for target in "${TARGETS[@]}"; do
    env -u CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_STRIP=symbols \
        cargo build --release --target "$target" -p seepd -p seepctl 2>&1 | tail -2
done

# ---- universal2 合并 + Mach-O 断言 ----
for binname in seepd seepctl; do
    lipo -create \
        -output "$stage/$BUNDLE/$binname" \
        "target/aarch64-apple-darwin/release/$binname" \
        "target/x86_64-apple-darwin/release/$binname"
    # 断言 grep 不带 -q（同 deb 产线 SIGPIPE 教训）
    lipo -info "$stage/$BUNDLE/$binname" | grep "arm64 x86_64" >/dev/null || {
        echo "lipo 断言失败：$binname 非 universal2" >&2; exit 1; }
    chmod 755 "$stage/$BUNDLE/$binname"
done

install -m644 platforms/launchd/com.seep.seepd.plist "$stage/$BUNDLE/com.seep.seepd.plist"
install -m755 platforms/launchd/install.sh "$stage/$BUNDLE/install.sh"
install -m755 platforms/launchd/uninstall.sh "$stage/$BUNDLE/uninstall.sh"
install -m644 platforms/launchd/seep.yaml.example "$stage/$BUNDLE/seep.yaml.example"

tar -czf "$TARBALL" -C "$stage" "$BUNDLE"
echo "=== 完成：$TARBALL ==="
