#!/usr/bin/env bash
# platforms/windows/build.sh —— RILLANE Windows zip 交付包产线（P3-3，platform-packaging.md §3）
#
# 用法：
#   platforms/windows/build.sh                    # x86_64-pc-windows-gnu（缺省）
#   OUT_DIR=/tmp/rillane-win platforms/windows/build.sh
#
# 依赖：cross（容器内 MinGW C 工具链；CI 同款目标，aws-lc-sys 已证可编）、python3（zip 组装/断言）。
# 产物：$OUT_DIR/rillane_<版本>_x86_64_windows.zip（rillaned.exe + rillanectl.exe +
#       rillane.yaml.example + install/uninstall-service.ps1 + README.txt）+
#       .build-log.txt（PE 静态核验 + zip 布局断言记录）。
# 验证分层：L1/L2 本机全跑；L3 运行冒烟与 L4 服务安装需 Windows——边界见 README。

set -euo pipefail
cd "$(dirname "$0")/../.."

TARGET=${1:-x86_64-pc-windows-gnu}
OUT_DIR=${OUT_DIR:-dist/windows}
PKG_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/rillaned/Cargo.toml | head -1)"
LOG="$OUT_DIR/.build-log.txt"
ZIP="$OUT_DIR/rillane_${PKG_VERSION}_x86_64_windows.zip"
BUNDLE="rillane-${PKG_VERSION}-x86_64-windows"

mkdir -p "$OUT_DIR"
echo "=== rillane windows zip 打包 $(date -Is) ===" > "$LOG"

env -u CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_STRIP=symbols \
    cross build --release --target "$TARGET" -p rillaned -p rillanectl 2>&1 | tail -2
echo "[$TARGET] build ok" | tee -a "$LOG"
BIN="target/$TARGET/release"

# ---- 静态核验（L2：PE32+ x86-64 断言；file 输出措辞随版本浮动，拆双断言；
#      断言 grep 不带 -q——匹配即退会让上游 file 收 SIGPIPE 误杀）----
file "$BIN/rillaned.exe" | tee -a "$LOG"
file "$BIN/rillaned.exe" | grep "PE32+ executable" >/dev/null || {
    echo "file 核验失败：非 PE32+ 可执行" >&2; exit 1; }
file "$BIN/rillaned.exe" | grep "x86-64" >/dev/null || {
    echo "file 核验失败：非 x86-64" >&2; exit 1; }

# ---- zip 组装（python3 zipfile，免装 zip 包）----
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$BUNDLE"
install -m755 "$BIN/rillaned.exe" "$stage/$BUNDLE/rillaned.exe"
install -m755 "$BIN/rillanectl.exe" "$stage/$BUNDLE/rillanectl.exe"
install -m644 platforms/windows/rillane.yaml.example "$stage/$BUNDLE/rillane.yaml.example"
install -m644 platforms/windows/install-service.ps1 "$stage/$BUNDLE/install-service.ps1"
install -m644 platforms/windows/uninstall-service.ps1 "$stage/$BUNDLE/uninstall-service.ps1"
install -m644 platforms/windows/README.txt "$stage/$BUNDLE/README.txt"
rm -f "$ZIP"
python3 - "$stage" "$ZIP" <<'EOF'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
root = os.path.join(stage, os.listdir(stage)[0])
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dirpath, _, files in sorted(os.walk(root)):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            z.write(p, os.path.relpath(p, stage))
EOF

# ---- zip 布局断言（L2）----
python3 - "$ZIP" "$BUNDLE" <<'EOF'
import sys, zipfile
zpath, bundle = sys.argv[1], sys.argv[2]
names = set(zipfile.ZipFile(zpath).namelist())
need = {f"{bundle}/{n}" for n in (
    "rillaned.exe", "rillanectl.exe", "rillane.yaml.example",
    "install-service.ps1", "uninstall-service.ps1", "README.txt")}
missing = need - names
if missing:
    sys.exit(f"zip 布局缺件：{sorted(missing)}")
EOF
echo "[$TARGET] zip 布局断言通过" | tee -a "$LOG"
ls -la "$ZIP" | tee -a "$LOG"
echo "=== 完成：$ZIP ===" | tee -a "$LOG"