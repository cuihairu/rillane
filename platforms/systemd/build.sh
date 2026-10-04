#!/usr/bin/env bash
# platforms/systemd/build.sh —— SEEP Linux deb 打包产线（P3-3，platform-packaging.md §2）
#
# 用法：
#   platforms/systemd/build.sh                                  # amd64 + arm64 双目标（缺省矩阵）
#   platforms/systemd/build.sh aarch64-unknown-linux-gnu        # 指定目标
#   OUT_DIR=/tmp/seep-deb platforms/systemd/build.sh            # 产物目录覆盖
#
# 依赖：cross（arm64 走容器内 C 工具链）、dpkg-deb、qemu-aarch64（arm64 冒烟）。
# 产物：$OUT_DIR/seep_<版本>_<deb架构>.deb × 目标 + 同目录 .build-log.txt
#       （file 静态核验 + dpkg 布局断言 + 抽取冒烟记录，同 OpenWrt 产线约定）。
# 验证分层：L1/L2/L3 本机全跑（platform-packaging.md §5）；真机 systemd
# enable/start 面（L4）不在本机能力面——边界见 README「验证边界」节。

set -euo pipefail
cd "$(dirname "$0")/../.."

TARGETS=(${@:-x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu})
OUT_DIR=${OUT_DIR:-dist/deb}
PKG_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/seepd/Cargo.toml | head -1)"
PKG_RELEASE=1
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
LOG="$OUT_DIR/.build-log.txt"

# rust triple → Debian 架构
deb_arch() {
    case "$1" in
        x86_64-unknown-linux-gnu) echo amd64 ;;
        aarch64-unknown-linux-gnu) echo arm64 ;;
        *) echo "未映射的 deb 架构：$1" >&2; return 1 ;;
    esac
}

mkdir -p "$OUT_DIR"
echo "=== seep deb 打包 $(date -Is) ===" > "$LOG"

for target in "${TARGETS[@]}"; do
    arch="$(deb_arch "$target")"
    deb="$OUT_DIR/seep_${PKG_VERSION}-${PKG_RELEASE}_${arch}.deb"
    stage="$OUT_DIR/stage-$arch"
    runner=()

    # ---- 构建（host 原生 / 他机 cross；OpenWrt 同款 env 约定）----
    if [ "$target" = "$HOST_TARGET" ]; then
        BIN_DIR="target/release"
        env -u CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_STRIP=symbols \
            cargo build --release -p seepd -p seepctl 2>&1 | tail -2
    else
        BIN_DIR="target/$target/release"
        if [ -x "$(command -v qemu-aarch64)" ]; then
            runner=(qemu-aarch64 -L /usr/aarch64-linux-gnu)
        fi
        env -u CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_STRIP=symbols \
            cross build --release --target "$target" -p seepd -p seepctl 2>&1 | tail -2
    fi
    echo "[$target] build ok（bin=$BIN_DIR）" | tee -a "$LOG"

    # ---- 静态核验（L2：file 架构断言；gnu 目标为 PIE，只断 ELF64 位面 + 架构）----
    # 断言 grep 一律不带 -q（-q 找到即退出 → 上游进程 SIGPIPE → pipefail 误杀）
    file "$BIN_DIR/seepd" | tee -a "$LOG"
    file "$BIN_DIR/seepd" | grep "ELF 64-bit LSB" >/dev/null || {
        echo "[$target] file 核验失败：非 ELF 64-bit" >&2; exit 1; }
    case "$arch" in
        amd64) file "$BIN_DIR/seepd" | grep "x86-64" >/dev/null || { echo "[$target] 非 x86-64" >&2; exit 1; } ;;
        arm64) file "$BIN_DIR/seepd" | grep "ARM aarch64" >/dev/null || { echo "[$target] 非 aarch64" >&2; exit 1; } ;;
    esac

    # ---- deb 组装（免 root：--root-owner-group）----
    rm -rf "$stage"
    mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/etc/seep" "$stage/lib/systemd/system"
    install -m755 "$BIN_DIR/seepd" "$stage/usr/bin/seepd"
    install -m755 "$BIN_DIR/seepctl" "$stage/usr/bin/seepctl"
    install -m644 platforms/systemd/seep.yaml.example "$stage/etc/seep/seep.yaml.example"
    install -m644 platforms/systemd/seep.service "$stage/lib/systemd/system/seep.service"
    cat > "$stage/DEBIAN/control" <<EOF
Package: seep
Version: ${PKG_VERSION}-${PKG_RELEASE}
Section: net
Priority: optional
Architecture: ${arch}
Maintainer: SEEP Project <seep@example.invalid>
Description: SEEP smart egress proxy daemon
 Homepage: https://github.com/cuihairu/seep
EOF
    # conffiles：登记包内真实存在的示例文件（新版 dpkg-deb --build 严格校验
    # conffile 必须在包数据内，登记缺席的真配置路径会被拒绝——偏差回填
    # platform-packaging.md §9）；真配置由部署者 cp 自示例，天然不受包管辖
    echo "/etc/seep/seep.yaml.example" > "$stage/DEBIAN/conffiles"
    cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# 建系统用户（幂等，platform-packaging.md §2.2）
if ! getent passwd seep >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/seep --shell /usr/sbin/nologin seep 2>/dev/null || true
fi
mkdir -p /etc/seep
chown -R seep:seep /etc/seep 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # 只 enable 不 start：配置须部署者显式落位（README「快速开始」），
    # 避免无配置状态反复重启刷屏
    systemctl enable seep.service >/dev/null 2>&1 || true
fi
exit 0
EOF
    cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop seep.service 2>/dev/null || true
    systemctl disable seep.service 2>/dev/null || true
fi
exit 0
EOF
    chmod 755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm"
    dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null

    # ---- 包结构断言（L2：dpkg-deb -I/-c 布局 + 维护脚本齐）----
    # 注：断言 grep 不带 -q（-q 匹配即退 → 上游 dpkg-deb/tee 收 SIGPIPE，
    # pipefail 下整链 141 误杀——run3/run4 实录）；>/dev/null 全量读入无此虞
    info="$(dpkg-deb -I "$deb")"
    echo "$info" >> "$LOG"
    echo "$info" | grep -E "^ Package: seep$" >/dev/null
    echo "$info" | grep -E "^ Architecture: ${arch}$" >/dev/null
    echo "$info" | grep -E "^ Version: ${PKG_VERSION}-${PKG_RELEASE}$" >/dev/null
    dpkg-deb -c "$deb" | grep " ./usr/bin/seepd$" >/dev/null
    dpkg-deb -c "$deb" | grep " ./usr/bin/seepctl$" >/dev/null
    dpkg-deb -c "$deb" | grep " ./lib/systemd/system/seep.service$" >/dev/null
    dpkg-deb -c "$deb" | grep " ./etc/seep/seep.yaml.example$" >/dev/null
    for s in control conffiles postinst prerm; do
        [ -f "$stage/DEBIAN/$s" ] || { echo "[$target] DEBIAN/$s 缺失" >&2; exit 1; }
    done
    echo "[$target] dpkg 结构断言通过" | tee -a "$LOG"

    # ---- 抽取布局冒烟（L3：--version 短路，platform-packaging.md §1.1 禁止 --help）----
    x="$(mktemp -d)"
    trap 'rm -rf "$x"' EXIT
    dpkg-deb -x "$deb" "$x"
    [ "$(stat -c '%a' "$x/usr/bin/seepd")" = 755 ] || { echo "[$target] 二进制权限断言失败" >&2; exit 1; }
    if [ -z "${runner[*]:-}" ]; then
        "$x/usr/bin/seepd" --version 2>&1 | tee -a "$LOG"
        "$x/usr/bin/seepd" --version 2>&1 | grep "^seepd ${PKG_VERSION}$" >/dev/null
    else
        [ -x "$(command -v qemu-aarch64)" ] || { echo "[$target] 缺 qemu-aarch64，跳过 arm64 冒烟" | tee -a "$LOG"; continue; }
        "${runner[@]}" "$x/usr/bin/seepd" --version 2>&1 | tee -a "$LOG"
        "${runner[@]}" "$x/usr/bin/seepd" --version 2>&1 | grep "^seepd ${PKG_VERSION}$" >/dev/null || {
            echo "[$target] qemu 冒烟失败（可能需要 /usr/aarch64-linux-gnu sysroot）" >&2; exit 1; }
    fi
    echo "[$target] 抽取冒烟通过（${runner[*]:-native}）" | tee -a "$LOG"
    rm -rf "$x"
    trap - EXIT
done

echo "=== 完成：$(ls -1 "$OUT_DIR"/*.deb) ===" | tee -a "$LOG"