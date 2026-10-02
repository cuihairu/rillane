#!/usr/bin/env bash
# platforms/openwrt/build.sh —— SEEP OpenWrt musl 静态交叉编译 + ipk 组装（P3-3）
#
# 用法：
#   platforms/openwrt/build.sh                 # 三目标全量（缺省矩阵）
#   platforms/openwrt/build.sh aarch64-unknown-linux-musl   # 指定目标
#   OUT_DIR=/tmp/seep-ipk platforms/openwrt/build.sh        # 产物目录覆盖
#
# 依赖：docker（cross 走容器内 C 工具链）、cross、rustup（目标 std 自动装）。
# 产物：$OUT_DIR/seep_<版本>_<openwrt架构>.ipk（含 seepd + seepctl + init.d +
#       示例配置），以及同目录 .build-log.txt（file/readelf 静态核验记录）。
#
# 已知边界（README.md「验证边界」节详述）：
# - mips/mipsel：rust 1.99 起不再分发 32 位 mips musl 预编译 std（两端序皆
#   弃），且 aws-lc-sys（rustls 默认密码学后端）不支持 mips——当前矩阵不含，
#   需 nightly -Z build-std + ring 供给改造后另行落地；
# - 产物为「静态 ELF 元数据 + ipk 结构」级验证，真机/仿真运行面见 README。

set -euo pipefail
cd "$(dirname "$0")/../.."

TARGETS=(${@:-aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf x86_64-unknown-linux-musl})
OUT_DIR=${OUT_DIR:-dist/openwrt}
PKG_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/seepd/Cargo.toml | head -1)"
PKG_RELEASE=1

# rust triple → OpenWrt DISTRIB_ARCH 映射（ABI 族代表值；实际设备按
# /etc/openwrt_release 的 DISTRIB_ARCH 用 ROUTER_ARCH_<triple 大写下划线>
# 覆盖，如 ROUTER_ARCH_AARCH64_UNKNOWN_LINUX_MUSL=aarch64_cortex-a76）
openwrt_arch() {
    case "$1" in
        aarch64-unknown-linux-musl) echo "${ROUTER_ARCH_AARCH64_UNKNOWN_LINUX_MUSL:-aarch64_generic}" ;;
        armv7-unknown-linux-musleabihf) echo "${ROUTER_ARCH_ARMV7_UNKNOWN_LINUX_MUSLEABIHF:-arm_cortex-a7_neon-vfpv4}" ;;
        x86_64-unknown-linux-musl) echo "${ROUTER_ARCH_X86_64_UNKNOWN_LINUX_MUSL:-x86_64}" ;;
        mipsel-unknown-linux-musl) echo "${ROUTER_ARCH_MIPSEL_UNKNOWN_LINUX_MUSL:-mipsel_24kc}" ;;
        *) echo "未映射的 OpenWrt 架构：$1（可用 ROUTER_ARCH_* 覆盖）" >&2; return 1 ;;
    esac
}

mkdir -p "$OUT_DIR"
: > "$OUT_DIR/.build-log.txt"

for target in "${TARGETS[@]}"; do
    arch="$(openwrt_arch "$target")"
    echo "=== [$target → $arch] cross build ===" | tee -a "$OUT_DIR/.build-log.txt"

    rustup target add "$target" 1>&2
    # 交叉产物统一落仓库 ./target（环境 CARGO_TARGET_DIR 剔除——cross 需
    # workspace 内挂载点，外部路径会脱挂）
    env -u CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_STRIP=symbols \
        cross build --release --target "$target" -p seepd -p seepctl 1>&2

    bdir="target/$target/release"
    for bin in seepd seepctl; do
        [ -x "$bdir/$bin" ] || { echo "缺产物 $bdir/$bin" >&2; exit 1; }
    done

    # 静态核验：ELF 机器类型 + 无动态依赖（musl 静态面）
    {
        echo "--- $target ---"
        file "$bdir/seepd" "$bdir/seepctl"
        (readelf -d "$bdir/seepd" 2>/dev/null || true) | grep -E "NEEDED|Machine" || echo "(no dynamic section — static)"
    } >> "$OUT_DIR/.build-log.txt"

    # ---- ipk 组装（ar 归档：debian-binary + control.tar.gz + data.tar.gz）----
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' EXIT
    mkdir -p "$stage/control" "$stage/data/etc/init.d" "$stage/data/usr/bin" "$stage/data/usr/share/seep"

    installed_size="$(du -sk "$bdir/seepd" "$bdir/seepctl" | awk '{s+=$1}END{print s}')"
    cat > "$stage/control/control" <<EOF
Package: seep
Version: ${PKG_VERSION}-${PKG_RELEASE}
Depends: libc, kmod-tun
Section: net
Architecture: ${arch}
Maintainer: cuihairu <cuihairu@users.noreply.github.com>
Installed-Size: ${installed_size}
Source: package/seep
SourceName: seep
Description: SEEP proxy daemon (socks/mixed ingress, direct/ss/trojan/vmess egress, mesh chains, DNS partition)
 Static musl build by cross; config at /etc/seep.yaml (SEEP_CONFIG), control API :9090.
EOF
    echo "/etc/seep.yaml" > "$stage/control/conffiles"
    cat > "$stage/control/postinst" <<'EOF'
#!/bin/sh
[ -f /etc/seep.yaml ] || cp /usr/share/seep/seep.yaml.example /etc/seep.yaml
/etc/init.d/seep enable 2>/dev/null || true
exit 0
EOF
    chmod 755 "$stage/control/postinst"

    install -m755 "$bdir/seepd" "$stage/data/usr/bin/seepd"
    install -m755 "$bdir/seepctl" "$stage/data/usr/bin/seepctl"
    install -m755 platforms/openwrt/init.d/seep "$stage/data/etc/init.d/seep"
    install -m644 platforms/openwrt/seep.yaml.example "$stage/data/usr/share/seep/seep.yaml.example"

    (cd "$stage/control" && tar czf ../control.tar.gz ./control ./conffiles ./postinst)
    (cd "$stage/data" && tar czf "$stage/data.tar.gz" .)
    echo "2.0" > "$stage/debian-binary"

    ipk="$OUT_DIR/seep_${PKG_VERSION}-${PKG_RELEASE}_${arch}.ipk"
    rm -f "$ipk"
    (cd "$stage" && ar rc "$OLDPWD/$ipk" debian-binary control.tar.gz data.tar.gz)

    # 结构核验：ar 三成员序 + 双 tar 可解
    ar t "$ipk" >> "$OUT_DIR/.build-log.txt"
    echo "=== [$target] 完成：$ipk ($(du -h "$ipk" | cut -f1)) ===" | tee -a "$OUT_DIR/.build-log.txt"
    unset stage
    trap - EXIT
done

echo "全部目标完成；核验记录：$OUT_DIR/.build-log.txt"
