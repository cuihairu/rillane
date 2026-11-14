#!/bin/bash
# install.sh —— RILLANE macOS 装机脚本（须在 macOS 以 sudo 运行；platform-packaging.md §4）
#
#   sudo ./install.sh            # 二进制 + 配置示例 + LaunchDaemon 装载
#
# 卸载对称见 uninstall.sh；配置保留策略：已存在的真配置一律不覆盖。

set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "请以 sudo 运行（写 /usr/local 与 /Library/LaunchDaemons 需 root）" >&2
    exit 1
fi

install -m755 "$BUNDLE_DIR/rillaned"   /usr/local/bin/rillaned
install -m755 "$BUNDLE_DIR/rillanectl" /usr/local/bin/rillanectl
mkdir -p /usr/local/etc/rillane /usr/local/var/log
if [ ! -f /usr/local/etc/rillane/rillane.yaml ]; then
    install -m644 "$BUNDLE_DIR/rillane.yaml.example" /usr/local/etc/rillane/rillane.yaml
    echo "已落位示例配置 /usr/local/etc/rillane/rillane.yaml（先改 admin_token）"
else
    echo "保留既有配置 /usr/local/etc/rillane/rillane.yaml"
fi

install -m644 "$BUNDLE_DIR/com.rillane.rillaned.plist" /Library/LaunchDaemons/com.rillane.rillaned.plist
launchctl bootstrap system /Library/LaunchDaemons/com.rillane.rillaned.plist 2>/dev/null \
    || echo "bootstrap 跳过（可能已装载；重装请先跑 uninstall.sh）"
launchctl enable system/com.rillane.rillaned
launchctl kickstart system/com.rillane.rillaned
echo "完成：launchctl print system/com.rillane.rillaned 可查状态"

# 注：network.tun 块为 Linux-only（P1-2）；macOS 隧道面走 NEPacketTunnelProvider
# （P3-4 rillane-ffi 方向），本 daemon 装机形态以 socks/DNS 代理面为界。
