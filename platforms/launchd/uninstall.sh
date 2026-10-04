#!/bin/bash
# uninstall.sh —— SEEP macOS 卸载（须在 macOS 以 sudo 运行；对称 install.sh）
#
#   sudo ./uninstall.sh          # 卸载 LaunchDaemon 与二进制（配置保留）
#   sudo ./uninstall.sh --purge  # 连同 /usr/local/etc/seep 一并清理

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "请以 sudo 运行" >&2
    exit 1
fi

launchctl bootout system/com.seep.seepd 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.seep.seepd.plist
rm -f /usr/local/bin/seepd /usr/local/bin/seepctl

if [ "${1:-}" = "--purge" ]; then
    rm -rf /usr/local/etc/seep
    echo "配置已清理"
else
    echo "配置保留于 /usr/local/etc/seep（--purge 一并清理）"
fi
echo "完成：LaunchDaemon 已卸载"
