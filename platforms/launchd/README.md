# platforms/launchd —— macOS launchd 交付（P3-3，脚本级）

macOS 原生产线（universal2 tar.gz）+ LaunchDaemon plist + 装卸脚本。
设计定稿与验证分层见 [docs/design/platform-packaging.md](../../docs/design/platform-packaging.md) §4/§5。

## 模板清单

| 文件 | 落位（tar.gz 内 / 装机） | 说明 |
|---|---|---|
| `build.sh` | —（产线） | **须 macOS 原生运行**：aarch64 + x86_64 双构建 → `lipo -create` universal2（`lipo -info` 断言）→ `dist/launchd/seep_<版本>_macos_universal2.tar.gz` |
| `com.seep.seepd.plist` | `/Library/LaunchDaemons/com.seep.seepd.plist` | LaunchDaemon：`SEEP_CONFIG=/usr/local/etc/seep/seep.yaml` 环境注入（seepd 无 `--config` 旗标）+ `KeepAlive{SuccessfulExit=false}`（对齐 `Restart=on-failure`）+ 日志落 `/usr/local/var/log/seepd.log` |
| `install.sh` | 随包 | `sudo ./install.sh`：二进制入 `/usr/local/bin`、配置示例不覆盖既有、`launchctl bootstrap system` + `enable` + `kickstart` |
| `uninstall.sh` | 随包 | `sudo ./uninstall.sh`（配置保留）/ `--purge`（连配置清理）；`launchctl bootout` 对称卸载 |
| `seep.yaml.example` | `/usr/local/etc/seep/seep.yaml`（装） | **无 `network.tun` 块**（Linux-only，P1-2；macOS 隧道走 NEPacketTunnelProvider 方向，P3-4 seep-ffi） |

## 用法（macOS 侧）

```bash
platforms/launchd/build.sh        # macOS 原生
tar -xzf dist/launchd/seep_0.1.0_macos_universal2.tar.gz
cd seep-0.1.0-macos-universal2
sudo ./install.sh
launchctl print system/com.seep.seepd    # 状态
```

## 验证边界（如实登记，platform-packaging.md §5 分层）

| 层 | 内容 | 状态 |
|---|---|---|
| L1 脚本结构 | build.sh / install.sh / uninstall.sh 语法（bash -n）；plist 结构（python3 plistlib 解析 + 键面断言） | 本机 Linux 验证 ✅ |
| L2 产物核验 | Mach-O universal2（`lipo -info` 断言在脚本内） | **本机不产 Mach-O**（Apple SDK 再分发限制，与 CI darwin 排除同口径），断言随脚本交付、实跑待 macOS |
| L3/L4 | tar 实产、launchctl bootstrap/kickstart 实装 | **需 macOS 未验** |

本机可跑的结构验证（Linux）：

```bash
bash -n platforms/launchd/build.sh platforms/launchd/install.sh platforms/launchd/uninstall.sh
python3 - <<'EOF'
import plistlib
with open("platforms/launchd/com.seep.seepd.plist","rb") as f:
    d = plistlib.load(f)
assert d["Label"] == "com.seep.seepd"
assert d["ProgramArguments"] == ["/usr/local/bin/seepd"]
assert d["EnvironmentVariables"]["SEEP_CONFIG"] == "/usr/local/etc/seep/seep.yaml"
assert d["KeepAlive"] == {"SuccessfulExit": False}
print("plist 结构断言通过")
EOF
```
