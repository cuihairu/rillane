# platforms/windows —— Windows 交付包 + 服务脚本模板（P3-3）

cross windows-gnu 交叉编译 + zip 交付包 + sc.exe 服务脚本（模板级）。
设计定稿与验证分层见 [docs/design/platform-packaging.md](../../docs/design/platform-packaging.md) §3/§5。

## 模板清单

| 文件 | 落位（zip 内） | 说明 |
|---|---|---|
| `build.sh` | —（产线） | cross `x86_64-pc-windows-gnu`（CI 同款目标）→ `dist/windows/seep_<版本>_x86_64_windows.zip`；PE32+ 静态核验 + zip 布局断言入 `.build-log.txt` |
| `seepd.exe` / `seepctl.exe` | 根目录 | 交叉产物（file PE32+ x86-64 核验仅 seepd.exe；seepctl 仅 zip 布局存在性断言） |
| `seep.yaml.example` | 根目录 | Windows 装机模板（**无 `network.tun` 块**——TUN 面 Linux-only，P1-2；Windows 隧道归平台增量） |
| `install-service.ps1` | 根目录 | `sc.exe create`（auto 启动）+ `sc.exe failure` 三段退避重启 + 注册表 `Environment` 键注入 `SEEP_CONFIG`（seepd 无 `--config` 旗标，sc.exe 也无环境参数面） |
| `uninstall-service.ps1` | 根目录 | `sc.exe stop/delete` 幂等卸载（1060/1062 容忍）；`-RemoveConfig` 连配置清理 |
| `README.txt` | 根目录 | 装机速览（英文，随包分发） |

## 用法

```powershell
# 构建（Linux 产线）
platforms/windows/build.sh          # → dist/windows/seep_0.1.0_x86_64_windows.zip

# Windows 装机：解压 → 管理员 PowerShell
.\install-service.ps1
# 服务项创建/配置/崩溃恢复策略生效；启动受 §边界 1 限制
```

## 验证边界（如实登记，platform-packaging.md §5 分层）

| 层 | 内容 | 状态 |
|---|---|---|
| L1 脚本结构 | build.sh 语法；ps1 参数/管理员检查/退出码面审读 | 本机已验 |
| L2 静态核验 | file PE32+ x86-64 + zip 布局断言（python3 zipfile） | 本机已验 |
| L3 运行冒烟 | `seepd.exe --version` 运行 | **需 Windows 未验** |
| L4 真机面 | `sc.exe create/start`、注册表 Environment 生效面 | **需 Windows 未验** |

## 已知边界

1. **SCM 1053**：seepd 未实现 SCM 控制协议（不调 `StartServiceCtrlDispatcher`、
   不报 SERVICE_RUNNING），`sc.exe start seep` 会被 SCM 在 30 秒内判错误 1053
   并停止。正解有二，归后续：`windows-service` crate 原生集成（windows 目标
   专属 main 分支）；或部署侧用 WinSW/NSSM 外部包装（README.txt 给了 NSSM
   全套命令，配置注入走 `AppEnvironmentExtra`）。
2. **运行面未验**：windows-gnu 仅过编译级（CI `cross check` 绿）；seepd 在
   Windows 上的运行行为（rustls/aws-lc-sys 运行期、socks 入口、direct 出口）
   需真机验证后才可宣称可用。
3. **TUN 未含**：`network.tun` 块 Linux-only（P1-2），Windows 模板刻意不带。
