# P3-3 平台打包（systemd / launchd / Windows Service 模板）— 实现级设计

> 上游：[roadmap.md](roadmap.md) 原 §6（平台适配）· [todo.md](../../../todo.md) P3-3 ·
> 先例：[platforms/openwrt/](https://github.com/cuihairu/rillane/tree/main/platforms/openwrt/)（2026-10-02 已落地半边：musl 静态交叉 + ipk + procd init.d，其产线约定与验证分层是本文的复用基线）。
> 本文是落地定稿：**三平台交付物形态、验证层级（模板验证 ≠ 真机验证，逐层如实登记）、unit/plist/service 脚本内容、deb/zip/tar 打包产线、边界登记**。落地后偏差回填 §9。

## 0. 范围

| 在本条目内 | 归其他条目 |
|-----------|-----------|
| `platforms/systemd/`：`rillane.service` unit + deb 组装产线（rillaned/rillanectl + conffile + postinst/prerm）+ 配置示例 | P3-5 零拷贝（已落地 2026-10，与打包产线无耦合，见 performance-io.md）；libloading 动态库直载崩溃隔离（V2，随 P3-2 裁决） |
| `platforms/launchd/`：`com.rillane.rillaned.plist` + macOS 原生 build.sh（universal2）+ install.sh（脚本级，结构可验） | darwin 交叉编译产出 Mach-O（Apple SDK 再分发限制，同 CI 排除口径；待 macOS runner 原生跑） |
| `platforms/windows/`：cross windows-gnu 产线 + zip 交付包 + `install-service.ps1`/`uninstall-service.ps1`（sc.exe 模板级） | Windows 真 SCM 协议集成（`windows-service` crate 让 rillaned 自报 SERVICE_RUNNING——归后续增量，§3.3） |
| `platforms/README.md` 矩阵回填 + todo P3-3 勾选注记 | CI 矩阵改动（打包脚本属发布工具，本地验证；windows-gnu build 已在 CI） |

**验收口径前置说明（对齐 P1-4 显式改写做法，不静默缩水）**：todo P3-3 验收「Linux/macOS/Windows 三平台产出可安装二进制；OpenWrt 出 musl 静态包」——OpenWrt 半边已落地（2026-10-02，三 ipk + 三目标冒烟全过）。本轮三半边的可验口径：

1. **Linux**：deb 全链本机可验——native amd64 构建 → dpkg-deb 组装 → `dpkg-deb -I/-c` 结构核验 → `dpkg -x` 抽取 → 抽取布局直接跑 `rillaned --version`；aarch64 交叉产包 + qemu-user 冒烟（复用 OpenWrt 先例）。
2. **Windows**：cross windows-gnu 产物（CI 已证 aws-lc-sys 在该目标可编）→ PE 头静态核验 → zip 布局断言；**真机服务安装/启动不在本机能力面**（§3.3 如实登记）。
3. **macOS**：脚本与 plist 结构验证（`bash -n` + python3 plistlib）；**Mach-O 产物本机不产**（与 CI darwin 排除同一限制），登记为「脚本级交付，产物待原生环境」。

「可安装」在 Linux 侧取最严口径（真 deb 且可抽取可运行），Windows/macOS 取交付包结构完备口径，真机安装面归后续。

## 1. 现状与约束（核对结论，非重述）

### 1.1 rillaned CLI 形状 → 模板一律环境变量注入

- 无 clap：`--version`/`-V` 在 `apps/rillaned/src/main.rs:13` 对 `args[1]` 短路（配置加载前），`--help` 会真启动（报 mTLS 要求错）——**打包脚本冒烟只可用 `--version`，不可用 `--help`**；
- 配置路径唯一入口是环境变量 `RILLANE_CONFIG`（`main.rs:46`，缺省相对路径 `config/rillane.yaml`），**没有 `--config` 旗标**。systemd 用 `Environment=`、launchd 用 `EnvironmentVariables`、Windows 服务用注册表 `Environment` 键（§3.2）注入——与 OpenWrt init.d（`procd_set_param env`）及根 Dockerfile 同一口径。

### 1.2 证书目录惯例

`rillane-config` 的 `config_dir()` 即 `/etc/rillane`——Linux 布局以 `/etc/rillane/rillane.yaml` 为 conffile、二进制 `/usr/bin/{rillaned,rillanectl}`、unit `/lib/systemd/system/rillane.service`（usr-merge 路径）。

### 1.3 CI 事实

windows-gnu 在 cross-compile 矩阵且绿（aws-lc-sys 0.45 该目标 build script 真编过）；darwin 明确排除（Apple SDK 许可 + cross 官方无 darwin 镜像，注记见 ci.yml）。本机工具面：cross 0.2.5、dpkg-deb、ar、file、readelf、qemu-user（aarch64/armv7 先例）齐备；rustup targets 三平台已装。

### 1.4 OpenWrt 产线约定（逐条复用）

`env -u CARGO_TARGET_DIR`（worktree 私有 target 约定，避免共享幽灵错）· `CARGO_PROFILE_RELEASE_STRIP=symbols` · file/readelf 静态核验入 `.build-log.txt` · mktemp -d stage + trap 清理 · ar 三成员组装（deb 用 dpkg-deb 替代，同属无 root 组装）。

## 2. Linux：systemd unit + deb 产线

### 2.1 `platforms/systemd/rillane.service`

```ini
[Unit]
Description=RILLANE smart egress proxy daemon
Documentation=https://github.com/cuihairu/rillane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rillane
Group=rillane
# rillaned 无 --config 旗标（§1.1）：配置路径环境变量注入
Environment=RILLANE_CONFIG=/etc/rillane/rillane.yaml
ExecStart=/usr/bin/rillaned
Restart=on-failure
RestartSec=5
# 最低权限面：低端口绑定（入口 0-1023）+ TUN 设备创建（P1-2 已落地）
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictRealtime=yes
# 注：不设 MemoryDenyWriteExecute=yes——wasmtime JIT（P3-2 插件面）需要
# W→X 映射的代码页，该旗标会使插件载入/实例化失败（§6 边界）。
# 注：不设 SystemCallFilter——过紧易误伤 aws-lc-sys/io_uring 面，硬化收紧归后续。

[Install]
WantedBy=multi-user.target
```

裁决三点：

1. **`CAP_NET_ADMIN` 进 bounding/ambient set**：TUN 面（P1-2 已落地）需创建/配置 `rillane0`；纯 socks 入口部署可在 drop-in（`systemctl edit rillane`）收窄为仅 `CAP_NET_BIND_SERVICE`——unit 缺省按全功能口径给齐，README 注明收窄法。
2. **`Type=simple` + `Restart=on-failure`**：rillaned 前台常驻（同 OpenWrt procd 口径）；崩溃退避 5s。
3. **user 建立归 postinst**（`getent`/`useradd --system`），unit 只引用——unit 文件本身保持可纯复制使用。

### 2.2 deb 布局与维护脚本

```
/usr/bin/rillaned                  0755
/usr/bin/rillanectl                0755
/etc/rillane/rillane.yaml.example     0644   （示例；真配置由部署者落位，避免覆盖）
/lib/systemd/system/rillane.service 0644
DEBIAN/control                          Package: rillane; Version: 0.1.0-1; Architecture: amd64|arm64
DEBIAN/conffiles                        /etc/rillane/rillane.yaml.example（示例文件登记 conffile）
DEBIAN/postinst                         建系统用户 rillane → chown /etc/rillane → daemon-reload → enable（不 start）
DEBIAN/prerm                            stop + disable（保留配置）
```

裁决：

- **包内只带 `rillane.yaml.example` 不带真配置**：装包即自动起服务不是本包策略（配置含 token/上游凭据，须部署者显式落位）；`conffiles` 登记**示例文件自身**（真配置由部署者 `cp` 自示例，不受包管辖）。※设计期原拟登记缺席的真配置路径，新版 `dpkg-deb --build` 严格校验 conffile 必须在包数据内而拒绝——偏差见 §9。postinst 只 enable 不 start——「装完即跑」留给部署者 `systemctl start rillane`，避免无配置状态反复重启刷屏。
- **Architecture 映射**：`x86_64`→`amd64`、`aarch64`→`arm64`（Debian triplet 口径）。
- **无 root 组装**：`dpkg-deb --build --root-owner-group`（fakeroot 语义内建），与 OpenWrt ar 组装同属免 sudo 产线。
- **Depends 留空**：gnu 目标动态链 libc6，版本约束不硬编码（Debian 老旧发行版容忍面更宽）；kmod-tun 之类的内核模块依赖属 OpenWrt ipk 语义，deb 侧以 Recommends 缺省不声明、README 注明 TUN 需内核 `/dev/net/tun`。

### 2.3 build.sh 验证链（`.build-log.txt` 落痕，同 OpenWrt 约定）

每目标：cross/native build → file ELF 核验 → dpkg-deb 组装 → `dpkg-deb -I`（control 面断言）+ `dpkg-deb -c`（布局断言：四产物 + DEBIAN 脚本齐）→ `dpkg -x` 抽取 → 抽取布局跑 `usr/bin/rillaned --version` 期望 `rillaned 0.1.0`（native 直接跑；aarch64 经 `qemu-aarch64 -L /usr/aarch64-linux-gnu`）。systemd 真机 enable/start 面不在本机能力面（无 systemd 权限面），登记 §6。

## 3. Windows：cross 产线 + 服务脚本模板

### 3.1 交付形态

`cross build --release --target x86_64-pc-windows-gnu`（CI 同款目标）→ 产物 `rillaned.exe`/`rillanectl.exe` → zip 交付包：

```
rillane_0.1.0_x86_64_windows.zip
├── rillaned.exe                PE32+ x86-64（file 核验）
├── rillanectl.exe
├── rillane.yaml.example
├── install-service.ps1
├── uninstall-service.ps1
└── README.txt               安装/边界速览（指向仓内 platforms/windows/README.md）
```

### 3.2 `install-service.ps1`（sc.exe 模板级）

- `sc.exe create rillane binPath= "<安装目录>\rillaned.exe" start= auto DisplayName= "RILLANE Proxy"` + `sc.exe failure rillane reset= 86400 actions= restart/5000/restart/5000/restart/30000`（崩溃恢复三段退避，systemd `Restart=on-failure` 对应面）；
- 配置路径注入走**服务级注册表 Environment**：`New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\rillane -Name Environment -PropertyType MultiString -Value "RILLANE_CONFIG=C:\ProgramData\rillane\rillane.yaml"`——`sc.exe` 无环境参数面（§1.1 同因）；
- `New-Service` 亦可但 failure 恢复设置仍须落 `sc.exe failure`，故直用 sc.exe 全程一致。

### 3.3 SCM 1053 caveat（本轮模板级的原因，如实登记）

rillaned 是普通控制台程序，**不与 SCM 交互**（不调 `StartServiceCtrlDispatcher`、不报 SERVICE_RUNNING）：`sc.exe create` 能成功、服务项能配置，但 `sc.exe start rillane` 会被 SCM 在 30 秒内判 **错误 1053**（服务未及时响应启动请求）并停止——SCM 要求服务进程在启动后立即连入控制管道。两条正解归后续：

1. **`windows-service` crate** 让 rillaned 原生实现 SCM 协议（windows 目标专属 main 分支）——登记为后续增量；
2. **外部包装器** WinSW/NSSM（把任意 exe 包成 SCM 服务）——README 提供注记，属部署侧选择，不入仓。

本脚本可验面（本机）：PowerShell 语法结构、zip 布局、PE 头；真机 `sc.exe` 行为需 Windows，登记边界。

## 4. macOS：launchd plist + 原生产线（脚本级）

### 4.1 交付形态

`platforms/launchd/build.sh` **设计为 macOS 原生运行**：`cargo build --release` × (aarch64-apple-darwin, x86_64-apple-darwin) → `lipo -create` universal2 → tar.gz：

```
rillane_0.1.0_macos_universal2.tar.gz
├── rillaned                    Mach-O universal2（lipo -info 核验）
├── rillanectl
├── com.rillane.rillaned.plist
├── install.sh
├── uninstall.sh
└── rillane.yaml.example
```

**本机（Linux）验证层级**：`bash -n` 语法核验 + plist 结构验证（python3 `plistlib` 解析 + 键面断言）。Mach-O 产物本机不产（§0 口径 3），build.sh 的 cargo/lipo 调用面以脚本审读 + 语法核验交付，实跑待 macOS。

### 4.2 `com.rillane.rillaned.plist`（LaunchDaemon 面）

- `Label=com.rillane.rillaned`；`ProgramArguments=(/usr/local/bin/rillaned)`；
- `EnvironmentVariables={RILLANE_CONFIG: /usr/local/etc/rillane/rillane.yaml}`（§1.1 同因；macOS 侧配置惯例 `/usr/local/etc/rillane/`，与 Linux `/etc/rillane` 分叉是有意选择——Homebrew 惯例路径）；
- `RunAtLoad=true` + `KeepAlive={SuccessfulExit=false}`（异常退出才拉起，对齐 `Restart=on-failure` 语义；正常 `rillanectl` 触发的干净退出不扯皮）+ `ThrottleInterval=5`；
- `StandardOutPath`/`StandardErrorPath=/usr/local/var/log/rillaned.log`；`ProcessType=Background`；
- 装载：`sudo launchctl bootstrap system <plist>`（macOS 10.11+ 弃用 `-w load` 老语法）+ `launchctl kickstart system/com.rillane.rillaned`。

## 5. 测试策略与验证落点

分层口径（「模板测试落点」即本节——谁验哪层，简报按此报告）：

| 层 | 内容 | 落点 | 本轮状态 |
|---|---|---|---|
| L1 脚本结构 | `bash -n` 全部 build.sh/install 脚本；plistlib 解析 plist + 键断言；ps1 语法结构审读 | 本机 Linux | **全跑** |
| L2 产物静态核验 | file（ELF x86-64/ARM aarch64、PE32+ x86-64）+ readelf（musl 面已在 OpenWrt 侧，本轮 gnu 面查 interpreter）+ zip/deb 布局断言 | 本机 Linux | **全跑**（linux amd64/arm64 + windows 三面） |
| L3 运行冒烟 | 抽取布局 `rillaned --version`；native 直接跑 + aarch64 qemu-user | 本机 Linux | **全跑**（amd64 native + arm64 qemu） |
| L4 真平台面 | systemd enable/start 真机、launchctl 装载、SCM 真启动 | 需对应平台 | **登记边界**（§6） |

单测面：本轮零 Rust 源码改动（纯模板/脚本/文档），`cargo test --workspace` 门禁照跑防回归；脚本侧断言全部在 build.sh 内联（非测试框架）——与 OpenWrt build.sh 同法（`.build-log.txt` 供事后审计）。

## 6. 边界登记（不静默缩水）

1. **darwin 交叉产出不做**：Apple SDK 再分发限制（同 CI darwin 排除口径）；macOS 半边 = 脚本级交付 + plist 结构验证，Mach-O 实产与 launchctl 实装待 macOS runner/真机。
2. **Windows SCM 真服务化归后续**：`windows-service` crate 集成（§3.3）；本轮 zip + sc.exe 模板可装配可配置，`sc start` 受 1053 限制；WinSW/NSSM 注记于 README。
3. **`MemoryDenyWriteExecute` 与 wasmtime JIT 冲突**：unit 有意不设该旗标（§2.1 注）；若部署收窄启用，插件面（P3-2）即失效——两难同真，留部署者裁决。
4. **`SystemCallFilter` 不设**：过紧易误伤 aws-lc-sys syscall 面；硬化收紧（含 seccomp profile 文件化）归后续。
5. **CAP_NET_ADMIN 缺省授予**：TUN 全功能口径；纯代理部署应 drop-in 收窄（README 给法）。
6. **CI 矩阵不动**：打包脚本属发布工具、本地验证；windows-gnu build 已在 CI 守护。
7. **P3-5 零拷贝已落地（2026-10，与打包产线无耦合）；libloading 崩溃隔离归 V2**（调度明示不动）。

## 7. 分步清单

- **R0**：本文设计稿。
- **R1**：`platforms/systemd/`（rillane.service + build.sh deb 产线 + rillane.yaml.example + README）+ 实况 L1–L3（amd64 native 全链 + arm64 cross+qemu）。
- **R2**：`platforms/windows/`（build.sh zip 产线 + ps1 ×2 + README）+ `platforms/launchd/`（build.sh + plist + install/uninstall.sh + README）+ 实况 L1–L2（windows 全链 + macos 脚本/plist 面）。
- **R3**：platforms/README.md 矩阵回填 + todo P3-3 勾选注记 + 全门禁（fmt/clippy/test）→ commit（引用本文 §节）→ fetch+rebase → push → 简报（模板清单 + 测试落点）。

## 9. 落地偏差回填（2026-10-04 实施收口）

1. **conffiles 登记缺席路径被拒**（§2.2 偏差）：新版 `dpkg-deb --build` 严格校验
   conffile 必须在包数据内，登记 `/etc/rillane/rillane.yaml`（包内不带）报
   `conffile does not appear in package`——改为登记包内真实存在的
   `/etc/rillane/rillane.yaml.example`，语义等价（示例文件升级不覆盖，真配置 cp 自
   示例天然不受包管辖）。§2.2 正文已同步改写。
2. **windows-gnu 编译破损（先于本轮，随本轮修复）**：P1-2 TUN 落地时
   `rillane-runtime/src/tun_ingress.rs` 的 `rillane_platform::network::linux` import
   无门控，x86_64-pc-windows-gnu 编译 E0432（CI Cross compile windows leg
   连红数轮）。修法即 §5 分层之外的正交面：TUN 三模块（tun_ingress /
   tun_process / tun_tcp）整体 `#[cfg(target_os = "linux")]`；runtime_builder
   装配/字段/stop/getter 双版本（非 Linux 配置了 TUN 显式 Err、未配置恒 None，
   口径同 network 四工厂）；`TunIngressStats` 独立平台无关模块 `tun_stats.rs`
   （控制面 `rillane_tun_*` 恒渲染口径 §2.8 不变）；control_plane 路由三端点
   非 Linux 恒 503（语义同 TUN 未装配分支）。windows-gnu `cross check
   --all-targets` 修后零警告。
3. **file 输出措辞浮动**（§2.3/§3.1 偏差）：native gnu 产物是 `ELF 64-bit LSB
   pie executable`（原断言 `LSB executable` 不匹配）；file 对 PE 报
   `PE32+ executable for MS Windows 5.02 (console), x86-64`（词序与措辞随
   file 版本浮动）——静态核验全部改为**宽断言拆分**（`ELF 64-bit LSB` +
   架构子串 / `PE32+ executable` + `x86-64`）。
4. **`grep -q` 断言在 pipefail 脚本里误杀**（产线教训）：`cmd | tee | grep -q`
   / `dpkg-deb -c | grep -q` 组合里 `-q` 匹配即退出，上游进程收 SIGPIPE
   （tee 死、dpkg-deb 报 `tar subprocess was killed by signal (Broken pipe)`），
   `set -euo pipefail` 下整链 141/非零——与断言内容无关的假失败。根治：断言
   grep 一律去 `-q` 改 `> /dev/null`（全量读入），三产线脚本统一。
5. **XML 注释不可含 `--`**（§4.2 教训）：plist 头注释里写 `--config` 字样使
   expat 解析 `not well-formed`——plistlib 结构断言（L1）当场拦截；措辞改
   「无 config 命令行旗标」。
6. **实况数据**：deb `rillane_0.1.0-1_{amd64,arm64}.deb` 双产出——`dpkg-deb -I/-c`
   布局断言（四产物 + control/conffiles/postinst/prerm）+ `dpkg-deb -x` 抽取
   布局 `rillaned 0.1.0` 冒烟（amd64 native + arm64 `qemu-aarch64 -L
   /usr/aarch64-linux-gnu`）全过，`.build-log.txt` 落痕；windows zip
   `rillane_0.1.0_x86_64_windows.zip`（六件，rillaned.exe 38.9MB / rillanectl.exe
   15.0MB，PE32+ x86-64）布局断言过；launchd L1（bash -n ×3 + plistlib 键面
   断言）过。门禁：`cargo fmt --check` + `clippy --workspace --all-targets
   --all-features` 零警告 + `cargo test --workspace` 261 项 0 failed 全绿。
