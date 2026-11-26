# 安装、恢复、Debug 与 MCP 示例

本页把运维示例与仓内真实产物对齐。它不是新验收声明：**构建/交叉编译 ≠ 本地契约门 ≠ 真机验收**。各平台当前状态见 [平台支持与交付状态](platform-support.md) 与 [验收证据索引](acceptance-evidence/README.md)。下列命令面均为真实 CLI/daemon/MCP 旗标；具名缺口保持缺口。

## 运行前先看三层

- **产物层** — `cargo build`、交叉构建、文件/布局核验与契约测试。它们只证明二进制或模板存在，不证明该主机上有流量转发。
- **本地门层** — `cargo test --workspace`（含对真实二进制的 REST/help/schema 契约门）。它们只证明文档面、机器账本与产物一致，不证明设备接受了流量。
- **真机层** — 目标 OS/路由器上的安装、接管、身份、重启与流量。只有真机证据文档能关掉本层。

## 各宿主安装与恢复

### 本地源码运行（Linux 开发机）

```bash
cargo run -p rillaned                       # 读 RILLANE_CONFIG，缺省 config/rillane.yaml
cargo run -p rillanectl -- --help           # -c/--config 选择 CLI 配置文件
cargo run -p rillanectl -- stats            # 需要运行中的控制面
```

`rillaned` 没有 `--config` 旗标。用别的文件需设环境变量：

```bash
RILLANE_CONFIG=/etc/rillane/rillane.yaml rillaned
rillanectl -c /etc/rillane/rillane.yaml stats
```

恢复就是进程重启；配置启动一次读入。当前守护进程没有 `rillanectl reload`，也没有文件 watch/SIGHUP 热更新。

### Linux systemd + deb 包

模板与验证分层见 `platforms/systemd/README.md`。**安装包只 enable，不 start。**

```bash
platforms/systemd/build.sh                  # 产 dist/deb/rillane_<version>_<arch>.deb
sudo dpkg -i rillane_0.1.0-1_amd64.deb
sudo install -m644 /etc/rillane/rillane.yaml.example /etc/rillane/rillane.yaml
sudoedit /etc/rillane/rillane.yaml          # 暴露控制面前先设 admin_token
sudo systemctl start rillane
journalctl -u rillane -f
```

恢复用 `sudo systemctl status rillane` / `sudo systemctl restart rillane`；unit 注入 `Environment=RILLANE_CONFIG=/etc/rillane/rillane.yaml` 且 `Restart=on-failure`。纯代理部署可用 `systemctl edit rillane` 收窄 `CAP_NET_ADMIN`。本机未做 `dpkg -i` + postinst/systemd 交互的真机层，是具名缺口。

### macOS launchd

`platforms/launchd/build.sh` **必须在 macOS 上跑**（`lipo` universal2）；本机 Linux 只核脚本/plist 结构。

```bash
platforms/launchd/build.sh
tar -xzf dist/launchd/rillane_0.1.0_macos_universal2.tar.gz
cd rillane-0.1.0-macos-universal2
sudo ./install.sh
launchctl print system/com.rillane.rillaned
```

恢复用 `sudo ./install.sh`（配置幂等）或 `sudo ./uninstall.sh` / `sudo ./uninstall.sh --purge` 卸载。plist 注入 `RILLANE_CONFIG=/usr/local/etc/rillane/rillane.yaml`；随包模板无 `network.tun`（Linux-only）。tar 实产、`launchctl bootstrap/kickstart`、universal2 运行均属真机层缺口。

### Windows 服务脚本

`platforms/windows/build.sh` 在 Linux 交叉构建 zip。在 Windows 上解压并用管理员 PowerShell：

```powershell
.\install-service.ps1 -InstallDir "C:\ProgramData\rillane" -ConfigPath "C:\ProgramData\rillane\rillane.yaml"
```

脚本参数：`-InstallDir` / `-ConfigPath`、卸载 `-RemoveConfig`；`RILLANE_CONFIG` 经注册表注入（`sc.exe` 无环境参数面）。**已知缺陷**：`sc.exe start rillane` 命中 SCM 1053，因 `rillaned` 未实现 SCM 控制协议；`windows-service` 集成或外部包装是后续工作。PE 产物与 zip 布局本机已核；服务启动与运行未验。

### OpenWrt ipk

`platforms/openwrt/build.sh` 构建 musl 目标（见其构建矩阵；当前 mips/mipsel 不可构建）。

```sh
scp dist/openwrt/rillane_*_<arch>.ipk root@router:/tmp/
ssh root@router opkg install /tmp/rillane_*.ipk
ssh root@router /etc/init.d/rillane enable && ssh root@router /etc/init.d/rillane start
```

init 脚本经 procd 注入 `RILLANE_CONFIG=/etc/rillane.yaml` 并 respawn。透明接管在 fw4 系 OpenWrt 需 `network.transparent.rule_backend: nft`。opkg 升级/conffile、respawn、nft 接管/撤销需路由器批次；交叉 ipk 不是设备验收。

### Android 与 iOS 边界

```sh
platforms/android/build.sh
adb install -r platforms/android/app/build/outputs/apk/debug/app-debug.apk
adb shell appops set com.rillane.rillane ACTIVATE_VPN allow   # 仅自动化
adb shell ping -c 3 10.111.0.1                               # TUN -> Rust echo -> 内核
```

Android 有 AVD API 33 echo 一轮记录；真机 consent/UI 与 TCP/UDP 代理转发未交付。iOS 只有 Swift/Provider 源码与 macOS 侧 `platforms/ios/build.sh`，无 Xcode 构建与真机运行；Network Extension 需签名 entitlement。两个示例都不能读成移动完整转发。

## Debug 示例

先让守护进程运行，并让 `rillanectl` 可达控制面（`-c` 指向同一文件）。下列四个面均为已实现命令；缺席码与脱敏口径属于 CLI 契约的一部分，不代表每个平台的流量都已真机追踪。

### diagnose — 收集可复核包

```bash
rillanectl diagnose --scope safe --output ./rillane-diagnose-safe
rillanectl diagnose --scope full --output ./rillane-diagnose-full --no-local
```

`safe`（缺省）不含订阅、运行配置与完整日志；`full` 仍剥秘密；`raw` / `--no-redact` 不脱敏落盘，只能留本机（`ai_upload_policy: do-not-upload`）。rillanectl 永不自动上传；分享前查 `meta.json`。

### trace — 真实连接，显式缺席

```bash
rillanectl trace list --state closed --limit 20 --json
rillanectl trace flow <flow-id> --json
rillanectl trace flow <flow-id> --svg
rillanectl trace events <flow-id> --from-seq 0 --limit 200
rillanectl trace inspect <flow-id>
```

用真实 `FlowId`；`/flows` 聚合键不作为流 ID 命中。退出 `0`=有答，`1`=用法/连接错误，`2`=显式缺席（`query.flow.unknown`、`collector.flow.*`、`query.tracing.disabled`）。无记录 ≠ 未发包。trace 读面带详细身份；配置 `admin_token` 时受权限门。

### explain — 纯重演

```bash
rillanectl explain example.com --port 443 --proto tcp --domain-source user_provided --json
rillanectl explain example.com --port 443 --proto tcp --generation <generation> --annotation role=game
```

不做 DNS、拨号或 OS 身份查询；证据缺失逐条列出、结论标注条件性。非法 `--proto` / `--domain-source` 在发请求前即拒。

### probe — 显式网络副作用

```bash
rillanectl probe list --json
rillanectl probe submit --kind connect --addr 203.0.113.1:443 --json
rillanectl probe result <job-id> --json
rillanectl probe cancel <job-id>
```

目标必须在守护进程 `probe.targets` 登记；无 `probe` 块则 `503 probe.disabled`。测量只含执行器实际观测（无回应时 `rtt_ms` 保持 null），不含机场内部路径推断。未知作业 ID 的 `probe result` 退出 `2`。

## 可选 MCP stdio 适配器

适配器默认不启用：无监听端口、无后台进程，需显式启动；stdout 每行一条 JSON-RPC，日志走 stderr。遵循冻结 modern era 版本 `2026-07-28`（逐请求 `_meta` 版本、`server/discover`、无 legacy `initialize` 握手）。

```bash
cargo build -p rillane-mcp -p rillaned -p rillanectl
rillane-mcp --config config/rillane.yaml --scope read --rate-limit 60
rillane-mcp --endpoint http://127.0.0.1:9090 --token "$RILLANE_ADMIN_TOKEN" --scope read,detailed,probe --rate-limit 0
```

真实旗标：`--config/-c`、`--endpoint`、`--token`、`--scope`、`--rate-limit`、`-h/--help`。scope 为 `read`、`detailed`、`probe`、`write`（逗号分隔；缺省 `read`）；`--rate-limit 0` 关闭每分钟窗。授权只来自启动参数——请求声明的 `scope`/`granted` 不能提权，被拒回 `-32001 mcp.scope.denied` 且不执行。凭据只进执行器，不出现在答复/日志。

只读会话这样发现与调用工具（stdin 每行一条消息）：

```json
{"jsonrpc":"2.0","id":1,"method":"server/discover"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"runtime_stats","arguments":{}}}
```

工具目录为冻结 `rillane-app` 边界的 16 个：`runtime_stats`、`routing_quality`、`flow_list`、`flow_trace`、`flow_events`、`flow_svg`、`explain`、`probe_list`、`probe_submit`、`probe_cancel`、`probe_result`、`validate_config`、`preview_config_change`、`apply_config_change`、`rollback_config`、`config_audit`。写工具需 `write` scope 与真实操作员签发的 proposal/approval ID；MCP 适配器绝不自批。EOF 干净退出并释放未了探测作业。

官方 SDK 互操作驱动在 `apps/rillane-mcp/sdk-acceptance/`（固定 `@modelcontextprotocol/sdk@1.32.2`、12 场景、零模型）：

```sh
cd apps/rillane-mcp/sdk-acceptance
npm install
CARGO_TARGET_DIR=<your target dir> node accept.cjs
```

精确通过/失败面见其 `EVIDENCE.md`；SDK 验收是本地契约门，不是设备批准。完整平台状态仍以 [平台支持](platform-support.md) 与 [验收证据索引](acceptance-evidence/README.md) 为准。
