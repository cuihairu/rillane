# platforms/systemd —— Linux systemd + deb 打包

systemd unit + deb 组装产线。设计定稿与验证分层见
[docs/design/architecture-v1.md](../../docs/design/architecture-v1.md) §2/§5。

## 模板清单

| 文件 | 落位（deb 内） | 说明 |
|---|---|---|
| `rillane.service` | `/lib/systemd/system/rillane.service` | `Type=simple` + 专用系统用户 `rillane` + `Environment=RILLANE_CONFIG=/etc/rillane/rillane.yaml`（rillaned 无 `--config` 旗标）+ `Restart=on-failure` + 硬化旗标组 |
| `build.sh` | —（产线） | 原生 amd64 + cross arm64 → `dist/deb/rillane_<版本>_ {amd64,arm64}.deb`；file 静态核验 + dpkg 布局断言 + 抽取冒烟全入 `.build-log.txt` |
| `rillane.yaml.example` | `/etc/rillane/rillane.yaml.example` | 装机最小可运行模板（socks 入口 + direct 出口 + DNS 分流）；示例文件自身登记 conffile（升级不覆盖），真配置由部署者 cp 落位 |

deb 维护脚本（build.sh 内联）：`postinst`（建系统用户 → chown → daemon-reload → **只 enable 不 start**）、`prerm`（stop + disable，保留配置）。

## 用法

```bash
# 构建（缺省 amd64+arm64 双目标；产物 dist/deb/）
platforms/systemd/build.sh

# 安装（部署机）
sudo dpkg -i rillane_0.1.0-1_amd64.deb
sudo install -m644 /etc/rillane/rillane.yaml.example /etc/rillane/rillane.yaml
sudoedit /etc/rillane/rillane.yaml          # 先改 admin_token
sudo systemctl start rillane
journalctl -u rillane -f                 # 日志走 journal（telemetry.log_level 可调）
```

## 硬化与能力面

- unit 缺省授予 `CAP_NET_BIND_SERVICE`（低端口入口）+ `CAP_NET_ADMIN`（TUN 面，
   已落地）。**纯代理部署建议收窄**：

  ```bash
  sudo systemctl edit rillane
  # 覆写两行，去掉 CAP_NET_ADMIN：
  #   [Service]
  #   AmbientCapabilities=CAP_NET_BIND_SERVICE
  #   CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  ```

- **有意不设 `MemoryDenyWriteExecute=yes`**：wasmtime JIT（ 插件面）需要
  W→X 映射代码页，设了插件即失效——若部署不用插件且要此项硬化，drop-in 自行
  开启即可。
- `ProtectSystem=strict` + `PrivateTmp` + `NoNewPrivileges` 等常规硬化已开；
  `SystemCallFilter` 未设（误伤面评估归后续，设计 §6 边界 4）。

## 验证边界（脚本、产物、运行与真机分别记录）

| 层 | 内容 | 状态 |
|---|---|---|
| L1 脚本结构 | build.sh 语法（bash -n） | 本机已验 |
| L2 静态核验 | file ELF 架构 + dpkg-deb -I/-c 布局断言 + 维护脚本齐 | 本机已验 |
| L3 运行冒烟 | 抽取布局 `rillaned --version`（amd64 native + arm64 qemu-user） | 本机已验 |
| L4 真机面 | `dpkg -i` + postinst 用户面 + systemd enable/start/restart | **需真实 Debian/Ubuntu 环境未验** |

注意：L4 中 postinst/systemd 交互（useradd、daemon-reload、enable）按 Debian
打包惯例手写，未经 lintian/pipeline 校验；进发行仓前建议过一遍 `lintian`。
