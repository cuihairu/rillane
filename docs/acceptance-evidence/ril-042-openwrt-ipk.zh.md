# RIL-042 OpenWrt ipk 结构（第一段，2026-11-27）

门禁：`crates/rillane-platform/tests/openwrt_ipk_contract.rs`（2 测）。对真实
构建产物 `dist/openwrt/rillane_0.1.0-1_x86_64.ipk` 用 `ar x` + `tar -xzf`
拆包，断言 `platforms/openwrt/build.sh` 声称的结构。无 `dist/openwrt/*.ipk`
（干净 CI 检出）时打印 skip，不冒充实测、不伪造通过。

## 对真包钉死的事实

1. `ar` 成员：`debian-binary` 为 `2.0`，加 `control.tar.gz`、`data.tar.gz`；
   两个 tar 均可解包。
2. `control`：`Package: rillane`、`Version: 0.1.0-1`、`Depends: libc, kmod-tun`、
   `Architecture: x86_64`、`Section: net`、`Maintainer:`、`Installed-Size:`、
   `Description:`。
3. `conffiles` 恰声明 `/etc/rillane.yaml`（升级保留面）。
4. `postinst` 首装幂等（`[ -f /etc/rillane.yaml ] || cp`）并 enable 开机自启
   （`/etc/init.d/rillane enable`）。
5. `data`：`usr/bin/rillaned`、`usr/bin/rillanectl`、`etc/init.d/rillane`、
   `usr/share/rillane/rillane.yaml.example`。
6. `init.d` 的 procd 契约：`USE_PROCD=1`、`START=99`、`STOP=10`、
   `start_service`、`procd_open_instance`、`procd_set_param command "$PROG"`、
   环境 `RILLANE_CONFIG="$CONF"`、`respawn`、`stdout 1`、`stderr 1`、
   `limits core="0 0"`、`procd_close_instance`、`config_load rillane` +
   `config_get enabled`，以及配置文件存在性守卫（`[ -f "$CONF" ]`）——
   缺配置不得静默起服务。
7. 包内 `init.d` 与 `platforms/openwrt/init.d/rillane` 逐字同形（trim 后）——
   装配漂移即失败。

## 执行面运维语义（第二段）

postinst 与 init.d 在临时根下用 `sh` **真跑**：平台专有命令
（`logger`/`config_get`/`procd_*`）替换为记录调用的桩，分支逻辑跑的仍是
包内脚本本体。钉死：

1. `postinst` 首装把示例配置落到 `/etc/rillane.yaml`；运维改过配置后再次
   执行**不覆盖**改动（脚本层面的升级 conffile 保留）。
2. `init.d start_service` 在 `enabled=0` 下零 procd 事件。
3. `enabled=1` 且 `config_load` 缺席（首次开机）照常起服务：config_get
   问了 enabled 值、procd_open/close 包住 `command "$PROG"`、
   `env RILLANE_CONFIG=...`、`respawn 3600 5 0`、`stdout 1`、`stderr 1`、
   `limits core=0 0`。
4. 缺配置 → 具名拒绝（退出 1 + 日志行），零 procd 事件。
5. `reload_service` = 先 `stop` 后 `start`，按此精确顺序记录。

脚本只做了路径本地化（绝对路径 `/etc/...`、`/usr/...` 改写到沙箱根）；
分支与参数一律不改写，不是另写的模拟脚本。

## 复现

```sh
bash platforms/openwrt/build.sh          # 产出 dist/openwrt/*.ipk
cargo test -p rillane-platform --test openwrt_ipk_contract
```

## 如实边界

这是**包结构契约**，不是真机验收。仍未跑：路由器上的真实 `opkg` 安装/升级
语义、procd 托管的起停与 respawn、kmod-tun 数据面、fw4 下的 nftables 规则
生效/撤销，以及实测 RSS/CPU/吞吐上限。这些归 OpenWrt 机批次，RIL-042 勾选
保持关闭。本门也不断言二进制静态链接（构建日志仅记录 `file`/`readelf` 输出）。
