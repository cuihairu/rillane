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
