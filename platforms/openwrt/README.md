# SEEP OpenWrt 包（P3-3）

musl 静态交叉编译 + ipk 组装。目标形态：路由器上 `opkg install seep_*.ipk`，
`/etc/init.d/seep start` 即起 daemon（procd 托管，配置 `/etc/seep.yaml`）。

## 构建矩阵

| rust triple | OpenWrt DISTRIB_ARCH（代表值） | 说明 |
|---|---|---|
| `aarch64-unknown-linux-musl` | `aarch64_generic` | MT7622/IPQ807x/ Filogic 等新平台 |
| `armv7-unknown-linux-musleabihf` | `arm_cortex-a7_neon-vfpv4` | MT7623/sunxi 等老 armv7 |
| `x86_64-unknown-linux-musl` | `x86_64` | x86 软路由 |

实际设备的架构名按 `/etc/openwrt_release` 的 `DISTRIB_ARCH` 用环境变量覆盖
（映射表见 `build.sh::openwrt_arch`，如 `ROUTER_ARCH_AARCH64_UNKNOWN_LINUX_MUSL=aarch64_cortex-a76`）——
ipk 的 `Architecture` 字段不符时 opkg 拒装，覆盖后重打包即可。

**mips / mipsel（32 位 MIPS，MT7621/ath79 一代经典）不在当前矩阵**：
1. rust 自 1.8x 起不再分发 mips/mipsel musl 预编译 `rust-std`（两端序皆弃，
   `rustup target add` 即报 no prebuilt artifacts）；
2. rustls 默认密码学后端 aws-lc-sys 不支持 mips（AWS-LC 无该架构汇编/构建面），
   需切 ring 供给（`tls_crypto_provider()` 运行时已支持 ring，构建期特征
   仍默认拉 aws-lc-rs）。

落地路径：nightly `-Z build-std` + workspace rustls 特征集 ring 化，另行
提交；登记为边界而非承诺。

## 用法

```sh
# 全量三目标（需 docker + cross + rustup）
platforms/openwrt/build.sh
# 单目标
platforms/openwrt/build.sh aarch64-unknown-linux-musl
# 产物与核验记录
ls dist/openwrt/
cat dist/openwrt/.build-log.txt   # file/readelf 静态核验 + ar 结构
```

装机：

```sh
scp dist/openwrt/seep_*_<arch>.ipk root@router:/tmp/
ssh root@router opkg install /tmp/seep_*.ipk
# 首次：模板落地 /etc/seep.yaml（postinst），按需编辑后
/etc/init.d/seep enable && /etc/init.d/seep start
```

ipk 内容：`/usr/bin/seepd`、`/usr/bin/seepctl`、`/etc/init.d/seep`（procd，
respawn + UCI `seep.@general[0].enabled` 预留开关）、`/usr/share/seep/seep.yaml.example`
（首装复制为 `/etc/seep.yaml`，conffile 语义——升级保留本地改动）。
Depends：`libc, kmod-tun`（TUN 虚拟化面；仅 socks 入口 + DNS 监听可不装 kmod-tun，
`network` 块缺席即可）。LuCI 页面后置（见 todo P3-3 注记）。

## 验证边界（如实说明）

本仓产线能验的与不能验的：

**已验（`build.sh` 内建）**
- 三目标 `cross build --release` 零失败；二进制 `file` 确认 static（musl 面
  无 interpreter/NEEDED 动态段）；`readelf -d` 复核；
- ipk 结构：ar 三成员（debian-binary / control.tar.gz / data.tar.gz）序与
  可解性、control 字段齐备、conffiles/postinst 就位。

**未验（需要真机或目标架构仿真环境）**
- 真机 opkg 安装/升级路径（DISTRIB_ARCH 命中、conffile 升级保留语义）；
- procd 托管下的起停/respawn 行为；
- TUN 数据面在 MIPS/ARM 内核上的吞吐与 kmod-tun 交互。

宿主机有 qemu-user 时可加跑冒烟（`qemu-aarch64-static target/aarch64-.../release/seepd --version`）；
CI/真机到位后在 todo P3-3 注记回填。
