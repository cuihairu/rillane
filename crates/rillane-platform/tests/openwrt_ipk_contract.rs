//! RIL-042 第一段：OpenWrt ipk 包结构与 procd/init 产物的**真包拆解**核验。
//!
//! RIL-041/042 的真机面（opkg 安装/升级、procd respawn、kmod-tun 数据面、RSS/CPU
//! 上限）归 OpenWrt 机批次未跑，本段只钉**本机已产 ipk 的可拆解结构事实**：
//! 真包 ar 三成员齐备且数据 tar 可解、control 齐字段、conffiles 声明升级保留面、
//! postinst 首装落配置幂等、init.d 脚本 procd 契约要素（USE_PROCD/respawn/
//! respawn 参数/env 注入/config_get 开关/limits）、两个二进制存在且 ELF、
//! 示例配置在场——把 `build.sh` 声称的产物形状从「日志记录」提升为「结构断言」。
//!
//! 诚实边界：不跑 procd 托管、不验真机升级语义、不测吞吐/RSS 上限；
//! run_verification 仍为 needs_device，勾选保持关闭。

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

/// 解包真 ipk 到临时目录并返回目录路径；缺 `ar`/`tar` 即跳过（不冒充实测）。
struct IpkUnpack {
    dir: PathBuf,
    _members: Vec<Vec<u8>>,
}

impl IpkUnpack {
    fn unpack() -> Option<Self> {
        if Command::new("ar")
            .arg("t")
            .arg("/dev/null")
            .output()
            .is_err()
        {
            return None; // 无 ar
        }
        if Command::new("tar").arg("--version").output().is_err() {
            return None; // 无 tar
        }
        let dir = std::env::temp_dir().join(format!(
            "rillane-openwrt-ipk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("临时目录");
        let ipk = repo_root().join("dist/openwrt/rillane_0.1.0-1_x86_64.ipk");
        if !ipk.is_file() {
            return None; // 未构建产物（CI 无 dist）——不冒充实测
        }
        let out = Command::new("ar")
            .arg("x")
            .arg(&ipk)
            .current_dir(&dir)
            .output()
            .expect("ar 解包");
        assert!(out.status.success(), "ar 解包失败：{out:?}");
        let mut members = Vec::new();
        for name in ["debian-binary", "control.tar.gz", "data.tar.gz"] {
            let p = dir.join(name);
            assert!(p.is_file(), "ipk 缺成员 {name}（build.sh 三成员契约）");
            members.push(std::fs::read(&p).expect("读成员"));
        }
        // 解 control 与 data
        for (tarball, subdir) in [("control.tar.gz", "control"), ("data.tar.gz", "data")] {
            std::fs::create_dir_all(dir.join(subdir)).expect("解包子目录");
            let out = Command::new("tar")
                .args(["-xzf"])
                .arg(dir.join(tarball))
                .current_dir(dir.join(subdir))
                .output()
                .expect("tar 解包");
            assert!(
                out.status.success(),
                "tar 解 {tarball} 失败：{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Some(Self {
            dir,
            _members: members,
        })
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join(rel))
            .unwrap_or_else(|e| panic!("读解包内容 {rel}: {e}"))
    }

    fn exists(&self, rel: &str) -> bool {
        self.dir.join(rel).is_file()
    }
}

impl Drop for IpkUnpack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn real_ipk_structure_matches_build_contract() {
    let Some(ipk) = IpkUnpack::unpack() else {
        eprintln!("skip: 本机无 ar/tar 或 dist/openwrt ipk 未构建——结构面未实测");
        return;
    };

    // ---- 成员：deb 版本号 + control/conffiles/postinst 齐件 ----
    assert_eq!(ipk.read("debian-binary").trim(), "2.0");
    let control = ipk.read("control/control");
    for field in [
        "Package: rillane",
        "Version: 0.1.0-1",
        "Depends: libc, kmod-tun",
        "Architecture: x86_64",
        "Section: net",
        "Maintainer:",
        "Installed-Size:",
        "Description:",
    ] {
        assert!(
            control.contains(field),
            "control 缺字段「{field}」\n{control}"
        );
    }

    // ---- conffiles：升级保留面只含 /etc/rillane.yaml ----
    let conffiles = ipk.read("control/conffiles");
    assert_eq!(
        conffiles.trim(),
        "/etc/rillane.yaml",
        "conffiles 须只声明升级保留配置，实际：{conffiles:?}"
    );

    // ---- postinst：首装落模板（存在才覆盖）+ enable ----
    let postinst = ipk.read("control/postinst");
    assert!(
        postinst.contains("[ -f /etc/rillane.yaml ] || cp"),
        "postinst 缺首装幂等落配置：{postinst}"
    );
    assert!(
        postinst.contains("/etc/init.d/rillane enable"),
        "postinst 缺开机自启 enable：{postinst}"
    );

    // ---- data 面：两个二进制 + init.d 脚本 + 示例配置 ----
    assert!(ipk.exists("data/usr/bin/rillaned"), "缺 rillaned 二进制");
    assert!(
        ipk.exists("data/usr/bin/rillanectl"),
        "缺 rillanectl 二进制"
    );
    assert!(ipk.exists("data/etc/init.d/rillane"), "缺 procd init 脚本");
    assert!(
        ipk.exists("data/usr/share/rillane/rillane.yaml.example"),
        "缺示例配置"
    );

    // ---- init.d 脚本：procd 契约要素 ----
    let init = ipk.read("data/etc/init.d/rillane");
    for needle in [
        "USE_PROCD=1",
        "START=99",
        "STOP=10",
        "start_service",
        "procd_open_instance",
        r#"procd_set_param command "$PROG""#,
        r#"procd_set_param env RILLANE_CONFIG="$CONF""#,
        "procd_set_param respawn",
        "procd_set_param stdout 1",
        "procd_set_param stderr 1",
        r#"procd_set_param limits core="0 0""#,
        "procd_close_instance",
        "config_load rillane",
        "config_get enabled",
    ] {
        assert!(
            init.contains(needle),
            "init.d 脚本缺 procd 要素「{needle}」"
        );
    }
    // 配置缺失不得静默起服务（半接管拒绝）
    assert!(
        init.contains("[ -f \"$CONF\" ]"),
        "init.d 须校验配置文件存在（缺配置不得起服务）"
    );
}

/// 仓库内 init.d 脚本与 ipk 内同形（ipk 装的就是这份）——防装配面漂移。
#[test]
fn repo_init_script_matches_ipk_content() {
    let Some(ipk) = IpkUnpack::unpack() else {
        eprintln!("skip: 本机无 ar/tar 或 dist/openwrt ipk 未构建");
        return;
    };
    let in_pkg = ipk.read("data/etc/init.d/rillane");
    let in_repo = read_text("platforms/openwrt/init.d/rillane");
    assert_eq!(
        in_pkg.trim(),
        in_repo.trim(),
        "ipk 内 init.d 与仓内源不一致（装配漂移）"
    );
}
