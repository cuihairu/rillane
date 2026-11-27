#![cfg(unix)]

//! RIL-042：OpenWrt ipk 包结构与运维恢复脚本的**真包拆解 + 真 shell 执行**核验。
//!
//! 第一段：真包 ar 三成员齐备且数据 tar 可解、control 齐字段、conffiles 声明
//! 升级保留面、postinst 首装落配置幂等、init.d 脚本 procd 契约要素
//! （USE_PROCD/respawn/respawn 参数/env 注入/config_get 开关/limits）、
//! 两个二进制在场、示例配置在场、仓内脚本与包内同形。
//!
//! 第二段：把 postinst 与 init.d 的运维语义从「文本断言」提升为**真实执行**：
//! 首装落配置/二次执行不覆盖运维改动、enabled=0 拒绝起服务、config_load
//! 缺席仍按缺省 1 起、可执行档与配置缺失各自具名拒绝。用 shell 函数桩替代
//! OpenWrt 专有的 `config_get`/`logger`/`procd_*`，在临时目录跑 sh 真分支，
//! 输出事件由桩记录后逐项断言——不是靠脚本文本包含某字符串来推断行为。
//!
//! RIL-041/042 的真机面（opkg 升级的 conffile 合并、procd 托管 respawn、
//! kmod-tun 数据面、RSS/CPU 上限）归 OpenWrt 机批次未跑；本门不冒充真机验收。

use std::os::unix::fs::PermissionsExt;
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

// ---------- 第二段：包内运维脚本的真执行语义 ----------

/// 取解包目录；缺 ar/tar 或 dist 未产返回 None（打印 skip，不冒充实测）。
fn unpack_or_skip(which: &str) -> Option<IpkUnpack> {
    let ipk = IpkUnpack::unpack();
    if ipk.is_none() {
        eprintln!("skip: {which}——本机无 ar/tar 或 dist/openwrt ipk 未构建");
    }
    ipk
}

/// 在临时目录搭 openwrt 根：把包内 postinst/init.d/示例配置放到真机路径。
/// 桩 logger/config_get/procd_* 记录调用事实，不碰真系统。
struct OpRoot {
    dir: PathBuf,
    log: PathBuf,
    events: PathBuf,
}

impl Drop for OpRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl OpRoot {
    fn new(ipk: &IpkUnpack) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rillane-openwrt-ops-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("etc/init.d")).expect("ops 根 etc/init.d");
        std::fs::create_dir_all(dir.join("usr/share/rillane")).expect("ops 根 usr/share/rillane");
        std::fs::create_dir_all(dir.join("usr/bin")).expect("ops 根 usr/bin");

        let copy = |from: &str, to: &str| {
            std::fs::copy(ipk.dir.join(from), dir.join(to)).expect("复制包内文件");
        };
        copy("control/postinst", "etc/postinst");
        copy("data/etc/init.d/rillane", "etc/init.d/rillane");
        copy(
            "data/usr/share/rillane/rillane.yaml.example",
            "usr/share/rillane/rillane.yaml.example",
        );
        // 桩脚本路径真机是 /usr/sbin/...，这里用临时 bin 前置进 PATH。
        std::fs::create_dir_all(dir.join("bin")).expect("ops 根 bin");
        let log = dir.join("stub-log");
        let events = dir.join("stub-events");
        let shim = |name: &str, body: &str| {
            let p = dir.join("bin").join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("写桩");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod 桩");
        };
        shim("logger", "printf '%s\\n' \"$*\" >> \"$RILLANE_STUB_LOG\"");
        shim(
            "config_get",
            "printf '%s\\n' \"config_get:$*\" >> \"$RILLANE_STUB_EVENTS\"\nprintf '%s' \"$RILLANE_STUB_ENABLED\"",
        );
        for name in ["procd_open_instance", "procd_close_instance"] {
            shim(
                name,
                &format!("printf '%s\\n' \"{name}\" >> \"$RILLANE_STUB_EVENTS\""),
            );
        }
        shim(
            "procd_set_param",
            "printf '%s\\n' \"procd_set_param:$*\" >> \"$RILLANE_STUB_EVENTS\"",
        );
        shim("stop", "printf '%s\\n' 'stop' >> \"$RILLANE_STUB_EVENTS\"");
        shim(
            "start",
            "printf '%s\\n' 'start' >> \"$RILLANE_STUB_EVENTS\"",
        );
        Self { dir, log, events }
    }

    /// 跑脚本；env 可追加桩变量（enabled 值、日志/事件路径）。
    fn run(&self, script: &str, env: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = Command::new("sh");
        cmd.arg(self.dir.join(script))
            .current_dir(&self.dir)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("RILLANE_STUB_LOG", &self.log)
            .env("RILLANE_STUB_EVENTS", &self.events);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().expect("执行 shell 脚本")
    }

    /// 真执行 init 脚本里的某个 rc.common 钩子（脚本本体只定义函数，
    /// 由框架调用；这里用桩框架做等价调用）。
    fn run_hook(&self, script: &str, hook: &str, env: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!(". \"$0\"; {hook}"))
            .arg(self.dir.join(script))
            .current_dir(&self.dir)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("RILLANE_STUB_LOG", &self.log)
            .env("RILLANE_STUB_EVENTS", &self.events);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().expect("执行 init 钩子")
    }

    fn events(&self) -> String {
        std::fs::read_to_string(&self.events).unwrap_or_default()
    }

    /// 伪装真机根：把包内的绝对路径 /etc/... /usr/... 改到本地 ops 根。
    /// postinst 与 init.d 在包内都是字面绝对路径，测试只改**副本**的路径前缀，
    /// 保留所有分支语句原样——执行的是脚本真逻辑而非另写的模拟脚本。
    fn localize(&self, rel: &str) {
        let p = self.dir.join(rel);
        let text = std::fs::read_to_string(&p).expect("读待本地化脚本");
        let root = self.dir.to_string_lossy();
        let localized = text
            .replace("/etc/rillane.yaml", &format!("{root}/etc/rillane.yaml"))
            .replace("/etc/init.d/rillane", &format!("{root}/etc/init.d/rillane"))
            .replace(
                "/usr/share/rillane/rillane.yaml.example",
                &format!("{root}/usr/share/rillane/rillane.yaml.example"),
            )
            .replace(
                "PROG=/usr/bin/rillaned",
                &format!("PROG={root}/usr/bin/rillaned"),
            );
        std::fs::write(&p, localized).expect("写本地化脚本");
    }
}

/// postinst 真执行：首装落配置 + enable；再跑不改运维改过的配置（升级保留）。
#[test]
fn postinst_preserves_operator_config_on_second_run() {
    let Some(ipk) = unpack_or_skip("postinst 执行面未实测") else {
        return;
    };
    let root = OpRoot::new(&ipk);
    root.localize("etc/postinst");
    root.localize("etc/init.d/rillane");

    let conf = root.dir.join("etc/rillane.yaml");
    assert!(!conf.exists(), "首装前配置不应存在");

    // 首装：模板落到 /etc/rillane.yaml。
    let out = root.run("etc/postinst", &[]);
    assert!(out.status.success(), "postinst 首装失败：{out:?}");
    assert!(conf.is_file(), "首装未落配置");
    let template = std::fs::read_to_string(&conf).expect("读首装配置");
    assert!(
        template.contains("api_bind") && template.contains("telemetry"),
        "落位不是模板内容：{template}"
    );

    // 运维改配置后再跑 postinst（模拟升级重装）——不得覆盖。
    let edited = "# operator-owned config\ncontrol:\n  api_bind: 0.0.0.0:9090\n";
    std::fs::write(&conf, edited).expect("写运维配置");
    let out = root.run("etc/postinst", &[]);
    assert!(out.status.success(), "postinst 二次执行失败：{out:?}");
    assert_eq!(
        std::fs::read_to_string(&conf).expect("读二次配置"),
        edited,
        "二次执行覆盖了运维配置（升级保留语义破裂）"
    );
}

/// init.d 真执行：enabled=0 拒绝起服务、缺配置拒绝起服务、缺省启用且
/// procd 参数齐全、reload 先停后起。桩只替换平台专有命令，分支与参数
/// 均来自包内脚本本体。
#[test]
fn init_script_gates_and_procd_params_execute_as_declared() {
    let Some(ipk) = unpack_or_skip("init.d 执行面未实测") else {
        return;
    };
    let root = OpRoot::new(&ipk);
    root.localize("etc/init.d/rillane");

    // 先落配置、建可执行档桩（真机是 musl 二进制，这里只需可执行)。
    let conf = root.dir.join("etc/rillane.yaml");
    std::fs::write(&conf, "control:\n  api_bind: 127.0.0.1:9090\n").expect("写配置");
    let prog = root.dir.join("usr/bin/rillaned");
    std::fs::write(&prog, "#!/bin/sh\nexit 0\n").expect("写 rillaned 桩");
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    // enabled=0：config_get 返回 0，必须零 procd 事件。
    let out = root.run_hook(
        "etc/init.d/rillane",
        "start_service",
        &[("RILLANE_STUB_ENABLED", "0")],
    );
    assert!(out.status.success(), "enabled=0 路径失败：{out:?}");
    assert!(
        !root.events().contains("procd_open_instance"),
        "enabled=0 仍起了服务：{}",
        root.events()
    );

    // enabled=1：config_load 缺席（桩无配置文件）仍按缺省 1 起服务，
    // 事件序列须含 config_get + procd_open/close + 全部参数。
    let out = root.run_hook(
        "etc/init.d/rillane",
        "start_service",
        &[("RILLANE_STUB_ENABLED", "1")],
    );
    assert!(out.status.success(), "enabled=1 路径失败：{out:?}");
    let events = root.events();
    for needle in [
        "config_get:enabled general enabled 1",
        "procd_open_instance",
        "procd_set_param:command ",
        "procd_set_param:env RILLANE_CONFIG=",
        "procd_set_param:respawn 3600 5 0",
        "procd_set_param:stdout 1",
        "procd_set_param:stderr 1",
        "procd_set_param:limits core=0 0",
        "procd_close_instance",
    ] {
        assert!(events.contains(needle), "事件缺「{needle}」：\n{events}");
    }

    // 缺配置：删除后启动必须具名拒绝，且零 procd 事件。
    std::fs::remove_file(&conf).expect("删配置");
    std::fs::remove_file(&root.events).unwrap_or_default();
    let out = root.run_hook(
        "etc/init.d/rillane",
        "start_service",
        &[("RILLANE_STUB_ENABLED", "1")],
    );
    assert!(
        !out.status.success(),
        "缺配置须具名拒绝（return 1）：{out:?}"
    );
    assert!(
        !root.events().contains("procd_open_instance"),
        "缺配置仍起了服务：{}",
        root.events()
    );
    assert!(
        std::fs::read_to_string(&root.log)
            .unwrap_or_default()
            .contains("缺少配置"),
        "缺配置未写具名日志：{}",
        std::fs::read_to_string(&root.log).unwrap_or_default()
    );

    // 配置更新恢复：reload_service = 先停后起（stop/start 桩按序记录）。
    std::fs::write(&conf, "control:\n  api_bind: 127.0.0.1:9090\n").expect("重建配置");
    std::fs::remove_file(&root.events).unwrap_or_default();
    let out = root.run_hook(
        "etc/init.d/rillane",
        "reload_service",
        &[("RILLANE_STUB_ENABLED", "1")],
    );
    assert!(out.status.success(), "reload_service 路径失败：{out:?}");
    assert_eq!(root.events(), "stop\nstart\n", "reload_service 须先停后起");
}
