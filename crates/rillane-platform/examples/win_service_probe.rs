//! RIL-035 Windows 服务与退出恢复——真机验收探针。
//!
//! 两条模式（同一二进制，服务以 ImagePath 尾参 `svc` 启动）：
//! - **`svc`**（SCM 启动路径，ImagePath=`"…\probe.exe" svc`）：服务主体
//!   ——`recover_windows` 先行（崩溃残留先撤），随后按 `ServiceRun.args`
//!   判定两态：带 `apply-route <dest> <mask> <gw> <metric> <ifidx>` →
//!   记账式装路由；**SCM 崩溃自动重启不带参 → 纯恢复态**（这就是「服务
//!   崩溃→SCM 重启→无参恢复」闭环）。
//! - **默认**（管理员会话编排）：P0 净场 → P1 SCM 安装 → P2 Wintun 适配器
//!   → P3 崩溃-恢复 → P4 停止-卸载 → P5 切网重放 → P6 驱动依赖 → P7 清理。
//!
//! 真机纪律（同 RIL-033/034）：任何 FFI 面手写必真机验证；进程清除按
//! PID 不用映像名（服务进程自身即 probe.exe，`taskkill /IM` 会误杀）；
//! 路由/地址/适配器/服务全部幂等清理，不遗留。

#![cfg_attr(not(windows), allow(dead_code, unused_imports, unused_variables))]

fn main() {
    #[cfg(windows)]
    probe::main();
    #[cfg(not(windows))]
    eprintln!("win_service_probe: 仅 Windows 目标可用（本平台无 SCM/Wintun 面）");
}

#[cfg(windows)]
mod probe {
    use std::io::Write;
    use std::process::Command;
    use std::sync::{Arc, Mutex, OnceLock};

    use rillane_platform::network::{
        recovery::CrashJournal,
        win_net::{adapter_if_index, win_step_executor},
        win_recovery::{handle_network_event_windows, recover_windows, win_journaling_executor},
        win_service::{run_service, ScmClient, ServiceRun, SERVICE_RUNNING, SERVICE_STOPPED},
        win_takeover::WinAppliedStep,
        win_tun::{WintunApi, WintunDevice},
        NetworkEvent,
    };

    const SVC_NAME: &str = "rillane-probe-svc";
    const SVC_DISPLAY: &str = "Rillane RIL-035 Probe Service";
    const DATA_DIR: &str = "C:\\ProgramData\\ril035";
    const JOURNAL_PATH: &str = "C:\\ProgramData\\ril035\\crash.jsonl";
    const SVC_LOG: &str = "C:\\ProgramData\\ril035\\svc.log";
    const ADAPTER: &str = "ril035-probe";
    const ADAPTER_IP: &str = "198.51.100.1";
    const ADAPTER_MASK: &str = "255.255.255.255"; // /32 点对点（RIL-033 同形）
    const CAPTURE_NET: &str = "198.51.100.0";
    const CAPTURE_MASK: &str = "255.255.255.0";
    const ROUTE_METRIC: u32 = 9999;
    const TUNNEL_TYPE: &str = "Rillane RIL-035 Probe";

    type SecMutex<T> = Mutex<T>;

    fn say(section: &str, ok: bool, detail: &str) {
        println!(
            "PROBE {section} {} {detail}",
            if ok { "OK" } else { "FAIL" }
        );
        sections()
            .lock()
            .expect("汇总锁")
            .push((section.to_string(), ok));
        let _ = std::io::stdout().flush();
    }

    fn sections() -> &'static SecMutex<Vec<(String, bool)>> {
        static S: OnceLock<SecMutex<Vec<(String, bool)>>> = OnceLock::new();
        S.get_or_init(|| SecMutex::new(Vec::new()))
    }

    fn run(argv: &[&str]) -> Result<String, String> {
        match Command::new(argv[0]).args(&argv[1..]).output() {
            Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
            Ok(o) => Err(format!(
                "{} exit {:?}: {}{}",
                argv[0],
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim(),
                String::from_utf8_lossy(&o.stdout).trim()
            )),
            Err(e) => Err(format!("{} spawn fail: {e}", argv[0])),
        }
    }

    fn poll_until(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        cond()
    }

    fn slog(line: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(SVC_LOG)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    fn exe_dir() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.display().to_string()))
            .unwrap_or_else(|| "C:\\Users\\cui\\ril035".to_string())
    }

    fn if_index_os() -> Option<u32> {
        let text = run(&["netsh", "interface", "ipv4", "show", "interfaces"]).ok()?;
        for line in text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols.last() == Some(&ADAPTER) {
                if let Ok(idx) = cols[0].parse::<u32>() {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// route print -4 是否存在捕获网段路由行（目的+掩码双列匹配；
    /// RIL-033 同口径——真机 route 表文本形状已实证）
    fn route_present() -> bool {
        let Ok(text) = run(&["route", "print", "-4"]) else {
            return false;
        };
        text.lines().any(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.len() >= 2 && cols[0] == CAPTURE_NET && cols[1] == CAPTURE_MASK
        })
    }

    /// WintunDeleteDriverW（卸载适配器；wintun.dll 动态解析，缺失=静默
    /// ——RIL-033 实证 CloseAdapter 即移除，此为硬崩残留的兜底面）
    fn delete_wintun_adapter(name: &str) {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(p: *const u16) -> *mut c_void;
            fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
        }
        let dll = format!("{}\\wintun.dll", exe_dir());
        let w: Vec<u16> = dll.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let lib = LoadLibraryW(w.as_ptr());
            if lib.is_null() {
                return;
            }
            let sym = GetProcAddress(lib, c"WintunDeleteDriver".as_ptr().cast());
            if sym.is_null() {
                return;
            }
            let f = std::mem::transmute::<*mut c_void, unsafe extern "system" fn(*const u16) -> i32>(
                sym,
            );
            let n: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let _ = f(n.as_ptr());
        }
    }

    fn service_exists_quiet() -> bool {
        ScmClient::open()
            .map(|s| s.service_exists(SVC_NAME))
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // 服务主体（svc 模式）
    // ------------------------------------------------------------------
    fn svc_body() -> impl FnOnce(&ServiceRun) + Send {
        move |run: &ServiceRun| {
            let _ = std::fs::create_dir_all(DATA_DIR);
            slog(&format!("SVC START args={:?}", run.args));
            let journal = CrashJournal::open(JOURNAL_PATH);
            let exec = win_step_executor();
            // 1) 恢复先行（两态通用：崩溃残留/上次未清先撤）
            match recover_windows(&journal, &exec) {
                Ok(r) => slog(&format!(
                    "SVC RECOVER undone={} already_gone={} failed={} snapshots_restored={} snapshots_skipped={}",
                    r.undone.len(),
                    r.already_gone.len(),
                    r.failed.len(),
                    r.snapshots_restored,
                    r.snapshots_skipped
                )),
                Err(e) => slog(&format!("SVC RECOVER ERR {e}")),
            }
            // 2) apply-route <dest> <mask> <gw> <metric> <ifidx>
            if run.args.first().map(|s| s.as_str()) == Some("apply-route") {
                if run.args.len() >= 6 {
                    let step = WinAppliedStep::RouteAdded {
                        destination: run.args[1].clone(),
                        mask: run.args[2].clone(),
                        gateway: run.args[3].clone(),
                        metric: run.args[4].parse().unwrap_or(0),
                        interface_index: run.args[5].parse().unwrap_or(0),
                    };
                    let journalled = win_journaling_executor(
                        Arc::new(CrashJournal::open(JOURNAL_PATH)),
                        exec.clone(),
                    );
                    match journalled(&step.argv()) {
                        Ok(()) => slog("SVC APPLY-ROUTE OK"),
                        Err(e) => slog(&format!("SVC APPLY-ROUTE FAIL {e}")),
                    }
                } else {
                    slog(&format!("SVC APPLY-ROUTE BADARGS {:?}", run.args));
                }
            }
            slog("SVC BODY DONE idle-until-stop");
        }
    }

    // ------------------------------------------------------------------
    // 编排主序（默认模式）
    // ------------------------------------------------------------------
    fn orchestrator() -> Result<(), String> {
        let _ = std::fs::create_dir_all(DATA_DIR);
        let journal = CrashJournal::open(JOURNAL_PATH);
        let exec = win_step_executor();

        // ---------- P0 基线净场（前次残留幂等清） ----------
        if let Ok(scm) = ScmClient::open() {
            if let Ok(svc) = scm.open_service(SVC_NAME) {
                let _ = svc.stop();
                poll_until(10, || {
                    svc.query_state()
                        .map(|s| s == SERVICE_STOPPED)
                        .unwrap_or(false)
                });
                let _ = svc.delete();
                drop(svc);
                poll_until(10, || !scm.service_exists(SVC_NAME));
            }
        }
        let _ = exec(&[
            "route".into(),
            "delete".into(),
            CAPTURE_NET.into(),
            "mask".into(),
            CAPTURE_MASK.into(),
        ]);
        let _ = run(&[
            "netsh",
            "interface",
            "ip",
            "delete",
            "address",
            &format!("name={ADAPTER}"),
            &format!("addr={ADAPTER_IP}"),
        ]);
        delete_wintun_adapter(ADAPTER);
        let _ = journal.clear();
        let p0_clean = !service_exists_quiet() && !route_present() && if_index_os().is_none();
        say(
            "P0-BASELINE",
            p0_clean,
            &format!(
                "service_absent={} route_absent={} adapter_absent={}",
                !service_exists_quiet(),
                !route_present(),
                if_index_os().is_none()
            ),
        );

        // ---------- P1 SCM 安装（服务 + 崩溃自动重启动作） ----------
        let scm = ScmClient::open()?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let bin_path = format!("\"{}\" svc", exe.display());
        let svc = scm.create_service(SVC_NAME, SVC_DISPLAY, &bin_path)?;
        svc.set_restart_on_failure()?;
        let p1_ok = scm.service_exists(SVC_NAME);
        say(
            "P1-SCM-INSTALL",
            p1_ok,
            &format!(
                "service_registered={p1_ok} start_type=demand failure_action=restart(5s) image=\"{}\"",
                exe.display()
            ),
        );

        // ---------- P2 Wintun 适配器（隔离捕获面，不触真实网络） ----------
        let api = Arc::new(
            WintunApi::load(&format!("{}\\wintun.dll", exe_dir())).map_err(|e| e.to_string())?,
        );
        let device = WintunDevice::create(&api, ADAPTER, TUNNEL_TYPE)
            .or_else(|_| WintunDevice::open(&api, ADAPTER))
            .map_err(|e| format!("P2 adapter: {e}"))?;
        let set_addr = run(&[
            "netsh",
            "interface",
            "ip",
            "set",
            "address",
            &format!("name={ADAPTER}"),
            "source=static",
            &format!("addr={ADAPTER_IP}"),
            &format!("mask={ADAPTER_MASK}"),
        ]);
        let luid_if = device.if_index();
        let if_index = adapter_if_index(ADAPTER).unwrap_or(luid_if);
        // 会话把适配器置 connected（on-link 网关可达→路由 active 可见）；
        // 无会话时适配器 disconnected，route add 仍成功但 route print 不见
        // （RIL-033 同口径：先会话后路由）。_session 持有至 P7 收尾。
        let _session = device
            .start_session(0x40000)
            .map_err(|e| format!("P2 session: {e}"))?;
        let p2_ok = set_addr.is_ok() && if_index != 0;
        say(
            "P2-ADAPTER",
            p2_ok,
            &format!(
                "if_index_os={if_index} if_index_luid={luid_if} addr_set={} session_up=true {}",
                set_addr.is_ok(),
                set_addr.err().unwrap_or_default()
            ),
        );

        // ---------- P3 服务崩溃 → SCM 自动重启 → 无参恢复 ----------
        let ifs = if_index.to_string();
        svc.start(&[
            "apply-route",
            CAPTURE_NET,
            CAPTURE_MASK,
            ADAPTER_IP,
            &ROUTE_METRIC.to_string(),
            &ifs,
        ])?;
        let running = poll_until(15, || {
            svc.query_state()
                .map(|s| s == SERVICE_RUNNING)
                .unwrap_or(false)
        });
        // RUNNING 先于 body 置位（SCM 常规：快报 RUNNING 再干活）→ 检查
        // 路由须轮询，不瞬时断言（否则抢跑 body 的 route add）
        let route_up = poll_until(15, || route_present());
        let journaled = journal.pending().entries.len() == 1;
        let sp = svc.query_status_process()?;
        let svc_pid = sp.process_id;
        // 崩溃：按 PID 杀（勿用 /IM——服务自身就是 probe.exe）
        let kill = run(&["taskkill", "/F", "/PID", &svc_pid.to_string()]);
        let restarted = poll_until(40, || {
            svc.query_status_process()
                .map(|s| s.base.current_state == SERVICE_RUNNING && s.process_id != svc_pid)
                .unwrap_or(false)
        });
        // SCM 重启不带参 → 纯恢复 → 路由被撤销
        let recovered = poll_until(40, || !route_present());
        let log_text = std::fs::read_to_string(SVC_LOG).unwrap_or_default();
        let log_recover = log_text.contains("SVC RECOVER")
            && (log_text.contains("undone=1") || log_text.contains("already_gone=1"));
        say(
            "P3-CRASH-RECOVER",
            running && route_up && journaled && kill.is_ok() && restarted && recovered && log_recover,
            &format!(
                "running={running} route_up={route_up} journaled={journaled} svc_pid={svc_pid} killed={} restarted={restarted} recovered_route_absent={recovered} log_recover={log_recover}",
                kill.is_ok()
            ),
        );

        // ---------- P4 停止 → 卸载（服务 + 路由 + 账本全清） ----------
        let stop = svc.stop();
        let stopped = poll_until(15, || {
            svc.query_state()
                .map(|s| s == SERVICE_STOPPED)
                .unwrap_or(false)
        });
        let del = svc.delete();
        drop(svc);
        let gone = poll_until(15, || !service_exists_quiet());
        let p4_ok = stop.is_ok()
            && stopped
            && del.is_ok()
            && gone
            && !route_present()
            && journal.pending().entries.is_empty();
        say(
            "P4-STOP-UNINSTALL",
            p4_ok,
            &format!(
                "stopped={stopped} deleted={gone} route_absent={} journal_empty={}",
                !route_present(),
                journal.pending().entries.is_empty()
            ),
        );

        // ---------- P5 切网：路由丢失 → 事件重放恢复 ----------
        let step = WinAppliedStep::RouteAdded {
            destination: CAPTURE_NET.into(),
            mask: CAPTURE_MASK.into(),
            gateway: ADAPTER_IP.into(),
            metric: ROUTE_METRIC,
            interface_index: if_index,
        };
        let _ = journal.clear();
        journal
            .append_route_step(&step.argv().join(" "))
            .map_err(|e| e.to_string())?;
        exec(&step.argv()).map_err(|e| e.to_string())?; // 在位
        let up1 = poll_until(15, || route_present());
        // 模拟切网丢路由（route delete）
        let _ = exec(&[
            "route".into(),
            "delete".into(),
            CAPTURE_NET.into(),
            "mask".into(),
            CAPTURE_MASK.into(),
            "if".into(),
            ifs.clone(),
        ]);
        let gone_after_loss = !route_present();
        // 出口恢复事件 → 幂等重放（DNS 形状跳过语义由 OS-free 单测覆盖）
        let action = handle_network_event_windows(
            &journal,
            &exec,
            &NetworkEvent::DefaultRouteChanged {
                interface: Some(ADAPTER.to_string()),
            },
        );
        let reasserted = poll_until(15, || route_present());
        let r = recover_windows(&journal, &exec).map_err(|e| e.to_string())?;
        let p5_ok = up1
            && gone_after_loss
            && action == "reassert_routes"
            && reasserted
            && !route_present()
            && journal.pending().entries.is_empty();
        say(
            "P5-NETCHANGE-REASSERT",
            p5_ok,
            &format!(
                "up_before={up1} gone_after_loss={gone_after_loss} action={action} reasserted={reasserted} recover_undone={} clean={}",
                r.undone.len(),
                journal.pending().entries.is_empty()
            ),
        );

        // ---------- P6 驱动依赖（wintun 已装载 = 依赖在位） ----------
        let ver = api.running_driver_version();
        let driver_ok = ver != 0;
        let wintun_svc = run(&["sc", "query", "wintun"]).is_ok();
        say(
            "P6-DRIVERS",
            driver_ok,
            &format!(
                "running_driver_version=0x{ver:08X} (0.14 风格编码) sc_query_wintun={wintun_svc} signature=见 run.ps1 Get-AuthenticodeSignature"
            ),
        );

        // ---------- P7 卸载清理（幂等、不遗留） ----------
        let _ = exec(&[
            "route".into(),
            "delete".into(),
            CAPTURE_NET.into(),
            "mask".into(),
            CAPTURE_MASK.into(),
        ]);
        let _ = run(&[
            "netsh",
            "interface",
            "ip",
            "delete",
            "address",
            &format!("name={ADAPTER}"),
            &format!("addr={ADAPTER_IP}"),
        ]);
        drop(_session); // EndSession（先断会话再关适配器，RIL-033 次序）
        drop(device); // CloseAdapter → 适配器移除（RIL-033 实证）
        let adapter_gone = poll_until(15, || if_index_os().is_none());
        let _ = journal.clear();
        let p7_ok = adapter_gone && !route_present() && !service_exists_quiet();
        say(
            "P7-CLEANUP",
            p7_ok,
            &format!(
                "adapter_absent={adapter_gone} route_absent={} service_absent={} journal_empty={}",
                !route_present(),
                !service_exists_quiet(),
                journal.pending().entries.is_empty()
            ),
        );

        Ok(())
    }

    pub(crate) fn main() {
        let is_svc = std::env::args().any(|a| a == "svc");
        if is_svc {
            match run_service(SVC_NAME, Box::new(svc_body())) {
                Ok(()) => eprintln!("win_service_probe svc: dispatcher 正常返回（已停止）"),
                Err(e) => {
                    eprintln!("win_service_probe svc: run_service 失败: {e}");
                    std::process::exit(2);
                }
            }
            return;
        }
        let result = orchestrator();
        let s = sections().lock().expect("汇总锁");
        let all_ok = !s.is_empty() && s.iter().all(|(_, ok)| *ok);
        if let Err(e) = &result {
            eprintln!("win_service_probe orchestrator 错误: {e}");
        }
        let detail = if all_ok {
            format!("all sections passed ({} sections)", s.len())
        } else {
            let bad: Vec<&str> = s
                .iter()
                .filter(|(_, ok)| !*ok)
                .map(|(n, _)| n.as_str())
                .collect();
            format!("FAILED sections: {}", bad.join(","))
        };
        println!(
            "PROBE OVERALL {} {detail}",
            if all_ok { "OK" } else { "FAIL" }
        );
        println!(
            "PROBE EXIT={}",
            if all_ok && result.is_ok() { 0 } else { 1 }
        );
        if !(all_ok && result.is_ok()) {
            std::process::exit(1);
        }
    }
}
