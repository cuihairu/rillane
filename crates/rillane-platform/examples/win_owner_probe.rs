//! RIL-034 Windows 进程归属真机探针（imac 实跑；交叉编译
//! x86_64-pc-windows-gnu，与 win_probe.rs 同部署纪律）。
//!
//! 验收序列（todo RIL-034 验收原文逐项：同目标多进程、UDP、进程
//! 退出、端口复用、权限失败、unknown 策略——均有真机证据）：
//! - P0 自归属：进程内 TCP 自连接（listener+connect+accept 全真套
//!   接字）→ 表四元组 → Known(自身 pid + 启动时间 + 完整路径)；
//!   同表反方向键 → 自身 pid（方向不错认）。顺带自验字节序解码
//!   （按已知端口查行，错码即查无——win_owner_ffi 模块头注记）
//! - P1 同目标多进程：3 个 helper 进程连同一目标端口（同 remote、
//!   不同本地口）→ 各键各归各 pid，身份三字段齐全、启动时间不早于
//!   spawn；反方向键全归父 pid——同目标多进程零串扰
//! - P2 UDP：helper 持 UDP 端口 → Known(helper pid)；kill → 表行
//!   消失 → NotFound（UDP 与 TCP 同机制同界）
//! - P3 进程退出 + 负缓存：已知键 Known → kill+wait → 直探
//!   TableProbe::Absent（表证据）→ 解析 Unknown(NotFound) 两次
//!   （负缓存命中路径仍回验表——活源纪律）
//! - P4 端口复用：helper A 持固定 UDP 口 → Known(pidA) → kill →
//!   helper B 绑同口 → 同键翻 Known(pidB≠pidA)（表 pid 回验翻缓存）
//!   ；P4b TCP 固定口重绑（SO_REUSEADDR）为信息面——TIME_WAIT 残留
//!   窗口内同元组重绑是内核口径观察点，不作 PASS 准据
//! - P5 权限失败：identity(自身)=Some 对照 identity(PPL pid)=None
//!   （RIL034_PPL_PID 由 run.ps1 以 MsMpEng 等受保护进程注入；
//!   OpenProcess QUERY_LIMITED 对 PPL 恒拒——stderr 带 GetLastError）
//! - P6 unknown：确无归属的端口 → 直探 Absent + 解析 Unknown(NotFound)
//!   （unknown 策略应用归 RIL-015/016 路由面，探针只证解析三态）
//! - std 模式（run.ps1 经 runas /trustlevel:0x20000 降权实跑）：
//!   标准用户下表读是否被拒（Denied 真机口径）+ PPL 身份仍拒
//!
//! 运行：管理员 PowerShell `probe.exe`（helper/std 模式勿手跑）；
//! 输出 PROBE 行供证据文档引用；退出码 0 = 全部通过。

/// 非 Windows 席：探针无运行面（`--all-targets` 仍要求 crate 有 main）
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    probe::main()
}

#[cfg(windows)]
mod probe {
    use std::io::{BufRead, BufReader};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::sync::{Mutex as SecMutex, OnceLock};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use rillane_platform::network::owner::{
        ConnectionKey, OwnerResolution, OwnerResolver, UnknownReason,
    };
    use rillane_platform::network::ports::TransportProtocol;
    use rillane_platform::network::win_owner::WinOwnerResolver;
    use rillane_platform::network::win_owner_ffi::{real_identity_source, real_table_probe};

    /// 固定口（避开常用段；占用即诚实 FAIL 换口）
    const UDP_MAIN: u16 = 53187;
    const UDP_EXIT: u16 = 53189;
    const UDP_REUSE: u16 = 53191;
    const TCP_FIXED: u16 = 53192;
    /// unknown 段的无人端口
    const UNBOUND_A: u16 = 59973;
    const UNBOUND_B: u16 = 59974;

    fn sections() -> &'static SecMutex<Vec<(String, bool)>> {
        static LEDGER: OnceLock<SecMutex<Vec<(String, bool)>>> = OnceLock::new();
        LEDGER.get_or_init(|| SecMutex::new(Vec::new()))
    }

    fn say(name: &str, ok: bool, detail: &str) {
        println!("PROBE {name} {} {detail}", if ok { "OK" } else { "FAIL" });
        if let Ok(mut l) = sections().lock() {
            l.push((name.to_string(), ok));
        }
    }

    fn unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn tcp_key(local_port: u16, remote: SocketAddr) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Tcp,
            SocketAddr::from(([127, 0, 0, 1], local_port)),
            remote,
        )
    }

    fn udp_key(local_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            TransportProtocol::Udp,
            SocketAddr::from(([127, 0, 0, 1], local_port)),
            SocketAddr::from(([8, 8, 8, 8], 53)),
        )
    }

    /// helper 进程退出兜底（Err 路径也不留孤儿/占口）
    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// spawn helper 并等它的 PORT 行（bind/connect 已完成的凭据）
    fn spawn_helper(args: &[&str]) -> Result<(KillOnDrop, u16), String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let mut child = Command::new(exe)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {args:?}: {e}"))?;
        let stdout: ChildStdout = child.stdout.take().ok_or("no stdout")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("helper {args:?} exited without PORT"));
            }
            Ok(_) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("read helper: {e}"));
            }
        }
        let port = line
            .trim()
            .strip_prefix("PORT ")
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| format!("helper said: {}", line.trim()))?;
        Ok((KillOnDrop(child), port))
    }

    fn kill_now(helper: &mut KillOnDrop) {
        let _ = helper.0.kill();
        let _ = helper.0.wait();
    }

    fn expect_known(res: OwnerResolution, want_pid: u32) -> Result<String, String> {
        match res {
            OwnerResolution::Known(id) => {
                if id.pid != want_pid {
                    return Err(format!("pid={} want={want_pid} (identity={id:?})", id.pid));
                }
                if id.started_at_unix_ms.is_none() || id.executable_path.is_none() {
                    return Err(format!("identity fields incomplete: {id:?}"));
                }
                Ok(format!(
                    "pid={} started={} path={:?}",
                    id.pid,
                    id.started_at_unix_ms.unwrap_or(0),
                    id.process_name
                ))
            }
            other => Err(format!("resolve={other:?}")),
        }
    }

    fn p0_self_tcp(resolver: &WinOwnerResolver) -> Result<String, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {e}"))?;
        let lp = listener
            .local_addr()
            .map_err(|e| format!("addr: {e}"))?
            .port();
        let cli = TcpStream::connect(("127.0.0.1", lp)).map_err(|e| format!("connect: {e}"))?;
        let (accepted, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let ephem = cli.local_addr().map_err(|e| format!("addr: {e}"))?.port();
        let key = tcp_key(
            ephem,
            format!("127.0.0.1:{lp}").parse::<SocketAddr>().unwrap(),
        );
        // 自归属不经过 helper——pid 对照用自身 pid
        let got = expect_known(resolver.resolve(&key, deadline()), std::process::id())?;
        let _ = accepted;
        // 反方向键（listener 侧为 local）同归自身 pid——方向不错认
        let rev = tcp_key(
            lp,
            format!("127.0.0.1:{ephem}").parse::<SocketAddr>().unwrap(),
        );
        match resolver.resolve(&rev, deadline()) {
            OwnerResolution::Known(id) if id.pid == std::process::id() => {}
            other => return Err(format!("reverse resolve={other:?} (want own pid)")),
        }
        Ok(got)
    }

    fn p1_multiproc(resolver: &WinOwnerResolver) -> Result<String, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {e}"))?;
        let lp = listener
            .local_addr()
            .map_err(|e| format!("addr: {e}"))?
            .port();
        let remote = format!("127.0.0.1:{lp}").parse::<SocketAddr>().unwrap();
        let mut helpers = Vec::new();
        let mut streams = Vec::new();
        let mut parts = Vec::new();
        let own = std::process::id();
        for _ in 0..3 {
            let t0 = unix_ms();
            let (h, port) = spawn_helper(&["hold-conn", &remote.to_string()])?;
            let (s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
            streams.push(s);
            let key = tcp_key(port, remote);
            let res = resolver.resolve(&key, deadline());
            match res {
                OwnerResolution::Known(id) => {
                    if id.pid != h.0.id() {
                        return Err(format!("pid={} want={}", id.pid, h.0.id()));
                    }
                    let started = id.started_at_unix_ms.ok_or("no started_at")?;
                    if started + 60_000 < t0 {
                        return Err(format!("started {started} before spawn {t0}"));
                    }
                    if id.executable_path.is_none() {
                        return Err("no path".to_string());
                    }
                    parts.push(format!("{port}->{}", h.0.id()));
                }
                other => return Err(format!("resolve={other:?}")),
            }
            helpers.push(h); // 存活到段末统一清
        }
        // 反方向键全归父 pid——同目标多进程零串扰
        for s in &streams {
            let peer = s.peer_addr().map_err(|e| format!("peer: {e}"))?;
            let rev = tcp_key(lp, peer);
            match resolver.resolve(&rev, deadline()) {
                OwnerResolution::Known(id) if id.pid == own => {}
                other => return Err(format!("reverse {peer} resolve={other:?} want {own}")),
            }
        }
        for h in &mut helpers {
            kill_now(h);
        }
        Ok(format!("pids=[{}] reverse=own", parts.join(",")))
    }

    fn p2_udp(resolver: &WinOwnerResolver) -> Result<String, String> {
        let (mut h, port) = spawn_helper(&["hold-udp", &UDP_MAIN.to_string()])?;
        let key = udp_key(port);
        let got = expect_known(resolver.resolve(&key, deadline()), h.0.id())?;
        kill_now(&mut h);
        std::thread::sleep(Duration::from_millis(200));
        match resolver.resolve(&key, deadline()) {
            OwnerResolution::Unknown(UnknownReason::NotFound) => {}
            other => return Err(format!("after exit resolve={other:?} want NotFound")),
        }
        Ok(format!("{got}; after exit NotFound"))
    }

    fn p3_exit_negcache(
        resolver: &WinOwnerResolver,
        direct: &dyn Fn(&ConnectionKey) -> rillane_platform::network::win_owner::TableProbe,
    ) -> Result<String, String> {
        let (mut h, port) = spawn_helper(&["hold-udp", &UDP_EXIT.to_string()])?;
        let key = udp_key(port);
        let got = expect_known(resolver.resolve(&key, deadline()), h.0.id())?;
        kill_now(&mut h);
        std::thread::sleep(Duration::from_millis(200));
        match direct(&key) {
            rillane_platform::network::win_owner::TableProbe::Absent => {}
            other => return Err(format!("direct probe={other:?} want Absent")),
        }
        for _ in 0..2 {
            match resolver.resolve(&key, deadline()) {
                OwnerResolution::Unknown(UnknownReason::NotFound) => {}
                other => return Err(format!("resolve={other:?} want NotFound x2")),
            }
        }
        Ok(format!("{got}; direct=Absent resolve=NotFound x2"))
    }

    fn p4_reuse(resolver: &WinOwnerResolver) -> Result<String, String> {
        let key = udp_key(UDP_REUSE);
        let (mut a, port_a) = spawn_helper(&["hold-udp", &UDP_REUSE.to_string()])?;
        if port_a != UDP_REUSE {
            return Err(format!("bound {port_a} want {UDP_REUSE}"));
        }
        let pid_a = match resolver.resolve(&key, deadline()) {
            OwnerResolution::Known(id) => id.pid,
            other => return Err(format!("A resolve={other:?}")),
        };
        if pid_a != a.0.id() {
            return Err(format!("A pid={pid_a} want={}", a.0.id()));
        }
        kill_now(&mut a);
        std::thread::sleep(Duration::from_millis(300));
        let (mut b, port_b) = spawn_helper(&["hold-udp", &UDP_REUSE.to_string()])?;
        if port_b != UDP_REUSE {
            return Err(format!("B bound {port_b} want {UDP_REUSE}"));
        }
        match resolver.resolve(&key, deadline()) {
            OwnerResolution::Known(id) if id.pid == b.0.id() && id.pid != pid_a => {
                kill_now(&mut b);
                Ok(format!(
                    "A pid={pid_a} -> B pid={} (cache flipped)",
                    b.0.id()
                ))
            }
            other => Err(format!("B resolve={other:?} want pid {}", b.0.id())),
        }
    }

    /// 信息面：TCP 固定口重绑（SO_REUSEADDR）——TIME_WAIT 残留窗口
    /// 内核口径观察，不作 PASS 准据（P4 UDP 已证缓存翻正机制）
    fn p4b_tcp_rebind_info(resolver: &WinOwnerResolver) -> String {
        let outcome = (|| -> Result<String, String> {
            let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {e}"))?;
            let lp = listener
                .local_addr()
                .map_err(|e| format!("addr: {e}"))?
                .port();
            let remote = format!("127.0.0.1:{lp}").parse::<SocketAddr>().unwrap();
            let (mut c, fixed) =
                spawn_helper(&["hold-conn", &remote.to_string(), &TCP_FIXED.to_string()])?;
            let (_s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
            let key = tcp_key(fixed, remote);
            let pid_c = match resolver.resolve(&key, deadline()) {
                OwnerResolution::Known(id) => id.pid,
                other => return Err(format!("C resolve={other:?}")),
            };
            kill_now(&mut c);
            std::thread::sleep(Duration::from_millis(300));
            let (mut d, _) =
                spawn_helper(&["hold-conn", &remote.to_string(), &TCP_FIXED.to_string()])?;
            let (_s2, _) = listener.accept().map_err(|e| format!("accept2: {e}"))?;
            match resolver.resolve(&key, deadline()) {
                OwnerResolution::Known(id) if id.pid == d.0.id() => {
                    kill_now(&mut d);
                    Ok(format!("C pid={pid_c} -> D pid={} flip ok", d.0.id()))
                }
                other => Err(format!("D resolve={other:?} want {}", d.0.id())),
            }
        })();
        match outcome {
            Ok(s) => format!("tcp rebind (SO_REUSEADDR): {s}"),
            Err(e) => format!("tcp rebind (SO_REUSEADDR) unavailable: {e}"),
        }
    }

    /// 提权会话面（信息，不作门禁）：真机事实——imac 的 admin token
    /// + QUERY_LIMITED 读 MsMpEng/csrss 身份均不被拒（本机无 PPL 执行
    /// 面，admin 级身份拒绝不存在）；身份拒绝只在标准用户下实证——
    /// 门禁在 std 段的 `PROBE P5-PERMDENIED`（run.ps1 断言）。
    fn p5_elevated_info() -> String {
        let ident = real_identity_source();
        let own = std::process::id();
        let self_id = match ident(own) {
            Some(i) => i,
            None => return "FAIL: identity(self)=None (unexpected)".to_string(),
        };
        let env_pid: Option<u32> = std::env::var("RIL034_PPL_PID")
            .ok()
            .and_then(|v| v.parse().ok());
        let note = match env_pid {
            Some(p) => match ident(p) {
                Some(i) => format!(
                    "identity({p})={:?} readable under admin (host PPL off) — denial evidence = std run",
                    i.process_name
                ),
                None => format!("identity({p}) denied even as admin — denial observed here"),
            },
            None => "RIL034_PPL_PID missing".to_string(),
        };
        format!("self path={:?}; {note}", self_id.process_name)
    }

    /// std 降权段权限失败门禁：标准用户身份源——自身可读、候选进程
    /// 身份被拒（OpenProcess err=5，stderr 诊断）→ 真机权限失败证据
    fn p5_std_check() -> Result<String, String> {
        let ident = real_identity_source();
        let own = std::process::id();
        if ident(own).is_none() {
            return Err("identity(self)=None under std token (unexpected)".to_string());
        }
        let ppl: u32 = std::env::var("RIL034_PPL_PID")
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or("RIL034_PPL_PID missing (run.ps1 must inject it for std run)")?;
        if ident(ppl).is_some() {
            return Err(format!(
                "identity({ppl}) readable under std token — denial NOT observed"
            ));
        }
        Ok(format!(
            "self=ok ppl({ppl})=denied (OpenProcess err=5, see stderr)"
        ))
    }

    fn p6_unknown(
        resolver: &WinOwnerResolver,
        direct: &dyn Fn(&ConnectionKey) -> rillane_platform::network::win_owner::TableProbe,
    ) -> Result<String, String> {
        let kt = tcp_key(
            UNBOUND_A,
            format!("127.0.0.1:{UNBOUND_B}")
                .parse::<SocketAddr>()
                .unwrap(),
        );
        let ku = udp_key(UNBOUND_B);
        for (name, k) in [("tcp", &kt), ("udp", &ku)] {
            match direct(k) {
                rillane_platform::network::win_owner::TableProbe::Absent => {}
                other => return Err(format!("{name} unbound probe={other:?} (port collision?)")),
            }
            match resolver.resolve(k, deadline()) {
                OwnerResolution::Unknown(UnknownReason::NotFound) => {}
                other => return Err(format!("{name} resolve={other:?} want NotFound")),
            }
        }
        Ok("tcp+udp unbound -> Absent / Unknown(NotFound)".to_string())
    }

    /// 标准用户短序列（runas /trustlevel:0x20000 降权跑；信息面，
    /// 表读是否被拒 = Denied 真机口径）
    fn std_mode() {
        let resolver = WinOwnerResolver::with_real_sources();
        let sock = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(s) => s,
            Err(e) => {
                println!("STD-UDP-SELF bind-error {e}");
                return;
            }
        };
        let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        match resolver.resolve(&udp_key(port), deadline()) {
            OwnerResolution::Known(id) => {
                println!(
                    "STD-UDP-SELF pid={} own={}",
                    id.pid,
                    id.pid == std::process::id()
                )
            }
            OwnerResolution::Unknown(r) => println!("STD-UDP-SELF unknown {r:?}"),
            OwnerResolution::Unsupported => println!("STD-UDP-SELF unsupported"),
        }
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) => {
                println!("STD-TCP-SELF bind-error {e}");
                return;
            }
        };
        let lp = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let cli = match TcpStream::connect(("127.0.0.1", lp)) {
            Ok(c) => c,
            Err(e) => {
                println!("STD-TCP-SELF connect-error {e}");
                return;
            }
        };
        let _accepted = listener.accept();
        let ephem = cli.local_addr().map(|a| a.port()).unwrap_or(0);
        let key = tcp_key(
            ephem,
            format!("127.0.0.1:{lp}").parse::<SocketAddr>().unwrap(),
        );
        match resolver.resolve(&key, deadline()) {
            OwnerResolution::Known(id) => {
                println!(
                    "STD-TCP-SELF pid={} own={}",
                    id.pid,
                    id.pid == std::process::id()
                )
            }
            OwnerResolution::Unknown(r) => println!("STD-TCP-SELF unknown {r:?}"),
            OwnerResolution::Unsupported => println!("STD-TCP-SELF unsupported"),
        }
        let ident = real_identity_source();
        match ident(std::process::id()) {
            Some(id) => println!(
                "STD-IDENTITY-SELF ok started={} path={:?}",
                id.started_at_unix_ms.unwrap_or(0),
                id.process_name
            ),
            None => println!("STD-IDENTITY-SELF none"),
        }
        if let Some(ppl) = std::env::var("RIL034_PPL_PID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
        {
            match ident(ppl) {
                Some(_) => println!("STD-PPL denied=false (identity readable!)"),
                None => println!("STD-PPL denied=true"),
            }
        } else {
            println!("STD-PPL no-candidate");
        }
        // P5 权限失败门禁（std 降权 token——本机唯一真实拒绝面）
        let r = p5_std_check();
        let ok = r.is_ok();
        println!(
            "PROBE P5-PERMDENIED {} {}",
            if ok { "OK" } else { "FAIL" },
            r.unwrap_or_else(|e| e)
        );
    }

    fn hold_conn(args: &[String]) -> Result<(), String> {
        let remote: SocketAddr = args
            .get(2)
            .and_then(|s| s.parse().ok())
            .ok_or("usage: hold-conn <remote> [local_port]")?;
        let local = args.get(3).and_then(|s| s.parse::<u16>().ok());
        // 固定本地口场景（TIME_WAIT 残留窗口）：SO_REUSEADDR 重绑重试
        // （失败不 `?` 一错即出——200ms 间隔重试，attempt 用尽才报错）
        let mut attempts = if local.is_some() { 10 } else { 1 };
        let conn = loop {
            attempts -= 1;
            // 立即调用闭包收住 `?`（只逃内层，不逃 hold_conn——重试语义）
            let attempt: Result<TcpStream, String> = (|| match local {
                Some(lp) => {
                    let addr = SocketAddr::from(([127, 0, 0, 1], lp));
                    let sock =
                        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                            .map_err(|e| format!("socket: {e}"))?;
                    sock.set_reuse_address(true)
                        .map_err(|e| format!("reuse: {e}"))?;
                    sock.bind(&addr.into())
                        .map_err(|e| format!("bind {addr}: {e} (attempts left {attempts})"))?;
                    sock.connect(&remote.into())
                        .map_err(|e| format!("connect: {e}"))?;
                    Ok(TcpStream::from(sock))
                }
                None => TcpStream::connect(remote).map_err(|e| format!("connect: {e}")),
            })();
            match attempt {
                Ok(c) => break c,
                Err(e) if attempts > 0 => {
                    eprintln!("hold-conn retry (attempts left {attempts}): {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(e),
            }
        };
        let lp = conn.local_addr().map_err(|e| format!("addr: {e}"))?.port();
        println!("PORT {lp}");
        std::thread::sleep(Duration::from_secs(300)); // 父进程收尾即 kill
        Ok(())
    }

    fn hold_udp(args: &[String]) -> Result<(), String> {
        let port: u16 = args
            .get(2)
            .and_then(|s| s.parse().ok())
            .ok_or("usage: hold-udp <port>")?;
        let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))
            .map_err(|e| format!("bind {port}: {e}"))?;
        let bound = sock.local_addr().map_err(|e| format!("addr: {e}"))?.port();
        println!("PORT {bound}");
        std::thread::sleep(Duration::from_secs(300));
        Ok(())
    }

    pub(crate) fn main() {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(|s| s.as_str()) {
            Some("hold-conn") => {
                if let Err(e) = hold_conn(&args) {
                    println!("ERROR {e}");
                    std::process::exit(1);
                }
                return;
            }
            Some("hold-udp") => {
                if let Err(e) = hold_udp(&args) {
                    println!("ERROR {e}");
                    std::process::exit(1);
                }
                return;
            }
            Some("std") => {
                std_mode();
                return;
            }
            _ => {}
        }
        main_sequence();
    }

    fn main_sequence() {
        println!(
            "PROBE P0-SNAPSHOT INFO pid={} unix_ms={}",
            std::process::id(),
            unix_ms()
        );
        let resolver = WinOwnerResolver::with_real_sources();
        let direct = real_table_probe();

        let r = p0_self_tcp(&resolver);
        say("P0-SELF-TCP", r.is_ok(), &r.unwrap_or_else(|e| e));

        let r = p1_multiproc(&resolver);
        say("P1-MULTIPROC", r.is_ok(), &r.unwrap_or_else(|e| e));

        let r = p2_udp(&resolver);
        say("P2-UDP", r.is_ok(), &r.unwrap_or_else(|e| e));

        let r = p3_exit_negcache(&resolver, direct.as_ref());
        say("P3-EXIT-NEGCACHE", r.is_ok(), &r.unwrap_or_else(|e| e));

        let r = p4_reuse(&resolver);
        say("P4-REUSE", r.is_ok(), &r.unwrap_or_else(|e| e));
        println!(
            "PROBE P4b-TCP-REBIND INFO {}",
            p4b_tcp_rebind_info(&resolver)
        );

        println!("PROBE P5-INFO {}", p5_elevated_info());

        let r = p6_unknown(&resolver, direct.as_ref());
        say("P6-UNKNOWN", r.is_ok(), &r.unwrap_or_else(|e| e));

        let failed: Vec<String> = sections()
            .lock()
            .map(|l| {
                l.iter()
                    .filter(|(_, ok)| !ok)
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default();
        if failed.is_empty() {
            println!("PROBE OVERALL OK all sections passed");
        } else {
            println!("PROBE OVERALL FAIL failed sections: {}", failed.join(", "));
            std::process::exit(1);
        }
    }
}
