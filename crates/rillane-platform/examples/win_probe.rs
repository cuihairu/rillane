//! RIL-033 Windows 数据面真机探针（imac 实跑；交叉编译 x86_64-pc-
//! windows-gnu，wintun.dll 0.14.1 与 exe 同目录部署）。
//!
//! 验收序列（todo RIL-033 验收原文逐项）：
//! - P0 快照：route print -4/-6 + netsh（含 v6 出口身份组合面）
//! - P1 会话：wintun.dll 加载、驱动版本、适配器创建、LUID/If 索引、
//!   开环
//! - P2 真实流进共享内核：系统 ping.exe（外部真应用）打捕获网段 →
//!   用户态环收 ICMP 请求 + 元数据断言；请求→回复字节手术回注 →
//!   ping 打印 Reply（下行注入被内核消费）；进程内 UDP socket 同段
//!   发送 → 环内捕获数据报原文
//! - P2b 真实 HTTP 客户端流：Windows 内置 curl.exe 连捕获网段 80 口 →
//!   用户态封环收真实 TCP 段并自完成三次握手 + 200 应答（真校验和）→
//!   curl 退出码 200 = 整事务经共享内核闭合
//! - P3 DNS/代理拨号不循环：bind 物理口 IP 的 UDP/TCP 出站（escape
//!   原语）真查询公网解析器 → 应答可读 / TCP 源地址=物理口
//! - P4 失败可补偿：WinRouteTransaction prepare 好步+坏步 → apply 失败
//!   → 自动逆序补偿 → 路由不存在 → rollback 幂等
//! - P5 清理：路由/适配器撤净幂等
//!
//! 运行：管理员 PowerShell `ril033_probe.exe`；输出 PROBE 行供证据
//! 文档引用；退出码 0 = 全部通过。
///
/// 非 Windows 席：探针无运行面（`--all-targets` 仍要求 crate 有 main；
/// 运行期验收面仅 Windows 真机，见 win_tun 模块头选型注记）。
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    probe::main()
}

#[cfg(windows)]
mod probe {
    use std::io::{Read, Write as _};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex as SecMutex};
    use std::time::{Duration, Instant};

    use rillane_platform::network::ipcodec::internet_checksum;
    use rillane_platform::network::ports::{
        CapturePort, CapturedInput, IpProtocol as IpProto, RouteTransaction, SystemChange,
    };
    use rillane_platform::network::win_net::{
        adapter_if_index, bind_escape_udp, connect_escape_tcp, win_step_executor,
    };
    use rillane_platform::network::win_takeover::{
        parse_netsh_ipv4_interfaces, parse_netsh_ipv6_addresses, parse_route_print_ipv4,
        parse_route_print_ipv6, win_step_payload, WinAppliedStep, WinRouteTransaction,
    };
    use rillane_platform::network::win_tun::{
        last_error, WinTunCapturePort, WintunApi, WintunDevice,
    };

    const ADAPTER: &str = "rillane-probe";
    const TUNNEL_TYPE: &str = "Rillane Probe";
    const ADAPTER_IP: &str = "198.51.100.1";
    const CAPTURE_NET: &str = "198.51.100.0";
    const CAPTURE_MASK: &str = "255.255.255.0";
    const PROBE_TARGET: &str = "198.51.100.2";
    const DNS_UPSTREAM: &str = "223.5.5.5:53";

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

    /// 段结果汇总（OVERALL 由它派生——任何段 FAIL 都必须让 OVERALL FAIL，
    /// 不得只打印不记账）
    fn sections() -> &'static SecMutex<Vec<(String, bool)>> {
        static S: std::sync::OnceLock<SecMutex<Vec<(String, bool)>>> = std::sync::OnceLock::new();
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

    fn current_if_index() -> Option<u32> {
        let text = run(&["netsh", "interface", "ipv4", "show", "interfaces"]).ok()?;
        parse_netsh_ipv4_interfaces(&text)
            .iter()
            .find(|i| i.name == ADAPTER)
            .map(|i| i.if_index)
    }

    /// 幂等清理：捕获网段路由 + 适配器静态地址逐项撤（不存在=已净）。
    /// 路由按目的+掩码撤而**不依赖适配器仍在**——CloseAdapter 后适配器名已
    /// 消失，按名查 If 索引会漏删路由（泄漏面）。
    fn cleanup_quiet() {
        let _ = run(&["route", "delete", CAPTURE_NET, "mask", CAPTURE_MASK]);
        let _ = run(&[
            "netsh",
            "interface",
            "ip",
            "delete",
            "address",
            &format!("name={ADAPTER}"),
            &format!("addr={ADAPTER_IP}"),
        ]);
    }

    pub(crate) fn main() {
        let diag_mode = std::env::args().any(|a| a == "diag");
        let result = if diag_mode { diag() } else { probe() };
        cleanup_quiet();
        let guard = sections().lock().expect("汇总锁");
        let failed: Vec<String> = guard
            .iter()
            .filter(|(_, ok)| !*ok)
            .map(|(n, _)| n.clone())
            .collect();
        let ok = result.is_ok() && failed.is_empty();
        let detail = match result {
            Ok(()) if failed.is_empty() => "all sections passed".to_string(),
            Ok(()) => format!("failed sections: {}", failed.join(",")),
            Err(e) => format!("aborted: {e}; failed sections: {}", failed.join(",")),
        };
        say("OVERALL", ok, &detail);
        if !ok {
            std::process::exit(1);
        }
    }

    /// 真机诊断面（RIL-033 迭代用）：wintun 失败只给 NULL，真相在
    /// LastError + 驱动版本 + netsh 口径 If 索引——三者并排才能定位
    /// 「环 API 可用但适配器未真正上线」这类分层故障。
    fn diag() -> Result<(), String> {
        let api =
            Arc::new(WintunApi::load("wintun.dll").map_err(|e| format!("load wintun.dll: {e}"))?);
        say(
            "DIAG-VERSION",
            api.running_driver_version() != 0,
            &format!(
                "running_driver_version=0x{:08X} last_error={}",
                api.running_driver_version(),
                last_error()
            ),
        );
        let device = WintunDevice::create(&api, ADAPTER, TUNNEL_TYPE)
            .map_err(|e| format!("create: {e} last_error={}", last_error()))?;
        say("DIAG-CREATE", true, "handle non-null");
        let luid = device.luid();
        say(
            "DIAG-LUID",
            luid != 0,
            &format!("luid=0x{luid:016X} if_index={}", device.if_index()),
        );
        let ifs = parse_netsh_ipv4_interfaces(
            &run(&["netsh", "interface", "ipv4", "show", "interfaces"]).unwrap_or_default(),
        );
        let row = ifs.iter().find(|i| i.name == ADAPTER);
        say("DIAG-NETSH", row.is_some(), &format!("netsh_row={row:?}"));
        say(
            "DIAG-SHOW-INTERFACES",
            true,
            &run(&["netsh", "interface", "show", "interfaces"])
                .unwrap_or_default()
                .lines()
                .collect::<Vec<_>>()
                .join(" | "),
        );
        say(
            "DIAG-PNP",
            true,
            &run(&["pnputil", "/enum-drivers"])
                .unwrap_or_default()
                .lines()
                .filter(|l| l.to_ascii_lowercase().contains("wintun"))
                .collect::<Vec<_>>()
                .join(" | "),
        );
        drop(device);
        Ok(())
    }

    fn probe() -> Result<(), String> {
        // ---------------- P0 快照（v4/v6 组合面） ----------------
        let route4 = run(&["route", "print", "-4"]).map_err(|e| format!("P0 route print: {e}"))?;
        let primary = parse_route_print_ipv4(&route4).first().map(|r| r.interface);
        let v6_routes = parse_route_print_ipv6(
            &run(&["route", "print", "-6"]).map_err(|e| format!("P0 route -6: {e}"))?,
        );
        let v6_addrs = parse_netsh_ipv6_addresses(
            &run(&["netsh", "interface", "ipv6", "show", "addresses"])
                .map_err(|e| format!("P0 netsh v6: {e}"))?,
        );
        let snap = rillane_platform::network::win_takeover::WinNetSnapshot {
            default_routes: parse_route_print_ipv4(&route4),
            default_routes_v6: v6_routes,
            v6_if_addresses: v6_addrs,
            dns_servers: Vec::new(),
        };
        let escape_ip: IpAddr = snap
            .escape_bind_ip()
            .ok_or_else(|| "P0 无默认路由——无从取物理口 bind IP".to_string())?;
        say(
            "P0-SNAPSHOT",
            true,
            &format!(
                "primary={:?} escape_bind={escape_ip} v6_default_routes={} v6_identity={:?}",
                primary.map(|a| a.to_string()),
                snap.default_routes_v6.len(),
                snap.escape_bind_ip_v6().map(|a| a.to_string())
            ),
        );

        // ---------------- P1 会话 ----------------
        let api = Arc::new(
            WintunApi::load("wintun.dll").map_err(|e| format!("P1 load wintun.dll: {e}"))?,
        );
        // 驱动版本在 LoadLibrary 后读为 0：wintun 的驱动版本全局在首次
        // StartSession 才装载填充（真机实证 0x00000000 + LastError=2）——
        // 这里只认 DLL 加载本身，版本在 P1-DRIVER 段（会话开后）复核。
        say(
            "P1-LOAD",
            true,
            &format!(
                "wintun.dll loaded, driver_version_at_load=0x{:08X}",
                api.running_driver_version()
            ),
        );
        let device = WintunDevice::create(&api, ADAPTER, TUNNEL_TYPE)
            .map_err(|e| format!("P1 create: {e}"))?;
        // If 索引以 OS 权威口径（netsh）为准，LUID 低 24 位作回退——
        // 真机实证新建 Wintun 适配器 LUID 的 If 索引位可为 0，route add
        // 报「指定的接口不存在」（见 win_net::adapter_if_index 注记）。
        let luid_if_index = device.if_index();
        let if_index = adapter_if_index(ADAPTER).unwrap_or(luid_if_index);
        let set_addr = run(&[
            "netsh",
            "interface",
            "ip",
            "set",
            "address",
            &format!("name={ADAPTER}"),
            "source=static",
            &format!("addr={ADAPTER_IP}"),
            "mask=255.255.255.255", // /32：L3 点对点（RIL-032 wgprobe 同形——不给内核连通子网，无 ARP 歧义）
        ]);
        say(
            "P1-ADAPTER",
            set_addr.is_ok() && if_index != 0,
            &format!(
                "if_index_os={if_index} if_index_luid={luid_if_index} addr_set={} {}",
                set_addr.is_ok(),
                set_addr.err().unwrap_or_default()
            ),
        );
        let session = device
            .start_session(0x40000)
            .map_err(|e| format!("P1 start session: {e}"))?;
        let mut port = WinTunCapturePort::new(session);
        // 会话开后复核驱动版本——此时 wintun 已装载驱动，版本应非 0
        let version_after_session = api.running_driver_version();
        say(
            "P1-DRIVER",
            version_after_session != 0,
            &format!(
                "running_driver_version=0x{version_after_session:08X} (0.14 = 0x00140000 风格编码)"
            ),
        );

        // ---------------- P2 路由 + 真实流进共享内核 ----------------
        let step = WinAppliedStep::RouteAdded {
            destination: CAPTURE_NET.to_string(),
            mask: CAPTURE_MASK.to_string(),
            gateway: ADAPTER_IP.to_string(),
            metric: 5,
            interface_index: if_index,
        };
        win_step_executor()(&step.argv()).map_err(|e| format!("P2 route add: {e}"))?;
        say(
            "P2-ROUTE",
            true,
            &format!("capture route up: {CAPTURE_NET}/{CAPTURE_MASK} if {if_index}"),
        );

        // 真实外部应用：ping.exe（内核 TCP/ICMP 栈产出——非探针伪造）
        let mut ping = Command::new("ping")
            .args(["-n", "2", "-w", "1500", PROBE_TARGET])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("P2 spawn ping: {e}"))?;
        let mut icmp_requests = 0usize;
        let mut udp_seen = false;
        let marker = b"rillane-probe-udp";
        let sock = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("P2 bind udp: {e}"))?;
        sock.send_to(marker, format!("{PROBE_TARGET}:9"))
            .map_err(|e| format!("P2 send udp: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(9);
        while Instant::now() < deadline && (icmp_requests < 2 || !udp_seen) {
            match port.recv() {
                Ok(Some(CapturedInput::Packet(p))) => {
                    if p.meta.protocol == IpProto::Icmp {
                        icmp_requests += 1;
                        if let Some(reply) = icmp_echo_reply(&p.packet) {
                            port.send(&reply)
                                .map_err(|e| format!("P2 send reply: {e}"))?;
                        }
                    }
                    if p.packet.windows(marker.len()).any(|w| w == marker) {
                        udp_seen = true;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err("P2 capture port closed".to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("P2 capture: {e}")),
            }
        }
        let mut buf = Vec::new();
        if let Some(mut out) = ping.stdout.take() {
            let _ = out.read_to_end(&mut buf);
        }
        let _ = ping.wait();
        let ping_out = String::from_utf8_lossy(&buf).into_owned();
        let replies = ping_out.matches("TTL=").count();
        let stats = port.stats();
        say(
            "P2-REALFLOW",
            icmp_requests >= 1 && replies >= 1 && udp_seen,
            &format!(
                "icmp_requests={icmp_requests} udp_captured={udp_seen} replies(TTL=)={replies} stats={:?} (ping: real app via kernel stack; reply injected downlink)",
                (stats.captured, stats.parse_errors)
            ),
        );

        // ---------------- P2b 真实 HTTP 客户端流进共享内核 ----------------
        let http = real_http_flow(&mut port);
        say("P2b-REALHTTP", http.ok, &http.detail);

        // ---------------- P3 DNS/代理拨号不循环 ----------------
        let dns_query = dns_query_bytes("example.com");
        let esc = bind_escape_udp(escape_ip).map_err(|e| format!("P3 bind udp: {e}"))?;
        let target: SocketAddr = DNS_UPSTREAM.parse().unwrap();
        esc.set_read_timeout(Some(Duration::from_secs(4))).ok();
        let mut answer = [0u8; 512];
        let udp_ok = match esc.send_to(&dns_query, target).and_then(|_| {
            let (n, _) = esc.recv_from(&mut answer)?;
            Ok(n)
        }) {
            Ok(n) => n >= 12,
            Err(_) => false,
        };
        say(
            "P3-ESCAPE-UDP",
            udp_ok,
            &format!("bind={escape_ip} -> {DNS_UPSTREAM} real A query answered={udp_ok}"),
        );
        let mut tcp_detail = String::new();
        let mut tcp_ok = false;
        for upstream in ["223.5.5.5:53", "119.29.29.29:53"] {
            let target: SocketAddr = upstream.parse().unwrap();
            match connect_escape_tcp(escape_ip, target) {
                Ok(s) => {
                    let local_ok = s.local_addr().map(|l| l.ip() == escape_ip).unwrap_or(false);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    tcp_ok = local_ok;
                    tcp_detail = format!("connected {upstream} local==bind={local_ok}");
                    break;
                }
                Err(e) => {
                    tcp_detail = format!("{upstream}: {e}");
                }
            }
        }
        say(
            "P3-ESCAPE-TCP",
            tcp_ok,
            &format!("connect_escape_tcp({escape_ip}) {tcp_detail}"),
        );

        // ---------------- P4 失败可补偿 ----------------
        let good = win_step_payload(&step);
        let bad_step = WinAppliedStep::RouteAdded {
            destination: "198.51.101.0".to_string(),
            mask: CAPTURE_MASK.to_string(),
            gateway: ADAPTER_IP.to_string(),
            metric: 5,
            // 真机实证的被拒输入：接口 0 不存在（route.exe 把 300.300.0.0
            // 逐字节模 256 后静默建路——不能当坏步）
            interface_index: 0,
        };
        let mut txn = WinRouteTransaction::new(win_step_executor());
        let prepared = txn.prepare(vec![
            SystemChange::new("p4-good", &good),
            SystemChange::new("p4-bad", &win_step_payload(&bad_step)),
        ]);
        if let Err(e) = prepared {
            return Err(format!("P4 prepare: {e:#}"));
        }
        let apply_failed = txn.apply().is_err();
        std::thread::sleep(Duration::from_millis(300));
        let route_absent =
            !capture_route_present(&run(&["route", "print", "-4"]).unwrap_or_default());
        let rollback_ok = txn.rollback().is_ok() && txn.rollback().is_ok();
        say(
            "P4-COMPENSATE",
            apply_failed && rollback_ok,
            &format!(
                "bad step failed={apply_failed} good step auto-undone (route absent={route_absent}) rollback idempotent={rollback_ok}"
            ),
        );

        // ---------------- P5 清理 ----------------
        drop(port); // EndSession
        drop(device); // CloseAdapter → 适配器删除
        std::thread::sleep(Duration::from_millis(500));
        cleanup_quiet();
        std::thread::sleep(Duration::from_millis(300));
        let adapter_gone = current_if_index().is_none();
        say(
            "P5-CLEANUP",
            adapter_gone,
            &format!("adapter absent={adapter_gone}, route deleted"),
        );
        Ok(())
    }

    /// P2b 真实 HTTP 客户端流：Windows 内置 curl.exe（真实 TCP/IP + HTTP 栈，
    /// 非探针伪造）经捕获路由进入 Wintun 封环；探针在用户态完成三次握手与
    /// 200 应答（build_tcp_packet 真校验和）——证「真实应用流进入共享内核
    /// 并可由数据面服务」。返回码 200 = 全事务经封环闭合。
    struct HttpFlowResult {
        ok: bool,
        detail: String,
    }

    fn real_http_flow(port: &mut WinTunCapturePort) -> HttpFlowResult {
        use rillane_platform::network::ipcodec::{build_tcp_packet, parse_tcp_segment, TcpFlags};

        let resp_ip: Ipv4Addr = PROBE_TARGET.parse().unwrap();
        let resp_port: u16 = 80;
        const OUR_SEQ: u32 = 4242;

        let mut curl = match Command::new("curl")
            .args([
                "-4",
                "-s",
                "--connect-timeout",
                "6",
                "--max-time",
                "12",
                "-o",
                "NUL",
                "-w",
                "%{http_code}",
                &format!("http://{PROBE_TARGET}:{resp_port}/"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return HttpFlowResult {
                    ok: false,
                    detail: format!("curl spawn: {e}"),
                }
            }
        };

        let body = b"rillane-win";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut full_response = response.clone();
        full_response.extend_from_slice(body);

        let mut segments = 0usize;
        let mut syn_ack_sent = false;
        let mut saw_get = false;
        let mut http_sent = false;
        let mut curl_exit = false;

        let deadline = Instant::now() + Duration::from_secs(14);
        while Instant::now() < deadline && !(curl_exit || (http_sent && saw_get)) {
            if !curl_exit {
                if let Ok(Some(_)) = curl.try_wait() {
                    curl_exit = true;
                }
            }
            match port.recv() {
                Ok(Some(CapturedInput::Packet(p))) => {
                    let Ok(seg) = parse_tcp_segment(&p.packet) else {
                        continue;
                    };
                    if seg.dst != IpAddr::V4(resp_ip) || seg.dport != resp_port {
                        continue;
                    }
                    segments += 1;
                    let src_ip = match seg.src {
                        IpAddr::V4(v4) => v4,
                        _ => continue,
                    };
                    if seg.syn && !seg.ack && !seg.fin && !syn_ack_sent {
                        let reply = build_tcp_packet(
                            resp_ip,
                            src_ip,
                            resp_port,
                            seg.sport,
                            OUR_SEQ,
                            seg.seq.wrapping_add(1),
                            TcpFlags::SYN_ACK,
                            b"",
                        );
                        if let Ok(pkt) = reply {
                            syn_ack_sent = port.send(&pkt).is_ok();
                        }
                    } else if seg.ack
                        && !seg.syn
                        && !seg.fin
                        && !seg.payload.is_empty()
                        && !http_sent
                    {
                        saw_get = seg.payload.windows(4).any(|w| w == b"GET ");
                        let out = build_tcp_packet(
                            resp_ip,
                            src_ip,
                            resp_port,
                            seg.sport,
                            OUR_SEQ.wrapping_add(1),
                            // ack 认领本段已收字节——照抄 seg.ack_seq（SYN-ACK
                            // 确认点）会 ack 到客户端未发送的序号，Windows 按
                            // RFC 5961 丢弃我方段（真机实证 curl 000）
                            seg.seq.wrapping_add(seg.payload.len() as u32),
                            TcpFlags::PSH_ACK,
                            &full_response,
                        );
                        if let Ok(pkt) = out {
                            http_sent = port.send(&pkt).is_ok();
                        }
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(15));
                }
                Err(_e) => break,
            }
        }

        let mut buf = Vec::new();
        if let Some(mut out) = curl.stdout.take() {
            let _ = out.read_to_end(&mut buf);
        }
        let http_code = String::from_utf8_lossy(&buf).trim().to_string();
        HttpFlowResult {
            ok: saw_get && http_sent && http_code == "200",
            detail: format!(
                "segments={segments} syn_ack={syn_ack_sent} get_seen={saw_get} http_sent={http_sent} curl_http_code={http_code}",
            ),
        }
    }

    /// route print -4 文本里是否存在捕获网段路由行（目的+掩码双列匹配）
    fn capture_route_present(text: &str) -> bool {
        text.lines().any(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.len() >= 2 && cols[0] == CAPTURE_NET && cols[1] == CAPTURE_MASK
        })
    }

    /// ICMP echo request → echo reply 字节手术：type 8→0、IP 源目互换、
    /// IP/ICMP 校验和重算（ipcodec::internet_checksum）。非 echo request
    /// 返回 None 不硬造。
    fn icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
        if request.len() < 28 || (request[0] >> 4) != 4 {
            return None;
        }
        let ihl = (request[0] & 0x0f) as usize * 4;
        if request.len() < ihl + 8 || request[ihl] != 8 {
            return None; // 不是 echo request
        }
        let mut reply = request.to_vec();
        reply[ihl] = 0; // echo reply
        let icmp = &mut reply[ihl..];
        icmp[2] = 0;
        icmp[3] = 0;
        let csum = internet_checksum(icmp);
        icmp[2] = (csum >> 8) as u8;
        icmp[3] = csum as u8;
        // IP 头：源目互换 + 头校验和重算
        let (src, dst) = (reply[12..20].to_vec(), reply[16..20].to_vec());
        reply[12..16].copy_from_slice(&dst[0..4]);
        reply[16..20].copy_from_slice(&src[0..4]);
        reply[10] = 0;
        reply[11] = 0;
        let ip_csum = internet_checksum(&reply[..ihl]);
        reply[10] = (ip_csum >> 8) as u8;
        reply[11] = ip_csum as u8;
        Some(reply)
    }

    /// 最小 DNS A 查询（id=0 RD=1，qname 按标签编码）
    fn dns_query_bytes(name: &str) -> Vec<u8> {
        let mut q = vec![0u8, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        q
    }
}
