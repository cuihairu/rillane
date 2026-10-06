//! 出站 fwmark（networking.md §2 direct 出口自环盲区正解半边①）。
//!
//! TUN include 路由会把 seep 自身 direct 出站拽回 TUN（auto-bypass 是捕获面
//! 排除，救不了内核路由面）——出站 TCP socket 打 `SO_MARK` + 配套
//! `ip rule fwmark` 逃逸规则（半边②：seep-platform LinuxRouteManager，
//! 批3 R3）实现逃逸。
//!
//! **缺省 0 = 不打 mark**（零差异）；`set_egress_fwmark` 启动期一次。
//! mark ≠ 0 但 `SO_MARK` 设置失败（缺 CAP_NET_ADMIN/非 Linux）→ 降级直连
//! （warn 一次，行为同缺省——不因逃逸功能自爆启动）。

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::net::TcpStream;

static EGRESS_FWMARK: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "linux")]
static MARK_DOWNGRADE_WARNED: AtomicBool = AtomicBool::new(false);

/// 设出站 fwmark（0 = 不打；启动期一次，测试可复位）。
pub fn set_egress_fwmark(mark: u32) {
    EGRESS_FWMARK.store(mark, Ordering::Relaxed);
}

/// 当前出站 fwmark（0 = 不打）。
pub fn egress_fwmark() -> u32 {
    EGRESS_FWMARK.load(Ordering::Relaxed)
}

/// 出站 TCP 连接统一入口（direct/proxy 各 connector、mesh 拨号面共用）。
///
/// - 解析：`std::net::ToSocketAddrs` 在 `spawn_blocking`；`A: Send + 'static`
///   （借用调用点需 clone）；
/// - 多候选：RFC 8305 Happy Eyeballs 竞速（[`order_candidates`] 排序 +
///   [`connect_racing`] 错峰并发）；单候选直连（免 spawn 开销，行为同前）；
/// - `egress_fwmark() == 0`：`TcpStream::connect`；
/// - `mark != 0`（Linux）：socket2 建 socket → `set_mark` → 非阻塞 connect →
///   注册 tokio → 等 writable → `take_error` 收敛（语义对齐
///   `connect().await`，含 ECONNREFUSED 等异步错误上抛）；
/// - `set_mark` 失败（无 CAP_NET_ADMIN）：warn 一次后该地址降级直连。
pub async fn connect_tcp<A>(addr: A) -> std::io::Result<TcpStream>
where
    A: std::net::ToSocketAddrs + Send + 'static,
    A::Iter: Send,
{
    let addrs = tokio::task::spawn_blocking(move || addr.to_socket_addrs())
        .await
        .map_err(std::io::Error::other)??;
    let mut candidates: Vec<std::net::SocketAddr> = addrs.collect();
    if candidates.len() <= 1 {
        // 单候选/无候选：原语义（无竞速收益，免 spawn 开销）
        return match candidates.pop() {
            Some(a) => connect_one(a).await,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "解析无地址",
            )),
        };
    }
    connect_racing(order_candidates(candidates)).await
}

/// RFC 8305 §5 候选排序：IPv6 优先、双栈交错（v6[0], v4[0], v6[1], v4[1]…）；
/// 单栈保持解析原序。
fn order_candidates(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6());
    let mut ordered = Vec::with_capacity(v6.len() + v4.len());
    let mut it6 = v6.into_iter();
    let mut it4 = v4.into_iter();
    loop {
        match (it6.next(), it4.next()) {
            (Some(a6), Some(a4)) => {
                ordered.push(a6);
                ordered.push(a4);
            }
            (Some(a6), None) => {
                ordered.push(a6);
                ordered.extend(it6);
                break;
            }
            (None, Some(a4)) => {
                ordered.push(a4);
                ordered.extend(it4);
                break;
            }
            (None, None) => break,
        }
    }
    ordered
}

/// 相邻候选错峰间隔（RFC 8305 §5 建议值 250ms）。
const HEAD_START: std::time::Duration = std::time::Duration::from_millis(250);

/// Happy Eyeballs 竞速连接（≥2 候选）：首选候选立即发起；后续候选按
/// `HEAD_START` 错峰补位，或任一在途失败即刻补位（不等错峰）；首个成功者
/// 胜出返回，其余在途任务随 channel 关闭自行收弃（socket 落盘即 drop）。
async fn connect_racing(candidates: Vec<std::net::SocketAddr>) -> std::io::Result<TcpStream> {
    let total = candidates.len();
    debug_assert!(total >= 2);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<TcpStream>>(total);
    let mut pending = candidates.into_iter();
    let mut started = 0usize;
    let mut finished = 0usize;
    // 错峰时点（首选启动后即排程；候选耗尽后不再更新）
    let mut next_at;

    // 首选候选立即发起
    let first = pending.next().expect("竞速候选非空");
    let tx_first = tx.clone();
    tokio::spawn(async move {
        let _ = tx_first.send(connect_one(first).await).await;
    });
    started += 1;
    next_at = tokio::time::Instant::now() + HEAD_START;

    loop {
        tokio::select! {
            // 错峰到点 → 补位下一候选
            _ = tokio::time::sleep_until(next_at), if started < total => {
                if let Some(a) = pending.next() {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(connect_one(a).await).await;
                    });
                    started += 1;
                    if started < total {
                        next_at = tokio::time::Instant::now() + HEAD_START;
                    }
                }
            }
            // 任一候选出结果：成功即胜出；失败即刻补位（不等错峰）；
            // 全败收敛到末个错误
            Some(res) = rx.recv() => {
                finished += 1;
                match res {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        if started < total {
                            if let Some(a) = pending.next() {
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    let _ = tx.send(connect_one(a).await).await;
                                });
                                started += 1;
                                if started < total {
                                    next_at = tokio::time::Instant::now() + HEAD_START;
                                }
                            }
                        }
                        if finished == total {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

/// 单地址连接：mark 非零走 SO_MARK 面，否则/非 Linux 走普通连接。
#[cfg(target_os = "linux")]
async fn connect_one(addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    let mark = egress_fwmark();
    if mark != 0 {
        connect_addr_marked(addr, mark).await
    } else {
        TcpStream::connect(addr).await
    }
}

#[cfg(not(target_os = "linux"))]
async fn connect_one(addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

#[cfg(target_os = "linux")]
async fn connect_addr_marked(addr: std::net::SocketAddr, mark: u32) -> std::io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    if let Err(e) = sock.set_mark(mark) {
        if MARK_DOWNGRADE_WARNED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(
                mark,
                error = %e,
                "SO_MARK 设置失败，降级直连（逃逸需 CAP_NET_ADMIN）"
            );
        }
        drop(sock);
        return TcpStream::connect(addr).await;
    }
    // 非阻塞 connect：进行中（WouldBlock/EINPROGRESS）与即刻成败都收敛到
    // 下方等待；即刻失败（如 ECONNREFUSED）由 connect 冒泡
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)?;
    // 等连接完成（对齐 connect().await 语义），再收割异步错误。
    // writable 可能先于握手落定触发（内核/时序差），take_error 拿到
    // InProgress 属「未落定」——继续等下一次可写事件，不当作失败冒泡。
    loop {
        stream.writable().await?;
        match stream.take_error()? {
            // EINPROGRESS：握手未落定，等下一次可写事件再收
            Some(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => continue,
            Some(e) => return Err(e),
            None => return Ok(stream),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 读 /proc/self/status CapEff 判 CAP_NET_ADMIN（bit 12）是否在——容器内
    /// root 常剥该 cap，set_mark 降级后 SO_MARK 读回恒 0，读回断言需跳过。
    #[cfg(target_os = "linux")]
    fn has_cap_net_admin() -> bool {
        const CAP_NET_ADMIN_BIT: u64 = 1 << 12;
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("CapEff:"))
                    .map(|l| l.trim_start_matches("CapEff:").trim().to_string())
            })
            .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
            .map(|caps| caps & CAP_NET_ADMIN_BIT != 0)
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    fn has_cap_net_admin() -> bool {
        true
    }

    #[test]
    fn set_get_roundtrip_and_reset() {
        set_egress_fwmark(0);
        assert_eq!(egress_fwmark(), 0, "缺省 0 不打 mark");
        set_egress_fwmark(0x5E45);
        assert_eq!(egress_fwmark(), 0x5E45);
        set_egress_fwmark(0);
    }

    /// mark=0 路径与 TcpStream::connect 等价（回环 echo 写读通）。
    #[tokio::test]
    async fn zero_mark_connects_like_plain() {
        set_egress_fwmark(0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let mut client = connect_tcp(addr).await.expect("缺省路径应连通");
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    /// mark ≠ 0 但无 CAP_NET_ADMIN（常规测试环境）→ 降级直连，连接仍成功。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn marked_connect_downgrades_without_cap() {
        set_egress_fwmark(0x5E45);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).await.unwrap();
        });
        // root（CAP_NET_ADMIN 在）→ 真打 mark；普通用户 → 降级。两态都应连通
        let mut client = connect_tcp(addr).await.expect("降级/真打 mark 都应连通");
        client.write_all(b"ok").await.unwrap();
        server.await.unwrap();
        set_egress_fwmark(0);
    }

    /// mark 生效面读回（root 守卫：SO_MARK getsockopt 仅特权可读；
    /// 非 root 跳过——降级路径已由上测覆盖）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn marked_connect_sets_mark_readable_as_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("跳过：需 root 验证 SO_MARK 读回");
            return;
        }
        // 有 root 但无 CAP_NET_ADMIN（容器默认剥离）→ set_mark 降级，mark 读回恒 0，跳过
        if !has_cap_net_admin() {
            eprintln!("跳过：缺 CAP_NET_ADMIN，降级路径由上测覆盖");
            return;
        }
        set_egress_fwmark(0x5E45);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.read_exact(&mut [0u8; 2]).await;
        });
        let mut stream = connect_tcp(addr).await.expect("root 下应真打 mark");
        // 反向查：本端连接 socket 的 SO_MARK 读回
        let sock = socket2::SockRef::from(&stream);
        let got = sock.mark().expect("root 读 SO_MARK 应成功");
        assert_eq!(got, 0x5E45, "SO_MARK 应生效");
        stream.write_all(b"ok").await.unwrap();
        server.await.unwrap();
        set_egress_fwmark(0);
    }

    /// RFC 8305 §5 排序：IPv6 优先、双栈交错，单栈保序。
    #[test]
    fn order_candidates_interleaves_v6_first() {
        let v6a: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v6b: std::net::SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let v4a: std::net::SocketAddr = "192.0.2.10:443".parse().unwrap();
        let v4b: std::net::SocketAddr = "192.0.2.11:443".parse().unwrap();

        assert_eq!(
            order_candidates(vec![v4a, v6a, v4b, v6b]),
            vec![v6a, v4a, v6b, v4b],
            "双栈交错：v6 优先"
        );
        assert_eq!(
            order_candidates(vec![v4b, v4a]),
            vec![v4b, v4a],
            "单栈 v4 保持解析原序"
        );
        assert_eq!(
            order_candidates(vec![v6b, v6a]),
            vec![v6b, v6a],
            "单栈 v6 保持解析原序"
        );
    }

    /// 竞速：首选候选快速失败（loopback :1 拒连）→ 即刻补位次选 →
    /// 次选回环 echo 胜出（失败加速语义，不等 HEAD_START 错峰）。
    #[tokio::test]
    async fn racing_second_candidate_wins_on_first_failure() {
        set_egress_fwmark(0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        let refused: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let mut c = connect_racing(vec![refused, echo_addr])
            .await
            .expect("次选应胜出");
        c.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");
        server.await.unwrap();
    }

    /// 竞速：全部候选失败 → last_err 收敛（Err 上抛，不挂死）。
    #[tokio::test]
    async fn racing_all_fail_returns_error() {
        set_egress_fwmark(0);
        let refused_a: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let refused_b: std::net::SocketAddr = "127.0.0.1:2".parse().unwrap();
        let err = connect_racing(vec![refused_a, refused_b])
            .await
            .expect_err("全败应返回 Err");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }
}
