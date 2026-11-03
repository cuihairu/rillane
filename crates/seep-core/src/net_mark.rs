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

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use tokio::net::TcpStream;

static EGRESS_FWMARK: AtomicU32 = AtomicU32::new(0);
#[cfg(test)]
static ACTIVE_CONNECTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static CONNECT_GATES: std::sync::Mutex<
    Vec<(std::net::SocketAddr, std::sync::Arc<tokio::sync::Notify>)>,
> = std::sync::Mutex::new(Vec::new());
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
/// 胜出返回，其余在途任务经 `abort` 取消（socket 随取消 drop，不再持握手）。
async fn connect_racing(candidates: Vec<std::net::SocketAddr>) -> std::io::Result<TcpStream> {
    let total = candidates.len();
    debug_assert!(total >= 2);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<TcpStream>>(total);
    let mut pending = candidates.into_iter();
    let mut started = 0usize;
    let mut finished = 0usize;
    let mut in_flight: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(total);
    // 错峰时点（首选启动后即排程；候选耗尽后不再更新）
    let mut next_at;

    // 首选候选立即发起
    let first = pending.next().expect("竞速候选非空");
    let tx_first = tx.clone();
    let h = tokio::spawn(async move {
        let _ = tx_first.send(connect_one(first).await).await;
    });
    in_flight.push(h);
    started += 1;
    next_at = tokio::time::Instant::now() + HEAD_START;

    loop {
        tokio::select! {
            // 错峰到点 → 补位下一候选
            _ = tokio::time::sleep_until(next_at), if started < total => {
                if let Some(a) = pending.next() {
                    let tx = tx.clone();
                    let h = tokio::spawn(async move {
                        let _ = tx.send(connect_one(a).await).await;
                    });
                    in_flight.push(h);
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
                    Ok(s) => {
                        // 胜出：中止仍在途的落选候选（取消其拨号/握手，
                        // 资源随任务取消释放）。
                        for h in in_flight {
                            h.abort();
                        }
                        return Ok(s);
                    }
                    Err(e) => {
                        if started < total {
                            if let Some(a) = pending.next() {
                                let tx = tx.clone();
                                let h = tokio::spawn(async move {
                                    let _ = tx.send(connect_one(a).await).await;
                                });
                                in_flight.push(h);
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
    #[cfg(test)]
    let _active = ActiveConnectGuard::new();
    #[cfg(test)]
    gate_wait(addr).await;
    let mark = egress_fwmark();
    if mark != 0 {
        connect_addr_marked(addr, mark).await
    } else {
        TcpStream::connect(addr).await
    }
}

#[cfg(test)]
async fn gate_wait(addr: std::net::SocketAddr) {
    let notify = {
        let gates = CONNECT_GATES.lock().unwrap_or_else(|e| e.into_inner());
        gates
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, n)| n.clone())
    };
    if let Some(notify) = notify {
        notify.notified().await;
    }
}

#[cfg(test)]
fn gate_set(addr: std::net::SocketAddr, notify: std::sync::Arc<tokio::sync::Notify>) {
    CONNECT_GATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((addr, notify));
}

#[cfg(test)]
fn gate_clear() {
    CONNECT_GATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
struct ActiveConnectGuard;

#[cfg(test)]
impl ActiveConnectGuard {
    fn new() -> Self {
        ACTIVE_CONNECTS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for ActiveConnectGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTS.fetch_sub(1, Ordering::SeqCst);
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
    // 非阻塞 connect：进行中与即刻成败都收敛到下方等待；即刻失败（如
    // ECONNREFUSED）由 connect 冒泡。Linux 恒返 EINPROGRESS(115)——stable 上
    // kind() 映射为 InProgress（不可命名变体）而非 WouldBlock，须按裸错码收敛，
    // 否则凡 set_mark 生效的环境每次连接都误报（runner 实录：code 115 冒泡）
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
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

    /// mark 全局态串行化：egress_fwmark 是进程级单例，并行测试互相改写会把
    /// plain 路径测成 marked 路径（runner 实录：readable 测试 panic 未复位，
    /// 同进程 zero_mark/downgrades 连带全军覆没）。凡 `set_egress_fwmark`
    /// 调用者先取锁；毒化容忍（前测 panic 不拖垮后测）。
    fn mark_lock() -> std::sync::MutexGuard<'static, ()> {
        static MARK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        MARK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn set_get_roundtrip_and_reset() {
        let _lk = mark_lock();
        set_egress_fwmark(0);
        assert_eq!(egress_fwmark(), 0, "缺省 0 不打 mark");
        set_egress_fwmark(0x5E45);
        assert_eq!(egress_fwmark(), 0x5E45);
        set_egress_fwmark(0);
    }

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// mark=0 路径与 TcpStream::connect 等价（回环 echo 写读通）。
    #[tokio::test]
    async fn zero_mark_connects_like_plain() {
        let _lk = mark_lock();
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

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// mark ≠ 0 但无 CAP_NET_ADMIN（常规测试环境）→ 降级直连，连接仍成功。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn marked_connect_downgrades_without_cap() {
        let _lk = mark_lock();
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

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// mark 生效面读回（root 守卫 + 直接探针）：SO_MARK getsockopt 仅特权可读；
    /// 能力判定用 setsockopt 探针而非 CapEff——seccomp/权限面可在 cap 齐备下
    /// 仍拦截 SO_MARK（runner 实录：CapEff bit 12 在、读回恒 0 假阳连红），
    /// 探针失败 → 降级语义已由上测覆盖；探针成功 → 硬断言读回。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn marked_connect_sets_mark_readable_as_root() {
        let _lk = mark_lock();
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("跳过：需 root 验证 SO_MARK 读回");
            return;
        }
        let probe = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        );
        let probe = match probe {
            Ok(p) => p,
            Err(e) => {
                eprintln!("跳过：无法建探针 socket（{e}）");
                return;
            }
        };
        if let Err(e) = probe.set_mark(0x5E45) {
            eprintln!("跳过：环境不支持 SO_MARK（{e}），降级路径由上测覆盖");
            return;
        }
        drop(probe);
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

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// 竞速：首选候选快速失败（loopback :1 拒连）→ 即刻补位次选 →
    /// 次选回环 echo 胜出（失败加速语义，不等 HEAD_START 错峰）。
    #[tokio::test]
    async fn racing_second_candidate_wins_on_first_failure() {
        let _lk = mark_lock();
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

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// 竞速：全部候选失败 → last_err 收敛（Err 上抛，不挂死）。
    #[tokio::test]
    async fn racing_all_fail_returns_error() {
        let _lk = mark_lock();
        set_egress_fwmark(0);
        let refused_a: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let refused_b: std::net::SocketAddr = "127.0.0.1:2".parse().unwrap();
        let err = connect_racing(vec![refused_a, refused_b])
            .await
            .expect_err("全败应返回 Err");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[allow(clippy::await_holding_lock)] // 测试有意持锁跨 await 串行化 mark 全局态
    /// P3（2026-11-03）：胜出后落选在途候选应被 abort（不再持握手/socket）。
    /// 两候选均经 gate 挂起：先放行 echo（胜出），此时次选确已在途（非因
    /// 250ms 错峰尚未启动）。胜出返回后、放行次选前断言在途计数归零——
    /// 若未 abort，次选仍挂起（计数 1），断言即红，可区分 abort 与否。
    #[tokio::test]
    async fn racing_winner_aborts_in_flight_losers() {
        let _lk = mark_lock();
        set_egress_fwmark(0);
        gate_clear();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        // 次选回环地址（未监听 → connect 立即 ECONNREFUSED），经 gate 挂起
        // 直至胜出后断言，确保胜出瞬间其确在途。
        let hang: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let echo_gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let hang_gate = std::sync::Arc::new(tokio::sync::Notify::new());
        gate_set(echo_addr, echo_gate.clone());
        gate_set(hang, hang_gate.clone());
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            let _ = s.read_exact(&mut buf).await;
        });
        let racing = tokio::spawn(connect_racing(vec![echo_addr, hang]));
        // 等次选也启动（250ms 错峰后已在途），两候选均 gate 挂起。
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        assert_eq!(
            ACTIVE_CONNECTS.load(Ordering::SeqCst),
            2,
            "两候选应均已启动并挂起于 gate"
        );
        // 放行首选 → 胜出 → abort 落选。
        echo_gate.notify_waiters();
        let c = tokio::time::timeout(std::time::Duration::from_secs(5), racing)
            .await
            .expect("首选胜出应在 5s 内返回")
            .expect("首选应胜出")
            .expect("首选应胜出");
        drop(c);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // 关键断言：放行次选前，在途计数须归零——未 abort 则次选仍挂起。
        assert_eq!(
            ACTIVE_CONNECTS.load(Ordering::SeqCst),
            0,
            "落选在途候选应被 abort，连接计数归零"
        );
        hang_gate.notify_waiters();
        server.abort();
        gate_clear();
    }
}
