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
/// - 解析：`std::net::ToSocketAddrs` 在 `spawn_blocking`（tokio 内部对字符串
///   地址同为此路径——多候选逐个试连取首个成功，`last_err` 收敛，与
///   `TcpStream::connect` 同构）；故 `A: Send + 'static`（借用调用点需 clone）；
/// - `egress_fwmark() == 0`：候选逐个 `TcpStream::connect`（等价现状）；
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
    let mut last_err: Option<std::io::Error> = None;
    for a in addrs {
        match connect_one(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "解析无地址")))
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
}
