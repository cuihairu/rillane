//! SOCKS5 入口协议实现

use std::{net::Ipv6Addr, sync::Arc};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use rillane_config::Credential;
use rillane_core::udp::UdpAssociateService;
use rillane_core::{
    BoxedIo, Flow, FlowId, FlowMetadata, FlowOutput, FlowRouter, FlowTarget, IngressEndpoint,
    TargetProto,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub(crate) async fn handle_socks5_stream(
    ingress_node_name: &str,
    credentials: &[Credential],
    mut stream: TcpStream,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
    udp: Option<Arc<UdpAssociateService>>,
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
) -> Result<()> {
    let client_addr = stream.peer_addr().ok();
    let auth_required = !credentials.is_empty();

    // 协商认证方法
    negotiate_method(&mut stream, auth_required).await?;

    // 执行认证（用户名用于 UDP 粘滞键 user 维度，udp-session-table.md §3.1）
    let username = if auth_required {
        Some(perform_auth(&mut stream, credentials).await?)
    } else {
        None
    };

    // 解析请求（命令分派：0x01 CONNECT / 0x03 UDP ASSOCIATE，其余 0x07）
    let (cmd, target_host, target_port) = parse_request_cmd(&mut stream).await?;
    match cmd {
        0x01 => {
            send_success(&mut stream).await?;
            forward_tcp(
                ingress_node_name,
                client_addr,
                stream,
                router,
                output,
                target_host,
                target_port,
                fake_ip,
            )
            .await
        }
        0x03 => match udp {
            // udp_enabled=false → 0x07（udp-relay-path.md §2.1）
            None => {
                send_error(&mut stream, 0x07).await?;
                bail!("UDP ASSOCIATE 未启用（udp.enabled=false）");
            }
            Some(svc) => svc.serve(&mut stream, username).await,
        },
        _ => {
            send_error(&mut stream, 0x07).await?;
            bail!("不支持的 SOCKS5 命令: {cmd}");
        }
    }
}

/// CONNECT 既有路径：构建 Flow 流式转发（行为不变）。
/// fake-ip 回填（G1-10）：target 为池段 IPv4 时反查原域名改写（DNS 面分配
/// 的假地址），路由按域名规则命中；原域名记 `dns.fakeip` 注解可观测。
#[allow(clippy::too_many_arguments)]
async fn forward_tcp(
    ingress_node_name: &str,
    client_addr: Option<std::net::SocketAddr>,
    stream: TcpStream,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
    target_host: String,
    target_port: u16,
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
) -> Result<()> {
    let mut metadata = FlowMetadata {
        tags: vec![
            "ingress:socks5".into(),
            format!("node:{}", ingress_node_name),
        ],
        ..Default::default()
    };
    if let Some(addr) = client_addr {
        metadata
            .annotations
            .insert("client.addr".into(), addr.to_string());
    }
    metadata
        .annotations
        .insert("ingress.node".into(), ingress_node_name.to_string());

    let target_host = match fake_ip
        .as_ref()
        .and_then(|t| rillane_core::fake_ip::reverse_host(t, &target_host))
    {
        Some(domain) => {
            metadata
                .annotations
                .insert("dns.fakeip".into(), domain.clone());
            domain
        }
        None => target_host,
    };

    let flow = Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: target_host,
            port: target_port,
            proto: TargetProto::Tcp,
        },
        io: Box::new(stream) as BoxedIo,
        metadata,
    };

    let ctx = flow.context();
    let decision = router.route(ctx).await.context("路由计算失败")?;
    output
        .forward(decision, flow)
        .await
        .context("出口转发失败")?;

    Ok(())
}

/// SOCKS5 入口服务
pub struct Socks5Ingress {
    name: String,
    bind: String,
    credentials: Vec<Credential>,
    /// UDP ASSOCIATE 服务（None = udp.enabled=false → 0x03 应 0x07）
    udp: Option<Arc<UdpAssociateService>>,
    /// fake-ip 池（G1-10；None = 关闭，target 原样路由）
    fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
}

impl Socks5Ingress {
    pub fn new(
        name: String,
        bind: String,
        credentials: Vec<Credential>,
        udp: Option<Arc<UdpAssociateService>>,
        fake_ip: Option<Arc<rillane_core::fake_ip::FakeIpTable>>,
    ) -> Self {
        Self {
            name,
            bind,
            credentials,
            udp,
            fake_ip,
        }
    }

    async fn handle_client(
        self: Arc<Self>,
        stream: TcpStream,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        handle_socks5_stream(
            self.name.as_str(),
            &self.credentials,
            stream,
            router,
            output,
            self.udp.clone(),
            self.fake_ip.clone(),
        )
        .await
    }
}

#[async_trait]
impl IngressEndpoint for Socks5Ingress {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn run(
        self: Arc<Self>,
        router: Arc<dyn FlowRouter>,
        output: Arc<dyn FlowOutput>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("无法监听 {}", self.bind))?;

        tracing::info!(
            target: "rillane::socks5",
            bind = %self.bind,
            "SOCKS5 入口启动"
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = self.clone();
            let router = router.clone();
            let output = output.clone();

            tokio::spawn(async move {
                if let Err(err) = this.handle_client(stream, router, output).await {
                    tracing::warn!(
                        target: "rillane::socks5",
                        client = %addr,
                        error = %err,
                        "SOCKS5 连接处理失败"
                    );
                }
            });
        }
    }
}

/// 协商认证方法
async fn negotiate_method<S>(stream: &mut S, auth_required: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        bail!("SOCKS5 版本错误");
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let desired = if auth_required { 0x02 } else { 0x00 };
    if !methods.contains(&desired) {
        stream.write_all(&[0x05, 0xFF]).await?;
        bail!("客户端不支持所需认证方式");
    }

    stream.write_all(&[0x05, desired]).await?;
    Ok(())
}

/// 执行用户名密码认证，成功返回用户名（UDP 粘滞键 user 维度）
async fn perform_auth<S>(stream: &mut S, users: &[Credential]) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;

    if ver[0] != 0x01 {
        bail!("SOCKS5 认证版本错误");
    }

    // 读取用户名
    let username_len = read_u8(stream).await? as usize;
    let mut username = vec![0u8; username_len];
    stream.read_exact(&mut username).await?;

    // 读取密码
    let password_len = read_u8(stream).await? as usize;
    let mut password = vec![0u8; password_len];
    stream.read_exact(&mut password).await?;

    let username = String::from_utf8(username)?;
    let password = String::from_utf8(password)?;

    let valid = users.iter().any(|cred| {
        rillane_core::constant_time_eq(cred.username.as_bytes(), username.as_bytes())
            && rillane_core::constant_time_eq(cred.password.as_bytes(), password.as_bytes())
    });

    if valid {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(username)
    } else {
        stream.write_all(&[0x01, 0x01]).await?;
        bail!("认证失败")
    }
}

/// 解析 SOCKS5 请求头，返回 (命令, 目标地址, 端口)。命令分派由调用方处理
/// （0x01 CONNECT / 0x03 UDP ASSOCIATE；其余由调用方应 0x07）
async fn parse_request_cmd<S>(stream: &mut S) -> Result<(u8, String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        bail!("SOCKS5 请求版本错误");
    }
    let cmd = header[1];

    // 解析地址
    let host = match header[3] {
        // IPv4
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        // 域名
        0x03 => {
            let len = read_u8(stream).await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let host = String::from_utf8(buf)?;
            // P1 安全：域名字符串不得含空/CR/LF/控制字符——HTTP CONNECT
            // 出口把 host 内插进请求行与 Host 头，未校验即请求走私/头注入
            // （SOCKS5 客户端可向上游代理注入任意头）。
            if crate::host_has_injection_chars(&host) {
                send_error(stream, 0x08).await?; // 地址类型不支持（拒绝语义）
                bail!("SOCKS5 域名含非法控制字符或为空");
            }
            host
        }
        // IPv6
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        atyp => {
            send_error(stream, 0x08).await?; // Address type not supported
            bail!("不支持的地址类型: {atyp}");
        }
    };

    let port = read_u16(stream).await?;
    Ok((cmd, host, port))
}

/// 发送成功响应
async fn send_success<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let resp = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&resp).await?;
    Ok(())
}

/// 发送错误响应
async fn send_error<S>(stream: &mut S, rep: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let resp = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&resp).await?;
    Ok(())
}

async fn read_u8<S>(stream: &mut S) -> Result<u8>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16<S>(stream: &mut S) -> Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// P1 回归：SOCKS5 域名字符串含 CR/LF/控制字符 → parse_request_cmd 拒绝。
    /// 此前未校验，HTTP CONNECT 出口把 host 内插进请求行与 Host 头，
    /// 客户端可经此向上游代理注入任意头（请求走私/头伪造）。
    #[tokio::test]
    async fn rejects_crlf_in_domain() {
        // VER=5 CMD=CONNECT RSV=0 ATYP=0x03(域名) LEN=11 "evil.com\r\n"
        let mut payload = vec![0x05, 0x01, 0x00, 0x03, 0x0B];
        payload.extend_from_slice(b"evil.com\r\nX-Injected: 1");
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&payload).await.unwrap();
        let res = parse_request_cmd(&mut server).await;
        assert!(res.is_err(), "含 CRLF 的域名字符串应被拒绝（头注入防御）");
    }

    /// 合法域名（纯 ASCII 字母数字点横）应正常解析。
    #[tokio::test]
    async fn accepts_plain_domain() {
        let mut payload = vec![0x05, 0x01, 0x00, 0x03, 0x0B];
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&[0x00, 0x50]); // 端口 80
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&payload).await.unwrap();
        let (cmd, host, port) = parse_request_cmd(&mut server).await.unwrap();
        assert_eq!(cmd, 0x01);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    /// P1 安全回归：SOCKS5 域名字符串含空格/authority 元字符（`@`/`/`/`?`/`#`）
    /// 亦应被拒绝——host 内插进 CONNECT 请求行与 `Host` 头时这些字符可被上游
    /// 按 `userinfo@host`/`host/path`/`host?query`/`host#fragment` 解析致目标混淆
    /// （请求走私/SSRF 变体）。
    #[tokio::test]
    async fn rejects_authority_metachars_and_space_in_domain() {
        for bad in [
            "evil.com @x",
            "evil.com@x",
            "evil.com/x",
            "evil.com?x",
            "evil.com#x",
        ] {
            let mut payload = vec![0x05, 0x01, 0x00, 0x03, bad.len() as u8];
            payload.extend_from_slice(bad.as_bytes());
            let (mut client, mut server) = tokio::io::duplex(256);
            client.write_all(&payload).await.unwrap();
            let res = parse_request_cmd(&mut server).await;
            assert!(res.is_err(), "含 {bad:?} 的域名字符串应被拒绝");
        }
    }
}
