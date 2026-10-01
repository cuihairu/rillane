//! SOCKS5 入口协议实现

use std::{net::Ipv6Addr, sync::Arc};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use seep_config::Credential;
use seep_core::udp::UdpAssociateService;
use seep_core::{
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

/// CONNECT 既有路径：构建 Flow 流式转发（行为不变）
async fn forward_tcp(
    ingress_node_name: &str,
    client_addr: Option<std::net::SocketAddr>,
    stream: TcpStream,
    router: Arc<dyn FlowRouter>,
    output: Arc<dyn FlowOutput>,
    target_host: String,
    target_port: u16,
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
}

impl Socks5Ingress {
    pub fn new(
        name: String,
        bind: String,
        credentials: Vec<Credential>,
        udp: Option<Arc<UdpAssociateService>>,
    ) -> Self {
        Self {
            name,
            bind,
            credentials,
            udp,
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
            target: "seep::socks5",
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
                        target: "seep::socks5",
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

    let valid = users
        .iter()
        .any(|cred| cred.username == username && cred.password == password);

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
            String::from_utf8(buf)?
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
