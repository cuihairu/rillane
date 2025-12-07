use std::{net::Ipv6Addr, sync::Arc};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use seep_config::Credential;
use seep_core::{
    BoxedIo, EgressConnector, Flow, FlowId, FlowMetadata, FlowMiddleware, FlowOutput, FlowReport,
    FlowRouter, FlowTarget, IngressEndpoint, TargetProto,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, Duration},
};

pub mod inbound {
    use super::*;

    pub struct Socks5Ingress {
        name: String,
        bind: String,
        credentials: Vec<Credential>,
    }

    impl Socks5Ingress {
        pub fn new(name: String, bind: String, credentials: Vec<Credential>) -> Self {
            Self {
                name,
                bind,
                credentials,
            }
        }

        async fn handle_client(
            self: Arc<Self>,
            mut stream: TcpStream,
            router: Arc<dyn FlowRouter>,
            output: Arc<dyn FlowOutput>,
        ) -> Result<()> {
            let client_addr = stream.peer_addr().ok();
            let auth_required = !self.credentials.is_empty();
            negotiate_method(&mut stream, auth_required).await?;
            if auth_required {
                perform_auth(&mut stream, &self.credentials).await?;
            }

            let (target_host, target_port) = parse_request(&mut stream).await?;
            send_success(&mut stream).await?;

            let mut metadata = FlowMetadata::default();
            metadata.tags = vec!["ingress:socks5".into(), format!("node:{}", self.name)];
            if let Some(addr) = client_addr {
                metadata
                    .annotations
                    .insert("client.addr".into(), addr.to_string());
            }
            metadata
                .annotations
                .insert("ingress.node".into(), self.name.clone());
            let flow = Flow {
                id: FlowId::new(),
                target: FlowTarget {
                    host: target_host.clone(),
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
                "Socks5 入口启动"
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
                            "Socks5 连接处理失败"
                        );
                    }
                });
            }
        }
    }

    async fn negotiate_method(stream: &mut TcpStream, auth_required: bool) -> Result<()> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            bail!("Socks5 版本错误");
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        let desired = if auth_required { 0x02 } else { 0x00 };
        if !methods.contains(&desired) {
            bail!("客户端不支持所需认证方式");
        }
        stream.write_all(&[0x05, desired]).await?;
        Ok(())
    }

    async fn perform_auth(stream: &mut TcpStream, users: &[Credential]) -> Result<()> {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await?;
        if ver[0] != 0x01 {
            bail!("Socks5 认证版本错误");
        }
        let username_len = read_u8(stream).await? as usize;
        let mut username = vec![0u8; username_len];
        stream.read_exact(&mut username).await?;
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
            Ok(())
        } else {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("认证失败")
        }
    }

    async fn parse_request(stream: &mut TcpStream) -> Result<(String, u16)> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            bail!("Socks5 请求版本错误");
        }
        if header[1] != 0x01 {
            bail!("仅支持 CONNECT 命令");
        }

        let host = match header[3] {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                std::net::Ipv4Addr::from(addr).to_string()
            }
            0x03 => {
                let len = read_u8(stream).await? as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                String::from_utf8(buf)?
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                Ipv6Addr::from(addr).to_string()
            }
            atyp => bail!("不支持的地址类型: {atyp}"),
        };

        let port = read_u16(stream).await?;
        Ok((host, port))
    }

    async fn send_success(stream: &mut TcpStream) -> Result<()> {
        let mut resp = Vec::with_capacity(10);
        resp.extend_from_slice(&[0x05, 0x00, 0x00, 0x01]);
        resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        stream.write_all(&resp).await?;
        Ok(())
    }

    async fn read_u8(stream: &mut TcpStream) -> Result<u8> {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        Ok(buf[0])
    }

    async fn read_u16(stream: &mut TcpStream) -> Result<u16> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        Ok(u16::from_be_bytes(buf))
    }
}

pub mod outbound {
    use super::*;
    use tokio::net::TcpStream as TokioTcpStream;

    pub type DynEgressConnector = Arc<dyn EgressConnector>;

    #[derive(Default)]
    pub struct DirectConnector;

    #[async_trait]
    impl EgressConnector for DirectConnector {
        fn name(&self) -> &'static str {
            "direct"
        }

        async fn forward(&self, mut flow: Flow) -> Result<FlowReport> {
            let target = format!("{}:{}", flow.target.host, flow.target.port);
            tracing::debug!(
                target: "seep::direct",
                id = %flow.id.as_uuid(),
                %target,
                "direct dialing"
            );

            let mut outbound = TokioTcpStream::connect(&target)
                .await
                .with_context(|| format!("连接目标 {target} 失败"))?;
            let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut outbound)
                .await
                .context("双向转发失败")?;
            Ok(FlowReport {
                upstream: up,
                downstream: down,
            })
        }
    }
}

pub mod middleware {
    use super::*;

    pub struct LatencyProbe;

    #[async_trait]
    impl FlowMiddleware for LatencyProbe {
        fn name(&self) -> &'static str {
            "latency_probe"
        }

        async fn handle(&self, flow: Flow) -> Result<Flow> {
            sleep(Duration::from_millis(1)).await;
            Ok(flow)
        }
    }
}
