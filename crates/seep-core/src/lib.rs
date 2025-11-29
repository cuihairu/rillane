use std::{collections::BTreeMap, fmt, pin::Pin, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

/// Trait object safe IO stream with AsyncRead/AsyncWrite combined.
pub trait IoStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// Boxed bidirectional IO stream used by inbound/outbound handlers.
pub type BoxedIo = Pin<Box<dyn IoStream + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId(Uuid);

impl FlowId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetProto {
    Tcp,
    Udp,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTarget {
    pub host: String,
    pub port: u16,
    pub proto: TargetProto,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowMetadata {
    pub tags: Vec<String>,
    pub annotations: BTreeMap<String, String>,
}

pub struct Flow {
    pub id: FlowId,
    pub target: FlowTarget,
    pub io: BoxedIo,
    pub metadata: FlowMetadata,
}

impl fmt::Debug for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow")
            .field("id", &self.id)
            .field("target", &self.target)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Flow {
    pub fn context(&self) -> FlowContext {
        FlowContext {
            id: self.id,
            target: self.target.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub id: FlowId,
    pub target: FlowTarget,
    pub metadata: FlowMetadata,
}

#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub next_hop: String,
    pub reason: Option<String>,
}

#[async_trait]
pub trait FlowRouter: Send + Sync {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision>;
}

#[async_trait]
pub trait FlowMiddleware: Send + Sync {
    fn name(&self) -> &'static str;
    async fn handle(&self, flow: Flow) -> Result<Flow>;
}

#[async_trait]
pub trait EgressConnector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn forward(&self, flow: Flow) -> Result<()>;
}

#[async_trait]
pub trait IngressEndpoint: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(self: Arc<Self>, router: Arc<dyn FlowRouter>) -> Result<()>;
}
