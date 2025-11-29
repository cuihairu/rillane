use std::sync::Arc;

use anyhow::{anyhow, Result};
use seep_config::{IngressConfig, IngressDescriptor, SeepConfig};
use seep_core::IngressEndpoint;
use seep_protocols::inbound::Socks5Ingress;
use seep_routing::RoutingEngine;
use tokio::task::JoinSet;
use tracing::info;

pub struct RuntimeBuilder {
    config: SeepConfig,
}

impl RuntimeBuilder {
    pub fn new(config: SeepConfig) -> Self {
        Self { config }
    }

    pub fn build(self) -> Result<SeepRuntime> {
        let router = Arc::new(RoutingEngine::new(self.config.routing.clone()));
        let ingress = build_ingress(&self.config)?;
        Ok(SeepRuntime { router, ingress })
    }
}

pub struct SeepRuntime {
    router: Arc<RoutingEngine>,
    ingress: Vec<Arc<dyn IngressEndpoint>>,
}

impl SeepRuntime {
    pub async fn run(self) -> Result<()> {
        info!(
            target: "seep::runtime",
            ingress = self.ingress.len(),
            "启动 Seep runtime"
        );

        let mut join_set = JoinSet::new();
        for endpoint in self.ingress.into_iter() {
            let router = self.router.clone();
            join_set.spawn(async move { endpoint.run(router).await });
        }

        while let Some(result) = join_set.join_next().await {
            result??;
        }

        Ok(())
    }
}

type DynIngress = Arc<dyn IngressEndpoint>;

fn build_ingress(config: &SeepConfig) -> Result<Vec<DynIngress>> {
    config
        .ingress
        .iter()
        .map(instantiate_ingress)
        .collect::<Result<Vec<_>>>()
        .map_err(|err| anyhow!("入口配置错误: {err}"))
}

fn instantiate_ingress(descriptor: &IngressDescriptor) -> Result<DynIngress> {
    match &descriptor.spec {
        IngressConfig::Socks5 { bind, .. }
        | IngressConfig::Http { bind }
        | IngressConfig::Mixed { bind } => {
            Ok(Arc::new(Socks5Ingress { bind: bind.clone() }) as DynIngress)
        }
    }
}
