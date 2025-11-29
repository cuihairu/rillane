use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use seep_core::{EgressConnector, Flow, FlowMiddleware, FlowRouter, IngressEndpoint};
use tokio::time::{sleep, Duration};

pub mod inbound {
    use super::*;

    pub struct Socks5Ingress {
        pub bind: String,
    }

    #[async_trait]
    impl IngressEndpoint for Socks5Ingress {
        fn name(&self) -> &'static str {
            "socks5"
        }

        async fn run(self: Arc<Self>, router: Arc<dyn FlowRouter>) -> Result<()> {
            tracing::info!(target: "seep::socks5", bind = %self.bind, "listener bootstrap");
            let _ = router;
            Ok(())
        }
    }
}

pub mod outbound {
    use super::*;

    pub struct DirectConnector;

    #[async_trait]
    impl EgressConnector for DirectConnector {
        fn name(&self) -> &'static str {
            "direct"
        }

        async fn forward(&self, flow: Flow) -> Result<()> {
            tracing::debug!(
                target: "seep::direct",
                id = %flow.id.as_uuid(),
                "forwarding via system stack"
            );
            Ok(())
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
