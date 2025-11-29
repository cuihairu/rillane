use std::sync::RwLock;

use anyhow::Result;
use async_trait::async_trait;
use seep_config::{MatchCondition, RouteRule, RoutingConfig};
use seep_core::{FlowContext, FlowRouter, RouteDecision};

pub struct RoutingEngine {
    config: RwLock<RoutingConfig>,
}

impl RoutingEngine {
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    pub fn reload(&self, next: RoutingConfig) {
        *self.config.write().expect("routing poisoned") = next;
    }

    fn snapshot(&self) -> RoutingConfig {
        self.config.read().expect("routing poisoned").clone()
    }
}

#[async_trait]
impl FlowRouter for RoutingEngine {
    async fn route(&self, ctx: FlowContext) -> Result<RouteDecision> {
        let config = self.snapshot();
        for rule in &config.rules {
            if matches_rule(rule, &ctx) {
                return Ok(RouteDecision {
                    next_hop: rule.target.clone(),
                    reason: Some(rule.name.clone()),
                });
            }
        }

        Ok(RouteDecision {
            next_hop: config.default_node.clone(),
            reason: Some("default".into()),
        })
    }
}

fn matches_rule(rule: &RouteRule, ctx: &FlowContext) -> bool {
    rule.matches.iter().all(|matcher| match matcher {
        MatchCondition::DomainSuffix { values } => values
            .iter()
            .any(|suffix| ctx.target.host.ends_with(suffix)),
        MatchCondition::DomainKeyword { values } => values
            .iter()
            .any(|keyword| ctx.target.host.contains(keyword)),
        MatchCondition::Geoip { country } => ctx
            .metadata
            .annotations
            .get("geoip.country")
            .map(|c| c == country)
            .unwrap_or(false),
        MatchCondition::Network { cidrs } => ctx
            .metadata
            .annotations
            .get("client.cidr")
            .map(|cidr| cidrs.iter().any(|rule_cidr| rule_cidr == cidr))
            .unwrap_or(false),
        MatchCondition::Port { values } => values.contains(&ctx.target.port),
    })
}
