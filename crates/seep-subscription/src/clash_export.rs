//! Seep → Clash 回导出（subscription.md §7 边界第二条的兑现）。
//!
//! 方向与 [`crate::clash`]（Clash → Seep 导入）对称：`seep.yaml` 的
//! egress/policy-groups/rules 映射为 Clash `proxies`/`proxy-groups`/`rules`
//! YAML，供 Clash 系客户端消费。映射口径（不可线性化处如实登记进
//! [`ClashExportReport::skipped`]，绝不静默丢弃）：
//!
//! - **规则**：seep `RouteRule.matches` 为 AND 语义（seep-routing
//!   `matches.iter().all`），Clash 规则为首中即停的 OR 列表——单条件规则
//!   逐值展开为 Clash 规则串；多条件规则跳过并登记。
//! - **组策略**：`Fixed`→select；`Latency`→url-test；`RoundRobin`/
//!   `Random`/`Bandwidth`/`Weighted`→load-balance(round-robin)，
//!   `ConsistentHash`→load-balance(consistent-hashing)（Random/Weighted/
//!   Bandwidth 无精确对应，登记降级）。
//! - **direct 出口**：不产出 proxy，组内/规则目标映射 Clash 内置 `DIRECT`。
//! - **字段降级**：seep 独有字段（vmess/vless `tls_fingerprint`、http `sni`、
//!   组成员权重、hy1 `protocol/up/down` 的非标值等）无 Clash 对应时不阻塞
//!   导出，登记到 skipped。

use anyhow::{Context, Result};
use seep_config::{
    EgressConfig, GroupMember, MatchCondition, SeepConfig as ProjectConfig, Strategy,
};
use serde::Serialize;
use serde_yaml::{Mapping, Value};

use crate::clash::{ClashProxyGroup, ClashProxyGroupType};

/// 回导出产物 + 逐条登记（skipped 非空 = 有损导出，调用方应呈现）
#[derive(Debug, Clone, Default)]
pub struct ClashExportReport {
    pub exported_proxies: Vec<String>,
    pub exported_groups: Vec<String>,
    pub exported_rules: usize,
    /// 跳过/降级条目（「对象：原因」），不静默
    pub skipped: Vec<String>,
}

/// 回导出文档根（proxies 用裸 Mapping——Clash 规范键为 kebab-case
/// `skip-cert-verify`/`alterId` 等，与导入侧 `ClashProxy` 的 snake 序列化
/// 面解耦，保证写出即 Clash 可读）
#[derive(Debug, Serialize)]
struct ClashExportDoc {
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    mixed_port: Option<u16>,
    proxies: Vec<Value>,
    #[serde(rename = "proxy-groups")]
    proxy_groups: Vec<ClashProxyGroup>,
    rules: Vec<String>,
}

/// Seep → Clash 回导出器（无状态；`export` 纯函数）
#[derive(Debug, Clone, Copy, Default)]
pub struct ClashExporter;

impl ClashExporter {
    /// 导出为 Clash YAML 文本 + 登记报告
    pub fn export(&self, config: &ProjectConfig) -> Result<(String, ClashExportReport)> {
        let mut report = ClashExportReport::default();
        let mut proxies = Vec::new();
        // direct 出口名集（组/规则目标映射 DIRECT 用）
        let direct_names: Vec<String> = config
            .egress
            .iter()
            .filter(|e| matches!(e.spec, EgressConfig::Direct))
            .map(|e| e.name.clone())
            .collect();

        for egress in &config.egress {
            if let Some(map) = proxy_mapping(&egress.name, &egress.spec, &mut report) {
                proxies.push(Value::Mapping(map));
                report.exported_proxies.push(egress.name.clone());
            }
        }

        let mut groups = Vec::new();
        for group in &config.routing.groups {
            // 无精确对应的策略降级登记（口径见模块注记）
            if matches!(
                group.strategy,
                Strategy::Random | Strategy::Weighted | Strategy::Bandwidth
            ) {
                report.skipped.push(format!(
                    "组 {}: 策略 {:?} 无 Clash 精确对应，降级 load-balance(round-robin)",
                    group.name, group.strategy
                ));
            }
            let members: Vec<String> = group
                .members
                .iter()
                .map(|m| member_name(m, &direct_names))
                .collect();
            groups.push(ClashProxyGroup {
                name: group.name.clone(),
                group_type: group_type(&group.strategy),
                proxies: members,
                url: url_test_url(&group.strategy),
                interval: interval_ms(&group.strategy),
                strategy: load_balance_strategy(&group.strategy),
            });
            report.exported_groups.push(group.name.clone());
        }

        let mut rules = Vec::new();
        for rule in &config.routing.rules {
            if rule.matches.len() != 1 {
                report.skipped.push(format!(
                    "规则 {}：seep 多条件 AND 语义（{} 个条件）不可线性化为 Clash 首中即停列表",
                    rule.name,
                    rule.matches.len()
                ));
                continue;
            }
            let target = target_name(&rule.target, &direct_names);
            let before = rules.len();
            condition_to_rules(&rule.matches[0], &target, &mut rules);
            if rules.len() == before {
                report.skipped.push(format!(
                    "规则 {}：Any/Not 逻辑条件暂不导出 Clash",
                    rule.name
                ));
            } else {
                report.exported_rules += rules.len() - before;
            }
        }
        // 默认路由 → MATCH（default_node 指向 direct 出口时映射 DIRECT）
        rules.push(format!(
            "MATCH,{}",
            target_name(&config.routing.default_node, &direct_names)
        ));

        let doc = ClashExportDoc {
            mixed_port: None,
            proxies,
            proxy_groups: groups,
            rules,
        };
        let yaml = serde_yaml::to_string(&doc).context("Clash 文档序列化失败")?;
        Ok((yaml, report))
    }
}

/// 单出口 → Clash proxy Mapping；Direct 返回 None（内置 DIRECT，不产出）
fn proxy_mapping(
    name: &str,
    spec: &EgressConfig,
    report: &mut ClashExportReport,
) -> Option<Mapping> {
    let mut m = Mapping::new();
    ins(&mut m, "name", name);
    match spec {
        EgressConfig::Direct => None,
        EgressConfig::Socks5 {
            server,
            port,
            username,
            password,
        } => {
            ins(&mut m, "type", "socks5");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            if let Some(u) = username {
                ins(&mut m, "username", u);
            }
            if let Some(p) = password {
                ins(&mut m, "password", p);
            }
            Some(m)
        }
        EgressConfig::Http {
            server,
            port,
            username,
            password,
            tls,
            skip_cert_verify,
            sni,
            tls_fingerprint,
        } => {
            ins(&mut m, "type", if *tls { "https" } else { "http" });
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            if let Some(u) = username {
                ins(&mut m, "username", u);
            }
            if let Some(p) = password {
                ins(&mut m, "password", p);
            }
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            degrade(report, name, sni.is_some(), "http.sni 无 Clash 对应");
            degrade(
                report,
                name,
                tls_fingerprint.is_some(),
                "http.tls_fingerprint 无 Clash 对应",
            );
            Some(m)
        }
        EgressConfig::Shadowsocks {
            server,
            port,
            method,
            password,
            plugin,
            plugin_opts,
        } => {
            ins(&mut m, "type", "ss");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "cipher", method);
            ins(&mut m, "password", password);
            // SIP003 插件面无 Clash 等价表达（clash 侧 plugin-opts 为 map，
            // 语义换算归后续批）：插件字段降级不导出
            degrade(
                report,
                name,
                plugin.is_some() || plugin_opts.is_some(),
                "shadowsocks.plugin/plugin_opts 无 Clash 对应",
            );
            Some(m)
        }
        EgressConfig::Vmess {
            server,
            port,
            uuid,
            alter_id,
            security,
            network,
            path,
            host,
            grpc_service_name,
            tls,
            skip_cert_verify,
            sni,
            alpn,
            tls_fingerprint,
        } => {
            ins(&mut m, "type", "vmess");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "uuid", uuid);
            ins(&mut m, "alterId", *alter_id as u64);
            ins(&mut m, "cipher", security);
            if *tls {
                ins(&mut m, "tls", true);
            }
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            if let Some(s) = sni {
                ins(&mut m, "servername", s);
            }
            if let Some(a) = alpn {
                ins(&mut m, "alpn", a.clone());
            }
            ws_opts(&mut m, network, path.as_deref(), host.as_deref());
            h2_opts(&mut m, network, path.as_deref(), host.as_deref());
            if network == "grpc" {
                if let Some(svc) = grpc_service_name {
                    let mut gopts = Mapping::new();
                    ins(&mut gopts, "grpc-service-name", svc.as_str());
                    ins(&mut m, "grpc-opts", gopts);
                }
            }
            degrade(
                report,
                name,
                tls_fingerprint.is_some(),
                "vmess.tls_fingerprint 无 Clash 对应",
            );
            Some(m)
        }
        EgressConfig::Vless {
            server,
            port,
            uuid,
            flow,
            network,
            path,
            host,
            grpc_service_name,
            tls,
            skip_cert_verify,
            sni,
            alpn,
            tls_fingerprint,
        } => {
            ins(&mut m, "type", "vless");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "uuid", uuid);
            if let Some(f) = flow {
                ins(&mut m, "flow", f);
            }
            if *tls {
                ins(&mut m, "tls", true);
            }
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            if let Some(s) = sni {
                ins(&mut m, "servername", s);
            }
            if let Some(a) = alpn {
                ins(&mut m, "alpn", a.clone());
            }
            ws_opts(&mut m, network, path.as_deref(), host.as_deref());
            h2_opts(&mut m, network, path.as_deref(), host.as_deref());
            if network == "grpc" {
                if let Some(svc) = grpc_service_name {
                    let mut gopts = Mapping::new();
                    ins(&mut gopts, "grpc-service-name", svc.as_str());
                    ins(&mut m, "grpc-opts", gopts);
                }
            }
            degrade(
                report,
                name,
                tls_fingerprint.is_some(),
                "vless.tls_fingerprint 无 Clash 对应",
            );
            Some(m)
        }
        EgressConfig::Trojan {
            server,
            port,
            password,
            network,
            path,
            host,
            grpc_service_name,
            tls: _,
            skip_cert_verify,
            sni,
            alpn,
            tls_fingerprint,
        } => {
            // seep trojan 缺省 tls=true；Clash trojan 恒 TLS，tls 字段不导
            ins(&mut m, "type", "trojan");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "password", password);
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            if let Some(s) = sni {
                ins(&mut m, "sni", s);
            }
            if let Some(a) = alpn {
                ins(&mut m, "alpn", a.clone());
            }
            ws_opts(&mut m, network, path.as_deref(), host.as_deref());
            if network == "grpc" {
                if let Some(svc) = grpc_service_name {
                    let mut gopts = Mapping::new();
                    ins(&mut gopts, "grpc-service-name", svc.as_str());
                    ins(&mut m, "grpc-opts", gopts);
                }
            }
            degrade(
                report,
                name,
                tls_fingerprint.is_some(),
                "trojan.tls_fingerprint 无 Clash 对应",
            );
            Some(m)
        }
        EgressConfig::Hysteria {
            server,
            port,
            password,
            protocol,
            up_mbps,
            down_mbps,
            auth,
            auth_str,
            obfs,
            obfs_param,
            server_name,
            skip_cert_verify,
            alpn,
        } => {
            ins(&mut m, "type", "hysteria");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "protocol", protocol);
            if let Some(a) = auth_str.clone().or_else(|| auth.clone()) {
                ins(&mut m, "auth-str", a);
            } else {
                ins(&mut m, "auth-str", password);
            }
            if let Some(u) = up_mbps {
                ins(&mut m, "up", *u as u64);
            }
            if let Some(d) = down_mbps {
                ins(&mut m, "down", *d as u64);
            }
            if let Some(o) = obfs {
                ins(&mut m, "obfs", o);
            }
            if let Some(op) = obfs_param {
                ins(&mut m, "obfs-param", op);
            }
            if let Some(s) = server_name {
                ins(&mut m, "sni", s);
            }
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            if let Some(a) = alpn {
                ins(&mut m, "alpn", a.clone());
            }
            Some(m)
        }
        EgressConfig::Hysteria2 {
            server,
            port,
            password,
            mport,
            obfs,
            obfs_param,
            server_name,
            skip_cert_verify,
            alpn,
        } => {
            ins(&mut m, "type", "hysteria2");
            ins(&mut m, "server", server);
            ins(&mut m, "port", *port as u64);
            ins(&mut m, "password", password);
            if let Some(mp) = mport {
                ins(&mut m, "ports", mp);
            }
            if let Some(o) = obfs {
                ins(&mut m, "obfs", o);
            }
            if let Some(op) = obfs_param {
                ins(&mut m, "obfs-password", op);
            }
            if let Some(s) = server_name {
                ins(&mut m, "sni", s);
            }
            if *skip_cert_verify {
                ins(&mut m, "skip-cert-verify", true);
            }
            if let Some(a) = alpn {
                ins(&mut m, "alpn", a.clone());
            }
            Some(m)
        }
        EgressConfig::Wireguard {
            endpoint,
            private_key,
            public_key,
            address,
            allowed_ips,
            preshared_key,
            persistent_keepalive,
            listen_port,
            mtu,
            dns,
        } => {
            // endpoint "host:port"（host 允许 IPv6 字面量——右起最后一个冒号切分）
            let (server, port) = endpoint
                .rsplit_once(':')
                .map(|(h, p)| (h.to_string(), p.to_string()))
                .unwrap_or_else(|| (endpoint.clone(), String::new()));
            if port.is_empty() || port.parse::<u16>().is_err() {
                report.skipped.push(format!(
                    "出口 {name}: wireguard.endpoint「{endpoint}」缺端口或端口非法"
                ));
                return None;
            }
            ins(&mut m, "type", "wireguard");
            ins(&mut m, "server", server);
            ins(&mut m, "port", port.parse::<u64>().unwrap_or(0));
            ins(&mut m, "private-key", private_key);
            ins(&mut m, "public-key", public_key);
            ins(&mut m, "ip", vec![address.clone()]);
            if let Some(a) = allowed_ips {
                ins(&mut m, "allowed-ips", a.clone());
            }
            if let Some(p) = preshared_key {
                ins(&mut m, "preshared-key", p);
            }
            if let Some(k) = persistent_keepalive {
                ins(&mut m, "persistent-keepalive", *k as u64);
            }
            if let Some(p) = listen_port {
                degrade(
                    report,
                    name,
                    true,
                    &format!("wireguard.listen_port={p} 无 Clash 对应（客户端自选）"),
                );
            }
            if let Some(mt) = mtu {
                ins(&mut m, "mtu", *mt as u64);
            }
            if let Some(d) = dns {
                ins(&mut m, "dns", d.clone());
            }
            Some(m)
        }
    }
}

/// ws 传输面（vmess/vless/trojan 共用）：network=ws 且有 path/host 时写
/// `ws-opts` 块（Host 取首值）；network=tcp 不写 network 键（Clash 缺省 tcp）
fn ws_opts(m: &mut Mapping, network: &str, path: Option<&str>, host: Option<&[String]>) {
    if network != "ws" {
        return;
    }
    ins(m, "network", "ws");
    let mut ws = Mapping::new();
    if let Some(p) = path {
        ins(&mut ws, "path", p);
    }
    if let Some(hosts) = host {
        if let Some(first) = hosts.first() {
            let mut headers = Mapping::new();
            ins(&mut headers, "Host", first);
            ins(&mut ws, "headers", headers);
        }
    }
    ins(m, "ws-opts", ws);
}

/// h2 传输导出：`network: h2` + `h2-opts` 块（host 数组 + path）。
/// trojan 无 h2 传输（Clash 同口径），不调用本助手。
fn h2_opts(m: &mut Mapping, network: &str, path: Option<&str>, host: Option<&[String]>) {
    if network != "h2" {
        return;
    }
    ins(m, "network", "h2");
    let mut h = Mapping::new();
    if let Some(p) = path {
        ins(&mut h, "path", p);
    }
    if let Some(hosts) = host {
        if !hosts.is_empty() {
            ins(&mut h, "host", hosts.to_vec());
        }
    }
    ins(m, "h2-opts", h);
}

fn condition_to_rules(cond: &MatchCondition, target: &str, rules: &mut Vec<String>) {
    match cond {
        MatchCondition::Any { .. } | MatchCondition::Not { .. } => {}
        MatchCondition::DomainSuffix { values } => {
            for v in values {
                rules.push(format!("DOMAIN-SUFFIX,{v},{target}"));
            }
        }
        MatchCondition::DomainKeyword { values } => {
            for v in values {
                rules.push(format!("DOMAIN-KEYWORD,{v},{target}"));
            }
        }
        MatchCondition::Geoip { country } => {
            rules.push(format!("GEOIP,{country},{target}"));
        }
        MatchCondition::Network { cidrs } => {
            for c in cidrs {
                // IPv6 前缀走 IP-CIDR6（Clash 规范键）；IPv4 走 IP-CIDR
                if c.contains(':') {
                    rules.push(format!("IP-CIDR6,{c},{target}"));
                } else {
                    rules.push(format!("IP-CIDR,{c},{target}"));
                }
            }
        }
        MatchCondition::IpCidr { cidrs } => {
            for c in cidrs {
                if c.contains(':') {
                    rules.push(format!("IP-CIDR6,{c},{target}"));
                } else {
                    rules.push(format!("IP-CIDR,{c},{target}"));
                }
            }
        }
        MatchCondition::Port { values } => {
            for p in values {
                rules.push(format!("DST-PORT,{p},{target}"));
            }
        }
        MatchCondition::Process { values } => {
            for v in values {
                rules.push(format!("PROCESS-NAME,{v},{target}"));
            }
        }
    }
}

/// 组成员名：指向 direct 出口的成员映射 Clash 内置 DIRECT；权重为 seep
/// 侧选择语义，Clash load-balance 无权重面——不阻塞导出
fn member_name(member: &GroupMember, direct_names: &[String]) -> String {
    let name = match member {
        GroupMember::Node { name } => name,
        GroupMember::Group { name } => name,
        GroupMember::WeightedNode { name, .. } => name,
        GroupMember::WeightedGroup { name, .. } => name,
    };
    if direct_names.iter().any(|d| d == name) {
        "DIRECT".to_string()
    } else {
        name.clone()
    }
}

/// 规则/默认路由目标名（direct 出口 → DIRECT）
fn target_name(target: &str, direct_names: &[String]) -> String {
    if direct_names.iter().any(|d| d == target) {
        "DIRECT".to_string()
    } else {
        target.to_string()
    }
}

/// 组策略 → Clash 组类型（映射口径见模块注记）
fn group_type(strategy: &Strategy) -> ClashProxyGroupType {
    match strategy {
        Strategy::Fixed => ClashProxyGroupType::Select,
        Strategy::Latency => ClashProxyGroupType::UrlTest,
        Strategy::Random
        | Strategy::Bandwidth
        | Strategy::Weighted
        | Strategy::RoundRobin
        | Strategy::ConsistentHash => ClashProxyGroupType::LoadBalance,
    }
}

/// url-test 的测速 URL（仅 Latency 策略生成）
fn url_test_url(strategy: &Strategy) -> Option<String> {
    match strategy {
        Strategy::Latency => Some("http://www.gstatic.com/generate_204".to_string()),
        _ => None,
    }
}

/// url-test 测速间隔（毫秒）
fn interval_ms(strategy: &Strategy) -> Option<u64> {
    match strategy {
        Strategy::Latency => Some(300_000),
        _ => None,
    }
}

/// load-balance 的 strategy 子键
fn load_balance_strategy(strategy: &Strategy) -> Option<String> {
    match strategy {
        Strategy::ConsistentHash => Some("consistent-hashing".to_string()),
        Strategy::Random | Strategy::Bandwidth | Strategy::Weighted | Strategy::RoundRobin => {
            Some("round-robin".to_string())
        }
        Strategy::Fixed | Strategy::Latency => None,
    }
}

/// serde_yaml::Value 缺 `From<&String>`：导出面大量借用绑定，此处统一收口
trait IntoValue {
    fn into_value(self) -> Value;
}
impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}
impl IntoValue for &str {
    fn into_value(self) -> Value {
        Value::String(self.into())
    }
}
impl IntoValue for &String {
    fn into_value(self) -> Value {
        Value::String(self.clone())
    }
}
impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::String(self)
    }
}
impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::Bool(self)
    }
}
impl IntoValue for u64 {
    fn into_value(self) -> Value {
        Value::Number(self.into())
    }
}
impl IntoValue for Vec<String> {
    fn into_value(self) -> Value {
        self.into()
    }
}
impl IntoValue for Mapping {
    fn into_value(self) -> Value {
        Value::Mapping(self)
    }
}

/// 写键值小工具（统一 Value 包装）
fn ins(m: &mut Mapping, key: &str, value: impl IntoValue) {
    m.insert(Value::String(key.to_string()), value.into_value());
}

/// 字段降级登记（有该字段即记一条；不阻塞导出）
fn degrade(report: &mut ClashExportReport, node: &str, present: bool, reason: &str) {
    if present {
        report
            .skipped
            .push(format!("出口 {node}: {reason}（字段降级不导出）"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clash::ClashConverter;
    use seep_config::{EgressDescriptor, PolicyGroup, RouteRule, RoutingConfig, Strategy};

    fn sample_config() -> ProjectConfig {
        ProjectConfig {
            egress: vec![
                EgressDescriptor {
                    name: "direct-out".into(),
                    spec: EgressConfig::Direct,
                },
                EgressDescriptor {
                    name: "vm".into(),
                    spec: EgressConfig::Vmess {
                        server: "vm.example.com".into(),
                        port: 443,
                        uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                        alter_id: 0,
                        security: "auto".into(),
                        network: "ws".into(),
                        path: Some("/ray".into()),
                        host: Some(vec!["cdn.example.com".into()]),
                        grpc_service_name: None,
                        tls: true,
                        skip_cert_verify: false,
                        sni: Some("sni.example.com".into()),
                        alpn: Some(vec!["h2".into(), "http/1.1".into()]),
                        tls_fingerprint: None,
                    },
                },
                EgressDescriptor {
                    name: "ss".into(),
                    spec: EgressConfig::Shadowsocks {
                        server: "ss.example.com".into(),
                        port: 8388,
                        method: "aes-256-gcm".into(),
                        password: "pass-ss".into(),
                        plugin: None,
                        plugin_opts: None,
                    },
                },
                EgressDescriptor {
                    name: "hy2".into(),
                    spec: EgressConfig::Hysteria2 {
                        server: "hy.example.com".into(),
                        port: 36712,
                        password: "pass-hy2".into(),
                        mport: Some("36712-36720".into()),
                        obfs: Some("salamander".into()),
                        obfs_param: Some("obfs-pass".into()),
                        server_name: Some("hy-sni.example.com".into()),
                        skip_cert_verify: true,
                        alpn: None,
                    },
                },
                EgressDescriptor {
                    name: "wg".into(),
                    spec: EgressConfig::Wireguard {
                        endpoint: "wg.example.com:51820".into(),
                        private_key: "priv".into(),
                        public_key: "pub".into(),
                        address: "10.7.0.2/32".into(),
                        allowed_ips: Some(vec!["0.0.0.0/0".into()]),
                        preshared_key: None,
                        persistent_keepalive: Some(25),
                        listen_port: None,
                        mtu: Some(1420),
                        dns: None,
                    },
                },
            ],
            routing: RoutingConfig {
                default_node: "direct-out".into(),
                groups: vec![PolicyGroup {
                    name: "auto".into(),
                    strategy: Strategy::Latency,
                    members: vec![
                        GroupMember::Node { name: "vm".into() },
                        GroupMember::Node {
                            name: "direct-out".into(),
                        },
                    ],
                    slo: None,
                }],
                rules: vec![
                    RouteRule {
                        name: "cn-direct".into(),
                        matches: vec![MatchCondition::DomainSuffix {
                            values: vec!["example.cn".into()],
                        }],
                        target: "direct-out".into(),
                    },
                    RouteRule {
                        name: "multi-cond".into(),
                        matches: vec![
                            MatchCondition::DomainSuffix {
                                values: vec!["a.com".into()],
                            },
                            MatchCondition::Port { values: vec![443] },
                        ],
                        target: "vm".into(),
                    },
                ],
            },
            ..serde_yaml::from_str(
                "control:\n  api_bind: 127.0.0.1:1\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
            )
            .unwrap()
        }
    }

    /// 全类型映射 + 组 + 规则 + MATCH + DIRECT 映射逐项断言
    #[test]
    fn export_maps_proxies_groups_rules() {
        let (yaml, report) = ClashExporter.export(&sample_config()).unwrap();
        // 导出面：direct 不产 proxy；vm/ss/hy2/wg 四个导出
        assert_eq!(report.exported_proxies, vec!["vm", "ss", "hy2", "wg"]);
        assert!(report.exported_groups == vec!["auto"]);
        assert_eq!(report.exported_rules, 1, "多条件规则跳过后仅单条件规则计入");
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("multi-cond") && s.contains("AND")),
            "多条件规则应登记：{:?}",
            report.skipped
        );
        // MATCH 落 default_node（direct-out → DIRECT）
        assert!(yaml.contains("MATCH,DIRECT"), "{yaml}");
        // 单条件规则逐值展开 + target 直连映射
        assert!(yaml.contains("DOMAIN-SUFFIX,example.cn,DIRECT"), "{yaml}");
        // vmess 键形（kebab/alterId/servername）与 ws-opts 块
        assert!(
            yaml.contains("type: vmess") && yaml.contains("alterId: 0"),
            "{yaml}"
        );
        assert!(yaml.contains("servername: sni.example.com"), "{yaml}");
        assert!(
            yaml.contains("ws-opts:") && yaml.contains("path: /ray"),
            "{yaml}"
        );
        assert!(yaml.contains("Host: cdn.example.com"), "{yaml}");
        // hy2 mport→ports、obfs-param→obfs-password、skip-cert-verify kebab
        assert!(yaml.contains("ports: 36712-36720"), "{yaml}");
        assert!(yaml.contains("obfs-password: obfs-pass"), "{yaml}");
        assert!(yaml.contains("skip-cert-verify: true"), "{yaml}");
        // wireguard 键形与 endpoint 拆分
        assert!(
            yaml.contains("type: wireguard") && yaml.contains("private-key: priv"),
            "{yaml}"
        );
        assert!(
            yaml.contains("server: wg.example.com") && yaml.contains("port: 51820"),
            "{yaml}"
        );
        assert!(yaml.contains("persistent-keepalive: 25"), "{yaml}");
        // 组：Latency → url-test + 测速 URL + direct 成员映射 DIRECT
        assert!(yaml.contains("type: url-test"), "{yaml}");
        assert!(yaml.contains("generate_204"), "{yaml}");
        assert!(yaml.contains("- DIRECT"), "{yaml}");
    }

    /// 回读对账：导出 YAML 可被既有 ClashConverter.parse 完整解析，
    /// proxies/groups/rules 数量与导出报告一致（真往返证据）
    #[test]
    fn exported_yaml_reparses_via_clash_converter() {
        let (yaml, report) = ClashExporter.export(&sample_config()).unwrap();
        let parsed = ClashConverter::new()
            .parse(&yaml)
            .expect("导出应可被导入侧解析");
        assert_eq!(parsed.proxies.len(), report.exported_proxies.len());
        assert_eq!(parsed.proxy_groups.len(), report.exported_groups.len());
        assert_eq!(parsed.rules.len(), report.exported_rules + 1); // + MATCH
    }

    /// 组策略映射口径：Fixed→select、ConsistentHash→consistent-hashing、
    /// Weighted→round-robin（降级登记）
    #[test]
    fn strategy_mapping_and_degrade_notes() {
        assert!(matches!(
            group_type(&Strategy::Fixed),
            ClashProxyGroupType::Select
        ));
        assert_eq!(
            load_balance_strategy(&Strategy::ConsistentHash).as_deref(),
            Some("consistent-hashing")
        );
        assert_eq!(
            load_balance_strategy(&Strategy::Weighted).as_deref(),
            Some("round-robin")
        );
        assert!(group_type(&Strategy::Latency) == ClashProxyGroupType::UrlTest);

        let mut cfg = sample_config();
        cfg.routing.groups[0].strategy = Strategy::Weighted;
        cfg.routing.rules.clear();
        let (_, report) = ClashExporter.export(&cfg).unwrap();
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("组 auto") && s.contains("Weighted")),
            "Weighted 降级应有登记（成员权重面）：{:?}",
            report.skipped
        );
    }

    /// 多出口负形：endpoint 非法登记且不出 proxy；vmess ws 缺 host 不炸
    #[test]
    fn export_rejects_bad_endpoint_and_tolerates_missing_host() {
        let mut cfg = sample_config();
        if let EgressConfig::Wireguard { endpoint, .. } = &mut cfg.egress[4].spec {
            *endpoint = "no-port-here".into();
        }
        let (yaml, report) = ClashExporter.export(&cfg).unwrap();
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("wg") && s.contains("endpoint")),
            "非法 endpoint 应登记：{:?}",
            report.skipped
        );
        assert!(!yaml.contains("type: wireguard"));

        let mut cfg = sample_config();
        if let EgressConfig::Vmess { host, network, .. } = &mut cfg.egress[1].spec {
            *host = None;
            *network = "ws".into();
        }
        let (yaml, _) = ClashExporter.export(&cfg).unwrap();
        assert!(
            yaml.contains("path: /ray") && !yaml.contains("Host:"),
            "{yaml}"
        );
    }

    /// grpc 节点导出：grpc-opts.grpc-service-name 落块内键，ws-opts 不产
    #[test]
    fn grpc_opts_exported_for_grpc_network() {
        let mut cfg = sample_config();
        if let EgressConfig::Vmess {
            network,
            path,
            grpc_service_name,
            ..
        } = &mut cfg.egress[1].spec
        {
            *network = "grpc".into();
            *path = None;
            *grpc_service_name = Some("GunService".into());
        }
        let (yaml, _) = ClashExporter.export(&cfg).unwrap();
        assert!(
            yaml.contains("grpc-opts:") && yaml.contains("grpc-service-name: GunService"),
            "{yaml}"
        );
        assert!(!yaml.contains("ws-opts:"), "{yaml}");
    }

    #[test]
    fn h2_opts_exported_for_h2_network() {
        let mut cfg = sample_config();
        if let EgressConfig::Vmess {
            network,
            path,
            host,
            grpc_service_name,
            ..
        } = &mut cfg.egress[1].spec
        {
            *network = "h2".into();
            *path = Some("/h2path".into());
            *host = Some(vec!["cdn.example.com".into()]);
            *grpc_service_name = None;
        }
        let (yaml, _) = ClashExporter.export(&cfg).unwrap();
        assert!(yaml.contains("network: h2"), "{yaml}");
        assert!(
            yaml.contains("h2-opts:")
                && yaml.contains("path: /h2path")
                && yaml.contains("cdn.example.com"),
            "{yaml}"
        );
        assert!(!yaml.contains("grpc-opts:"), "{yaml}");
        assert!(!yaml.contains("ws-opts:"), "{yaml}");
    }
}
