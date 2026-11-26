//! nftables 规则规划面（RIL-041 OpenWrt 网关）：fw4/nftables 共存纪律——
//! 专用表（inet `rillane` / ip `rillane` / ip6 `rillane`，fw4 只管自己的
//! inet fw4 表，互不清除；fw4 reload 不触碰外来表），OS-free 纯 argv
//! 构造，执行归调用方（透明入口 StepExecutor shell-out / 机批次特权
//! 验收门）。
//!
//! 与 RIL-139 iptables 规划面（transparent.rs）同形状（[`TransparentRule`]
//! apply/undo argv + label 幂等键），机制差异具名：
//! - 族面：redirect 一张 inet 表覆盖 IPv4+IPv6（iptables 面无 ip6tables
//!   步骤——nft 面天然闭合双栈）；tproxy 拆 ip/ip6 两张同名词表（对齐
//!   mihomo 部署实证形状——inet 族 tproxy 的内核版本面不由本面下注）；
//! - 撤销纪律：nft 无按表达式删规则（delete 需 handle），专用表使
//!   **表级 delete 即整面精确撤销**——每步 undo 恒为表 delete（逆向
//!   执行首删即净，后续步 missing 视为已撤销，与 RIL-029 is_missing
//!   同语义）；ip rule/route 步逐条 undo（与 iptables 面同构）；
//! - 重入幂等：`add table`/`add chain` 重复 = EEXIST（"File exists"，
//!   与 is_already_applied 同语义）；规则重复在 nft 不报错——规则步前
//!   置 `flush chain` 清陈旧面，重 apply 不叠加副本。
//!
//! 语义与 iptables 面逐项对齐：逐端口规则仅 tcp（iptables `-p tcp`）；
//! 全端口 = 无协议过滤；tproxy `--on-ip` 字面镜像（`tproxy ip to
//! <listen_ip>:<port>` / `tproxy ip6 to [<listen_ip6>]:<port>`，0.0.0.0/::
//! = 内核"按原目标查 socket"特例）。边界：UDP 应用面不交付（RIL-139
//! catalog 口径同族）；规则应用需 root/CAP_NET_ADMIN + nft 二进制；
//! 真机验收归 OpenWrt 机批次。语法面经 nftables 1.1.6 `nft -c` 解析
//! 仲裁（语法错/EPERM 可区分，全形态零解析错）。

use std::net::SocketAddr;

use super::transparent::{TransparentRule, TPROXY_MARK};

/// 专用表名（inet/ip/ip6 三族同名词——族命名空间天然分表；fw4 表名
/// 为 `fw4`，永不冲突）
pub const NFT_TABLE: &str = "rillane";

/// REDIRECT 规划（inet 表单张，双栈）：建表 → 双链（nat dstnat，policy
/// accept——非 rillane 流量直通，不改 fw4 语义）→ flush（重入清陈旧）
/// → 逐端口规则（PREROUTING = 经路由器 LAN 入站面；OUTPUT = 本机产生
/// 流量，排除逃逸 mark——本进程出站不回收）。`ports` 空 = 全端口单规则。
pub fn plan_nft_redirect_rules(
    listen: SocketAddr,
    ports: &[u16],
    escape_mark: u32,
) -> Vec<TransparentRule> {
    let mut rules = Vec::new();
    // 建表（undo = 表 delete——整面撤销锚）
    rules.push(TransparentRule {
        label: "nft:table".into(),
        apply: vec![
            "nft".into(),
            "add".into(),
            "table".into(),
            "inet".into(),
            NFT_TABLE.into(),
        ],
        undo: delete_table_argv("inet"),
    });
    for chain in ["prerouting", "output"] {
        // 建链：nat dstnat 优先级 + policy accept（非 rillane 流量直通）
        rules.push(TransparentRule {
            label: format!("nft:chain-{chain}"),
            apply: add_chain_argv("inet", chain, "nat", "dstnat"),
            undo: delete_table_argv("inet"),
        });
    }
    for chain in ["prerouting", "output"] {
        // flush：重入场景清陈旧规则（nft 重复 add rule 不报错会叠加）
        rules.push(TransparentRule {
            label: format!("nft:flush-{chain}"),
            apply: vec![
                "nft".into(),
                "flush".into(),
                "chain".into(),
                "inet".into(),
                NFT_TABLE.into(),
                chain.into(),
            ],
            undo: delete_table_argv("inet"),
        });
    }
    let to_ports = format!(":{}", listen.port());
    for p in port_specs(ports) {
        // PREROUTING：LAN 客户端经路由器的入站面
        let mut prerouting = vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            NFT_TABLE.into(),
            "prerouting".into(),
        ];
        prerouting.extend(port_match(p));
        prerouting.extend(["redirect".into(), "to".into(), to_ports.clone()]);
        rules.push(TransparentRule {
            label: format!("nft:redirect-prerouting-{}", port_label(p)),
            apply: prerouting,
            undo: delete_table_argv("inet"),
        });
        // OUTPUT：本机产生流量，排除逃逸 mark（自环防制面——mark 口径
        // 与 RIL-029 逃逸表同值）
        let mut output = vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            NFT_TABLE.into(),
            "output".into(),
            "meta".into(),
            "mark".into(),
            "!=".into(),
            escape_mark.to_string(),
        ];
        output.extend(port_match(p));
        output.extend(["redirect".into(), "to".into(), to_ports.clone()]);
        rules.push(TransparentRule {
            label: format!("nft:redirect-output-{}", port_label(p)),
            apply: output,
            undo: delete_table_argv("inet"),
        });
    }
    rules
}

/// TPROXY 规划（ip/ip6 双表 + ip rule/route 双栈）：机制链 = filter
/// mangle（`tproxy` 目标 + `mark set`——标记流量经 ip rule fwmark 回
/// 本机监听）。v6 面是 iptables 面没有的增量（ip6tables 缺口的闭合）。
/// `rule_table` 语义与 iptables 面同（缺省 100，RIL-029 逃逸表号）。
pub fn plan_nft_tproxy_rules(
    listen: SocketAddr,
    ports: &[u16],
    rule_table: u32,
) -> Vec<TransparentRule> {
    let mut rules = Vec::new();
    // tproxy 地址形态：--on-ip 字面镜像（iptables 面传 listen.ip() 原文）；
    // 显式 ip/ip6 关键词（仲裁验证形态——0.0.0.0/:: = 内核按原目标查
    // socket 特例，与 iptables --on-ip 0.0.0.0 语义对齐）
    let to_v4 = format!("{}:{}", listen.ip(), listen.port());
    let to_v6 = format!("[{}]:{}", listen.ip(), listen.port());
    for (family, tproxy_keyword, to_ports) in
        [("ip", "ip", to_v4.as_str()), ("ip6", "ip6", to_v6.as_str())]
    {
        rules.push(TransparentRule {
            label: format!("nft:table-{family}"),
            apply: vec![
                "nft".into(),
                "add".into(),
                "table".into(),
                family.into(),
                NFT_TABLE.into(),
            ],
            undo: delete_table_argv(family),
        });
        rules.push(TransparentRule {
            label: format!("nft:chain-{family}"),
            apply: add_chain_argv(family, "prerouting", "filter", "mangle"),
            undo: delete_table_argv(family),
        });
        rules.push(TransparentRule {
            label: format!("nft:flush-{family}"),
            apply: vec![
                "nft".into(),
                "flush".into(),
                "chain".into(),
                family.into(),
                NFT_TABLE.into(),
                "prerouting".into(),
            ],
            undo: delete_table_argv(family),
        });
        for p in port_specs(ports) {
            let mut rule = vec![
                "nft".into(),
                "add".into(),
                "rule".into(),
                family.into(),
                NFT_TABLE.into(),
                "prerouting".into(),
            ];
            rule.extend(port_match(p));
            rule.extend([
                "meta".into(),
                "mark".into(),
                "set".into(),
                TPROXY_MARK.to_string(),
            ]);
            rule.extend([
                "tproxy".into(),
                tproxy_keyword.into(),
                "to".into(),
                to_ports.into(),
            ]);
            rules.push(TransparentRule {
                label: format!("nft:tproxy-{family}-{}", port_label(p)),
                apply: rule,
                undo: delete_table_argv(family),
            });
        }
    }
    // 标记流量回本机监听：ip rule fwmark + local 路由，v4/v6 双栈
    //（undo 逆序：route 先于 rule del）；v6 是 iptables 面没有的增量
    for v6 in [false, true] {
        let prefix: &[&str] = if v6 { &["-6"] } else { &[] };
        let dest = if v6 { "::/0" } else { "0.0.0.0/0" };
        let mut add_rule = vec!["ip".to_string()];
        add_rule.extend(prefix.iter().map(|s| s.to_string()));
        add_rule.extend(["rule".into(), "add".into(), "fwmark".into()]);
        add_rule.push(TPROXY_MARK.to_string());
        add_rule.extend(["table".into(), rule_table.to_string()]);
        rules.push(TransparentRule {
            label: format!("tproxy:rule-{}", if v6 { "v6" } else { "v4" }),
            apply: add_rule,
            undo: {
                let mut del = vec!["ip".to_string()];
                del.extend(prefix.iter().map(|s| s.to_string()));
                del.extend(["rule".into(), "del".into(), "fwmark".into()]);
                del.push(TPROXY_MARK.to_string());
                del.extend(["table".into(), rule_table.to_string()]);
                del
            },
        });
        let mut add_route = vec!["ip".to_string()];
        add_route.extend(prefix.iter().map(|s| s.to_string()));
        add_route.extend([
            "route".into(),
            "replace".into(),
            "local".into(),
            dest.into(),
            "dev".into(),
            "lo".into(),
            "table".into(),
        ]);
        add_route.push(rule_table.to_string());
        rules.push(TransparentRule {
            label: format!("tproxy:route-{}", if v6 { "v6" } else { "v4" }),
            apply: add_route,
            undo: {
                let mut del = vec!["ip".to_string()];
                del.extend(prefix.iter().map(|s| s.to_string()));
                del.extend([
                    "route".into(),
                    "del".into(),
                    "local".into(),
                    dest.into(),
                    "dev".into(),
                    "lo".into(),
                    "table".into(),
                ]);
                del.push(rule_table.to_string());
                del
            },
        });
    }
    rules
}

/// 端口规格（空 = 全端口单规格 None——与 iptables 面同语义）
fn port_specs(ports: &[u16]) -> Vec<Option<u16>> {
    if ports.is_empty() {
        vec![None]
    } else {
        ports.iter().map(|p| Some(*p)).collect()
    }
}

/// label 后缀（None = "all"）
fn port_label(port: Option<u16>) -> String {
    port.map_or("all".into(), |p| p.to_string())
}

/// 逐端口 = 仅 tcp（iptables `-p tcp` 语义）；全端口 = 无协议过滤
fn port_match(port: Option<u16>) -> Vec<String> {
    match port {
        Some(p) => vec!["tcp".into(), "dport".into(), p.to_string()],
        None => Vec::new(),
    }
}

/// 表级 delete（nft 无按表达式删规则——专用表使整面撤销精确幂等；
/// 表不存在 = "No such table"，与 is_missing 同语义）
fn delete_table_argv(family: &str) -> Vec<String> {
    vec![
        "nft".into(),
        "delete".into(),
        "table".into(),
        family.into(),
        NFT_TABLE.into(),
    ]
}

/// 建链 argv：机制链规格以单元素传 nft（shell-out join 空格后即
/// `nft -f` 文件形态；`policy accept` = 非 rillane 流量直通）。hook
/// 随链名（prerouting/output 各挂各面——hook 与链名是两件事，挂错面
/// 流量根本不经过）。
fn add_chain_argv(family: &str, chain: &str, kind: &str, priority: &str) -> Vec<String> {
    vec![
        "nft".into(),
        "add".into(),
        "chain".into(),
        family.into(),
        NFT_TABLE.into(),
        chain.into(),
        format!("{{ type {kind} hook {chain} priority {priority} ; policy accept ; }}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen() -> SocketAddr {
        "127.0.0.1:3128".parse().expect("listen")
    }

    #[test]
    fn redirect_plan_shapes_table_chain_flush_then_rules() {
        let rules = plan_nft_redirect_rules(listen(), &[80, 443], 24173);
        // 顺序：建表 → 双链 → 双 flush → 逐端口双面（2 端口 × 2）
        assert_eq!(rules[0].label, "nft:table");
        assert_eq!(rules[0].apply, ["nft", "add", "table", "inet", "rillane"]);
        assert_eq!(rules[1].label, "nft:chain-prerouting");
        assert_eq!(rules[2].label, "nft:chain-output");
        let chain_spec = rules[1].apply.last().expect("chain spec");
        assert_eq!(
            chain_spec,
            "{ type nat hook prerouting priority dstnat ; policy accept ; }"
        );
        // output 链挂 output hook（hook 与链名是两件事——挂错面流量不经过）
        let out_spec = rules[2].apply.last().expect("output chain spec");
        assert_eq!(
            out_spec,
            "{ type nat hook output priority dstnat ; policy accept ; }"
        );
        assert_eq!(rules[3].label, "nft:flush-prerouting");
        assert_eq!(rules[4].label, "nft:flush-output");
        assert_eq!(rules.len(), 5 + 4, "2 端口 × PREROUTING/OUTPUT 两面");
        // 逐端口规则：仅 tcp dport + redirect 目标端口
        let p80 = &rules[5];
        assert_eq!(p80.label, "nft:redirect-prerouting-80");
        assert_eq!(
            p80.apply,
            [
                "nft",
                "add",
                "rule",
                "inet",
                "rillane",
                "prerouting",
                "tcp",
                "dport",
                "80",
                "redirect",
                "to",
                ":3128"
            ]
        );
        // OUTPUT 面带逃逸 mark 排除（本进程出站不回收）
        let out80 = &rules[6];
        assert_eq!(out80.label, "nft:redirect-output-80");
        assert_eq!(out80.apply[6..10], ["meta", "mark", "!=", "24173"]);
        assert!(out80.apply.iter().any(|i| i == ":3128"));
    }

    #[test]
    fn redirect_all_ports_drops_protocol_filter() {
        let rules = plan_nft_redirect_rules(listen(), &[], 24173);
        let prerouting = rules
            .iter()
            .find(|r| r.label == "nft:redirect-prerouting-all")
            .expect("all-ports prerouting rule");
        assert!(
            !prerouting.apply.iter().any(|i| i == "tcp"),
            "全端口无协议过滤"
        );
        assert!(prerouting
            .apply
            .ends_with(&["redirect".into(), "to".into(), ":3128".into()]));
    }

    #[test]
    fn redirect_undo_is_uniform_idempotent_table_delete() {
        let rules = plan_nft_redirect_rules(listen(), &[80], 24173);
        assert!(rules
            .iter()
            .all(|r| r.undo == ["nft", "delete", "table", "inet", "rillane"]));
        // label 全唯一（幂等键/对账面）
        let mut labels: Vec<_> = rules.iter().map(|r| r.label.clone()).collect();
        labels.sort();
        let n = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), n, "label 不得重复");
    }

    #[test]
    fn tproxy_plan_dual_table_dual_stack() {
        let rules = plan_nft_tproxy_rules(listen(), &[443], 100);
        // v4 表 → v6 表 → rule/route ×2 栈
        let table_v4 = rules
            .iter()
            .find(|r| r.label == "nft:table-ip")
            .expect("v4 table");
        assert_eq!(table_v4.apply, ["nft", "add", "table", "ip", "rillane"]);
        let table_v6 = rules
            .iter()
            .find(|r| r.label == "nft:table-ip6")
            .expect("v6 table");
        assert_eq!(table_v6.apply, ["nft", "add", "table", "ip6", "rillane"]);
        // 机制链 = filter mangle
        let chain_v4 = rules
            .iter()
            .find(|r| r.label == "nft:chain-ip")
            .expect("v4 chain");
        assert_eq!(
            chain_v4.apply.last().expect("chain spec"),
            "{ type filter hook prerouting priority mangle ; policy accept ; }"
        );
        // 规则带 mark set + tproxy 地址镜像（显式 ip 关键词，--on-ip 字面）
        let r443 = rules
            .iter()
            .find(|r| r.label == "nft:tproxy-ip-443")
            .expect("v4 443 rule");
        assert_eq!(
            r443.apply,
            [
                "nft",
                "add",
                "rule",
                "ip",
                "rillane",
                "prerouting",
                "tcp",
                "dport",
                "443",
                "meta",
                "mark",
                "set",
                &TPROXY_MARK.to_string(),
                "tproxy",
                "ip",
                "to",
                "127.0.0.1:3128"
            ]
        );
        let r443v6 = rules
            .iter()
            .find(|r| r.label == "nft:tproxy-ip6-443")
            .expect("v6 443 rule");
        assert!(r443v6.apply.iter().any(|i| i == "ip6"));
        assert!(r443v6.apply.iter().any(|a| a.contains("3128")));
    }

    #[test]
    fn tproxy_policy_routing_covers_both_stacks() {
        let rules = plan_nft_tproxy_rules(listen(), &[], 100);
        // v4 + v6 各一对 rule/route（iptables 面只有 v4——v6 是本面增量）
        for (rule_label, has_v6) in [("tproxy:rule-v4", false), ("tproxy:rule-v6", true)] {
            let rule = rules
                .iter()
                .find(|r| r.label == rule_label)
                .expect(rule_label);
            assert_eq!(rule.apply[0], "ip", "{rule_label} 程序面");
            assert_eq!(
                rule.apply.iter().filter(|a| a.as_str() == "-6").count(),
                usize::from(has_v6),
                "{rule_label} -6 前缀有无"
            );
            assert!(rule.apply.contains(&"fwmark".into()));
            assert!(rule.apply.contains(&"100".into()), "{rule_label} 表号");
        }
        // route 步：local 目标 + lo 设备 + 表号；undo = del 形态（逆序撤销
        // 先 route 后 rule）
        for (route_label, dest, has_v6) in [
            ("tproxy:route-v4", "0.0.0.0/0", false),
            ("tproxy:route-v6", "::/0", true),
        ] {
            let route = rules
                .iter()
                .find(|r| r.label == route_label)
                .expect(route_label);
            assert_eq!(route.apply[0], "ip");
            assert_eq!(
                route.apply.iter().filter(|a| a.as_str() == "-6").count(),
                usize::from(has_v6),
                "{route_label} -6 前缀有无"
            );
            let kw = ["local", dest, "dev", "lo", "table", "100"];
            for k in kw {
                assert!(route.apply.contains(&k.into()), "{route_label} 含 {k}");
            }
            assert!(
                route.undo.contains(&"del".into()) && !route.undo.contains(&"replace".into()),
                "{route_label} undo 是 del 形态"
            );
            assert!(route.undo.contains(&dest.into()));
        }
    }

    #[test]
    fn tproxy_listen_v6_mirrors_bracketed_form() {
        let listen: SocketAddr = "[::1]:3129".parse().expect("v6 listen");
        let rules = plan_nft_tproxy_rules(listen, &[443], 100);
        let r = rules
            .iter()
            .find(|r| r.label == "nft:tproxy-ip6-443")
            .expect("v6 rule");
        assert_eq!(r.apply.last().expect("tproxy form"), "[::1]:3129");
    }
}
