//! 受管能力协商（RIL-050）：mesh 能力交换经受管信道（mTLS 认证后的
//! NodeId 才算受管声明），数据面按协商结果决策——不认证的声明一律拒
//! 绝；缺失能力显式保守回退并把原因记录进协商结果；绝不静默 fail-open
//! （对照 P1-4 混布升级窗口的「无法确认对端版本时不填充」——那是发送
//! 侧的连通性兜底，不是协商面：协商面给出的是受管声明下的显式判定）。

use serde::{Deserialize, Serialize};

use crate::NodeId;

/// 稳定原因码：能力声明未经认证（不受管——一律拒绝）
pub const CODE_CAP_UNTRUSTED: &str = "mesh.cap.untrusted";
/// 稳定原因码：帧版本无公共交集（不兼容——点名两侧版本集）
pub const CODE_CAP_INCOMPATIBLE: &str = "mesh.cap.incompatible";

/// 能力申报（封闭字段集——协商器逐字段显式判定，不猜语义）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityOffer {
    /// 支持的 MeshEnvelope 帧版本（升序声明；P1-4：1 = 基础帧、2 = 填充帧）
    pub envelope_versions: Vec<u32>,
    /// 帧填充能力（P1-4 版本门——单侧缺即显式关闭）
    pub padding: bool,
    /// UDP mesh 完整安全承载是否就绪（未就绪 = UDP mesh 明确拒绝，
    /// 不能明文旁路——mesh.md「安全与数据面」同口径）
    pub udp_secure_carriage: bool,
}

/// 对端信任面：受管 = mTLS 认证信道上的声明；其余一律不受管
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// 经认证（身份已绑定）的管理信道声明
    Managed,
    /// 未经认证（明文信道 / 匿名来源）——声明不可信
    Untrusted,
}

/// 对端 hello（能力声明 + 信任面）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub peer: NodeId,
    pub offer: CapabilityOffer,
    pub trust: PeerTrust,
}

/// 协商错误（稳定原因码 + 点名细节）
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationError {
    #[error("{CODE_CAP_UNTRUSTED}: 对端能力声明未经认证（{0}）——只接受受管信道声明")]
    Untrusted(NodeId),
    #[error("{CODE_CAP_INCOMPATIBLE}: 帧版本无公共交集（本端 {local:?} / 对端 {peer:?}）")]
    IncompatibleVersions {
        /// 本端申报版本集
        local: Vec<u32>,
        /// 对端申报版本集
        peer: Vec<u32>,
    },
}

/// 协商结果（数据面决策输入）；保守回退必带原因（可审计，不静默）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub peer: NodeId,
    /// 数据面帧版本 = 两侧版本集交集的最大公共版本
    pub envelope_version: u32,
    /// 帧填充 = 双侧申报齐备才开；单侧缺即 false + 原因
    pub padding: bool,
    /// UDP mesh = 双侧安全承载齐备才放行；任一未就绪即拒绝 + 原因
    pub udp_mesh_allowed: bool,
    /// 保守回退原因（显式记录进决策，绝不静默降级）
    pub notes: Vec<String>,
}

/// 受管协商：先验信任面，再求版本交集，最后逐能力显式判定。
///
/// - **信任优先**：非受管声明直接拒绝（`mesh.cap.untrusted`）——能力
///   面不接受匿名申报，混布升级窗口的连通性兜底（发送侧不填充）与此
///   正交：协商面没有声明就没有能力，不会把缺失当作具备；
/// - **版本交集**：取双方申报版本集交集的最大公共版本（升序约定下的
///   最高兼容档）；无交集 `mesh.cap.incompatible` 点名两侧版本集；
/// - **显式保守**：填充 / UDP 安全承载逐字段判定，缺失方向记入
///   `notes`——回退可审计，不 fail-open。
pub fn negotiate(
    local: &CapabilityOffer,
    hello: &PeerHello,
) -> Result<Negotiated, NegotiationError> {
    if hello.trust != PeerTrust::Managed {
        return Err(NegotiationError::Untrusted(hello.peer.clone()));
    }
    let mut common = local
        .envelope_versions
        .iter()
        .filter(|v| hello.offer.envelope_versions.contains(v))
        .copied()
        .collect::<Vec<_>>();
    common.sort_unstable();
    let Some(envelope_version) = common.pop() else {
        return Err(NegotiationError::IncompatibleVersions {
            local: local.envelope_versions.clone(),
            peer: hello.offer.envelope_versions.clone(),
        });
    };
    let mut notes = Vec::new();
    let padding = local.padding && hello.offer.padding;
    if local.padding && !hello.offer.padding {
        notes.push("padding: 对端未申报——显式关闭（不 fail-open）".to_string());
    } else if !local.padding && hello.offer.padding {
        notes.push("padding: 本端未申报——显式关闭".to_string());
    }
    let udp_mesh_allowed = local.udp_secure_carriage && hello.offer.udp_secure_carriage;
    if !udp_mesh_allowed {
        let side = match (local.udp_secure_carriage, hello.offer.udp_secure_carriage) {
            (true, false) => "对端",
            (false, true) | (false, false) => "本端",
            (true, true) => "无",
        };
        notes.push(format!(
            "udp mesh: {side}安全承载未完成——明确拒绝（不能明文旁路发布）"
        ));
    }
    Ok(Negotiated {
        peer: hello.peer.clone(),
        envelope_version,
        padding,
        udp_mesh_allowed,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(versions: &[u32], padding: bool, udp: bool) -> CapabilityOffer {
        CapabilityOffer {
            envelope_versions: versions.to_vec(),
            padding,
            udp_secure_carriage: udp,
        }
    }

    fn hello(versions: &[u32], padding: bool, udp: bool, trust: PeerTrust) -> PeerHello {
        PeerHello {
            peer: "peer-1".to_string(),
            offer: offer(versions, padding, udp),
            trust,
        }
    }

    /// 版本交集取最大公共版本（双方声明集不同也收敛）
    #[test]
    fn common_version_takes_max_of_intersection() {
        let local = offer(&[1, 2], true, true);
        let out = negotiate(&local, &hello(&[2, 3], true, true, PeerTrust::Managed))
            .expect("有交集应成功");
        assert_eq!(out.envelope_version, 2, "最大公共版本");
        assert_eq!(out.peer, "peer-1");
        assert!(out.padding && out.udp_mesh_allowed);
        assert!(out.notes.is_empty(), "齐备无回退说明: {:?}", out.notes);
    }

    /// 未受管声明一律拒绝——能力面不接受匿名申报（稳定原因码）
    #[test]
    fn untrusted_hello_is_rejected_with_stable_code() {
        let local = offer(&[1, 2], true, true);
        let err = negotiate(&local, &hello(&[1, 2], true, true, PeerTrust::Untrusted))
            .expect_err("未受管须拒绝");
        assert!(err.to_string().contains(CODE_CAP_UNTRUSTED), "实际: {err}");
        assert!(err.to_string().contains("peer-1"), "点名对端: {err}");
    }

    /// 无公共版本：点名两侧版本集（稳定原因码，不猜语义）
    #[test]
    fn no_common_version_names_both_sets() {
        let local = offer(&[1], true, true);
        let err = negotiate(&local, &hello(&[3, 4], true, true, PeerTrust::Managed))
            .expect_err("无交集须拒绝");
        let NegotiationError::IncompatibleVersions { local, peer } = &err else {
            panic!("应为 IncompatibleVersions: {err:?}");
        };
        assert_eq!(local, &[1]);
        assert_eq!(peer, &[3, 4]);
        assert!(err.to_string().contains(CODE_CAP_INCOMPATIBLE));
    }

    /// 单侧缺填充：显式关闭 + 原因可审计（双向各验一路——绝不静默）
    #[test]
    fn one_sided_padding_conserves_with_note() {
        let local = offer(&[1, 2], true, true);
        let out =
            negotiate(&local, &hello(&[2], false, true, PeerTrust::Managed)).expect("协商应成功");
        assert!(!out.padding, "单侧缺即关闭");
        assert_eq!(out.notes.len(), 1, "回退必带原因: {:?}", out.notes);
        assert!(out.notes[0].contains("对端未申报"), "点名缺失方向");

        let local = offer(&[1, 2], false, true);
        let out =
            negotiate(&local, &hello(&[2], true, true, PeerTrust::Managed)).expect("协商应成功");
        assert!(!out.padding);
        assert!(
            out.notes[0].contains("本端未申报"),
            "双向点名: {:?}",
            out.notes
        );
    }

    /// UDP 安全承载未完成：任一侧未就绪即明确拒绝 + 原因（不能明文旁路）
    #[test]
    fn incomplete_udp_carriage_is_refused_explicitly() {
        let local = offer(&[1, 2], true, true);
        let out =
            negotiate(&local, &hello(&[2], true, false, PeerTrust::Managed)).expect("协商应成功");
        assert!(!out.udp_mesh_allowed, "对端未就绪即拒绝");
        assert!(
            out.notes[0].contains("对端") && out.notes[0].contains("明文"),
            "{:?}",
            out.notes
        );

        let local = offer(&[1, 2], true, false);
        let out =
            negotiate(&local, &hello(&[2], true, true, PeerTrust::Managed)).expect("协商应成功");
        assert!(!out.udp_mesh_allowed, "本端未就绪同样拒绝");
        assert!(out.notes[0].contains("本端"), "{:?}", out.notes);

        // 双侧就绪才放行且无说明
        let local = offer(&[1, 2], true, true);
        let out = negotiate(&local, &hello(&[2], true, true, PeerTrust::Managed)).expect("齐备");
        assert!(out.udp_mesh_allowed);
        assert!(out.notes.is_empty());
    }
}
