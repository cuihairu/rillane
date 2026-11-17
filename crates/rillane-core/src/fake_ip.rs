//! fake-ip 地址池（G1-10，todo.md）：DNS 面为域名分配段内稳定假地址，
//! 出站面按假地址反查原域名回填路由。
//!
//! 语义：
//! - 同域名恒得同一假地址（forward 表稳定命中，进程生命周期内有效）；
//! - 池按游标顺序分配，耗尽回绕（counter 取模容量）；回绕后旧域名条目
//!   保留在 forward 表（同域名仍命中旧地址），reverse 表被新域名覆盖
//!   ——极端长跑下 reverse 可能指向较新域名，属已登记的回绕语义；
//! - `in_range` 判定地址是否属本池（入站改写前的快速门槛），
//!   `reverse` 反查原域名（命中即改写 target host）。
//!
//! **双栈（RIL-142）**：v4 池之外可挂独立 v6 池（[`FakeIpTable::with_v6_cidr`]，
//! 配置 `network.dns.fake_ip.range6` 在场时装配）——AAAA 查询按 v6 池段
//! 稳定假地址应答，两族各自独立分配/反查/钉住（地址空间不相交，forward
//! 表按域名共享但记录带族地址；同域名 A 与 AAAA 各得各族稳定地址）。
//! v6 池缺席时 v6 分配显式 [`FakeIpError::NoV6Pool`]（DNS 面回真实解析，
//! 存量零差异）。[`reverse_host`] 统一漏斗自动认两族（入站 target 字符串
//! 解析为 IPv4/IPv6 均可反查）——入站改写调用面零改动。
//!
//! **生命周期与解析上下文（RIL-020）**：会话可对在用的假地址 `pin`
//! 钉住（活跃流持有引用）——钉住的地址分配面**永不转手**：回绕分配
//! 跳过钉住条目，全部钉住耗尽时显式 `Exhausted`（不偷活跃会话的地址
//! ——验收「旧会话引用不被提前复用」）。钉住期间绑定冻结：域名与
//! 代际上下文都不被后续分配改写；`release` 后恢复可回收。`reverse`
//! 是纯域名视图（既有回填路径零差异）；`reverse_with_context` 返回
//! [`ResolutionContext`]（域名 + 分配时所在配置代际），调用方据此在
//! 正确代际上做路由裁决（RIL-006 计划契约的消费侧入口）。历史遗留
//! `alloc`（不感知钉住、无上下文）保留为存量入口，RIL-020 后新接面
//! 一律走 [`FakeIpTable::alloc_with_generation`]（v6 面走
//! [`FakeIpTable::alloc_v6_with_generation`]）。
//!
//! 分配与命中同走一把互斥锁（检查+插入原子，双表不漂移）——分配是
//! 每域名一次的低频路径，反查是每流一次，锁窗为纯内存操作。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// 解析上下文（RIL-020）：一条假地址绑定携带的裁决凭据——域名 + 分配
/// （或最近一次未钉住重解析）时所在的配置代际身份。路由面据此在正确
/// 代际上建计划（RIL-006 `RoutePlan::generation`），代际缺失（空串 =
/// 存量路径未挂代际源）显式呈现，不伪造。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionContext {
    /// 绑定域名（小写规范化）
    pub domain: String,
    /// 分配时所在配置代际（空串 = 未挂代际源）
    pub generation_id: String,
}

/// 假地址分配错误（RIL-020/RIL-142）：文案可演进，`code()` 恒定。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FakeIpError {
    /// 池满且全部地址被活跃会话钉住——不偷在用地址，显式失败
    ///（DNS 面对应对答 SERVFAIL，绝不把活跃会话的地址转手新域名）。
    #[error(
        "fake-ip 池满（容量 {capacity}）且全部地址被活跃会话钉住，拒绝为 {domain:?} 转手在用地址"
    )]
    Exhausted {
        /// 触发分配的域名
        domain: String,
        /// 池容量（地址数）
        capacity: u64,
    },
    /// v6 池未配置（`range6` 缺席）却请求 v6 分配——调用方（DNS 引擎）
    /// 据此回真实解析（存量零差异路径），不伪造地址。
    #[error("fake-ip v6 池未配置（range6 缺席），拒绝 v6 分配：{domain:?}")]
    NoV6Pool {
        /// 触发分配的域名
        domain: String,
    },
}

impl FakeIpError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            FakeIpError::Exhausted { .. } => "fake_ip.pool.exhausted",
            FakeIpError::NoV6Pool { .. } => "fake_ip.pool.no_v6",
        }
    }
}

/// 单地址绑定：域名 + 代际上下文 + 钉住标记（RIL-020 升级自裸域名）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    domain: String,
    generation_id: String,
    pinned: bool,
}

/// 地址族（RIL-142）：v4/v6 各自独立的池定界与游标；forward/reverse
/// 表共享（键分别为域名/IpAddr——族由地址自身承载，不相交）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// v6 池定界与游标（RIL-142）：与 v4 池同构（base/host_bits/cursor）。
struct V6Pool {
    base: u128,
    host_bits: u32,
    cursor: AtomicU64,
}

/// fake-ip 池：`base`/`host_bits` 定界（v4），可选 v6 池（RIL-142），
/// `forward`/`reverse` 双向表（两族共享，键族明确）。
pub struct FakeIpTable {
    base: u32,
    host_bits: u32,
    cursor: AtomicU64,
    v6: Option<V6Pool>,
    state: Mutex<PoolState>,
}

struct PoolState {
    /// forward 键 =（域名, 族）——A/AAAA 交错查询各得各族稳定地址
    /// （RIL-142：单键会被后查族覆盖，破坏「同域名每族恒同地址」）。
    forward: HashMap<(String, u8), IpAddr>,
    reverse: HashMap<IpAddr, Binding>,
}

impl FakeIpTable {
    /// 从 CIDR（如 `198.18.0.0/15`）构建。仅认 IPv4；前缀 ≤30（池至少
    /// 4 个地址）。v6 池经 [`FakeIpTable::with_v6_cidr`] 追加。
    pub fn from_cidr(cidr: &str) -> Result<Self, String> {
        let (ip_part, prefix_part) = cidr
            .split_once('/')
            .ok_or_else(|| format!("fake-ip 段缺前缀长度：{cidr:?}"))?;
        let ip: Ipv4Addr = ip_part
            .parse()
            .map_err(|_| format!("fake-ip 段地址非法：{ip_part:?}"))?;
        let prefix: u32 = prefix_part
            .parse()
            .map_err(|_| format!("fake-ip 段前缀非法：{prefix_part:?}"))?;
        if prefix == 0 || prefix > 30 {
            return Err(format!(
                "fake-ip 段前缀须在 1..=30（池至少 4 地址）：{cidr:?}"
            ));
        }
        let host_bits = 32 - prefix;
        Ok(Self {
            base: u32::from(ip) & Self::mask(host_bits),
            host_bits,
            cursor: AtomicU64::new(0),
            v6: None,
            state: Mutex::new(PoolState {
                forward: HashMap::new(),
                reverse: HashMap::new(),
            }),
        })
    }

    /// 追加 v6 池（RIL-142）：合法 IPv6 CIDR、前缀 1..=126（池至少 4
    /// 地址）。仅 v4 表可调用（一次性装配；重复调用报错）。
    pub fn with_v6_cidr(mut self, cidr: &str) -> Result<Self, String> {
        if self.v6.is_some() {
            return Err("fake-ip v6 池已配置（不可重复装配）".to_string());
        }
        let (ip_part, prefix_part) = cidr
            .split_once('/')
            .ok_or_else(|| format!("fake-ip v6 段缺前缀长度：{cidr:?}"))?;
        let ip: Ipv6Addr = ip_part
            .trim()
            .parse()
            .map_err(|_| format!("fake-ip v6 段地址非法：{ip_part:?}"))?;
        let prefix: u32 = prefix_part
            .trim()
            .parse()
            .map_err(|_| format!("fake-ip v6 段前缀非法：{prefix_part:?}"))?;
        if prefix == 0 || prefix > 126 {
            return Err(format!(
                "fake-ip v6 段前缀须在 1..=126（池至少 4 地址）：{cidr:?}"
            ));
        }
        let host_bits = 128 - prefix;
        let mask = if host_bits >= 128 {
            u128::MAX
        } else {
            u128::MAX << host_bits
        };
        self.v6 = Some(V6Pool {
            base: u128::from(ip) & mask,
            host_bits,
            cursor: AtomicU64::new(0),
        });
        Ok(self)
    }

    fn mask(host_bits: u32) -> u32 {
        if host_bits == 0 {
            u32::MAX
        } else {
            u32::MAX << host_bits
        }
    }

    /// 族定界参数（base u128 统一表示、host_bits、容量）。
    fn family_params(&self, family: Family) -> (u128, u32, u64) {
        match family {
            Family::V4 => (
                u128::from(self.base),
                self.host_bits,
                1u64 << self.host_bits,
            ),
            Family::V6 => {
                let v6 = self.v6.as_ref().expect("v6 池在场（调用方已检）");
                (
                    v6.base,
                    v6.host_bits,
                    if v6.host_bits >= 64 {
                        u64::MAX
                    } else {
                        1u64 << v6.host_bits
                    },
                )
            }
        }
    }

    fn family_cursor(&self, family: Family) -> &AtomicU64 {
        match family {
            Family::V4 => &self.cursor,
            Family::V6 => &self.v6.as_ref().expect("v6 池在场").cursor,
        }
    }

    fn make_addr(&self, family: Family, offset: u128) -> IpAddr {
        match family {
            Family::V4 => IpAddr::V4(Ipv4Addr::from(u32::try_from(offset).expect("v4 偏移"))),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(offset)),
        }
    }

    /// 地址是否属本池（网络位相同即在内，含网络地址本身）。
    pub fn in_range(&self, ip: &Ipv4Addr) -> bool {
        (u32::from(*ip) & Self::mask(self.host_bits)) == self.base
    }

    /// 地址是否属本池任一族（RIL-142：v6 池缺席时 v6 地址恒 false）。
    pub fn in_range_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.in_range(v4),
            IpAddr::V6(v6) => match &self.v6 {
                Some(pool) => {
                    let mask = if pool.host_bits >= 128 {
                        u128::MAX
                    } else {
                        u128::MAX << pool.host_bits
                    };
                    u128::from(*v6) & mask == pool.base
                }
                None => false,
            },
        }
    }

    /// 域名分配稳定假地址（存量入口，不感知钉住）：已分配直接命中；
    /// 未分配按游标取池内下一地址（回绕），写入双向表。域名统一小写
    /// （DNS 大小写不敏感口径）。RIL-020 后新接面一律走
    /// [`FakeIpTable::alloc_with_generation`]。
    pub fn alloc(&self, domain: &str) -> Ipv4Addr {
        let key = domain.to_ascii_lowercase();
        let mut state = self.state.lock().expect("fake-ip pool lock");
        if let Some(IpAddr::V4(ip)) = state.forward.get(&(key.clone(), Family::V4 as u8)) {
            return *ip;
        }
        let capacity = 1u64 << self.host_bits;
        let offset = (self.cursor.fetch_add(1, Ordering::Relaxed) % capacity) as u32;
        let ip = Ipv4Addr::from(self.base.wrapping_add(offset));
        state.forward.insert((key.clone(), Family::V4 as u8), IpAddr::V4(ip));
        state.reverse.insert(
            IpAddr::V4(ip),
            Binding {
                domain: key,
                generation_id: String::new(),
                pinned: false,
            },
        );
        ip
    }

    /// 域名分配稳定假地址并挂解析上下文（RIL-020 入口）：
    /// - 同域名再分配：已钉住 → 绑定**冻结**（地址与代际上下文原样返回，
    ///   活跃会话所见不变——验收「旧会话引用不被提前复用」）；未钉住 →
    ///   地址不变、代际上下文刷新为本次分配的代际；
    /// - 新域名：从游标起逐位扫描，**跳过钉住地址**；命中空闲或未钉住
    ///   （可回收）地址即占用。全部地址钉住 → `Exhausted`（不偷在用
    ///   地址，DNS 面对应对答 SERVFAIL）。
    pub fn alloc_with_generation(
        &self,
        domain: &str,
        generation_id: &str,
    ) -> Result<Ipv4Addr, FakeIpError> {
        match self.alloc_family(domain, generation_id, Family::V4)? {
            IpAddr::V4(ip) => Ok(ip),
            IpAddr::V6(_) => unreachable!("v4 族分配恒回 v4 地址"),
        }
    }

    /// 域名分配稳定假 v6 地址并挂解析上下文（RIL-142）：语义与
    /// [`FakeIpTable::alloc_with_generation`] 同（族独立——v6 池独立游标
    /// 与定界；钉住/冻结/耗尽按 v6 池判定）。v6 池未配置（`range6`
    /// 缺席）→ 显式 [`FakeIpError::NoV6Pool`]（调用方回真实解析，
    /// 不伪造地址）。
    pub fn alloc_v6_with_generation(
        &self,
        domain: &str,
        generation_id: &str,
    ) -> Result<Ipv6Addr, FakeIpError> {
        if self.v6.is_none() {
            return Err(FakeIpError::NoV6Pool {
                domain: domain.to_ascii_lowercase(),
            });
        }
        match self.alloc_family(domain, generation_id, Family::V6)? {
            IpAddr::V6(ip) => Ok(ip),
            IpAddr::V4(_) => unreachable!("v6 族分配恒回 v6 地址"),
        }
    }

    /// 族通用分配核（RIL-142 自 v4 逻辑泛化；扫描/钉住跳过/冻结语义
    /// 与 RIL-020 逐字一致，两族各自独立游标与定界）。
    fn alloc_family(
        &self,
        domain: &str,
        generation_id: &str,
        family: Family,
    ) -> Result<IpAddr, FakeIpError> {
        let key = domain.to_ascii_lowercase();
        let mut state = self.state.lock().expect("fake-ip pool lock");
        let fkey = (key.clone(), family as u8);
        if let Some(ip) = state.forward.get(&fkey).copied() {
            let binding = state.reverse.get_mut(&ip).expect("双表一致");
            if !binding.pinned {
                // 未钉住重解析：地址稳定，代际上下文随最新解析刷新
                binding.generation_id = generation_id.to_string();
            }
            return Ok(ip);
        }
        let (base, _host_bits, capacity) = self.family_params(family);
        // 从游标起逐位扫描（跳过钉住条目）；cursor 只在落定后前移
        let start = self.family_cursor(family).load(Ordering::Relaxed);
        for step in 0..capacity {
            let offset = (start + step) % capacity;
            let addr = self.make_addr(family, base.wrapping_add(u128::from(offset)));
            match state.reverse.get(&addr) {
                Some(b) if b.pinned => continue, // 活跃会话在用：永不转手
                Some(_) => {
                    // 未钉住可回收地址：既有回绕语义（forward 里旧域名
                    // 条目保留——同域名仍命中旧地址，reverse 归新域名）
                    state.forward.insert(fkey, addr);
                    state.reverse.insert(
                        addr,
                        Binding {
                            domain: key,
                            generation_id: generation_id.to_string(),
                            pinned: false,
                        },
                    );
                    self.family_cursor(family).store(start + step + 1, Ordering::Relaxed);
                    return Ok(addr);
                }
                None => {
                    // 空闲地址：直接占用
                    state.forward.insert(fkey, addr);
                    state.reverse.insert(
                        addr,
                        Binding {
                            domain: key,
                            generation_id: generation_id.to_string(),
                            pinned: false,
                        },
                    );
                    self.family_cursor(family).store(start + step + 1, Ordering::Relaxed);
                    return Ok(addr);
                }
            }
        }
        Err(FakeIpError::Exhausted {
            domain: key,
            capacity,
        })
    }

    /// 钉住地址（活跃流持有引用时调用）：钉住期间分配面永不转手该
    /// 地址、绑定冻结（域名与代际上下文不被改写）。地址不在池内返回
    /// false（幂等重钉 true）。
    pub fn pin(&self, ip: &Ipv4Addr) -> bool {
        self.pin_ip(&IpAddr::V4(*ip))
    }

    /// 族通用钉住（RIL-142）。
    pub fn pin_ip(&self, ip: &IpAddr) -> bool {
        let mut state = self.state.lock().expect("fake-ip pool lock");
        match state.reverse.get_mut(ip) {
            Some(binding) => {
                binding.pinned = true;
                true
            }
            None => false,
        }
    }

    /// 解除钉住（会话排空后调用）：地址恢复可回收；不在池内 no-op。
    pub fn release(&self, ip: &Ipv4Addr) {
        self.release_ip(&IpAddr::V4(*ip))
    }

    /// 族通用解除钉住（RIL-142）。
    pub fn release_ip(&self, ip: &IpAddr) {
        if let Some(binding) = self
            .state
            .lock()
            .expect("fake-ip pool lock")
            .reverse
            .get_mut(ip)
        {
            binding.pinned = false;
        }
    }

    /// 假地址反查原域名（入站改写用；未分配/非池内返回 None）。
    pub fn reverse(&self, ip: &Ipv4Addr) -> Option<String> {
        self.reverse_ip(&IpAddr::V4(*ip))
    }

    /// 族通用反查（RIL-142）。
    pub fn reverse_ip(&self, ip: &IpAddr) -> Option<String> {
        self.state
            .lock()
            .expect("fake-ip pool lock")
            .reverse
            .get(ip)
            .map(|b| b.domain.clone())
    }

    /// 假地址反查解析上下文（RIL-020）：域名 + 分配时所在配置代际。
    /// 钉住地址的上下文在钉住期间冻结——活跃会话所见恒定；非池内/
    /// 未分配返回 None（调用方不得由此臆造域名关联）。
    pub fn reverse_with_context(&self, ip: &Ipv4Addr) -> Option<ResolutionContext> {
        self.reverse_with_context_ip(&IpAddr::V4(*ip))
    }

    /// 族通用上下文反查（RIL-142）。
    pub fn reverse_with_context_ip(&self, ip: &IpAddr) -> Option<ResolutionContext> {
        self.state
            .lock()
            .expect("fake-ip pool lock")
            .reverse
            .get(ip)
            .map(|b| ResolutionContext {
                domain: b.domain.clone(),
                generation_id: b.generation_id.clone(),
            })
    }

    /// 池内已分配域名数（观测面；两族合计）。
    pub fn len(&self) -> usize {
        self.state.lock().expect("fake-ip pool lock").forward.len()
    }

    /// 池是否为空（观测面）。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 例外域名表（RIL-142）：全标签后缀匹配（小写规范化）——`example.com`
/// 命中 `example.com` 与 `a.example.com`，不命中 `notexample.com`。命中
/// 例外的 A/AAAA 查询跳过池分配、照常真实解析（虚拟应答不覆盖显式
/// 例外面）。空表恒不命中（存量零差异）。
pub struct FakeIpExceptions {
    suffixes: Vec<String>,
}

impl FakeIpExceptions {
    /// 从配置例外表构建（裸域名后缀；空白/前后点规范化剔除）。
    pub fn new(entries: &[String]) -> Self {
        Self {
            suffixes: entries
                .iter()
                .map(|e| {
                    e.trim()
                        .trim_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|e| !e.is_empty())
                .collect(),
        }
    }

    /// 例外命中（全标签后缀，大小写不敏感；尾点多标签根容错）。
    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        self.suffixes
            .iter()
            .any(|e| d == *e || d.ends_with(&format!(".{e}")))
    }

    /// 条目数（观测面）。
    pub fn len(&self) -> usize {
        self.suffixes.len()
    }

    /// 是否为空（观测面）。
    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }
}

/// 入站 target 回填（G1-10）：host 为本池假地址（RIL-142 起 IPv4/IPv6
/// 皆认）时反查原域名；host 为域名或池外地址返回 None（原样放行）。
/// 入站面用它把 DNS 面分配的假地址还原成域名，路由按域名规则命中。
pub fn reverse_host(table: &FakeIpTable, host: &str) -> Option<String> {
    let trimmed = host.trim_matches(|c| c == '[' || c == ']');
    // v6 字面量须带冒号（纯数字串是 v4）；解析失败按域名放行
    let ip: IpAddr = trimmed.parse().ok()?;
    if !table.in_range_ip(&ip) {
        return None;
    }
    table.reverse_ip(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_cidr_parses_and_bounds() {
        let t = FakeIpTable::from_cidr("198.18.0.0/15").expect("应可构建");
        assert!(t.in_range(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(t.in_range(&Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!t.in_range(&Ipv4Addr::new(198, 20, 0, 0)));
        assert!(!t.in_range(&Ipv4Addr::new(192, 168, 1, 1)));

        assert!(FakeIpTable::from_cidr("198.18.0.0").is_err(), "缺前缀");
        assert!(FakeIpTable::from_cidr("198.18.0.0/x").is_err(), "前缀非法");
        assert!(FakeIpTable::from_cidr("host/24").is_err(), "地址非法");
        assert!(FakeIpTable::from_cidr("198.18.0.0/0").is_err(), "前缀 0 拒");
        assert!(
            FakeIpTable::from_cidr("198.18.0.0/31").is_err(),
            "前缀 >30 拒"
        );
        assert!(FakeIpTable::from_cidr("::1/64").is_err(), "IPv6 拒");
    }

    #[test]
    fn alloc_is_stable_and_reversible() {
        let t = FakeIpTable::from_cidr("198.18.0.0/15").expect("应可构建");
        let a = t.alloc("Example.COM");
        let b = t.alloc("example.com");
        assert_eq!(a, b, "同域名（大小写不敏感）恒同地址");
        assert!(t.in_range(&a));
        assert_eq!(
            t.reverse(&a).as_deref(),
            Some("example.com"),
            "反查还原原域名"
        );
        assert_eq!(t.len(), 1);

        let c = t.alloc("other.example");
        assert_ne!(a, c, "异域名异地址");
        assert_eq!(t.reverse(&c).as_deref(), Some("other.example"));
        assert_eq!(t.reverse(&Ipv4Addr::new(8, 8, 8, 8)), None, "池外反查 None");
    }

    #[test]
    fn alloc_walks_pool_then_wraps() {
        // /30 池恰 4 地址：连续分配 5 次触发回绕（第 5 个复用第 1 个地址）
        let t = FakeIpTable::from_cidr("198.18.0.0/30").expect("应可构建");
        let first = t.alloc("d1");
        let mut seen = vec![first];
        for i in 2..=4 {
            seen.push(t.alloc(&format!("d{i}")));
        }
        for (i, ip) in seen.iter().enumerate() {
            assert!(t.in_range(ip), "d{} 越池", i + 1);
        }
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), 4, "池满前地址互异");
        let wrapped = t.alloc("d5");
        assert_eq!(wrapped, first, "回绕复用首地址");
    }

    #[test]
    fn reverse_host_rewrites_only_pool_ips() {
        let t = FakeIpTable::from_cidr("198.18.0.0/15").expect("应可构建");
        let ip = t.alloc("backfill.example");
        let ip_str = ip.to_string();

        assert_eq!(
            reverse_host(&t, &ip_str).as_deref(),
            Some("backfill.example"),
            "池内假地址回填域名"
        );
        assert_eq!(reverse_host(&t, "example.com"), None, "域名原样放行");
        assert_eq!(reverse_host(&t, "8.8.8.8"), None, "池外 IP 原样放行");
        assert_eq!(reverse_host(&t, "not an ip"), None, "非地址原样放行");
    }

    /// RIL-020 验收「旧会话引用不被提前复用」：钉住的地址在回绕分配
    /// 中永不转手，绑定（域名+代际）冻结；未钉住地址照常回收。
    #[test]
    fn pinned_binding_survives_wrap_and_freezes() {
        let t = FakeIpTable::from_cidr("198.18.0.0/30").expect("应可构建");
        let g1 = "gen-0001";
        let ip1 = t
            .alloc_with_generation("live.example", g1)
            .expect("首次分配");
        assert!(t.pin(&ip1), "钉住在用地址");

        // 回绕分配压满全池：d2/d3 占其余 3 地址中未钉住的（d4 落定后
        // 池里只剩钉住的 ip1 不可用）
        let mut others = Vec::new();
        for i in 2..=4 {
            others.push(
                t.alloc_with_generation(&format!("d{i}"), g1)
                    .expect("未钉满前可分配"),
            );
        }
        assert!(
            others.iter().all(|ip| *ip != ip1),
            "钉住地址不被转手: {others:?}"
        );
        // 钉住绑定冻结：域名与代际不被改写
        assert_eq!(
            t.reverse_with_context(&ip1),
            Some(ResolutionContext {
                domain: "live.example".to_string(),
                generation_id: g1.to_string(),
            }),
            "活跃会话所见恒定"
        );

        // release 后地址恢复可回收
        t.release(&ip1);
        let reuser = t
            .alloc_with_generation("next.example", g1)
            .expect("释放后可回收");
        assert_eq!(reuser, ip1, "释放后被新域名回收");
        assert_eq!(
            t.reverse_with_context(&ip1).map(|c| c.domain),
            Some("next.example".to_string()),
            "回收后 reverse 归新域名"
        );
    }

    /// RIL-020 验收：池满且全部钉住 → 显式 Exhausted（不偷在用地址，
    /// 稳定原因码机器口径可断言）。
    #[test]
    fn exhausted_when_all_addresses_pinned() {
        let t = FakeIpTable::from_cidr("198.18.0.0/30").expect("应可构建");
        let g = "gen-exhaust";
        let mut ips = Vec::new();
        for i in 1..=4 {
            let ip = t
                .alloc_with_generation(&format!("d{i}"), g)
                .expect("池内分配");
            t.pin(&ip);
            ips.push(ip);
        }
        let err = t
            .alloc_with_generation("d5", g)
            .expect_err("全钉住须拒绝分配");
        let FakeIpError::Exhausted { domain, capacity } = &err else {
            panic!("须为 Exhausted: {err:?}")
        };
        assert_eq!(domain, "d5");
        assert_eq!(*capacity, 4);
        assert_eq!(err.code(), "fake_ip.pool.exhausted");
        // 已钉住地址的绑定不受失败分配影响
        assert_eq!(
            t.reverse(&ips[0]).as_deref(),
            Some("d1"),
            "钉住绑定不受 Exhausted 分配影响"
        );
    }

    /// RIL-020 解析上下文：同域名未钉住重解析刷新代际；钉住后重解析
    /// 冻结（地址与代际均不动）；同代际分配返回同地址（stable）。
    #[test]
    fn context_refreshes_only_while_unpinned() {
        let t = FakeIpTable::from_cidr("198.18.0.0/15").expect("应可构建");
        let ip = t
            .alloc_with_generation("ctx.example", "gen-a")
            .expect("分配");
        // 未钉住：重解析刷新代际，地址不变
        let again = t
            .alloc_with_generation("ctx.example", "gen-b")
            .expect("重分配");
        assert_eq!(ip, again, "同域名恒同地址");
        assert_eq!(
            t.reverse_with_context(&ip).map(|c| c.generation_id),
            Some("gen-b".to_string()),
            "未钉住重解析刷新代际"
        );
        // 钉住后：重解析冻结，代际保持
        t.pin(&ip);
        let _ = t
            .alloc_with_generation("ctx.example", "gen-c")
            .expect("重分配");
        assert_eq!(
            t.reverse_with_context(&ip),
            Some(ResolutionContext {
                domain: "ctx.example".to_string(),
                generation_id: "gen-b".to_string(),
            }),
            "钉住期间绑定冻结（代际不随重解析漂移）"
        );
        t.release(&ip);
    }

    /// RIL-020 验收「未知域名来源不误关联进程」的反面守卫：非池内/
    /// 未分配地址反查恒 None——调用方拿不到任何域名凭据，不可能把
    /// 未知目标臆造到某个域名的会话上。
    #[test]
    fn reverse_context_never_invents_unknown_domains() {
        let t = FakeIpTable::from_cidr("198.18.0.0/30").expect("应可构建");
        let known = t
            .alloc_with_generation("known.example", "gen-k")
            .expect("分配");
        let unknown: Ipv4Addr = "203.0.113.9".parse().unwrap();
        assert_eq!(t.reverse_with_context(&unknown), None, "池外无凭据");
        // 池内未分配地址同样 None（in_range 但未入表；known 落首槽，次槽空闲）
        let in_range_unallocated = Ipv4Addr::from(u32::from(known).wrapping_add(1));
        assert!(t.in_range(&in_range_unallocated));
        assert_eq!(
            t.reverse_with_context(&in_range_unallocated),
            None,
            "池内未分配无凭据"
        );
    }

    /// RIL-142 双栈：v6 池独立分配/反查/钉住，与 v4 池互不相交；
    /// reverse_host 统一漏斗认两族（含方括号 v6 字面量）。
    #[test]
    fn v6_pool_allocates_isolates_and_reverse_hosts() {
        let t = FakeIpTable::from_cidr("198.18.0.0/30")
            .expect("v4 池")
            .with_v6_cidr("fd6e:fd93:5d8f::/126")
            .expect("v6 池");

        // v6 分配稳定 + 全在 v6 池段
        let a6 = t.alloc_v6_with_generation("dual.example", "g").expect("v6 分配");
        let a6_again = t
            .alloc_v6_with_generation("DUAL.EXAMPLE", "g")
            .expect("同域名（大小写不敏感）");
        assert_eq!(a6, a6_again, "v6 同域名恒同地址");
        assert!(t.in_range_ip(&IpAddr::V6(a6)), "v6 落 v6 池段");
        assert!(
            !t.in_range_ip(&IpAddr::V6("fe80::1".parse().unwrap())),
            "池外 v6 不入界"
        );
        assert_eq!(
            t.reverse_ip(&IpAddr::V6(a6)).as_deref(),
            Some("dual.example"),
            "v6 反查还原域名"
        );

        // v4 分配照常且与 v6 互不相交（族隔离）
        let a4 = t.alloc_with_generation("dual.example", "g").expect("v4 分配");
        assert!(t.in_range(&a4), "v4 落 v4 池段");
        assert_ne!(
            IpAddr::from(a4),
            IpAddr::from(a6),
            "两族地址空间不相交"
        );
        assert_eq!(
            t.reverse_with_context_ip(&IpAddr::V4(a4)).map(|c| c.domain),
            Some("dual.example".to_string()),
            "v4 反查不受 v6 绑定影响"
        );
        assert_eq!(
            t.reverse_with_context_ip(&IpAddr::V6(a6)).map(|c| c.domain),
            Some("dual.example".to_string()),
            "v6 反查不受 v4 绑定影响"
        );

        // reverse_host 漏斗：v6 字面量（带方括号）回填域名；池外 v6 放行
        assert_eq!(
            reverse_host(&t, &format!("[{a6}]")).as_deref(),
            Some("dual.example"),
            "带括号 v6 字面量回填"
        );
        assert_eq!(
            reverse_host(&t, "fe80::1"),
            None,
            "非池 v6 原样放行"
        );
    }

    /// RIL-142：v6 池缺席时 v6 分配显式 `NoV6Pool`（稳定码机器口径；
    /// DNS 引擎据此回真实解析）；v6 反查恒 None（不臆造）。
    #[test]
    fn v6_absent_alloc_is_explicit_no_v6() {
        let t = FakeIpTable::from_cidr("198.18.0.0/15").expect("应可构建");
        let err = t
            .alloc_v6_with_generation("v6.example", "g")
            .expect_err("v6 池缺席须显式拒绝");
        let FakeIpError::NoV6Pool { domain } = &err else {
            panic!("须为 NoV6Pool: {err:?}")
        };
        assert_eq!(domain, "v6.example");
        assert_eq!(err.code(), "fake_ip.pool.no_v6");
        assert_eq!(
            t.reverse_ip(&IpAddr::V6("fd00::1".parse().unwrap())),
            None,
            "无 v6 池反查恒 None"
        );
        assert!(
            FakeIpTable::from_cidr("198.18.0.0/30")
                .unwrap()
                .with_v6_cidr("fd00::/127")
                .is_err(),
            "v6 前缀 >126 拒（池至少 4 地址）"
        );
        assert!(
            FakeIpTable::from_cidr("198.18.0.0/30")
                .unwrap()
                .with_v6_cidr("fd00::")
                .is_err(),
            "v6 缺前缀拒"
        );
    }

    /// RIL-142 例外表：全标签后缀匹配（大小写/尾点容错）；空表恒否。
    #[test]
    fn exceptions_match_full_label_suffixes() {
        let x = FakeIpExceptions::new(&[
            "Example.COM".to_string(),
            "  .internal. ".to_string(),
            "".to_string(),
        ]);
        assert!(x.matches("example.com"), "全等命中");
        assert!(x.matches("a.Example.COM."), "子域命中（尾点容错）");
        assert!(x.matches("x.internal"), "规范化剔除空白与前后点");
        assert!(!x.matches("notexample.com"), "非全标签不命中");
        assert!(!x.matches("other.dev"), "缺席不命中");
        assert_eq!(x.len(), 2, "空条目剔除");
        assert!(!FakeIpExceptions::new(&[]).matches("anything.example"), "空表恒不命中");
    }

    /// RIL-142：v6 池钉住/回绕/耗尽语义与 v4 逐字一致（族独立判定）。
    #[test]
    fn v6_pin_wrap_and_exhaustion_mirror_v4() {
        // /126 池恰 4 地址
        let t = FakeIpTable::from_cidr("198.18.0.0/30")
            .expect("v4 池（哨兵，不参与）")
            .with_v6_cidr("fd6e:fd93:5d8f::/126")
            .expect("v6 池");
        let g = "gen-v6";
        let mut ips = Vec::new();
        for i in 1..=4 {
            let ip = t
                .alloc_v6_with_generation(&format!("d{i}.example"), g)
                .expect("v6 池内分配");
            t.pin_ip(&IpAddr::V6(ip));
            ips.push(ip);
        }
        let err = t
            .alloc_v6_with_generation("d5.example", g)
            .expect_err("v6 全钉住须拒绝");
        let FakeIpError::Exhausted { capacity, .. } = &err else {
            panic!("须为 Exhausted: {err:?}")
        };
        assert_eq!(*capacity, 4, "v6 池容量独立计数");
        assert!(
            ips.iter()
                .all(|ip| t.reverse_ip(&IpAddr::V6(*ip)).is_some()),
            "钉住 v6 绑定不受 Exhausted 分配影响"
        );
        // release 首地址后可回收
        t.release_ip(&IpAddr::V6(ips[0]));
        let reuser = t
            .alloc_v6_with_generation("next.example", g)
            .expect("释放后可回收");
        assert_eq!(reuser, ips[0], "v6 回收复用释放地址");
    }
}
