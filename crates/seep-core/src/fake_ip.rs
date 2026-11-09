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
//! 分配与命中同走一把互斥锁（检查+插入原子，双表不漂移）——分配是
//! 每域名一次的低频路径，反查是每流一次，锁窗为纯内存操作。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// fake-ip 池：`base`/`host_bits` 定界，`forward`/`reverse` 双向表。
pub struct FakeIpTable {
    base: u32,
    host_bits: u32,
    cursor: AtomicU64,
    state: Mutex<PoolState>,
}

struct PoolState {
    forward: HashMap<String, Ipv4Addr>,
    reverse: HashMap<Ipv4Addr, String>,
}

impl FakeIpTable {
    /// 从 CIDR（如 `198.18.0.0/15`）构建。仅认 IPv4；前缀 ≤30（池至少
    /// 4 个地址）。
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
            state: Mutex::new(PoolState {
                forward: HashMap::new(),
                reverse: HashMap::new(),
            }),
        })
    }

    fn mask(host_bits: u32) -> u32 {
        if host_bits == 0 {
            u32::MAX
        } else {
            u32::MAX << host_bits
        }
    }

    fn capacity(&self) -> u64 {
        1u64 << self.host_bits
    }

    /// 地址是否属本池（网络位相同即在内，含网络地址本身）。
    pub fn in_range(&self, ip: &Ipv4Addr) -> bool {
        (u32::from(*ip) & Self::mask(self.host_bits)) == self.base
    }

    /// 域名分配稳定假地址：已分配直接命中；未分配按游标取池内下一地址
    /// （回绕），写入双向表。域名统一小写（DNS 大小写不敏感口径）。
    pub fn alloc(&self, domain: &str) -> Ipv4Addr {
        let key = domain.to_ascii_lowercase();
        let mut state = self.state.lock().expect("fake-ip pool lock");
        if let Some(ip) = state.forward.get(&key) {
            return *ip;
        }
        let offset = (self.cursor.fetch_add(1, Ordering::Relaxed) % self.capacity()) as u32;
        let ip = Ipv4Addr::from(self.base.wrapping_add(offset));
        state.forward.insert(key.clone(), ip);
        state.reverse.insert(ip, key);
        ip
    }

    /// 假地址反查原域名（入站改写用；未分配/非池内返回 None）。
    pub fn reverse(&self, ip: &Ipv4Addr) -> Option<String> {
        self.state
            .lock()
            .expect("fake-ip pool lock")
            .reverse
            .get(ip)
            .cloned()
    }

    /// 池内已分配域名数（观测面）。
    pub fn len(&self) -> usize {
        self.state.lock().expect("fake-ip pool lock").forward.len()
    }

    /// 池是否为空（观测面）。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 入站 target 回填（G1-10）：host 为本池 IPv4 时反查原域名；host 为域名
/// 或池外地址返回 None（原样放行）。入站面用它把 DNS 面分配的假地址还原
/// 成域名，路由按域名规则命中。
pub fn reverse_host(table: &FakeIpTable, host: &str) -> Option<String> {
    let ip: Ipv4Addr = host.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    if !table.in_range(&ip) {
        return None;
    }
    table.reverse(&ip)
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
}
