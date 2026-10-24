# P2-8 DNS split resolution (design draft)

> Ready 2026-10-02; **M0-M1 landed** (M0 750de34 engine + factory switch; M1
> config mirror + conversion + listener assembly + control plane metrics).
> Positioning basis: positioning.md "DNS split (web acceleration)" row -- domestic/foreign DNS split,
> cache, anti-poisoning.

## 0. Scope and acceptance criteria

**todo original text**: domestic/foreign DNS split, cache, anti-poisoning,
integrating with the `seep-platform::network::dns` design.
**Acceptance original text**: split resolution is correct and cache hit rate
has metrics; polluted domains return trusted results.

**Testable criteria (explicit rewrite)**:

1. **Split correctness**: the upstream group selected by the domain rule matches the server the actual
   query reaches (assert the arrival surface with mock local dual upstreams);
2. **Cache hit metrics**: a second query of the same domain counts as a hit, the stats snapshot
   `cache_hits/cache_misses/cache_hit_rate` is correct field by field;
3. **Anti-poisoning**: when the domestic upstream returns a polluted IP, the `cross_check` surface
   returns the trusted result and counts `pollution_suspected`; the `off` surface presents the domestic
   result as-is (three tests pin down the behavioral difference, see §7-4).

## 1. Current state and structural constraints

- `dns.rs` is the **data model layer** (DnsConfig/DnsServer/DnsStats/DnsHandler trait, 991 lines),
  zero engine-surface implementation -- `mod.rs::create_dns_handler` always returns Err
  "real implementation belongs to P2-8", the T0 pin test is in place;
- seep-platform dependencies already include tokio/socket2/regex/thiserror -- **MVP adds zero new
  dependencies**, wire format is hand-written (RFC 1035 A/AAAA/CNAME minimal surface);
- the seep-config mirror adds no dependencies (network-route.md §1.2 ruling precedent);
- `TunBlockConfig.dns_servers` is annotated "record only (consumption belongs to P2-8)";
- `DnsConfig` platform types have no domestic/trusted group concept -- grouping and rules are the
  responsibility of the **config mirror + conversion layer** (M1), the engine only receives "two
  upstream groups + a rule table".

## 2. Design decisions

- **D-1 minimal wire surface**: hand-written RFC 1035 -- query encoding (header + single QD, RD=1)
  + response decoding (header / skip question / A, AAAA, CNAME of the answer, other rdata skipped by
  rdlength); the read side supports compression pointers (jump cap §5-E5); UDP message surface
  (<=512B traditional query), no TCP/EDNS0 (§9-2).
- **D-2 split = domain rule -> upstream group**: two groups `Domestic`/`Trusted` (naming modeled on
  "pollution risk" semantics, the user can configure the domestic group as any local ISP DNS) + rule
  table (exact/suffix, two lightweight modes) + default fallback; the decision pure function is
  **first-match-wins** (config order is priority, same style as routing rules); suffix requires a
  leading dot (`.cn` matches `x.cn` but not `cn` -- use exact for bare domains, E1 validation).
- **D-3 anti-poisoning two states**: `off` (pure split, single-group direct query) / `cross_check`
  (queries selected by Domestic run **concurrent dual queries** domestic+trusted: disjoint answer sets
  judged as divergence -- take the trusted side + count `pollution_suspected`; on agreement or
  one-sided success take the successful side). `TrustedOnly` is not defined: pollution-sensitive
  domains going through the trusted group is already the expression of a split rule, "routing-style
  anti-poisoning" gets no separate mode (§9-3).
- **D-4 cache**: key `(domain normalized form, qtype)`, TTL clamped per answer to `[min_ttl, max_ttl]`
  (carried by `DnsCacheConfig` fields), entry expiry = the minimum of each answer's clamped values;
  `ttl=0` is not cached; NXDOMAIN negative cache (`enable_negative_cache` + `negative_ttl`); when
  `max_entries` is full evict the **earliest inserted** (seq order, simple and testable); domain
  normalization = lowercase folding + trailing dot stripping (prerequisite for cache hit correctness,
  §5-E4).
- **D-5 stats**: `DnsStats` (Mutex aggregate form) does not enter the engine hot path -- the engine
  uses an `AtomicU64` counter group (total/cache_hits/cache_misses/upstream_failures/
  pollution_suspected/per-group member query counts) + `stats_snapshot()` for an instantaneously
  consistent snapshot, hit_rate computed with the same criteria as
  `DnsStats::cache_hit_rate()`; control plane exposure belongs to M1.
- **D-6 factory switch**: `create_dns_handler` returns the real implementation for a `DnsConfig`
  "containing enabled UDP upstreams" (all UDP servers go into the default=Trusted group, no rules --
  the factory is the bridge of the existing `NetworkManager` path, split config surface belongs to
  M1 conversion); DoT/DoH/DoQ **enabled** upstreams -> Err with guidance (§9-1); zero usable
  upstreams -> Err. The T0 pin test half-side changes criteria (DNS: UDP usable + encrypted Err;
  filter unchanged).
- **D-7 local UDP listener = MVP delivery form**: `LocalDnsServer` binds `local_address:local_port`,
  recv -> decode -> resolve -> encode response (QR|RD|RA + rcode, the response writes back contained
  CNAMEs as-is); oneshot bridge-close drain exit (control_plane serve same semantics); TUN DNS
  hijack integration goes after P1-1/P1-2 lands (§9-4, does not block acceptance -- the listener is
  an independently usable surface).
- **D-8 file layout**: the engine lands in a new file `dns_engine.rs` (dns.rs stays the data model
  layer untouched, the 991 lines stop growing; mod.rs wiring pub mod + re-export).

## 3. Data structures (dns_engine.rs)

```rust
pub enum DnsAnswerData { A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(String), Other }
pub struct DnsAnswer { pub domain: String, pub rtype: DnsRecordType,
                       pub ttl: u32, pub data: DnsAnswerData }
pub struct DnsWireResponse { pub id: u16, pub rcode: u8, pub answers: Vec<DnsAnswer> }

pub fn encode_query(id: u16, domain: &str, qtype: DnsRecordType) -> Result<Vec<u8>>;
pub fn decode_response(buf: &[u8]) -> Result<DnsWireResponse>;
pub fn encode_response(id: u16, domain: &str, qtype: DnsRecordType,
                       rcode: u8, answers: &[DnsAnswer]) -> Vec<u8>;

pub enum UpstreamGroup { Domestic, Trusted }
pub enum PartitionPattern { Exact(String), Suffix(String) }   // normalized lowercase storage
pub struct DnsPartition { rules: Vec<(PartitionPattern, UpstreamGroup)>, default: UpstreamGroup }
impl DnsPartition { pub fn select(&self, norm_domain: &str) -> UpstreamGroup; }

#[derive(Debug, Default)]
pub struct DnsStatsCounters { /* AtomicU64 × 7 */ }
pub struct DnsStatsSnapshot { pub total_queries: u64, /* … */ pub cache_hit_rate: f64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiPoison { Off, CrossCheck }

pub enum ResolveError { NxDomain, UpstreamFailure(String), InvalidDomain(String) } // thiserror

pub struct DnsResolver { /* groups, partition, cache: Mutex<DnsCache>, anti_poison, timeout, retries, stats */ }
impl DnsResolver {
    pub fn new(cfg: ResolverConfig) -> Result<Self>;          // E1 validation
    pub async fn resolve(&self, domain: &str, qtype: DnsRecordType)
        -> Result<Vec<DnsAnswer>, ResolveError>;
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot;
    pub fn clear_cache(&self);
}

pub struct LocalDnsServer { /* Arc<DnsResolver>, bind addr */ }
impl LocalDnsServer {
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<()>;
}
```

## 4. Wiring points

| # | Point | Action | Step |
|---|----|------|----|
| 1 | `network/dns_engine.rs` new file | Engine in full (wire/cache/partition/resolver/server/stats) | M0 |
| 2 | `network/mod.rs` | pub mod + re-export; `create_dns_handler` switches to the real implementation; T0 test changes criteria (D-6) | M0 |
| 3 | seep-config `NetworkBlockConfig.dns` sub-block mirror + validate | deny_unknown_fields; rules/groups/cache/anti-poisoning surface | M1 |
| 4 | seep-runtime conversion + runtime_builder wiring + listener start/stop | `DnsBlockConfig -> ResolverConfig`; `TunBlockConfig.dns_servers` consumption lands | M1 |
| 5 | Control plane `/stats` dns section | `stats_snapshot()` exposure (acceptance "hit rate has metrics") | M1 |

## 5. Errors and boundaries

- **E1 config validation** (ResolverConfig construction): trusted group empty (required by
  cross_check) / the group pointed to by a split rule has no servers / suffix without leading dot /
  empty exact / default group has no servers -- errors carrying the original value;
- **E2 all upstreams fail**: per-server within group × retries, all fail -> `UpstreamFailure` (no
  fallback to system DNS -- behavior is deterministic and testable);
- **E3 TTL clamping**: `clamp(ttl, min_ttl, max_ttl)`; `ttl=0` is not cached;
- **E4 domain normalization**: trim trailing dot + ASCII lowercase folding; empty/overlong (>253)/
  empty label -> `InvalidDomain`;
- **E5 compression pointer loop**: pointer jump cap 32, total name length cap 255 -- exceeding limits
  decode Err (prevents malicious-response infinite loops);
- **E6 response validation**: id mismatch / source address not the target server / decode failure
  -> discard and count as a retry (prevents misconfiguration and Basic spoofing);
- **E7 divergence decision**: cross_check's two sides count as divergent only when the A/AAAA sets
  are **disjoint** (subset/superset do not count -- multi-answer CDN is normal); if either side
  fails, take the successful side and do not count divergence.

## 6. Control plane

M1: `/stats` gains a dns section (total/cache_hits/cache_misses/cache_hit_rate/
pollution_suspected/per-server counts within groups). No new endpoint (reuses the stats surface).

## 7. Test strategy

1. **wire pure functions**: query golden bytes (id/flags/qname/qtype at each offset); response
   decoding golden with compression pointers; E5 pointer loop / truncated message rejected;
2. **split decision**: rule hits in both modes / default fallback / first-match-wins order / hits
   after case and trailing-dot normalization;
3. **cache**: second-query hit count and hit_rate; TTL clamping three states; expiry invalidation;
   negative cache NXDOMAIN hit; max_entries evicts the oldest;
4. **anti-poisoning** (mock dual local UDP upstreams): off surface = domestic polluted result
   returned as-is; cross_check surface = disjoint sets -> trusted result + suspected=1; agreeing
   surface -> domestic result + suspected=0; one-side-failure surface -> the successful side;
5. **resolver integration**: mock UDP upstream full path (resolve -> response decoding -> server
   arrival surface assertion = acceptance criterion 1); E2 all-fail path;
6. **listener**: LocalDnsServer binds :0, client sends a query and receives a response
   (rcode/answers assertion) + oneshot bridge-close exit;
7. **factory**: UDP upstream Ok / DoH upstream Err with guidance / zero upstreams Err (T0 changed
   criteria).

## 8. Step-by-step implementation checklist

| Step | Content and landing points | Dependencies | Acceptance |
|----|-----------|------|------|
| M0 done 750de34 | Design draft + dns_engine.rs in full (§3) + mod.rs factory switch + §7-1..7 tests | -- | §7 all green; mock dual-upstream anti-poisoning three surfaces hold (17 tests) |
| M1 done | seep-config dns sub-block (`DnsBlockConfig`/groups/rules/cache/listen, deny_unknown_fields + validate E1) + runtime `dns_config.rs` conversion (domestic defaults to falling back to tun.dns_servers:53 -- the dns_servers consumption promise is honored here) / `DnsService` listener start/stop + runtime_builder assembly (independent of the network virtualization switch, §9-4) + control plane `GET /dns/stats` + doc backfill | M0 | Control plane hit rate visible (endpoint test pins the exposure surface); dig-style end-to-end (dns_config lifecycle test pinned) |

## 8.1 M1 landing supplement (2026-10-02)

- **Config surface**: `DnsBlockConfig.enabled` defaults to **true** (the opposite of obfuscation's
  false default -- the DNS listener is an explicit opt-in config block, presence means intent; false
  serves for temporary offline and short-circuits validate to tolerate half-configuration);
  `default_group` defaults to domestic; a leading dot in the rule pattern is the suffix discriminator
  (no separate mode field); duplicate patterns are rejected at build time (under first-match-wins
  semantics the latter never takes effect);
- **Fallback semantics**: `network.dns.domestic` empty -> fall back to `network.tun.dns_servers`
  with port 53 appended (the P2-8 consumption promise of `TunBlockConfig.dns_servers` is honored
  here); still empty after fallback yet referenced by default/rules -> build-time Err with guidance;
  trusted gets no fallback (§10-R-dns1 trust is guaranteed by the deployer);
- **Assembly semantics**: runtime_builder reads `config.network.dns` and assembles directly (not
  through `RuntimeConfig.network_config`/`enable_network_virtualization` -- the listener is an
  independent surface §9-4); `DnsService` start/stop oneshot bridge close, stop failure warns without
  interrupting; control plane `get_dns_service()` getter + `/dns/stats` DTO (absent =
  enabled:false all-zero form).

## 9. Deviations and assumptions

1. **DoT/DoH/DoQ upstreams not done in MVP** (data model has the shape, engine does not implement) --
   the trusted channel for "anti-poisoning" is carried by the **deployment choice of the trusted
   group** (trusted IP/self-built gateway UDP surface); encrypted upstreams go to V2. E6's id+source
   address validation is the Basic surface not the encrypted surface, plaintext UDP upstream links can
   be polluted by middleboxes -- R-dns1;
2. **UDP message surface**: <=512B without EDNS0, the A/AAAA/CNAME surface suffices for web
   acceleration scenarios; TCP retransmission/large responses go to V2;
3. **No TrustedOnly mode** (D-3): a pollution-sensitive domain's explicit rule going through the
   trusted group is the equivalent expression, one fewer mode is one fewer set of criteria;
4. **TUN hijack integration not in this step**: P1-1/P1-2 belongs to another session in flight; the
   local listener is already an independently usable surface (pointing resolv.conf at it takes effect),
   acceptance does not depend on TUN;
5. **filter rule surface suspended**: `DnsConfig.filters` (ad filtering) is not part of this item's
   acceptance, the factory path ignores non-empty filters + warn (not Err -- does not block the
   existing shape); the existing filter.rs problem of compiling regex rules per query is not carried
   into the engine (the split uses lightweight exact/suffix).

## 10. Risks and open issues

- **R-dns1**: trusted group trust is guaranteed by the deployer (plaintext UDP links can still be
  link-level polluted) -- noted in docs; encrypted channels go to V2 (§9-1);
- **O-dns1**: ~~geosite/chnroutes bulk rule source import~~ (**landed 2026-10-10**:
  `seepctl import-rules <source> --target <name> [--face routing|dns] [--name <n>] [--out <p>]` --
  v2fly text list line-set parsed line by line; the routing surface yields `routing.rules` fragments
  (domain -> DomainSuffix union, keyword -> DomainKeyword, CIDR -> Network, AND semantics so each
  type gets its own column), the dns surface yields `network.dns.rules` fragments (bare domain/
  `domain:` -> exact + suffix double pattern, D-2 leading-dot criteria; `full:` -> exact);
  `regexp:`/`include:`/`@attr`/bad lines go into the skip report one by one without blocking,
  keyword/CIDR on the dns surface raise explicit errors without silent downgrade; the converter lives
  in seep-subscription `rule_source`);
- **O-dns2**: DoH/DoT upstreams, EDNS0, TCP surface go to V2.
