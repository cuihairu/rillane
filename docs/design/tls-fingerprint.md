# P2-5 Client TLS Fingerprint Emulation (design draft)

> 2026-10-02 ready; **M0-M1 landed** (M0 `48f633a` common layer + capture test / M1 this commit: config surface
> + pool key + factory + doc backfill). uTLS-class capability mounts onto the common egress TLS layer (tls.rs).
> Positioning basis: positioning.md section 2.4 "fingerprint emulation" row (uTLS/client TLS fingerprints
> chrome/ios/safari, benchmarked against sing-box `utls`).

## 0. Scope and acceptance criteria

**todo original text**: mount uTLS-class capability onto the common egress TLS layer (`tls.rs`). **Acceptance
original text**: the externally visible handshake fingerprint is selectable by config (chrome/ios etc.), and
fingerprint detection tools can distinguish them.

**Testable criteria (explicitly rewritten, not watered down; includes an honest downgrade of the word
"emulation", see section 9-1)**:

1. **Common-layer mounting**: add a fingerprint shape parameter to `tls.rs::build_client_config` -- all egress
   TLS (the per-flow path + the P1-5 factory path) is reshaped through the same funnel, no bypass;
2. **Selectable by config**: the fingerprint shape is a config value (preset enum none/chrome/ios/safari),
   default none = zero difference from existing traffic;
3. **Fingerprint distinguishable**: local ClientHello capture (an in-test TCP server directly reads the first
   record and parses the hello quintuple: version / cipher_suites / extensions / supported_groups /
   signature_algorithms) asserts that each pair of presets is distinct -- being distinguishable at the JA3
   quintuple input level is the reproducible form of "fingerprint detection tools can distinguish".

## 1. Current state and structural constraints

- All egress TLS goes through rustls 0.23 (single `build_client_config` funnel: the per-flow path
  `create_tls_connector*` + the factory path `TlsConnectorFactory::shared_config`);
- The deformable surface of the hello exposed by rustls (verified against 0.23.21 source, client/hs.rs):
  - `cipher_suites`: the CryptoProvider suite list is emitted in full in order (hs.rs:424), with a trailing
    renegotiation SCSV -- **subset + ordering controllable**;
  - `kx_groups`: the supported_groups extension in provider order (first = the TLS1.3 key_share default group)
    -- **subset + ordering controllable**;
  - `signature_algorithms`: = `config.verifier.supported_verify_schemes()` (hs.rs:258-260) -- **verifier
    wrapping makes subset + ordering controllable** (NoVerifier is a precedent; the webpki path can wrap
    `WebPkiServerVerifier` to delegate verification while changing only the list);
  - The protocol version surface: `with_protocol_versions` determines the supported_versions contents, and the
    1.2/1.3 choice drags the hello extension set shape along with it (1.3-only key_share /
    psk_key_exchange_modes);
  - Whether ALPN is present changes the extension set (an existing config surface, not managed by the
    fingerprint presets -- a semantic field).
- **rustls immutable surface**: the extension set members are fixed (no GREASE / padding / compress_certificate
  and other Chrome-specific extensions) -- the extensions dimension of the hello quintuple can only vary within
  the "rustls shape set", see section 9-1; **from 0.23.4x onward rustls randomizes the extension order per
  handshake** (hs.rs `extension_order_seed`) -- the stable criterion for the extensions dimension is the set,
  not the sequence (same rule as test section 7-5), and this upstream anti-fingerprint behavior simultaneously
  weakens the meaning of static JA3 (section 9-5).

## 2. Design decisions

- **D-1 Presets = parameter tables, not a new stack**: each preset is a `{protocol_versions, cipher_suites
  order, kx_groups order, sig_schemes order}` table -- taking a subset and reordering from the rustls/ring
  support set, all of which negotiate successfully (no combination a server must reject is introduced); no
  BoringSSL bundling / no self-assembled ClientHello (section 9-1).
- **D-2 Single-funnel mounting**: add a parameter to `build_client_config(skip_cert_verify, alpn, profile)`; the
  two callers (per-flow/factory) pass the same parameter; the factory cache key is extended to `(skip, alpn,
  profile)` (different fingerprint = different config -- the P1-5 semantics of sharing a session cache under the
  same key are preserved by the key).
- **D-3 Verifier wrapping**: sig_schemes reshaping = wrapping the existing verifier (delegating verify_* while
  changing only `supported_verify_schemes`) -- the skip and webpki paths are isomorphic, verification semantics
  unchanged (the list is the hello advertisement surface, not the verification surface).
- **D-4 Pool key carries identity**: the fingerprint enters `TransportKey` (pool D-2 transport identity) --
  connections with different hello shapes cannot be lent to each other; the hot-reload key self-invalidates per
  the existing key-field semantics.
- **D-5 Preset set**: `none` (rustls default = zero difference from existing traffic) / `chrome` / `ios` /
  `safari` -- chrome uses dual versions + an AES-first long chain; ios uses single 1.3 + P256-first; safari uses
  single 1.3 + ChaCha-first -- the presets differ in at least one place each across the three dimensions of
  version/suite/group (the pairwise-distinct construction guarantee in section 7-3).
- **D-6 Observability**: no new metric family -- the fingerprint is a static config shape, not a runtime dynamic
  quantity; the `shape_material()` shape string (four dimensions: version/suite/group/scheme, a pure function
  exported from the preset table) for debugging/test comparison -- the naming deliberately avoids JA3: the
  extensions dimension is decided by rustls at runtime, and a static table must not claim to be a complete JA3
  (same rule as section 9-1).

## 3. Data structures

```rust
// seep-protocols/src/fingerprint.rs
pub enum TlsFingerprint { None, Chrome, Ios, Safari }

impl TlsFingerprint {
    pub fn parse(s: &str) -> Result<Self>;   // used by the M1 conversion layer (E1 errors with the original value)
}

struct ShapeSpec {                                   // real shape (fingerprint.rs:138)
    versions: Versions,                              // enum Versions { V13Only, V13AndV12 }
    cipher_suites: &'static [rustls::CipherSuite],   // subset ordering within the ring set
    kx_groups: &'static [rustls::NamedGroup],
    sig_schemes: &'static [rustls::SignatureScheme],
}

impl TlsFingerprint {
    fn spec(&self) -> Option<ShapeSpec>; // None = rustls default (zero difference)
    pub fn shape_material(&self) -> String;    // shape string (D-6)
}
```

seep-config surface (M1): the four TLS-carrying egress variants (http/vmess/vless/trojan) gain `tls_fingerprint:
Option<String>` (none by default; the conversion layer validates legal values).

## 4. Wiring points

| # | Point | Action |
|---|----|------|
| 1 | `tls.rs::build_client_config` | add a profile parameter -- install provider/versions/verifier per preset |
| 2 | `create_tls_connector*` / `TlsConnectorFactory` | pass through + cache key extension (D-2) |
| 3 | trojan/vless/http connector construction | pass through (M1, including the pool `TransportKey` field D-4) |
| 4 | seep-config egress variants + conversion | config surface (M1) |

## 5. Errors and boundaries

- E1 unknown fingerprint value: the config conversion layer errors with the original value (network/obfs
  precedent);
- E2 none default: zero difference -- do not install a reshaping provider, do not wrap the verifier;
- E3 pool hit keys contain the fingerprint: different fingerprints are not lent to each other (D-4); warm keys
  derive the same key with the fingerprint;
- E4 fingerprint against a TLS1.2-only server: the chrome preset includes 1.2 suites and can negotiate;
  ios/safari are single 1.3 and mark the handshake as a failure path against 1.2-only servers (the user choosing
  a preset owns the risk, documented);
- E5 compatibility risk of advertising a dishonest sig_schemes subset: the presets only take the mainstream five
  schemes (RSA_PKCS1_SHA256/384, ECDSA_NISTP256_SHA256, RSA_PSS_SHA256/384...), all genuinely supported by the
  verifier -- shrinking the advertisement surface introduces no verification blind spot (D-3 delegation
  semantics).

## 6. Control plane

No new endpoints/metric families (D-6). `seep_obfs_*`/`seep_tls_handshakes_total` are unaffected (the factory
observability surface counts under the same key).

## 7. Test strategy

1. Preset tables as pure functions: none = the rustls default shape (zero difference); each preset's
   suites/groups/schemes are subsets of the ring support set (preventing construction-time panics);
2. Hello capture parsing: an in-test TCP server receives the first record and parses the quintuple per the TLS
   ClientHello structure -- chrome/ios/safari/none each dial a local black-hole server (the handshake may be cut
   after ServerHello, no need to complete it);
3. Pairwise distinct: the four shapes' quintuples (version/suites/groups/sigalgs/extensions) have at least two
   differing dimensions for any pair (asserted on the section 7-2 data);
4. Cache keys: same fingerprint = same Arc, different fingerprints = different Arcs for the factory
   (`Arc::ptr_eq`, section 8.1 precedent);
5. Zero regression on existing TLS tests (the none path untouched byte for byte).

## 8. Step-by-step implementation checklist

| Step | Content and landing points | Dependency | Acceptance |
|----|-----------|------|------|
| M0 | Design draft + seep-protocols fingerprint.rs (preset tables/shape_material/single-funnel mounting) + sections 7-1..3/5 tests | -- | all of section 7 green; none zero difference |
| M1 | seep-config four-variant config surface + conversion validation (E1) + connector/pool key/factory wiring (sections 4-2/3) + section 7-4 + doc backfill | M0 | section 7-4 green; the pool does not lend across different fingerprints |

## 9. Deviations and assumptions

1. **"Emulation" downgraded to "shape mutation"**: true browser-equivalent JA3 simulation needs hello freedom
   rustls does not provide (GREASE, extension reordering, Chrome-only extensions, exact random/session-ID
   shapes) -- this step delivers within the rustls constraints a **fingerprint that is mutable and distinct
   across presets** (the reproducible form of the acceptance "distinguishable" = section 0-3); "presenting as
   real Chrome to a detection tool" is not promised and is explicitly not achieved; uTLS-grade simulation is
   deferred to V2 (requires switching stacks to BoringSSL or developing a ClientHello assembler, same note as
   positioning section 2.4). The preset names chrome/ios/safari express a "shape orientation", not "equivalent
   impersonation";
2. **The distinguishability criterion surface = the JA3 input quintuple** (locally parsed), not an online
   comparison against a third-party detection service -- offline reproducibility takes priority;
3. Preset table values drift with the ring support set: when ring upgrades add or remove suites, the preset
   tables need table-side revision (pure constant changes);
4. Non-rustls egress such as hysteria2/wireguard is outside this capability surface (QUIC hello belongs to the
   quicotls stack, discussed separately);
5. **Upstream behavior discovered (0.23.45 source verified during implementation)**: rustls already randomizes
   the ClientHello extension order per handshake -- the stable carrier dimensions of "distinguishability" = the
   four dimensions we control: version / suite order / groups / signature schemes; the extensions dimension is
   compared as a set in tests. This also means static JA3 was already weakened for rustls clients, and this
   step's value center falls further on "mutable and separable shape" rather than "simulation".

## 10. Risks and open items

- **R-tfp1**: the fingerprint shape itself becomes a new feature ("a deformable rustls") -- the MVP targets
  "dispersing same-shape multi-instances", and simulation-grade countermeasures are re-evaluated after the V2
  stack switch;
- **O-tfp1**: ~~`seepctl` debug subcommand printing a shape_material comparison table for each preset~~
  (**landed 2026-10-10**: `seepctl tls-fingerprint` prints the four presets (none/chrome/ios/safari) and their
  shape_material four-dimension shape strings -- none is `default`, the others exported as
  version|suite|group|signature scheme, with pairwise distinctness across presets guaranteed by the section 7-3
  construction);
- **O-tfp2**: custom presets (config directly writing suite/group lists) -- the preset table is opened as a
  config form to be done on demand.
