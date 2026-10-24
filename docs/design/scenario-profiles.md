# P2-3 Scenario profile presets (design draft)

> 2026-10-02 ready and landed in the same round (the top-level `profile:` field fills defaults and
> expands, explicit always wins, zero runtime branches; pick one of `examples/profile-*.yaml` and run --
> see the positioning.md §2.5 note). Three config templates for `proxy` / `game` / `web` (routing rules +
> obfuscation switches + scheduling targets), the same engine underneath. positioning.md §2.5: the
> differences between the three scenarios = routing strategy templates + middleware composition +
> egress protocol choice, all of which are configuration-layer composition, with no branching code paths
> required.
>
> **Landing status**: implemented (M0 2369c0d: ProfileKind + apply_profile default filling + the
> §7-1..5 unit tests; M1 this commit: three examples under examples/ + the §7-6 integration test +
> documentation backfill).

## 0. Scope and acceptance wording

**todo original text**: three config templates for `proxy` / `game` / `web` (routing rules + obfuscation switches + scheduling targets), the same engine underneath.
**Acceptance original text**: pick one of the three example configs and it runs; between profiles there are only policy differences, no separate code paths.

**Measurable wording (explicit rewrite, not shrinking)**:

1. **Pick one of three and run**: `examples/profile-{proxy,game,web}.yaml`, three self-contained
   examples; pick any one and `SEEP_CONFIG=<path> seepd` passes config parsing and runtime construction
   (the integration test reads the three files and asserts the full chain through `load_from_path`);
2. **Only policy differences**: the diff of the three examples falls only on routing (groups/rules),
   obfuscation, egress_pool, udp (carried explicitly in the game example, §9-1) and the one `profile:`
   line -- ingress/egress/control/telemetry are isomorphic (pinned by the integration test asserting
   full equality);
3. **No separate code paths**: a profile is a **build-time expansion** (a pure function in seep-config
   fills the presets into the existing blocks); at runtime the `profile` field does not appear and no
   runtime branch is added -- the expansion output and an equivalently hand-written config go through
   exactly the same build()/conversion chain.

## 1. Current state and structural constraints

- `SeepConfig` (seep-config): `routing.groups/rules`, `obfuscation` (P1-4 M0) and `egress_pool`
  (P1-5) are all in shape; `udp` is a non-Option `UdpConfig` (default `enabled: false`) -- **an
  "explicit false" cannot be distinguished from a "default false"**, so the profile mechanism cannot
  safely rewrite it (see the §9 deviation);
- the single config loading entry: `load_from_path` -> `from_str` (the only production call at
  seepd main.rs:29; the subscription conversion constructs a `SeepConfig` literal programmatically, without going through from_str);
- obfuscation-middleware.md §3.5 already designs `obfuscation.profiles` as "the landing-point container
  of the P2-3 three-scenario presets" -- this draft lands **scenario-level** presets (one top-level
  field), while `obfuscation.profiles` keeps its original meaning (a named padding policy set); the two are orthogonal;
- group member references use user egress names: the mechanism cannot foresee a user's topology, so a
  template group member can only land on `default_node` (see D-5).

## 2. Design decisions

- **D-1 shape = one top-level field** `profile: <proxy|game|web>`: an `Option<ProfileKind>` enum
  (serde snake_case; an unknown value is reported as an unknown variant at the serde layer, so no
  hand-written validation is needed); default None = zero difference for existing configs.
- **D-2 semantics = fill defaults, explicit always wins**: a profile only fills presets into
  "unspecified" positions, and blocks the user gave explicitly (groups non-empty / rules non-empty /
  obfuscation explicit Some / egress_pool explicit Some) are never touched -- no overwrite, no
  deletion, no merge. The expansion is therefore naturally idempotent (once filled it is non-empty, and
  a second expansion is a no-op).
- **D-3 the expansion point = the tail of `SeepConfig::from_str`**: a single-entry `apply_profile` pure
  function (`&mut self`), covered automatically by `load_from_path` through from_str; programmatic
  constructions such as the subscription conversion do not trigger it (the same precedent as
  obfuscation's "subscription does not produce an obfuscation block").
- **D-4 the "unspecified" judgment surface** (only surfaces decidable by Option/emptiness count):
  `routing.groups.is_empty()`, `routing.rules.is_empty()`, `obfuscation.is_none()`,
  `egress_pool.is_none()`; `udp` is not in the surface (§9 deviation 1).
- **D-5 group template members = `[default_node]`**: the minimal runnable shape; a real multi-member
  topology must be decided by the user's egress, and the mechanism does not guess names -- the example
  YAML demonstrates the multi-member writing (once the user fills nodes into the group, the full
  SLO-scored path selection surface is obtained).
- **D-6 scenario = a row of the policy matrix** (§4); the three rows are each other's proof of "only
  policy differences"; game is the only row carrying a scheduling target (the group-level `slo`) and an
  obfuscation switch, web is the only row carrying a connection pool, and the proxy row = the policy
  shape of the existing config/seep.yaml (the baseline).

## 3. Data structures

```rust
/// Scenario preset (P2-3): expanded at config time into the existing blocks, invisible at runtime
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind { Proxy, Game, Web }

// added to SeepConfig:
#[serde(default)]
pub profile: Option<ProfileKind>,
// Does SeepConfig already hand-write Default? (it does -- existing fields come along); None default as per the precedent
```

## 4. Filling matrix (D-6)

| Slot | proxy | game | web |
|----|-------|------|-----|
| `routing.groups` empty -> | `auto`: latency, [default_node], no slo | `game-auto`: latency, [default_node], slo{p95_ms:80, loss_ratio:0.02} (the scheduling target -- the group-level `slo:` YAML surface in slo-scoring.md) | `web-auto`: latency, [default_node], no slo |
| `routing.rules` empty -> | `cn`: geoip CN -> auto | the game platform domain template (domain_suffix: steampowered/steamcontent/epicgames/riotgames/battle.net/playstation/xbox/nintendo) -> game-auto | `cn`: geoip CN -> web-auto |
| `obfuscation` None -> | untouched | `Some(enabled: true, padding: bucket{buckets:[128,256,512,1024]})` -- QoS packet-length scattering (positioning §2.4; apply_to defaults to chain = the MVP frame execution side) | untouched |
| `egress_pool` None -> | untouched | untouched | `Some(enabled: true, the rest default)` -- reuse of short web connections (P1-5) |
| `udp` | untouched (§9 deviation 1: carried explicitly in the example YAML) | untouched (as left; the game example explicitly sets `enabled: true` + `session_lifetime_secs` for a long session) | untouched |

The rule templates contain no catch-all: an unmatched rule falls to `default_node` naturally (the existing routing semantics),
and the templates place only scenario-specific entries.

## 5. Wiring points

| # | Point | Action |
|---|----|------|
| 1 | the tail of `SeepConfig::from_str` | `config.apply_profile();` (the single entry; the subscription/programmatic construction does not trigger it) |
| 2 | at runtime | **zero contact** -- the expansion output is an ordinary config; build()/hot update/control plane are unaware of the profile |
| 3 | `examples/` | three self-contained examples (M1); the integration test reads the three through `load_from_path` |

## 6. Errors and boundaries

- E1 a `profile` value not one of the three enum values: serde unknown variant (reported at parse time, listing the legal values);
- E2 a profile coexisting with explicit blocks: legal (D-2 explicit wins, judged surface by surface, no conflict error);
- E3 the expansion output references `default_node` but that name is not in egress: managed by the
  existing build() group-member validation surface (the same path as a hand-written config; the
  mechanism does not revalidate);
- E4 idempotent expansion: a second apply_profile on the same config is a no-op (once filled it is non-empty);
- E5 `profile` and obfuscation.profiles have orthogonal naming sets: the former is a scenario-level
  top-level expansion, the latter a named padding policy set; neither references nor overwrites the other;
- E6 the rule template and the group template **rise and fall together**: a template rule's target
  points to a group template name (auto/game-auto/web-auto) -- when a user group is present (groups
  non-empty) the group template is not created, and the rule template is not filled either (a user
  group name cannot be guessed, avoiding a dangling target; in that case an empty rules is a legal
  shape, and an unmatched falls to default_node).

## 7. Test strategy

1. the three-profile expansion matrix: empty routing + each profile -> group name/policy/slo/rule
   target, obfs/pool asserted surface by surface (cell by cell of the §4 table);
2. explicit wins: a config with groups/rules + profile: game -> the two groups and one rule
   untouched; obfs None is still filled (proven independently per surface);
3. zero difference for existing: no profile field -> every slot untouched (including default None
   deserialization);
4. illegal value: `profile: fps` -> unknown variant error;
5. idempotence: two expansions == one expansion (E4);
6. pick one of three examples (M1): read `examples/profile-*.yaml` through `load_from_path` on the
   full chain (including the expansion + existing validate); the diff of the three is only the policy
   blocks (wording 2).

## 8. Step-by-step implementation checklist

| Step | Content and landing points | Depends on | Acceptance |
|----|-----------|------|------|
| M0 | the seep-config ProfileKind + SeepConfig.profile + apply_profile + the §7-1..5 unit tests | - | §7-1..5 green; zero regression over existing tests |
| M1 | three examples under examples/ + the §7-6 integration test + documentation backfill (todo/PROTOCOLS/roadmap/the positioning §2.5 current-state note/landing note in this draft) | M0 | §7-6 green; the wordings 1-3 are reproducible item by item |

## 9. Deviations and assumptions

1. **udp is not in the filling surface**: `SeepConfig.udp` is not Option, so an explicit/default
   false cannot be distinguished; a profile flipping it would overwrite an explicit disable (violating
   D-2). The game's UDP need (G1 already solved, a long session does not drop) is carried explicitly by
   the example YAML, and the mechanism does not touch the udp block;
2. **a single-member group template** is the minimal runnable shape, not the best practice of the
   scenario -- the real shape of multi-member + SLO-scored path selection is demonstrated in the
   example YAML, and the mechanism keeps "do not guess a user's topology";
3. **the game slo thresholds** (p95 80ms / loss 2%) are preset defaults, not a standard -- a user's
   group-level `slo:` explicit configuration always wins (D-2), and the thresholds are a tuning surface,
   not a protocol surface;
4. the game platform domain template is an **illustrative** domain set (common platforms), not an
   exhaustive one -- the value of the rule template is in showing "how a policy block is written", and
   the precise list is maintained by the user.

## 10. Risks and open items

- **R-prof1**: preset values drift with the ecosystem (the game domain list, the slo thresholds) -- a
  preset is configuration-layer, and the example YAML can be revised independently without a release;
- **O-prof1**: ~~the `seepctl profile` subcommand generates a scenario skeleton config~~ (**landed
  2026-10-10**: `seepctl profile <proxy|game|web> [--out <path>]` parses and validates through
  `from_str` with the scenario expansion inlined, then outputs YAML -- pick one of three and run; an
  out-of-whitelist scenario name is an error listing the legal values);
- **O-prof2**: the merge semantics of profile and subscription (a subscription pushes egress, the main
  config produces policy, currently naturally orthogonal by design; revisit only if a conflict demand
  appears).
