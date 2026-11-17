# AI/LLM traffic identification and routing (proposal)

Status: **proposal only (2026-11-17, new user requirement)**. This document records the semantics and the rule-template design; implementation is scheduled for a later batch under RIL-153.

User question: "can we identify AI model traffic and route it separately?" Answer: yes, but identification is **by domain/CDN/SNI prefix only — never by guessing traffic content**. This proposal reduces "identify AI provider traffic" to a versioned, source-verifiable routing rule template; a matched flow is routed to a user-chosen node/group.

## Semantics

### Identification: domain-prefix rule template, no content guessing

- Covers common AI provider domains (`openai.com` / `anthropic.com` / `claude.ai` / `gemini.google.com` / `api.kaipulse` etc.) plus CDN prefixes (`domain_keyword`, e.g. `openai`/`anthropic` substrings in third-party carrier domains).
- **The first template revision uses domain-face conditions only** (`domain_suffix` / `domain_full` / `domain_keyword`) — the existing `MatchCondition` set already expresses them; no new engine.
- **SNI/HTTP-Host identification depends on bounded sniffing (RIL-143, not yet delivered)**: pure-IP target flows on the TUN face are not identified until sniffing ships (stated honestly — no IP-range tables, no guessing ownership as a substitute for identification).
- **"openai/anthropic HTTP header features" require a new condition face**: the current `MatchCondition` set has no header condition type. If delivered later, evidence comes only from the RIL-143 bounded evidence face (no HTTPS decryption, no crossing authentication boundaries, bounded first-packet time/bytes). Scheduled for the implementation batch; excluded from template v1.

### Direction: match → user-chosen node/group

- A matched flow routes to `target` — a group name or direct node name, same semantics as existing rule `target`; the user picks a proxy group (proxied) or a direct node (direct).
- **No new execution engine**: the template lands as ordinary `routing.rules` entries (first match wins), inserted before generalized region/scenario rules so AI traffic is not captured by later "CN direct" style rules.

### Configuration face: subscription-conversion rule template + CLI shortcut

1. **Subscription-conversion rule template**: the template is an in-tree constant (ships with the version; domain list source-verifiable and versioned), merged into `routing.rules` at import/conversion time by user choice. **The template is never fetched remotely** — no supply-chain face.
2. **CLI shortcut**: `rillane ai on --proxy <group>` / `rillane ai off` (rillanectl subcommand sugar) — generates/removes template rules. It lands on the **config transaction face** (RIL-073–077 proposal/approval/receipt chain), never bypassing config generations; template rules carry the recognizable name prefix `ai-`, so `off` addresses removal by prefix and never touches user-written rules.

### Special cases (stated honestly)

- **Streaming SSE long connections are never interrupted**: the routing decision is made once at connection establishment; existing connections do not re-route on rule/mode hot updates (existing SessionPin/generation semantics). The template introduces no per-packet re-identification — no interruption face.
- **WebSocket compatibility**: the ws upgrade rides inside the TCP stream; the routing face is application-protocol agnostic. A domain match routes the whole flow (ws and SSE included) to the chosen egress — no protocol special-casing.
- **No AI model API uses UDP**: mainstream AI provider APIs are HTTPS/TCP. The template involves no UDP face (nothing reserved, nothing claimed); any future UDP endpoint is evaluated separately.

## Rule template (YAML sample, expressed in existing condition faces)

```yaml
routing:
  rules:
    # RIL-153 AI/LLM provider template (domain face, v1; target is user-chosen)
    # Rule names carry the ai- prefix: CLI on/off merges/removes by prefix.
    - name: ai-openai
      target: ai-proxy                # user-chosen: group name or direct node name
      matches:
        - type: any
          conditions:
            - type: domain_suffix
              values: [openai.com, oaistatic.com, oaiusercontent.com]
            - type: domain_keyword
              values: [openai]        # CDN prefix face (carrier domains containing "openai")
    - name: ai-anthropic
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_suffix
              values: [anthropic.com, claude.ai]
            - type: domain_keyword
              values: [anthropic]
    - name: ai-gemini
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_full
              values: [gemini.google.com, aistudio.google.com]
    - name: ai-other
      target: ai-proxy
      matches:
        - type: any
          conditions:
            - type: domain_full
              values: [api.kaipulse.com]   # example: add own/niche endpoints as full/suffix
```

Conditions inside one rule are AND; `any` is OR. The four rules evaluate first-match-wins; the matched `reason` is the rule name (readable in the diagnostics face, per-provider).

## Implementation boundary (later batch)

- Template constant plus merge/removal logic (subscription-conversion face + rillanectl `ai` subcommand);
- Insertion-position guarantee (before generalized region rules) and idempotency (repeated `on` never duplicates rules);
- SNI/HTTP-Host identification integrates after RIL-143 ships (any new condition type follows the same discipline: semantics first, implementation later);
- Acceptance anchors: template roundtrip (merge → export → re-read, zero loss), on/off idempotency, a `target` pointing at a nonexistent group is rejected by the existing reference-graph validation, SSE/ws long connections survive rule hot updates.
