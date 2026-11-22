# v1 UI prototypes and network-control semantics

Status: **visual prototypes and interaction specification, not completed clients**. All nodes, rates, latency and tests are fictional. Design v1 is separate from release version. See the [saved prototype gallery](ui/README.md).

## Structure and references

Desktop: Overview, Nodes/subscriptions, Rules/regions, Network/DNS, Connections, Developer proxy, Settings. iOS/Android: Home, Nodes, Connections, Settings. Mobile has no arbitrary third-party PID routing. Android app lists remain optional. OpenWrt reuses authorized control-plane concepts rather than claiming a desktop app.

References: [Clash Verge official previews](https://github.com/clash-verge-rev/clash-verge-rev) and [Shadowrocket App Store](https://apps.apple.com/us/app/shadowrocket/id932747118). Reuse familiar navigation, connection controls and lists with an original Rillane identity; Android uses native Material patterns. No claim of an official Android Shadowrocket.

SSH confirmed clash-verge/service/mihomo processes on iMac, but no usable cua-driver was found and no live window screenshot was obtained. Official previews inform this design; it is not an inspection of the user's configuration.

## Independent controls

| Layer | Controls | Scope |
|---|---|---|
| Capture | System proxy/TUN/platform VPN | Which traffic reaches the core |
| Routing | Rule/global/direct | How captured business flows choose egress |
| DNS/identity | fake-ip/redir-host/sniff | DNS answer form and evidence, independent of routing |

Rule mode evaluates local/imported/region/scenario policies together. Global mode uses an explicit global group and suspends ordinary scenario/region selection. Direct uses Direct but does not mean stopping capture, DNS or accounting. Authentication, hard security boundaries, resource checks and loop prevention remain; ordinary subscription REJECT rules are bypassed with ordinary routing in global/direct and previews must disclose that effect. Control/bootstrap/probes have explicit scopes. Never silently fall back to direct after a global proxy failure.

Compile modes through one RoutePlan entry, not three executors. Preview changes, validate, apply and show actual generation/receipt. New sessions adopt changes; existing sessions keep their egress. Explicitly closing existing flows is a separate interrupting action. Platform permissions/capabilities govern switches; do not report enabled without host confirmation.

## Regional presets

Use explicit presets such as “mainland direct, others proxy” and its inverse, backed by versioned domain/IP rule sets. Show source/update time; GeoIP is not evidence of the user's location or content-service region. LAN/node/bootstrap bypass is separate. Explicit user rules precede chosen regional defaults with visible ordering; provider refresh cannot rewrite user priority. Unknown/conflicting geography uses declared fallback with reasons. Global/direct shows regional selection suspended. Offer Explain examples before changes.

## DNS answer modes

Fake-IP returns a reserved virtual address mapped to a domain. Redir-host returns real addresses and uses DNS/connection evidence, which may be ambiguous with shared addresses, caches and app-owned DoH. Neither inherently chooses a proxy. See [Mihomo DNS terminology](https://wiki.metacubex.one/config/dns/). These are target modes, not a claim about current config support.

Define dual-stack pool, TTL/capacity/persistence, reverse lookup, exceptions and active-session references. Do not reuse mappings before surviving sessions drain. Missing mappings must fail/recover explicitly, never send virtual addresses to the Internet. Detect range conflicts. Mode changes explain resolver/app caches and retained mappings; clearing state is not seamless migration.

## Domain sniffing

Offer off/on-demand/scoped modes, initially filling missing evidence using supported HTTP Host, TLS ClientHello SNI and QUIC Initial formats. Version/ECH/encryption/deadlines limit detection; no MITM certificate is required for basic metadata sniffing. Preserve evidence sources and conflicts; overriding the destination requires explicit configuration. Untrusted Host/SNI must not redefine authentication boundaries. Bound initial bytes/time and retain original bytes on failure. Sniffing is not process attribution or peer authentication; redact details and avoid default payload/history collection.

## DNS query routing

Separate answer mode, upstream transport (UDP/TCP/DoT/DoH), query egress (direct/group/follow rules), per-domain upstream and bootstrap. Encrypted DNS is not inherently proxied, and fake-IP is not a complete leak solution. Resolve DNS-server names, proxy-node names and business names through explicit non-circular paths. Apply socket bypass. Probe actual resolver/egress/answer mode/time; uncaptured app DoH prevents blanket privacy claims. Reject loops/unsupported candidates or use declared fallbacks without silent system DNS. OS DNS effects use existing transactions/compensation.

## Streaming availability

Present service/observed region/endpoint/method/time, with untested/running/available/restricted/unknown/failed/expired states. HTTP 200 or IP geography does not prove playback. Account/DRM/time restrictions may remain unknown. Do not collect passwords, install certificates or guarantee lasting unlocking. Active checks are scoped, cancellable, rate/traffic-limited ProbeJobs with cache TTL. Optional media-group automatic changes require explicit policy/hysteresis, affect new flows and do not promise seamless playback migration. Probe traffic is distinct from business usage.

## Developer proxy

Presets cover Git HTTPS, GitHub API, release/LFS/download hosts and Git-over-SSH, with maintained/versioned domain lists and redirect limits. SSH application traffic through TUN/validated ProxyCommand is separate from an SSH outbound protocol. Preserve host keys, credentials and end-to-end authentication.

Separate Rillane domain/desktop-process policy, current-terminal environment and Git/SSH snippets. Copy/preview does not change files. Any later write needs exact scope/authority, backup, idempotency, concurrency checking and recovery. Validate platform-specific shells/tools; do not assume nc is installed. SSH need not honor HTTP_PROXY. Optional GitHub SSH on ssh.github.com:443 is still SSH, per [GitHub documentation](https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port); do not rewrite other hosts. Mobile exposes domain presets, not fictional terminal integration.

Connectivity results separate DNS, proxy setup, HTTPS/Git and SSH handshake evidence. Reachability is not a guaranteed clone speedup. AI starts read-only and writes use proposals/rollback.

## States and delivery

Implement empty subscriptions/nodes, denied permission, offline, applying/failed config, stale probes, unknown owners, generation conflicts and overridden policies. Validate keyboard/screen-reader/touch access, themes, text scaling, safe areas and non-color status cues. Images are visual proposals; exact behavior follows this page and IO/Debug contracts. Clients and platform/FFI acceptance remain pending.

### Desktop page model (RIL-148)

The six desktop pages' **data projection layer** now lives in `rillane-app::pages` (pure functions, zero IO, no GUI-framework dependency): `DesktopPage` declares each page's closed operation names (`runtime_stats`/`routing_quality`/`config_audit`/`flow_list`/`flow_trace`/`flow_events`/`flow_svg`/`explain`), and data always goes through the unified app service (RIL-065). Three honesty constraints are structural:

- **Platform capability matrix**: `PlatformCapabilities::with_privilege(os, privilege)` yields per-OS status for all six `CAPABILITY_KINDS`; `CapabilityStatus::is_available` only accepts `Confirmed` — TUN/transparent/DNS capabilities requiring elevation are **not shown enabled** when the privilege state is `Unknown`/`Denied`. Streaming detection (control plane not wired) and host-file writing (persist only on the CLI side) are never `Confirmed` on any platform. Linux `transparent_capture` has an implementation (RIL-139); Windows is `Unsupported` (no nftables surface); macOS surfaces are not wired → `Unknown`.
- **Takeover state follows receipts**: `takeover_state(&/config/receipts)` trusts only the receipt chain — `apply.applied` + `os_applied == true` + `reconcile.agrees` + generation match → `Confirmed`; execution failure / OS not applied / generation mismatch / missing reconcile summary → `Failed`/`Unconfirmed` with the reason named; unreachable audit → `Unknown` (neither "not configured" nor "configured").
- **Stats never fake zero**: `StatValue::{Known,Unknown}` shows absent fields as "unknown"; age beyond `STALE_STATS_SECONDS` (30s) or unreachable data is marked stale. Empty subscription = `subscription_nodes == 0` → `Empty`, distinct from `Unknown`.

The network page (DNS/route-status reads are admin-grade, not promoted into the closed set) and developer page (RIL-147 snippets + write plan) are purely local generation; `DeveloperSnippetView::can_write_files` is always false — the page/service layer does not promise file writes, which require explicit CLI authorization. GUI components themselves await the per-platform client batches.
