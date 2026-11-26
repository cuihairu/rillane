# Install, recover, Debug and MCP examples

This page aligns operator examples with artifacts that exist in this repository. It is not a new acceptance claim: **build/cross-check ≠ local contract gate ≠ device acceptance**. Check [platform support](platform-support.md) and the [acceptance evidence index](acceptance-evidence/README.md) for the current status of each platform. Commands below use the real CLI/daemon/MCP flag surfaces; a named gap stays a gap.

## Three tiers before running anything

- **Artifact tier** — `cargo build`, cross builds, file/layout checks and contract tests. These prove a binary or template exists, not that it forwards traffic on a host.
- **Local gate tier** — `cargo test --workspace`, including REST/help/schema contract gates against the real binaries. These prove documentation faces and machine ledgers agree, not that a device accepted the flow.
- **Device tier** — install, capture/identity, restart and traffic on the target OS or router. Only device evidence documents can close this tier.

## Install and recover by host

### Local source run (Linux development host)

```bash
cargo run -p rillaned                       # reads RILLANE_CONFIG, default config/rillane.yaml
cargo run -p rillanectl -- --help           # -c/--config selects the CLI config file
cargo run -p rillanectl -- stats            # needs a running control plane
```

`rillaned` has no `--config` flag. To use another file, set the environment variable:

```bash
RILLANE_CONFIG=/etc/rillane/rillane.yaml rillaned
rillanectl -c /etc/rillane/rillane.yaml stats
```

Recovery is a process restart; config is read once at startup. There is no `rillanectl reload` and no file watch/SIGHUP reload in the current daemon.

### Linux systemd + deb package

Template and verification layers live in `platforms/systemd/README.md`. The package installs the unit but **only enables it; it does not start the service**.

```bash
platforms/systemd/build.sh                  # produces dist/deb/rillane_<version>_<arch>.deb
sudo dpkg -i rillane_0.1.0-1_amd64.deb
sudo install -m644 /etc/rillane/rillane.yaml.example /etc/rillane/rillane.yaml
sudoedit /etc/rillane/rillane.yaml          # set admin_token before exposing the control plane
sudo systemctl start rillane
journalctl -u rillane -f
```

Recover with `sudo systemctl status rillane` / `sudo systemctl restart rillane`; the unit sets `Environment=RILLANE_CONFIG=/etc/rillane/rillane.yaml` and `Restart=on-failure`. Pure-proxy deployments should narrow `CAP_NET_ADMIN` via `systemctl edit rillane`. `dpkg -i` with postinst/systemd interaction is a named device-tier gap on this machine.

### macOS launchd

`platforms/launchd/build.sh` **must run on macOS** (universal2 via `lipo`); this Linux host only checks script/plist structure.

```bash
platforms/launchd/build.sh
tar -xzf dist/launchd/rillane_0.1.0_macos_universal2.tar.gz
cd rillane-0.1.0-macos-universal2
sudo ./install.sh
launchctl print system/com.rillane.rillaned
```

Recover with `sudo ./install.sh` (idempotent config handling) or remove with `sudo ./uninstall.sh` / `sudo ./uninstall.sh --purge`. The plist injects `RILLANE_CONFIG=/usr/local/etc/rillane/rillane.yaml`; macOS has no `network.tun` block in the shipped template. tar production, `launchctl bootstrap/kickstart` and universal2 runtime remain device-tier gaps.

### Windows service script

`platforms/windows/build.sh` cross-builds the zip on Linux. On Windows, unpack and run PowerShell as administrator:

```powershell
.\install-service.ps1 -InstallDir "C:\ProgramData\rillane" -ConfigPath "C:\ProgramData\rillane\rillane.yaml"
```

The scripts take `-InstallDir` / `-ConfigPath` and `-RemoveConfig` (uninstall); `RILLANE_CONFIG` is injected through the registry because `sc.exe` has no environment parameter. **Known defect**: `sc.exe start rillane` hits SCM error 1053 because `rillaned` does not implement the SCM control protocol; `windows-service` integration or an external wrapper is future work. PE artifacts and zip layout are checked locally; service start and runtime are not.

### OpenWrt ipk

`platforms/openwrt/build.sh` builds musl targets (see its matrix for the supported architectures; mips/mipsel are not currently buildable).

```sh
scp dist/openwrt/rillane_*_<arch>.ipk root@router:/tmp/
ssh root@router opkg install /tmp/rillane_*.ipk
ssh root@router /etc/init.d/rillane enable && ssh root@router /etc/init.d/rillane start
```

The init script injects `RILLANE_CONFIG=/etc/rillane.yaml` through procd and respawns the daemon. Transparent capture needs `network.transparent.rule_backend: nft` on fw4-era OpenWrt. opkg upgrade/conffile behavior, respawn and nft takeover/undo need a router batch; cross-built ipks are not device acceptance.

### Android and iOS boundaries

```sh
platforms/android/build.sh
adb install -r platforms/android/app/build/outputs/apk/debug/app-debug.apk
adb shell appops set com.rillane.rillane ACTIVATE_VPN allow   # automation only
adb shell ping -c 3 10.111.0.1                               # TUN -> Rust echo -> kernel
```

Android has an AVD API 33 echo-round-trip record; real-device consent/UI and TCP/UDP proxy forwarding are not delivered. iOS has Swift/Provider source and `platforms/ios/build.sh` for macOS, but no Xcode build or device run; Network Extension needs a signed entitlement. Do not read either example as full mobile forwarding.

## Debug examples

Run the daemon with a config whose control plane is reachable from `rillanectl` (`-c` points at the same file). All four faces below are implemented commands; their absence codes and redaction behavior are part of the CLI contract, not a promise that every platform flow has been traced.

### diagnose — collect a reviewable bundle

```bash
rillanectl diagnose --scope safe --output ./rillane-diagnose-safe
rillanectl diagnose --scope full --output ./rillane-diagnose-full --no-local
```

`safe` (default) omits subscriptions, runtime config and full logs; `full` still strips secrets; `raw` / `--no-redact` writes unredacted data and must stay local (`ai_upload_policy: do-not-upload`). rillanectl never uploads a bundle. Inspect `meta.json` before sharing.

### trace — real connections, explicit absence

```bash
rillanectl trace list --state closed --limit 20 --json
rillanectl trace flow <flow-id> --json
rillanectl trace flow <flow-id> --svg
rillanectl trace events <flow-id> --from-seq 0 --limit 200
rillanectl trace inspect <flow-id>
```

Use a real `FlowId`; `/flows` aggregate keys never resolve as flow IDs. Exit `0` = answered, `1` = usage/connection error, `2` = explicit absence (`query.flow.unknown`, `collector.flow.*`, `query.tracing.disabled`). No record is not evidence of no traffic. Trace reads carry detailed identity; when `admin_token` is set they are permission-gated.

### explain — pure replay

```bash
rillanectl explain example.com --port 443 --proto tcp --domain-source user_provided --json
rillanectl explain example.com --port 443 --proto tcp --generation <generation> --annotation role=game
```

No DNS, dial or OS identity query; missing evidence is listed gap-by-gap and conditional conclusions are marked as such. Invalid `--proto` / `--domain-source` is rejected before a request is sent.

### probe — explicit network side effects

```bash
rillanectl probe list --json
rillanectl probe submit --kind connect --addr 203.0.113.1:443 --json
rillanectl probe result <job-id> --json
rillanectl probe cancel <job-id>
```

Targets must be registered in the daemon's `probe.targets`; absence of a `probe` block returns `503 probe.disabled`. Measurements are what the executor observed (`rtt_ms` stays null when nothing answered), never provider-internal path claims. `probe result` on an unknown ID exits `2`.

## Optional MCP stdio adapter

The adapter is off by default: no listener port, no background process. Start it explicitly; stdout carries one JSON-RPC message per line and logs go to stderr. It follows the frozen modern-era revision `2026-07-28` (per-request `_meta` version, `server/discover`, no legacy `initialize` handshake).

```bash
cargo build -p rillane-mcp -p rillaned -p rillanectl
rillane-mcp --config config/rillane.yaml --scope read --rate-limit 60
rillane-mcp --endpoint http://127.0.0.1:9090 --token "$RILLANE_ADMIN_TOKEN" --scope read,detailed,probe --rate-limit 0
```

Flags come from the real binary: `--config/-c`, `--endpoint`, `--token`, `--scope`, `--rate-limit`, `-h/--help`. Scopes are `read`, `detailed`, `probe`, `write` (comma-separated; default `read`); `--rate-limit 0` disables the per-minute window. Authorization comes only from startup flags — request-declared `scope`/`granted` fields cannot escalate, and denied calls answer `-32001 mcp.scope.denied` without executing. Credentials stay in the executor and never appear in replies or logs.

A read-only session discovers and calls tools like this (one line per message on stdin):

```json
{"jsonrpc":"2.0","id":1,"method":"server/discover"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"runtime_stats","arguments":{}}}
```

The catalog has 16 tools from the frozen `rillane-app` boundary: `runtime_stats`, `routing_quality`, `flow_list`, `flow_trace`, `flow_events`, `flow_svg`, `explain`, `probe_list`, `probe_submit`, `probe_cancel`, `probe_result`, `validate_config`, `preview_config_change`, `apply_config_change`, `rollback_config`, `config_audit`. Write tools require `write` scope and real operator-issued proposal/approval IDs; the MCP adapter never self-approves. EOF exits cleanly and releases outstanding probe jobs.

The official SDK interoperability driver is in `apps/rillane-mcp/sdk-acceptance/` (fixed `@modelcontextprotocol/sdk@1.32.2`, 12 scenarios, zero models):

```sh
cd apps/rillane-mcp/sdk-acceptance
npm install
CARGO_TARGET_DIR=<your target dir> node accept.cjs
```

Read `EVIDENCE.md` there for exact passing/failing faces; an SDK acceptance run is a local contract gate, not device approval. Full platform status remains in [platform support](platform-support.md) and the [acceptance evidence index](acceptance-evidence/README.md).
