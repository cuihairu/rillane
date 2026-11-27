# RIL-042 OpenWrt ipk structure (first segment, 2026-11-27)

Gate: `crates/rillane-platform/tests/openwrt_ipk_contract.rs` (2 tests).
It unpacks a real built package — `dist/openwrt/rillane_0.1.0-1_x86_64.ipk` —
with `ar x` + `tar -xzf` and asserts the structure that `platforms/openwrt/build.sh`
claims. When no `dist/openwrt/*.ipk` exists (clean CI checkout), the test prints
a skip line instead of pretending to have run; it never fabricates a pass.

## Facts pinned against the real package

1. `ar` members: `debian-binary` == `2.0`, plus `control.tar.gz` and `data.tar.gz`;
   both tarballs extract without error.
2. `control`: `Package: rillane`, `Version: 0.1.0-1`, `Depends: libc, kmod-tun`,
   `Architecture: x86_64`, `Section: net`, `Maintainer:`, `Installed-Size:`,
   `Description:`.
3. `conffiles` declares exactly `/etc/rillane.yaml` (the upgrade-preserved face).
4. `postinst` is idempotent on first install
   (`[ -f /etc/rillane.yaml ] || cp`) and enables autostart
   (`/etc/init.d/rillane enable`).
5. `data`: `usr/bin/rillaned`, `usr/bin/rillanectl`, `etc/init.d/rillane`,
   `usr/share/rillane/rillane.yaml.example`.
6. `init.d` procd contract: `USE_PROCD=1`, `START=99`, `STOP=10`, `start_service`,
   `procd_open_instance`, `procd_set_param command "$PROG"`, env
   `RILLANE_CONFIG="$CONF"`, `respawn`, `stdout 1`, `stderr 1`,
   `limits core="0 0"`, `procd_close_instance`, `config_load rillane` +
   `config_get enabled`, and a config-existence guard
   (`[ -f "$CONF" ]`) so a missing config never silently starts the service.
7. The packaged `init.d` is byte-identical (trimmed) to
   `platforms/openwrt/init.d/rillane` — assembly drift fails the gate.

## Executed ops semantics (second segment)

`postinst` and `init.d` run for real under `sh` in a temp root: platform
proprietary commands (`logger`, `config_get`, `procd_*`) are replaced by stubs
that record their calls; the branches themselves are the packaged script's own.
Pinned:

1. `postinst` first install drops the example config at `/etc/rillane.yaml`;
   running it again after an operator edits the config **does not overwrite**
   the edit (upgrade conffile preservation at the script level).
2. `init.d start_service` with `enabled=0` produces zero procd events.
3. With `enabled=1` (and no `config_load` state, as on first boot) it starts:
   `config_get` asked for the enabled value, `procd_open_instance` /
   `procd_close_instance` wrap `command "$PROG"`, `env RILLANE_CONFIG=...`,
   `respawn 3600 5 0`, `stdout 1`, `stderr 1`, `limits core=0 0`.
4. Missing config → named refusal (exit 1, log line), zero procd events.
5. `reload_service` = `stop` then `start`, recorded in that exact order.

The script is only path-localized to the temp root (absolute paths
`/etc/...`, `/usr/...` rewritten to the sandbox); no branch or parameter is
re-written into a test-only simulation.

## Small-profile runtime smoke (third segment)

`RILLANE_SMALL_SMOKE_BIN=<path> cargo test -p rillane-platform --test openwrt_ipk_contract small_profile_daemon_serves_control_and_socks`
starts a `--no-default-features --features small` `rillaned` with the OpenWrt
template minus its `network` block, on ephemeral loopback ports. It waits for
both the control plane and the SOCKS5 ingress, performs a raw HTTP
`GET /config/state` with the template token, and then a real SOCKS5 CONNECT
through the ingress to the control plane, asserting an HTTP response comes
back through the forwarder. The binary path is supplied by env because the
test harness cannot recursively `cargo build`; without it the test prints a
skip instead of fabricating a pass. Build the binary first:

```sh
cargo build --release -p rillaned --no-default-features --features small
RILLANE_SMALL_SMOKE_BIN=target/release/rillaned \
  cargo test -p rillane-platform --test openwrt_ipk_contract
```

Boundary: this is a **native small-profile** runtime check, not the cross-built
musl ipk and not a router. RSS/CPU/throughput ceilings on target hardware
remain unmeasured in the OpenWrt device batch.

## Reproduce

```sh
bash platforms/openwrt/build.sh          # produces dist/openwrt/*.ipk
cargo test -p rillane-platform --test openwrt_ipk_contract
```

## Honest boundary

This is a **package-structure contract**, not device acceptance. Still unrun:
real `opkg install`/upgrade semantics on a router, procd-managed start/stop and
respawn, kmod-tun data plane, nftables rule application/withdrawal under fw4,
and measured RSS/CPU/throughput limits. Those stay in the OpenWrt device batch;
the RIL-042 checkbox remains open. The gate also does not assert static linking
of the binaries (the build log records `file`/`readelf` only).
