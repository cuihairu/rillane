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
