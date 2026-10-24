# P3-3 Platform Packaging (systemd / launchd / Windows Service templates) -- implementation-level design

> Upstream: [roadmap.md](roadmap.md) original section 6 (platform adaptation) | [todo.md](../../todo.md) P3-3
> Precedent: [platforms/openwrt/](https://github.com/cuihairu/seep/tree/main/platforms/openwrt/) (the half landed 2026-10-02: musl static cross + ipk + procd init.d; its build-pipeline conventions and
> validation tiers are the reuse baseline for this document).
> This document is the landing finalization: **the three platforms' artifact shapes, validation tiers (template validation != real-machine validation, honestly recorded tier by tier),
> unit/plist/service script contents, the deb/zip/tar packaging build pipeline, boundary recording**. Deviations are backfilled into section 9 after landing.

## 0. Scope

| In this item | Deferred to other items |
|-----------|-----------|
| `platforms/systemd/`: the `seep.service` unit + the deb assembly pipeline (seepd/seepctl + conffile + postinst/prerm) + config example | P3-5 zero-copy (landed 2026-10, decoupled from the packaging pipeline, see performance-io.md); libloading direct dynamic library crash isolation (V2, per the P3-2 ruling) |
| `platforms/launchd/`: `com.seep.seepd.plist` + a macOS-native build.sh (universal2) + install.sh (script-level, structurally verifiable) | Cross-compiled darwin Mach-O (Apple SDK redistribution limits, same CI exclusion stance; waiting for a macOS runner to run natively) |
| `platforms/windows/`: the cross windows-gnu pipeline + a zip delivery package + `install-service.ps1`/`uninstall-service.ps1` (sc.exe template-level) | Real Windows SCM protocol integration (the `windows-service` crate letting seepd self-report SERVICE_RUNNING -- deferred to a later increment, section 3.3) |
| Backfilling the `platforms/README.md` matrix + a note checking off todo P3-3 | CI matrix changes (packaging scripts are release tooling, verified locally; the windows-gnu build is already in CI) |

**Acceptance criteria preamble (aligned with the P1-4 explicit-rewrite practice, no silent watering down)**: the todo P3-3 acceptance is "produce installable binaries for Linux/macOS/Windows; OpenWrt
ships a musl static package" -- the OpenWrt half is landed (2026-10-02, three ipks + three targets all smoke-passed). The verifiable criteria for the three halves this round:

1. **Linux**: the full deb chain is verifiable on this machine -- native amd64 build -> dpkg-deb assembly -> `dpkg-deb -I/-c` structural verification -> `dpkg -x` extraction -> run `seepd --version`
   directly on the extracted layout; aarch64 cross packaging + qemu-user smoke (reusing the OpenWrt precedent).
2. **Windows**: cross windows-gnu artifacts (CI has already proven aws-lc-sys compiles on that target) -> PE header static verification -> zip layout assertions; **real-machine service install/start
   is outside this machine's capability** (honestly recorded in section 3.3).
3. **macOS**: script and plist structural validation (`bash -n` + python3 plistlib); **no Mach-O artifact is produced on this machine** (the same limit as the CI darwin exclusion), recorded as
   "script-level delivery, artifacts pending a native environment".

"Installable" takes the strictest reading on the Linux side (a real deb that can be extracted and run); Windows/macOS take the delivery-package-completeness reading, with the real-machine install
surface deferred.

## 1. Current state and constraints (verified conclusions, not a restatement)

### 1.1 seepd CLI shape -> all templates inject via environment variables

- No clap: `--version`/`-V` short-circuits on `args[1]` at `apps/seepd/src/main.rs:13` (before config load), and `--help` actually starts up (reporting an mTLS requirement error) -- **packaging script
  smoke may only use `--version`, never `--help`**;
- The only entry to the config path is the `SEEP_CONFIG` environment variable (`main.rs:46`, default relative path `config/seep.yaml`), and **there is no `--config` flag**. systemd injects with
  `Environment=`, launchd with `EnvironmentVariables`, and the Windows service with the registry `Environment` key (section 3.2) -- the same stance as OpenWrt init.d (`procd_set_param env`) and the
  root Dockerfile.

### 1.2 Certificate directory convention

`seep-config`'s `config_dir()` is `/etc/seep` -- the Linux layout uses `/etc/seep/seep.yaml` as the conffile, binaries at `/usr/bin/{seepd,seepctl}`, and the unit at `/lib/systemd/system/seep.service`
(usr-merge paths).

### 1.3 CI facts

windows-gnu is in the cross-compile matrix and green (the aws-lc-sys 0.45 build script really compiled on that target); darwin is explicitly excluded (Apple SDK license + no official darwin cross
image, note in ci.yml). Local tooling surface: cross 0.2.5, dpkg-deb, ar, file, readelf, qemu-user (aarch64/armv7 precedent) all present; rustup targets installed for all three platforms.

### 1.4 OpenWrt pipeline conventions (reused item by item)

`env -u CARGO_TARGET_DIR` (the worktree-private target convention, avoiding shared ghost errors) | `CARGO_PROFILE_RELEASE_STRIP=symbols` | file/readelf static verification written into
`.build-log.txt` | mktemp -d stage + trap cleanup | ar three-member assembly (deb uses dpkg-deb instead, likewise rootless assembly).

## 2. Linux: systemd unit + deb pipeline

### 2.1 `platforms/systemd/seep.service`

```ini
[Unit]
Description=SEEP smart egress proxy daemon
Documentation=https://github.com/cuihairu/seep
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=seep
Group=seep
# seepd has no --config flag (section 1.1): config path injected via environment variable
Environment=SEEP_CONFIG=/etc/seep/seep.yaml
ExecStart=/usr/bin/seepd
Restart=on-failure
RestartSec=5
# Least-privilege surface: low-port binding (entry 0-1023) + TUN device creation (P1-2 landed)
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictRealtime=yes
# Note: MemoryDenyWriteExecute=yes is not set -- the wasmtime JIT (P3-2 plugin surface) needs
# W->X mapped code pages, and that flag would make plugin load/instantiate fail (section 6 boundary).
# Note: SystemCallFilter is not set -- too tight easily misfires on the aws-lc-sys/io_uring surface; hardening tightening is deferred.

[Install]
WantedBy=multi-user.target
```

Three rulings:

1. **`CAP_NET_ADMIN` enters the bounding/ambient set**: the TUN surface (P1-2 landed) must create/configure `seep0`; a pure socks ingress deployment can narrow it to only `CAP_NET_BIND_SERVICE` in a
   drop-in (`systemctl edit seep`) -- the unit ships full-featured by default, and the README notes how to narrow it.
2. **`Type=simple` + `Restart=on-failure`**: seepd runs in the foreground (same stance as OpenWrt procd); crash backoff 5s.
3. **Creating the user belongs to postinst** (`getent`/`useradd --system`), and the unit only references it -- the unit file itself stays purely copyable.

### 2.2 deb layout and maintenance scripts

```
/usr/bin/seepd                  0755
/usr/bin/seepctl                0755
/etc/seep/seep.yaml.example     0644   (example; the real config is placed by the deployer, avoiding overwrite)
/lib/systemd/system/seep.service 0644
DEBIAN/control                          Package: seep; Version: 0.1.0-1; Architecture: amd64|arm64
DEBIAN/conffiles                        /etc/seep/seep.yaml.example (the example file registered as conffile)
DEBIAN/postinst                         create the system user seep -> chown /etc/seep -> daemon-reload -> enable (not start)
DEBIAN/prerm                            stop + disable (config preserved)
```

Rulings:

- **The package ships only `seep.yaml.example`, not the real config**: auto-starting the service on install is not this package's policy (the config holds tokens/upstream credentials and must be
  placed explicitly by the deployer); `conffiles` registers **the example file itself** (the real config is `cp`-ed by the deployer from the example and is not under package jurisdiction). [*] At
  design time the plan was to register the absent real-config path, but newer `dpkg-deb --build` strictly validates that a conffile must be inside the package data and rejects it -- see section 9 for
  the deviation. postinst only enables, never starts -- "run right after install" is left to the deployer's `systemctl start seep`, avoiding repeated-restart spam in a no-config state.
- **Architecture mapping**: `x86_64` -> `amd64`, `aarch64` -> `arm64` (the Debian triplet stance).
- **Rootless assembly**: `dpkg-deb --build --root-owner-group` (fakeroot semantics built in), rootless assembly like the OpenWrt ar path.
- **Depends left empty**: the gnu targets dynamically link libc6 with no hardcoded version constraint (wider tolerance for older Debian releases); kernel module dependencies such as kmod-tun are
  OpenWrt ipk semantics, and on the deb side Recommends defaults to undeclared, with the README noting that TUN requires the kernel's `/dev/net/tun`.

### 2.3 build.sh validation chain (traces written to `.build-log.txt`, same convention as OpenWrt)

Per target: cross/native build -> file ELF verification -> dpkg-deb assembly -> `dpkg-deb -I` (control-surface assertions) + `dpkg-deb -c` (layout assertions: four artifacts + DEBIAN scripts present)
-> `dpkg -x` extraction -> run `usr/bin/seepd --version` on the extracted layout expecting `seepd 0.1.0` (native runs directly; aarch64 via `qemu-aarch64 -L /usr/aarch64-linux-gnu`). Real-machine
systemd enable/start is outside this machine's capability (no systemd privilege surface), recorded in section 6.

## 3. Windows: cross pipeline + service script templates

### 3.1 Delivery shape

`cross build --release --target x86_64-pc-windows-gnu` (the same target as CI) -> artifacts `seepd.exe`/`seepctl.exe` -> zip delivery package:

```
seep_0.1.0_x86_64_windows.zip
  |-- seepd.exe                PE32+ x86-64 (file verification)
  |-- seepctl.exe
  |-- seep.yaml.example
  |-- install-service.ps1
  |-- uninstall-service.ps1
  `-- README.txt               install/boundary quick reference (points to platforms/windows/README.md in the repo)
```

### 3.2 `install-service.ps1` (sc.exe template-level)

- `sc.exe create seep binPath= "<install dir>\seepd.exe" start= auto DisplayName= "SEEP Proxy"` + `sc.exe failure seep reset= 86400 actions= restart/5000/restart/5000/restart/30000` (three-stage crash
  recovery backoff, the counterpart of systemd's `Restart=on-failure`);
- The config path injection goes through the **service-level registry Environment**: `New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\seep -Name Environment -PropertyType MultiString
  -Value "SEEP_CONFIG=C:\ProgramData\seep\seep.yaml"` -- `sc.exe` has no environment parameter surface (same cause as section 1.1);
- `New-Service` would also work, but failure recovery must still be set via `sc.exe failure`, so using sc.exe throughout is consistently simpler.

### 3.3 SCM 1053 caveat (why this round is template-level, honestly recorded)

seepd is an ordinary console program and **does not talk to the SCM** (it does not call `StartServiceCtrlDispatcher` and does not report SERVICE_RUNNING): `sc.exe create` can succeed and the service
entry can be configured, but `sc.exe start seep` is judged **error 1053** by the SCM within 30 seconds (the service failed to respond to the start request in time) and stopped -- the SCM requires the
service process to attach to the control pipe immediately on startup. Both proper fixes are deferred:

1. **the `windows-service` crate** lets seepd natively implement the SCM protocol (a windows-target-specific main branch) -- recorded as a later increment;
2. **an external wrapper** WinSW/NSSM (wrapping any exe as an SCM service) -- noted in the README, a deploy-side choice, not committed to the repo.

What this script can verify locally: PowerShell syntax structure, zip layout, PE header; real `sc.exe` behavior needs Windows, recorded as a boundary.

## 4. macOS: launchd plist + native pipeline (script-level)

### 4.1 Delivery shape

`platforms/launchd/build.sh` **is designed to run natively on macOS**: `cargo build --release` x (aarch64-apple-darwin, x86_64-apple-darwin) -> `lipo -create` universal2 -> tar.gz:

```
seep_0.1.0_macos_universal2.tar.gz
  |-- seepd                    Mach-O universal2 (lipo -info verification)
  |-- seepctl
  |-- com.seep.seepd.plist
  |-- install.sh
  |-- uninstall.sh
  `-- seep.yaml.example
```

**Validation tiers on this machine (Linux)**: `bash -n` syntax verification + plist structural validation (python3 `plistlib` parsing + key assertions). No Mach-O artifact on this machine (section 0
criterion 3); the cargo/lipo invocation surface in build.sh is delivered by script review + syntax verification, with a real run pending macOS.

### 4.2 `com.seep.seepd.plist` (LaunchDaemon surface)

- `Label=com.seep.seepd`; `ProgramArguments=(/usr/local/bin/seepd)`;
- `EnvironmentVariables={SEEP_CONFIG: /usr/local/etc/seep/seep.yaml}` (same cause as section 1.1; the macOS-side config convention is `/usr/local/etc/seep/`, and forking from Linux's `/etc/seep` is a
  deliberate choice -- the Homebrew convention path);
- `RunAtLoad=true` + `KeepAlive={SuccessfulExit=false}` (only abnormal exits restart it, matching the `Restart=on-failure` semantics; a clean exit triggered by `seepctl` is not contested) +
  `ThrottleInterval=5`;
- `StandardOutPath`/`StandardErrorPath=/usr/local/var/log/seepd.log`; `ProcessType=Background`;
- Loading: `sudo launchctl bootstrap system <plist>` (macOS 10.11+ deprecated the old `-w load` syntax) + `launchctl kickstart system/com.seep.seepd`.

## 5. Test strategy and validation landing points

Tiered criteria (the "template test landing points" are this section -- who verifies which tier, and reports follow this):

| Tier | Content | Landing point | Status this round |
|---|---|---|---|
| L1 script structure | `bash -n` on all build.sh/install scripts; plistlib parses the plist + key assertions; ps1 syntax structure review | local Linux | **all run** |
| L2 artifact static verification | file (ELF x86-64/ARM aarch64, PE32+ x86-64) + readelf (the musl side was on the OpenWrt path; this round's gnu side checks the interpreter) + zip/deb layout assertions | local Linux | **all run** (linux amd64/arm64 + windows, three sides) |
| L3 runtime smoke | `seepd --version` on the extracted layout; native direct run + aarch64 qemu-user | local Linux | **all run** (amd64 native + arm64 qemu) |
| L4 real platform surface | real-machine systemd enable/start, launchctl load, SCM real start | requires the corresponding platform | **boundary recorded** (section 6) |

Unit-test surface: this round has zero Rust source changes (pure templates/scripts/docs), and `cargo test --workspace` is still run as a regression gate; all script-side assertions are inlined in
build.sh (not a test framework) -- the same approach as the OpenWrt build.sh (`.build-log.txt` for post-hoc audit).

## 6. Boundary recording (no silent watering down)

1. **darwin cross production is not done**: Apple SDK redistribution limits (same stance as the CI darwin exclusion); the macOS half = script-level delivery + plist structural validation, with real
   Mach-O production and launchctl install pending a macOS runner/real machine.
2. **Real Windows SCM service-ification is deferred**: `windows-service` crate integration (section 3.3); this round's zip + sc.exe templates can be assembled and configured, but `sc start` is limited
   by 1053; WinSW/NSSM are noted in the README.
3. **`MemoryDenyWriteExecute` conflicts with wasmtime JIT**: the unit deliberately omits that flag (section 2.1 note); if a deployment narrows and enables it, the plugin surface (P3-2) fails -- two
   genuine constraints, left to the deployer's decision.
4. **`SystemCallFilter` is not set**: too tight easily misfires on the aws-lc-sys syscall surface; hardening tightening (including a file-based seccomp profile) is deferred.
5. **CAP_NET_ADMIN granted by default**: the full-featured TUN stance; a pure proxy deployment should narrow it via a drop-in (the README gives how).
6. **The CI matrix is untouched**: packaging scripts are release tooling, verified locally; the windows-gnu build is already guarded in CI.
7. **P3-5 zero-copy landed (2026-10, decoupled from the packaging pipeline); libloading crash isolation deferred to V2** (the ruling explicitly leaves it alone).

## 7. Step-by-step checklist

- **R0**: this design document.
- **R1**: `platforms/systemd/` (seep.service + the build.sh deb pipeline + seep.yaml.example + README) + practice L1-L3 (amd64 native full chain + arm64 cross+qemu).
- **R2**: `platforms/windows/` (the build.sh zip pipeline + ps1 x2 + README) + `platforms/launchd/` (build.sh + plist + install/uninstall.sh + README) + practice L1-L2 (windows full chain + macos
  script/plist surface).
- **R3**: backfill the platforms/README.md matrix + a note checking off todo P3-3 + all gates (fmt/clippy/test) -> commit (citing this document's sections) -> fetch+rebase -> push -> report (template
  list + test landing points).

## 9. Landing deviation backfill (2026-10-04 implementation closed out)

1. **Registering an absent path in conffiles was rejected** (the section 2.2 deviation): newer `dpkg-deb --build` strictly validates that a conffile must be inside the package data, and registering
   `/etc/seep/seep.yaml` (not shipped in the package) reports `conffile does not appear in package` -- changed to register the actually-present `/etc/seep/seep.yaml.example`, semantically equivalent
   (the example file is not overwritten on upgrade, and the real config copied from the example is naturally not under package jurisdiction). The section 2.2 body text was rewritten to match.
2. **windows-gnu compilation broken (predating this round, fixed with this round)**: when P1-2 TUN landed, the `seep_platform::network::linux` import in `seep-runtime/src/tun_ingress.rs` was ungated,
   and x86_64-pc-windows-gnu failed with E0432 (CI's Cross compile windows leg red for several rounds). The fix is orthogonal to the section 5 tiers: the three TUN modules (tun_ingress / tun_process /
   tun_tcp) are wholesale `#[cfg(target_os = "linux")]`; runtime_builder assembly/fields/stop/getter are dual-versioned (non-Linux: configuring TUN is an explicit Err, unconfigured is always None, the
   same stance as the four network factories); `TunIngressStats` is an independent platform-agnostic module `tun_stats.rs` (the control-plane `seep_tun_*` always-rendered stance in section 2.8 is
   unchanged); the three control_plane route endpoints are always 503 on non-Linux (the same semantics as the TUN-not-assembled branch). windows-gnu `cross check --all-targets` is warning-free after
   the fix.
3. **file output wording drift** (the section 2.3/3.1 deviation): the native gnu artifact is `ELF 64-bit LSB pie executable` (the original assertion `LSB executable` did not match); file reports
   `PE32+ executable for MS Windows 5.02 (console), x86-64` for PE (word order and phrasing drift with the file version) -- all static verifications changed to **broad assertion splitting** (`ELF
   64-bit LSB` + the architecture substring / `PE32+ executable` + `x86-64`).
4. **`grep -q` assertions misfire in pipefail scripts** (a pipeline lesson): in `cmd | tee | grep -q` / `dpkg-deb -c | grep -q` combinations, `-q` exits on the first match, the upstream process gets
   SIGPIPE (tee dies, dpkg-deb reports `tar subprocess was killed by signal (Broken pipe)`), and under `set -euo pipefail` the whole chain returns 141/non-zero -- a false failure unrelated to the
   assertion content. Root fix: assertion greps drop `-q` in favor of `> /dev/null` (full read), unified across the three pipeline scripts.
5. **XML comments cannot contain `--`** (the section 4.2 lesson): writing `--config` in the plist header comment made expat parse it as `not well-formed` -- caught on the spot by the plistlib
   structural assertions (L1); the wording changed to "no config command-line flag".
6. **Practice data**: the deb `seep_0.1.0-1_{amd64,arm64}.deb` dual output -- `dpkg-deb -I/-c` layout assertions (four artifacts + control/conffiles/postinst/prerm) + `dpkg-deb -x` extracted-layout
   `seepd 0.1.0` smoke (amd64 native + arm64 `qemu-aarch64 -L /usr/aarch64-linux-gnu`) all passed, traces in `.build-log.txt`; the windows zip `seep_0.1.0_x86_64_windows.zip` (six entries, seepd.exe
   38.9MB / seepctl.exe 15.0MB, PE32+ x86-64) layout assertions passed; launchd L1 (bash -n x3 + plistlib key assertions) passed. Gates: `cargo fmt --check` + `clippy --workspace --all-targets
   --all-features` warning-free + `cargo test --workspace` 261 tests, 0 failed, all green.
