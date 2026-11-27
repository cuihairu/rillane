# RIL-044 mobile host secret reference injection face (local verifiable segment, 2026-11-27)

## What is delivered

`crates/rillane-ffi/tests/secret_injection_contract.rs` (4/4 green) pins the
RIL-044 acceptance clause "config/secret reference injection" on its FFI half.
`rillane_ffi_start_with_secrets` (new C export, header + JNI bridge + Kotlin
`startWithSecrets` declaration in the same commit) resolves `${secret:<name>`
references in the config YAML from a JSON secret map before assembly:

- **Injected values really take effect (real RFC1929 round trip)**: a socks5
  ingress whose password is `${secret:ingress_pw}` is started through the
  injection entry; the correct secret value passes RFC1929 user/pass auth and
  completes a byte-exact CONNECT echo round trip through the direct egress,
  while a wrong password and a wrong username are both rejected (status 0x01)
  — proving the injected value is actually compared, not an anonymous pass.
- **Fail-closed, stable codes**: missing reference (`secret.ref.missing`,
  names the reference key), malformed reference — empty name or unterminated
  (`secret.ref.malformed`), invalid map — not an object / non-string values /
  bad JSON / null pointer (`secret.map.invalid`), and template drift in both
  directions (missing key names the ref; stale unused key names
  `secret.map.unused`) all return NULL with a named `last_error`. The same
  config starts successfully once the map is complete (no half-mounted state).
- **Pass-through misuse rejected**: plain `rillane_ffi_start` refuses a config
  that still contains `${secret:` markers instead of silently using the
  literal as a password, and points at the correct entry.
- **Non-recursive by behavior**: a replacement value that itself looks like a
  reference (`"${secret:phantom_ref}"`) is inserted literally — the instance
  starts and authenticates with that literal even though `phantom_ref` is not
  in the map; a second scan would have failed the start.
- **Secrets stay out of diagnostics**: after real traffic, the raw output of
  every query face (stats/routing/nodes/dns_stats/dns_resolvers/flows)
  contains neither the secret value nor the `${secret:` marker.
- **Bridge faces in lockstep**: the JNI symbol parity gate now pins 15
  methods (adds `startWithSecrets` on both the Kotlin and Rust sides), and
  the C header ↔ Rust export parity gate passes with the new declaration.

## Honest boundary

This gate pins the FFI resolution half only. The Kotlin host half — where the
secret values come from (Keystore/EncryptedSharedPreferences), the runtime
discipline that values never reach logs, and a real device run of
`startWithSecrets` — belongs to the RIL-043 device batch and stays open.
Network change notification and bounded diagnostic IPC (the remaining RIL-044
deliverables) are likewise unstarted. The parent checkbox stays unchecked.
