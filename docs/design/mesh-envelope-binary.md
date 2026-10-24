# P2-6 Mesh TCP envelope binarization (design draft)

> 2026-10-02 ready; **M0-M1 landed** (the same commit, a one-shot TCP-side switch + dual-format
> sniffing on the receiver). Positioning basis: todo P2-6 "mesh envelope binarization";
> `udp-mesh-dataplane.md` §2 (the UDP-side binary frame format) and the closing section "P2-6 directly
> adopts this format as the unified protocol v2; when the TCP side migrates, the UDP side is already in
> that format". The UDP-side `UdpEnvelope` has been binary since P0-4; this item swaps the serialization
> of the **TCP side** `MeshEnvelope` from JSON to a binary header (reusing the same style of layout),
> lowering the per-flow fixed overhead.

## 0. Measurable wording

1. **Frame form**: the frame body produced by `write_envelope` starts with the magic `'S''U'` + ver=2,
   no longer JSON text (starting with `{`); the binary decode roundtrip restores all fields (golden).
2. **Degraded receive**: an old JSON frame (first byte `{`) can still be parsed by
   `decode_envelope_payload` on the existing path (P1-4 pad/strip semantics unchanged); within a
   mixed-deployment upgrade window, this side can read old frames, while the old side cannot read this
   side's frames (fail-stop; a connection error = failover, not a silent mis-forward).
3. **Padding coexistence**: P1-4's `pad_len` enters the binary header (the `pad_len(4)` field); a
   padded frame = binary header + K x 0x00; the strip check (pad_len == the number of trailing 0x00)
   and the version gate (padding requires version >= 2) keep the same semantics as in the JSON era.

## 1. Current state

- The TCP-side `MeshEnvelope{version, flow_id, target_host, target_port, path, pad_len}`
  is serialized with `serde_json` into a `[len:u32][payload]` frame (`write_envelope` /
  `read_envelope`); each hop strips its own in `dial_and_tunnel` and re-encodes.
- P1-4 layered trailing 0x00 padding + a `pad_len` field on that JSON (the version=2 gate).
- The UDP side already has the binary `UdpEnvelope` (`UDP_ENVELOPE_VERSION=1`); the two codecs
  coexist in the same file `mesh_transport.rs`.

## 2. Rulings

- **D-1 dual-format sniffing on the receiver**: first frame byte `{` (0x7B) -> the old JSON path;
  otherwise the frame must start with the `'S''U'` magic and ver must be 2 -> the binary path. The
  sender sends binary only.
- **D-2 header layout** (big endian, the same style as UDP §2):

```
offset  field
0     magic(2) = 'S''U'
2     ver(1)   = 2 (binary TCP envelope; 1 reserved = old JSON, receive only, never send)
3     flags(1) : bit0..7 reserved, must be 0
4     version(4, BE)  the P1-4 padding capability gate (1 = normal / 2 = padded), the original env.version
8     flow_id_len(1) + flow_id bytes (the raw string, non-empty, <= 255)
...   host_len(1) + host bytes (domain/v4/v6 stringified, the same semantics as JSON)
...   target_port(2, BE)
...   hop_count(1) + node_id x hop_count (each item is len(1)+bytes)
...   pad_len(4, BE) (the P1-4 padding declaration; 0 = no padding)
...   [pad]    K x 0x00 (K == pad_len)
```

- **D-3 the `env.version` semantics are kept**: the binary header explicitly carries the original
  version field (the P1-4 gate is inherited: a padded frame has version=2, an unpadded one version=1);
  the structural ver=2 means "binary encoding v2", orthogonal to env.version and not mixed with it.
- **D-4 validation**: magic / ver / reserved flag bits / the upper bound of each len /
  pad_len == the number of trailing 0x00 (E7) / a version carrying padding must be >= 2 (E7); any
  truncation is an Err.
- **D-5 the `MeshEnvelope` struct is untouched**: only the codec is replaced; `pad_envelope_frame`
  internally switches to binary encoding (the fixed-point iteration wording is unchanged); assertions in
  the old tests of the form "an unpadded frame equals the old JSON byte for byte" are upgraded to "an
  unpadded frame equals the binary golden byte for byte", and the old JSON byte-level compatibility is
  downgraded to a receiver-side sniff unit test.
- **D-6 zero new dependencies, zero config surface**: no negotiation, the sender switches today; in a
  mixed-deployment window an old node receiving a binary frame -> the version check fails and the
  connection closes (the same R-obfs2 assumption as P1-4: same-version deployment is the MVP premise).

## 3. Error paths

| # | Condition | Semantics |
|---|------|------|
| E1 | magic mismatch | Err, drop the frame |
| E2 | ver != 2 and the first byte is not `{` | Err, drop the frame |
| E3 | reserved flag bits nonzero | Err, drop the frame |
| E4 | a len field out of range / truncation | Err, drop the frame |
| E5 | pad_len != the number of trailing 0x00 | Err (the same E7 semantics as the JSON era) |
| E6 | version < 2 and padding is carried | Err (the same E7 semantics as the JSON era) |

## 4. Wiring points

| Point | Action |
|---|------|
| `write_envelope` | JSON -> `encode_mesh_envelope_binary` |
| `decode_envelope_payload` | sniff: `{` -> the old JSON parse; otherwise the binary parse; the E5/E6 gates are shared by both formats |
| `pad_envelope_frame` | base takes the binary length, the fixed point is unchanged |
| `read_envelope` | unchanged (goes through `decode_envelope_payload`) |

## 5. Control plane / metrics

Nothing new. Binarization is transparent to callers.

## 6. Tests (§7)

1. Binary golden: encode -> decode roundtrip of all fields + byte-level shape pinned (magic/ver/flags/
   version/each len/pad_len).
2. Old JSON receive: old `serde_json` bytes go into `decode_envelope_payload` and restore the fields
   (the P1-4 pad/strip semantics are kept -- an old frame of version=2 + pad_len + zeros can also be parsed).
3. pad/strip full link: a fixed padded frame has total length == target, trailing zeros == pad_len,
   decode restores the fields, and version goes up to 2 (the P1-4 golden is inherited, the wording switched to binary).
4. E5/E6 frame refusal (constructed in the old JSON and the new binary forms).
5. TCP full link (a `dial_and_tunnel` mock of two planes): wire frame = the binary golden,
   the echo is not broken.

## 7. Steps

| Step | Content | Acceptance |
|---|------|------|
| M0 | design draft + binary codec (pure functions) + the §6-1/2/4 unit tests | the codec roundtrip is green |
| M1 | the `write_envelope`/`decode_envelope_payload`/`pad_envelope_frame` switch + §6-3/5 + documentation backfill | all green |

## 8. Deviations and open items

- **§9-1 the safety assumption of receiver-side sniffing**: a JSON frame always starts with `{`
  (`serde_json`
  indeed does this for a struct); a binary frame always starts with `'S'` (0x53) -- the two are
  disjoint.
  If a new format starting with `{` is introduced later it must be re-registered.
- **O-1**: in a mixed-deployment window an old node fails the connection as soon as it receives a
  binary frame (a hard version-check error,
  not a degraded ignore) -- the MVP same-version deployment assumption was already registered in P1-4
  (R-obfs2) and is
  inherited here; a rolling upgrade needs to either fully stop writing chain traffic first or upgrade in
  topology order.
- **O-2**: `flow_id` is carried as the raw len(1)+bytes string (different from UDP's `[u8;16]`
  -- the TCP side historically allowed non-UUID shapes, such as the test "flow1"); the pruning
  to a unified UUID shape is left to V2.
