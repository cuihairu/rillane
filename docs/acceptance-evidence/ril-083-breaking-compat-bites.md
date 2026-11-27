# RIL-083 contract & cross-language CI — breaking-compat bite matrix (local segment, 2026-11-27)

## What is delivered

The acceptance clause "breaking changes must fail clearly" was already
backed by self-proofs on three of the five frozen-face gates (config IR:
type drift + missing key; core trace: face-lagging + extra key; MCP tools:
two; FFI query: face-lagging). This segment completes the matrix where the
negative direction was unproven — no production code changed:

- **Dropped-key direction on the FFI query gate**
  (`crates/rillane-ffi/tests/contract_query_face.rs`
  `comparator_bites_on_dropped_key`): an implementation that removes a
  declared key (the worst breaking change — consumers read by field name)
  must be named by the comparator as `ffi 面漂移 @ stats_json：缺键`.
- **Both directions on the rillaned control-plane gate**
  (`apps/rillaned/src/control_plane.rs`, the gate previously had zero
  self-proofs): `comparator_bites_on_dropped_key` removes
  `total_connections` from the **real** `/runtime/stats` projection with
  the face frozen → `控制面漂移 @ runtime_stats：缺键`;
  `comparator_bites_on_extra_key` injects a phantom key into the real
  projection → `控制面漂移 @ runtime_stats：多键`. Both run the real
  control plane (build_runtime + handle), so the comparator is proven to
  bite on the production shape, not a hand-built stand-in.
- **Version-freeze bite on the cross-language structure gate**
  (`crates/rillane-platform/tests/schema_cross_language_contract.rs`): the
  schema_version check was an inline assert; it is now a callable
  comparator `assert_face_version_frozen` used by the main test, with
  `comparator_bites_on_version_bump` proving a sample bumped to
  `schema_version: 2` (without the whole-directory copy transaction) fails
  as `版本漂移`.

After this segment every frozen face (config IR, core trace, control DTO,
FFI query, MCP tools) plus the structure gate has at least one named
negative self-proof: when a face lags reality, a key is dropped or added,
or a version is bumped without the transaction, the corresponding gate
names the drift instead of passing silently.

## Honest boundary

- These self-proofs pin the comparators' bite on the machine-local faces;
  host-bridge and MCP official-protocol interpretations of the same
  version remain outside (per `contracts/schema_v1/README.md` boundary,
  device/host batches open).
- The self-proofs use injected/mutated in-memory values; they do not
  modify the frozen face files on disk.
