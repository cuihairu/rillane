# Acceptance evidence index

Evidence documents backing `todo.md` acceptance items. Two honest kinds live here:

- **Device evidence** — commands run on real hardware, output captured with timestamps. What was not run is recorded as a named gap inside the document.
- **Local verifiable ledgers** — machine-readable matrices (`contracts/*.json`) enforced by contract tests in `cargo test --workspace`, covering the clauses that can be verified on this machine only. Real-device acceptance stays unchecked where dependencies (device access, signing accounts) are unresolved.

| Item | Evidence | Kind | Status |
|---|---|---|---|
| RIL-032 Windows technical probe | [ril-032-windows-probe](./ril-032-windows-probe) (zh) | Device | Verified on `imac` |
| RIL-033 Windows takeover/bypass | [ril-033-windows-takeover](./ril-033-windows-takeover) (zh) | Device | Machine batch verified on `imac`; browser/game flows and DNS hijack end-to-end are named gaps |
| RIL-034 Windows process owner | [ril-034-windows-owner](./ril-034-windows-owner) (zh) | Device | Verified on `imac` |
| RIL-035 Windows service & exit recovery | [ril-035-windows-service-recovery](./ril-035-windows-service-recovery) (zh) | Device | Verified; suspend/resume is a named gap |
| RIL-084 six-platform artifact matrix | [ril-084-artifact-matrix](./ril-084-artifact-matrix) · [zh](./ril-084-artifact-matrix.zh) | Local ledger | Artifact face aligned; device/signing acceptance unchecked |
| RIL-085 three-desktop e2e clause matrix | [ril-085-desktop-e2e-matrix](./ril-085-desktop-e2e-matrix) · [zh](./ril-085-desktop-e2e-matrix.zh) | Local ledger | Clause×platform ledger; browser/game grouped traces not run |
| RIL-086 six-platform parallel scenario matrix | [ril-086-parallel-scenario-matrix](./ril-086-parallel-scenario-matrix) · [zh](./ril-086-parallel-scenario-matrix.zh) | Local ledger | Clause×platform ledger; real website/QUIC+game parallel matrix not run |

The ledgers' machine-readable sources live outside the docs tree:
`contracts/build_matrix_v1.json`, `contracts/desktop_e2e_matrix_v1.json`,
`contracts/parallel_scenario_matrix_v1.json`; contract gates run as part of
`cargo test --workspace` under `crates/rillane-platform/tests/`.

Statuses never claim more than the linked document shows: a `partial` or
`needs_*` cell means the scenario has not been verified — unit tests,
cross-compilation and artifact builds are not device acceptance.
