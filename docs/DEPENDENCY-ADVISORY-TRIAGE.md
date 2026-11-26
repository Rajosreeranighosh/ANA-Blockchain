# Dependency advisory triage

Last reviewed: 2026-11-26
Branch: `ana-security-baseline-v1`

The dependency audit currently reports three RustSec **unmaintained** advisories.
These are maintenance/lifecycle warnings, not confirmed exploitable vulnerabilities.
They remain visible in CI output and must be revisited; this document does not
claim the dependencies are secure or that the warnings are fixed.

| Advisory | Resolved dependency path | Current decision |
| --- | --- | --- |
| RUSTSEC-2026-0283 (`clear_on_drop` 0.2.5) | `ana-blockchain -> bulletproofs 5.0.0 -> clear_on_drop` | Do not patch cryptographic internals ad hoc. Evaluate a maintained Bulletproofs implementation/fork with test vectors and independent review before replacement. |
| RUSTSEC-2024-0436 (`paste` 1.0.15) | Present in the generated lockfile and downloaded by CI, but `cargo tree --locked --target all --edges all --invert paste` returned `nothing to print` in run `45768490749`; no active dependency path was established. | Treat as an unresolved lockfile/optional-dependency advisory. Identify which locked package declares it before attempting removal; do not claim it is unused or add a blanket ignore. |
| RUSTSEC-2026-0192 (`ttf-parser` 0.25.1) | `eframe 0.31.1 -> egui 0.31.1 -> epaint 0.31.1 -> ab_glyph 0.2.32 -> owned_ttf_parser 0.25.1 -> ttf-parser` | Evaluate a tested GUI stack migration. Do not remove font support without confirming the wallet remains usable on Windows and Linux. |

## CI policy

The workflow passed on commit `465891c4ec544fedcc4e16ece5906a36960fc87e`
(run `45768490749`). The audit reported three allowed `unmaintained` warnings:
`clear_on_drop` 0.2.5, `paste` 1.0.15, and `ttf-parser` 0.25.1. It blocks
RustSec vulnerability, unsound-code, and yanked-package findings. The pass is
therefore a successful policy/command check, not a clean advisory report or a
security certification. Unmaintained advisories remain visible and tracked.

## Exit criteria

- Remove or replace each unmaintained crate with a maintained, compatible
  dependency, then delete its row here.
- For the Bulletproofs replacement, retain fixed test vectors and verify
  proof generation/verification across supported platforms before adoption.
- For the GUI replacement, verify Windows and Linux builds and runtime text
  rendering before adoption.
- Re-run the complete dependency audit after each dependency graph change.
