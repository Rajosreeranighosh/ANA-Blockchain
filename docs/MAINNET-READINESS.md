# ANA Mainnet Readiness Gate

**Status: BLOCKED — experimental testnet only. No mainnet launch approval.**

This document is a release gate, not a claim that the checklist has passed. ANA's existing network identifier is `ANA-TESTNET-1`; its consensus and privacy code must not be treated as a production mainnet implementation.

## Verified repository state at assessment

- Integration PR #22 is open and Draft, targeting `main`.
- Privacy PR #23 is open and Draft, stacked on `ana-integration-v1`.
- The latest observed CI run for privacy commit `58083234dab7e4ab0350e540ce10709ee398125d` passed formatting and `cargo test --all-targets`.
- The successful CI run proves that the current test suite passes on the GitHub runner. It does not prove consensus safety, cryptographic security, production readiness, or successful public multi-node operation.

## Release blockers

### 1. Consensus and network identity

- Publish a complete, versioned consensus specification covering genesis, chain ID, block/header encoding, transaction encoding, proof-of-work input, difficulty retargeting, timestamp rules, fork choice, rewards, fees, and upgrade activation.
- Replace testnet-only network identifiers, RandomX seed assumptions, and development parameters with a reviewed mainnet configuration.
- Define canonical serialization independently of incidental Rust/Serde struct layout.
- Define deterministic RandomX seed epochs and test all nodes against published cross-implementation vectors.
- Specify hard-fork/versioning, activation thresholds, replay protection, checkpoints/recovery policy, and chain reorganization behavior.
- Perform adversarial tests for difficulty manipulation, timestamp manipulation, long-range forks, malformed chains, integer overflow, and state divergence.

### 2. Monetary policy: preserve the user's chosen constraints

- Maximum supply remains **21,000,000 ANA**.
- Atomic units remain **100,000,000 per ANA**.
- Initial subsidy remains up to **50 ANA per block**, capped by remaining supply.
- Fees are transfers to miners and are not newly minted supply.
- No premine and no tail emission are introduced.
- Add independent property/fuzz tests proving minted supply never exceeds the cap through ordinary blocks, reorgs, sync, restart, and boundary conditions.
- Publish test vectors for every subsidy boundary, fee accounting case, and maximum integer edge.

### 3. Privacy is not ready

The current `src/privacy.rs` is experimental scaffolding and stealth-output prototype code. Its transaction envelope performs structural checks only. It does **not** implement or verify CLSAG, Pedersen commitments, Bulletproofs/range proofs, authenticated amount encryption, balance proofs, key-image consensus enforcement, or private transaction integration with mempool, block validation, RPC, and wallet persistence.

- Do not accept privacy transactions in consensus.
- Do not advertise ANA as a private/Monero-equivalent chain.
- Require protocol design review, cryptographic implementation review, test vectors, differential testing, fuzzing, and an independent specialist audit before any privacy activation.
- Keep privacy features disabled by default until all gates pass.

### 4. Network and node security

- Peer transport is plaintext TCP; the shared bearer token is not encrypted.
- No TLS or authenticated per-peer cryptographic identity is implemented.
- Do not expose node ports directly to the public internet.
- Implement reviewed encrypted transport, peer identity/authentication, connection/resource controls, rate limiting, abuse handling, and robust peer discovery policy.
- Fuzz all network message decoders and test hostile peers, slow clients, oversized messages, connection exhaustion, and sync-session exhaustion.
- Define operator key management, secure configuration, firewall, backup, monitoring, and incident-response procedures.

### 5. Wallet and custody

- Audit key generation, KDF parameters, encryption, nonce handling, file permissions, migration, backup/restore, and secret zeroization.
- Review all legacy wallet APIs and ensure production CLI paths cannot accidentally create or expose plaintext keys.
- Add hardware-backed or offline signing guidance, recovery drills, address/network checks, transaction review, and secure release packaging.
- Complete independent wallet and cryptographic audits before real funds.

### 6. Production operations

- Run a public multi-operator testnet for a sustained period with independent operators and heterogeneous machines.
- Test node upgrades, rollback, state corruption recovery, disk-full behavior, clock skew, partitions, reconnects, chain reorgs, and sustained load.
- Establish reproducible, signed builds; dependency and license review; SBOM; vulnerability scanning; release provenance; and reproducible test vectors.
- Define monitoring, alerting, telemetry/privacy policy, seed nodes, explorers, RPC exposure policy, backup cadence, disaster recovery, and incident response.
- Commission independent consensus, networking, wallet, and cryptography audits; resolve every critical/high finding.
- Publish a launch runbook, upgrade policy, bug bounty, and emergency halt/coordination policy.

## Go / no-go checklist

A mainnet release is **NO-GO** while any of these remain true:

- [ ] Mainnet consensus specification and test vectors are approved.
- [ ] Mainnet genesis and immutable network parameters are independently verified.
- [ ] Supply cap and all economic invariants pass property/fuzz/adversarial tests.
- [ ] Independent nodes agree on state under adversarial network and reorg testing.
- [ ] Public multi-operator testnet has completed its agreed soak period.
- [ ] TLS or equivalent reviewed secure transport and peer identity are deployed.
- [ ] Wallet and key-management review is complete.
- [ ] Privacy is either fully audited and enabled, or clearly disabled and not marketed as implemented.
- [ ] Critical/high audit findings are fixed and retested.
- [ ] Reproducible signed release artifacts and rollback/recovery runbooks are ready.
- [ ] Operators, monitoring, incident response, and launch coordination are ready.

## Safe five-hour engineering target

Within a short engineering window, work can safely produce a documented release candidate, fix reproducible bugs, improve tests, and run CI. Five hours is not a substitute for protocol design, long-running network trials, specialist cryptographic review, or independent audits. Do not launch real funds based only on a green CI run.
