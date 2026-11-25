# ANA XMR-Inspired Security and Privacy Requirements (Draft)

## Status and safety boundary

This document is a security engineering plan, not a security certification. ANA's
privacy transaction envelope and stealth-address wallet code are experimental.
The current prototype does not implement or verify CLSAG, Pedersen commitments,
range proofs, authenticated amount encryption, or consensus key-image rules.
Do not use it to protect real funds or enable it in consensus.

ANA may learn from Monero's publicly documented design, but must not claim
Monero-equivalent privacy or security. Cryptographic protocol choices require
expert review and independent audit.

## Security goals

1. Hide recipient linkage using one-time output keys.
2. Hide transferred amounts using authenticated encrypted amounts and
   Pedersen commitments.
3. Hide which ring member is spent using a reviewed linkable ring signature.
4. Prevent double spends with consensus-enforced, globally unique key images.
5. Prove amounts are non-negative and within the monetary range.
6. Preserve deterministic consensus, reorg safety, and ANA's fixed economics.
7. Protect wallet secrets, peer communications, and node availability.

## Non-goals

- No promise of perfect anonymity or protection against endpoint compromise.
- No promise that a ring size of 16 provides a particular anonymity level.
- No custom cryptographic primitive invented by the ANA project.
- No mainnet activation based solely on passing unit tests.

## Required transaction cryptography

### Outputs and amounts
- Use a reviewed, domain-separated derivation for one-time output keys.
- Use a reviewed Pedersen commitment construction with documented generators.
- Encrypt amounts with authenticated encryption and bind ciphertext to the
  network, transaction, output index, and commitment context.
- Verify a vetted range-proof system; reject malformed, non-canonical, or
  out-of-range encodings before state mutation.
- Specify canonical point/scalar decoding and reject invalid, small-order,
  non-canonical, or identity encodings where prohibited.

### Inputs and double-spend prevention
- Use a reviewed CLSAG-compatible implementation or a maintained audited
  library; do not accept opaque signature bytes as proof.
- Derive key images according to the reviewed protocol and verify them in
  consensus. Maintain a persistent key-image spent set.
- Define deterministic ring construction, output eligibility, unlock/maturity
  rules, decoy sampling, and versioned changes.
- Verify all ring members exist and are distinct before signature validation.

### Balance and supply
- Verify commitment balance, including the explicit fee commitment.
- Prevent integer overflow and negative values in all amount conversions.
- Enforce the 21,000,000 ANA cap across mining rewards, fees, forks, reorgs,
  snapshots, and restart recovery. Fees are not newly minted.
- Add invariant/property tests for every consensus state transition.

## Wallet security
- Separate spend and view secrets; support view-only scanning without spend
  authority.
- Persist secrets only in an encrypted keystore using reviewed KDF and AEAD
  parameters, with versioned formats and authenticated metadata.
- Never log, serialize, debug-print, or expose secret scalars in errors.
- Define secure random generation, backup, restore, recovery, and migration.
- Add address checksums/network prefixes and test wrong-network rejection.
- Document that malware, compromised devices, screenshots, and unsafe backups
  can defeat wallet privacy.

## Network and node security
- Do not expose the current plaintext peer protocol to the public internet.
- Require authenticated, encrypted peer transport (for example, a reviewed
  TLS/noise-based channel) with peer identity and replay protection before
  public testnet use.
- Apply strict message/frame limits, timeouts, rate limits, connection caps,
  and bounded queues. Validate before allocating large buffers.
- Add peer scoring, ban/expiry policy, eclipse/Sybil threat analysis, and
  independent seed-node operation.
- Treat RPC as a separate trust boundary: bind locally by default, authenticate
  remote access, encrypt remote transport, and avoid leaking wallet metadata.
- Fuzz all network decoders and test malformed, oversized, slow, and replayed
  traffic.

## Consensus and implementation safety
- Publish a versioned consensus specification and canonical transaction/block
  encoding before activation.
- Use domain separation for signatures, hashes, key derivation, and network IDs.
- Keep transparent and private transaction versions explicitly separated.
- Make validation deterministic across supported platforms and implementations.
- Ensure failed validation cannot partially mutate chain, mempool, key-image,
  or wallet state.
- Test reorgs, crash recovery, snapshot import, duplicate transactions, and
  conflicting spends.

## Privacy leakage review
Assess and document leakage from:
- network-layer IP metadata and peer timing;
- transaction timing, amount/fee patterns, and ring decoy distributions;
- wallet address reuse, change outputs, and scanning behavior;
- RPC logs, telemetry, crash dumps, and backups;
- exchanges, merchants, endpoints, and user operational behavior.

Protocol privacy is not network anonymity. Recommend Tor/I2P-compatible
networking only after a separate threat model and operational review.

## Required release gates

A private-transaction testnet must not launch until all are complete:
- [ ] Protocol specification and canonical encoding frozen.
- [ ] Cryptographic components selected from reviewed implementations.
- [ ] Independent cryptographic design review completed.
- [ ] CLSAG/signature, commitment, range-proof, and amount-encryption vectors.
- [ ] Negative/adversarial/fuzz tests for every parser and verifier.
- [ ] Key-image uniqueness and reorg-safe persistence tests.
- [ ] Supply-cap and commitment-balance property tests.
- [ ] Wallet backup/restore and secret-handling review.
- [ ] Encrypted peer transport and RPC security review.
- [ ] Multi-operator testnet soak, attack simulation, and recovery drills.
- [ ] Independent audit findings resolved and reproducible release builds.

Mainnet activation additionally requires a public audit report, documented
upgrade/governance process, monitored testnet history, and explicit go/no-go
approval. Passing CI alone is insufficient.

## Immediate implementation order

1. Keep private transactions disabled in consensus.
2. Add canonical serialization and strict cryptographic encoding tests.
3. Select and integrate reviewed primitives for commitments, range proofs,
   authenticated amount encryption, and CLSAG; do not write bespoke crypto.
4. Implement key-image state with atomic persistence and reorg rollback.
5. Build wallet scanning, amount recovery, and encrypted key storage.
6. Add private mempool/block/RPC integration behind a new protocol version.
7. Run adversarial multi-node testnet and independent audit.

## References

- Monero source: https://github.com/monero-project/monero
- Monero documentation: https://www.getmonero.org/resources/developer-guides/
- Zero to Monero: https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf

These references are starting points for study, not a claim that ANA implements
Monero's protocol or inherits its security.
