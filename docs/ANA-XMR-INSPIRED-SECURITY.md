# ANA XMR-Inspired Security and Privacy Requirements (Draft)

Status: design requirements only. ANA's privacy prototype is experimental and is not safe for real funds. Private transactions must remain disabled in consensus until reviewed cryptography, full consensus verification, adversarial testing, and independent audit are complete.

## Security goals
- One-time stealth outputs to reduce recipient linkage.
- Confidential amounts using reviewed Pedersen commitments and authenticated amount encryption.
- Reviewed linkable ring signatures (CLSAG-family) to hide the spent ring member.
- Consensus-enforced unique key images to prevent double spends.
- Range proofs to prevent negative or out-of-range amounts.
- Reorg-safe spent-output/key-image state and deterministic consensus.
- Encrypted peer transport, authenticated node identities, RPC access controls, and wallet key protection.

## Required cryptography
Do not invent primitives or treat placeholder byte arrays as proofs. Select maintained, reviewed implementations for CLSAG-compatible signatures, Pedersen commitments, range proofs, and authenticated encryption. Specify canonical point/scalar encodings, domain separation, network binding, transcript construction, and strict rejection of malformed/non-canonical inputs. Verify ring membership, output eligibility, signature correctness, key-image validity/uniqueness, commitment balance including fees, and range proofs before mutating state.

## Wallet requirements
Separate spend and view keys; support view-only scanning. Encrypt secrets at rest with reviewed KDF and AEAD parameters. Never log or debug-print secrets. Test backup/restore, migration, wrong-network addresses, secure randomness, and failure handling. Endpoint compromise and unsafe backups remain privacy risks.

## Network requirements
The current plaintext peer protocol must not be exposed to the public internet. Before public testnet, add reviewed encrypted/authenticated transport, peer identity, replay protection, rate limits, bounded queues, strict frame limits, timeouts, peer scoring, and fuzzing. Keep RPC local by default; authenticate and encrypt remote access. Analyze Sybil/eclipse attacks and metadata leakage.

## Consensus/economics
Freeze a versioned consensus specification and canonical encoding. Keep transparent and private transaction versions explicitly separated. Enforce commitment balance, explicit fees, overflow-safe amount arithmetic, and the existing 21,000,000 ANA supply cap across blocks, forks, reorgs, snapshots, and restarts. Fees are not newly minted. Preserve zero premine and no tail emission.

## Privacy leakage review
Assess IP/timing metadata, transaction timing and fee patterns, decoy selection, address reuse, change outputs, RPC logs, telemetry, crash dumps, backups, exchanges, merchants, and endpoint behavior. Protocol privacy does not equal network anonymity. Tor/I2P support requires its own threat model and operational review.

## Release gates
- [ ] Versioned protocol specification and canonical encoding frozen.
- [ ] Cryptographic components selected from reviewed implementations.
- [ ] Independent cryptographic design review.
- [ ] Positive and negative test vectors for signatures, commitments, range proofs, and amount encryption.
- [ ] Parser/verifier fuzzing and adversarial tests.
- [ ] Key-image uniqueness, atomic persistence, and reorg rollback tests.
- [ ] Supply-cap and commitment-balance property tests.
- [ ] Wallet secret-handling and backup/restore review.
- [ ] Encrypted peer transport and RPC security review.
- [ ] Multi-operator testnet soak, attack simulation, and recovery drills.
- [ ] Independent audit findings resolved and reproducible release builds.

CI success alone is insufficient. Mainnet activation requires a public audit report, documented upgrade process, monitored testnet history, and explicit go/no-go approval.

## Implementation order
1. Keep private transactions disabled in consensus.
2. Add canonical serialization and cryptographic encoding tests.
3. Integrate reviewed commitments, range proofs, authenticated amount encryption, and CLSAG.
4. Implement persistent key-image state with atomic updates and reorg rollback.
5. Build wallet scanning, amount recovery, and encrypted key storage.
6. Integrate private transactions into mempool, blocks, wallet, and RPC behind a new protocol version.
7. Run adversarial multi-node testnet and independent audit.

## References
- Monero source: https://github.com/monero-project/monero
- Monero developer guides: https://www.getmonero.org/resources/developer-guides/
- Zero to Monero: https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf

These are study references, not evidence that ANA implements Monero or inherits its security.
