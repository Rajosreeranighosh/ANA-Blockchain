# ANA Security Threat Model — Testnet Alpha

## Scope

This document describes the current experimental Rust implementation and the controls still required before any public adversarial network. It is a security work plan, not a certification. The inspected baseline is the `ana-wallet-gui-v1` code plus the Windows RandomX migration branch. Re-review this document whenever consensus or networking code changes.

## Assets

1. Consensus correctness: valid balances, nonces, block history, and minted supply.
2. Wallet signing keys and encrypted backups.
3. Node availability and chain database integrity.
4. Peer identity, message integrity, and network isolation.
5. User privacy and transaction metadata.

## Trust boundaries and adversaries

- Peer TCP messages are untrusted, even when a shared token is configured.
- Chain files and mempool files may be corrupted or attacker-controlled.
- Wallet files and passphrases may be exposed by malware, backups, or unsafe host permissions.
- Miners may submit malformed blocks, manipulate timestamps, or attempt excess issuance.
- Network attackers may observe, replay, delay, alter, or suppress traffic.
- A malicious majority of proof-of-work can reorganize this prototype's chain.

## Existing protections observed

- Rust implementation with checked arithmetic in amount, balance, fee, nonce, and supply paths.
- Ed25519 transaction signatures bind the sender, recipient, amount, fee, nonce, and network string.
- Ledger transaction and block application use candidate copies so a failed operation does not partially mutate state.
- Block validation checks height, parent, timestamp, expected difficulty, RandomX hash, proof-of-work target, and ledger effects.
- Candidate chains are replayed from the fixed genesis and selected by cumulative work.
- The subsidy is derived from remaining supply; fees are credited to miners without increasing minted supply.
- The wallet CLI creates encrypted keystores using Argon2id and XChaCha20-Poly1305. A legacy plaintext wallet format still exists for migration compatibility.
- The node has message-size, socket-timeout, connection-count, and chain-sync session bounds.

## High-priority risks — do not expose this testnet as a public mainnet

### H1 — Peer transport is plaintext TCP

The node's shared `ANA_PEER_TOKEN` is sent in the message envelope over plaintext TCP. It can be captured and replayed by an on-path attacker. A shared token does not provide peer identity, forward secrecy, or message confidentiality.

**Required:** authenticated encrypted transport (for example, mutually authenticated TLS with per-node identities), token rotation, replay-resistant session binding, and negative tests for unauthenticated peers. Until then, bind to loopback or use a trusted VPN/SSH tunnel. The explicit insecure remote-bind opt-in is not a production solution.

### H2 — Consensus encoding is not a versioned canonical protocol

Block proof-of-work input and transaction signing payloads currently use serde JSON serialization. The encoding is deterministic for the present Rust struct layout, but it is not specified as a cross-implementation canonical byte format. A future field/order/encoding change could create incompatible hashes or signatures.

**Required:** publish a byte-level protocol specification, add versioned domain-separated encodings, and commit cross-platform known-answer vectors before supporting independent node implementations. Any encoding change is a consensus fork and must not be silently deployed.

### H3 — Chain selection has no deterministic finality

Nodes accept a valid higher-cumulative-work chain and rebuild the ledger. Confirmations can decrease after a reorganization. A proof-of-work majority can reorganize recent history.

**Required:** document confirmation risk, test deep reorganizations and transaction resurrection, and design an explicit checkpoint/finality policy only after threat analysis. Do not describe a confirmation count as irreversible settlement.

### H4 — Difficulty and timestamp rules are testnet-only

The simple retarget rule adjusts by one bit per ten-block window, and timestamps are constrained by median-time-past but lack a complete adversarial time/retarget design.

**Required:** formalize difficulty, timestamp bounds, overflow behavior, and manipulation resistance; use deterministic historical test vectors and adversarial simulations before mainnet.

### H5 — Wallet file compatibility includes plaintext legacy keys

The CLI's normal wallet creation uses the encrypted keystore, but the library still exposes a legacy plaintext `WalletFile` format and `open_wallet` for migration. Accidentally using or distributing that format exposes signing keys.

**Required:** isolate legacy import into an explicitly named migration-only path, warn loudly, add restrictive file permissions on every platform where supported, and never serialize a signing key to logs or diagnostics.

## Medium-priority risks

- No formal transaction/block maximums are part of the consensus specification. Network frame limits help, but per-field, per-block transaction-count, chain-sync CPU, and storage-growth budgets need explicit policy and tests.
- The peer protocol has no per-peer rate limiting or reputation/ban policy; connection limits alone do not prevent a single peer from consuming the available slots.
- Chain and mempool persistence need crash-consistency, disk-full, symlink/path, and hostile-file tests on Windows and Linux.
- The fixed testnet RandomX seed has no epoch schedule. Do not reuse testnet parameters for a production network.
- Private transaction primitives are prototypes only. They do not constitute a complete confidential transaction protocol and remain disabled in consensus.
- Dependency vulnerabilities and supply-chain compromise need a committed lockfile, automated advisory scanning, pinned CI actions, and periodic dependency review.

## Security release gates

Before any mainnet proposal:
1. Freeze a versioned consensus specification and genesis/parameter manifest.
2. Generate cross-platform known-answer vectors for transaction IDs, signatures, block headers, RandomX, reward accounting, and chain replay.
3. Add property-based and fuzz testing for parsers, transactions, blocks, chain sync, persistence, and reorganization.
4. Add a reproducible dependency lockfile, advisory/license checks, and pinned CI actions.
5. Implement authenticated encrypted peer transport and resource/rate limits.
6. Complete independent cryptographic and consensus audits; publish findings and fixes.
7. Run a long-lived adversarial testnet with multiple independent operators and document incident/recovery procedures.

## Explicit non-goals

This testnet is not secure for real funds. No document, successful build, or unit-test suite can substitute for independent review and adversarial operation.
