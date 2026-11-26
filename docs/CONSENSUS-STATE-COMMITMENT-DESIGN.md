# ANA Consensus State Commitment and Reorganization Design

**Status:** design only; no consensus fields or private-transaction activation are implemented by this document. The current block format and transparent ledger remain authoritative.

## 1. Current implementation boundary

The current `ChainState` stores a vector of blocks and a derived transparent `Ledger`. `append` validates a block, applies its transparent transactions to a cloned ledger, then appends the block. `replace_if_more_work` rebuilds a candidate chain from genesis and selects the greater cumulative-work chain (with a deterministic tip-hash tie-break). `load` rebuilds the ledger from stored blocks and compares it with the serialized ledger.

This replay-from-genesis model is useful as a correctness baseline, but it is not yet an efficient state database or a privacy-spend accumulator. Blocks do not currently commit a post-state root. The privacy key-image registry is not read by consensus. No private transaction may be accepted on the strength of the local registry.

## 2. Consensus commitment target

A future, versioned block header should commit to a deterministic post-state commitment. At minimum the commitment must bind:

- network/genesis identifier and consensus ruleset version;
- block height and parent block hash;
- transparent ledger state (balances, account nonces, and cumulative minted supply);
- privacy output accumulator root and output count;
- spent-key-image accumulator root;
- any other consensus state that can affect future transaction validity.

The commitment must be computed from the state produced after applying every transaction in canonical block order and then applying the block reward/fees. A block-provided root is untrusted input: every validating node independently recomputes it and rejects a mismatch.

Do not use ordinary JSON serialization as a permanent consensus encoding. Specify a canonical, versioned binary encoding with fixed-width integer endianness, explicit length prefixes, bounded collection counts, canonical key ordering, and domain-separated hashes. Publish test vectors before activation.

## 3. Accumulator requirements

The key-image structure must support deterministic membership/non-membership checks and efficient updates. Select the data structure only after documenting:

- collision and hash assumptions;
- canonical key-image encoding and network/domain separation;
- deterministic root computation independent of map iteration or platform;
- proof format and maximum proof size;
- update and deletion semantics (deletion is needed only for reverting a disconnected branch);
- historical root lookup or a deterministic rebuild strategy.

A sorted-list hash is acceptable only as a slow prototype, not as a scalable production accumulator. A Merkleized sparse tree or another reviewed authenticated data structure is a candidate. Cryptographic primitive and tree parameters require independent review and fixed cross-language test vectors.

## 4. Atomic state transition

For each candidate block, execute against an isolated candidate state:

1. Validate parent, height, timestamp, difficulty, PoW, and canonical block encoding.
2. Validate all transactions against the parent state plus prior transactions in this block.
3. For private transactions, verify ownership/signature proofs, range proofs, commitment balance, fees, output rules, and key-image non-membership. Structural parsing is not cryptographic verification.
4. Apply all spends, output insertions, transparent balance/nonce changes, and issuance accounting to the candidate state.
5. Enforce the 21,000,000 ANA maximum supply with checked arithmetic.
6. Compute the complete post-state commitment.
7. Compare it with the header commitment.
8. Commit block and state changes as one durable database transaction. If any stage fails, neither block nor state becomes visible.

No caller-supplied boolean or callback precondition may stand in for a consensus verifier. The verifier must be part of the deterministic consensus path and shared by block validation and mempool policy where appropriate.

## 5. Reorganization and undo model

Maintain a per-block state transition record sufficient to disconnect a block exactly, or maintain immutable versioned state roots with deterministic parent-state reconstruction. A disconnect must reverse every state domain, including key-image spends and output-index changes; reversing only balances is insufficient.

For a reorganization:

1. Find the common ancestor of the current and candidate canonical chains.
2. Validate the candidate branch from the ancestor using the exact consensus rules and parent state.
3. Stage all disconnect/connect operations in an isolated transaction.
4. Recompute every intermediate and final state root.
5. Select the branch using the existing cumulative-work rule (subject to any later consensus change being separately versioned).
6. Atomically publish the new canonical tip, state root, and database generation.
7. Retain enough undo/history data for the documented reorg window; define safe pruning and deep-reorg recovery.

A crash at any point must recover to either the complete old canonical state or the complete new canonical state. It must never expose a block tip paired with a ledger or privacy accumulator from another height.

## 6. Durable storage and freshness

Use a transactional database or append-only journal with documented durability guarantees, cross-process writer coordination, bounded recovery, schema migrations, and corruption handling. Store network ID, schema version, block height/hash, parent root, resulting root, and transition identifiers with each committed state version.

A database transaction prevents partial updates; it does not by itself prevent restoration of an old database backup. On startup, compare the restored database tip/root with the independently validated canonical chain and the rollback-protection anchor described in `PRIVACY-STATE-ROLLBACK-DESIGN.md`. If freshness cannot be established, refuse private-spend validation and block production that depends on private state. Never silently create an empty privacy accumulator when prior state is missing or unverifiable.

## 7. Migration and activation plan

- Phase A: keep current transparent consensus unchanged; publish canonical encoding and state-root test vectors.
- Phase B: implement a shadow state commitment for transparent state only; compare roots during full replay without affecting block validity.
- Phase C: implement versioned state storage, undo/reorg journal, crash recovery, and cross-platform tests; keep private transactions disabled.
- Phase D: add the privacy output and key-image accumulators in shadow mode; independently verify roots against full replay.
- Phase E: integrate fully audited transaction cryptography and consensus accounting under an explicitly versioned activation rule. Require external cryptographic, consensus, and implementation audits before activation.
- Phase F: test multi-node forks, reorgs, database rollback, interrupted writes, upgrades, and independent rebuilds on Windows and Linux before any public network release.

There must be no silent consensus upgrade and no fallback that accepts a block with a missing or mismatched state commitment after activation.

## 8. Required acceptance tests

- Identical state roots across Windows and Linux for fixed canonical test vectors.
- Root changes for every state mutation and remains unchanged for no-op transitions.
- Rejection of incorrect, missing, wrong-network, wrong-height, and wrong-parent roots.
- Replay of the same block is rejected or idempotently recognized without double-applying state.
- Reorg disconnect/connect restores the exact ancestor state and yields the same root as a clean replay of the winning branch.
- Crash injection at every database write/commit boundary yields only old-complete or new-complete state.
- Concurrent processes cannot lose updates or double-spend a key image.
- Old database snapshot restoration is detected by chain replay or independent freshness anchor.
- Supply, fee, nonce, output-index, and key-image invariants survive forks and reorgs.
- Property-based, fuzz, differential, and independent audit coverage for encodings, accumulators, and transitions.

## 9. Release restriction

This document is a design specification, not implementation evidence. The current chain has no consensus state-root field and the privacy registry is not integrated into `ChainState`. Keep private transactions disabled in consensus. Do not describe ANA as mainnet-ready until implementation, cross-platform validation, independent audits, and operational recovery procedures are complete.
