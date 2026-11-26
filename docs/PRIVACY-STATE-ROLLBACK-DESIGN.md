# ANA Privacy State Rollback Protection — Design

**Status:** design only; not implemented. Private transactions must remain disabled in consensus.

## 1. Threat model

The experimental key-image registry currently saves a network-scoped JSON snapshot
using an atomic temporary-file replacement. Atomic replacement reduces the chance
of a torn write; it does not prevent an operator, attacker, backup restore, filesystem
snapshot rollback, or compromised process from replacing the file with an older,
otherwise valid snapshot.

An older snapshot can omit key images recorded later. If a transaction verifier
trusted that restored state, a previously spent output could appear unspent. A
checksum, MAC, signature, sorted list, generation number, or hash chain stored only
inside the same replaceable file does **not** solve this: the entire old file can be
restored together with its old metadata.

## 2. Required invariant

For each network, accepted key-image state must be monotonic:

- Every accepted key image remains spent after restart and recovery.
- A node must detect state older than its independently trusted latest checkpoint.
- If freshness cannot be established, the node must fail closed and refuse private
  spend validation and block production that depends on that state.
- State from one network must never be accepted by another network.

## 3. External freshness anchor

A production design must select and implement at least one independently protected
freshness anchor. Candidate approaches:

1. **Consensus-committed state root (preferred for a decentralized chain):**
   commit the key-image accumulator root and monotonic height into validated blocks.
   Rebuild/verify local state from the canonical chain and reject a local snapshot
   whose height or root disagrees. Reorg handling must restore the exact state for
   the selected canonical tip, not simply trust a local file.
2. **Hardware-backed monotonic storage (single-node hardening):**
   store a signed checkpoint in a TPM/platform secure element with rollback-resistant
   counters. Define supported hardware, provisioning, reset/replacement recovery,
   and Windows/Linux parity. Do not assume ordinary filesystem metadata or TPM
   availability.
3. **Independent remote witness/quorum (operational alternative):**
   obtain signed, network-bound checkpoints from independently administered
   witnesses. Specify quorum, equivocation handling, outage behavior, key rotation,
   and how a fresh node bootstraps trust. A single remote server is not a trustless
   solution.

A local generation field may help detect accidental stale writes but is not a
rollback defense without one of these independent anchors.

## 4. Storage protocol requirements

Before persistence can be used by consensus:

- Replace whole-file JSON snapshots with a transactional, crash-recoverable store
  or append-only journal with documented fsync and directory-sync semantics.
- Serialize writers with a cross-platform process lock; in-process mutexes alone
  are insufficient when multiple processes can open the same data directory.
- Make each update idempotent and atomic across all key images in one transaction.
- Bind records to network ID, schema version, block height, canonical block hash,
  and the accumulator/state root.
- Bound record size, database growth, recovery work, and compaction.
- Detect truncated, reordered, duplicated, malformed, and stale records.
- Define backup/restore and reindex procedures that always revalidate against the
  canonical chain or independent freshness anchor.
- Never silently initialize an empty registry when an existing store is missing,
  corrupt, or has an unverifiable checkpoint.

## 5. Consensus and reorganization integration

A key-image set cannot be safely maintained as a standalone side database. The
consensus state transition must atomically validate a transaction and update its
spent-key-image state. Block disconnect/reorg must restore the prior accumulator
state deterministically. The block commitment must bind the resulting state root.
Nodes must independently recompute and compare the root.

The current `PrivacyKeyImageRegistryV1` is only an experimental in-memory/local
snapshot helper. Its `record_after_verification` method relies on a caller
precondition; it does not perform CLSAG, range-proof, ownership, fee, commitment,
or balance verification. It is not wired to consensus and is not a substitute for
the state-transition design above.

## 6. Required tests and release gates

- Restore an older valid snapshot after newer spends: detect rollback and fail closed.
- Restore an older backup and recover only by reindexing from the canonical chain
  or obtaining a valid independent checkpoint.
- Kill the process during each write/flush/rename stage; recovery yields either the
  old complete state or the new complete state, never a partial transaction.
- Run concurrent writers in separate processes; no lost updates or duplicate spends.
- Simulate block reorgs and verify exact key-image state restoration.
- Test corrupted, truncated, oversized, wrong-network, wrong-height, and wrong-root
  data on Windows and Linux.
- Test hardware/witness loss, reset, rotation, outage, equivocation, and bootstrap.
- Obtain independent cryptographic and consensus review before enabling private
  transactions or public mainnet use.

## 7. Current deployment restriction

Until the above gates are implemented and independently reviewed, keep privacy
transactions out of consensus and do not expose public mainnet functionality. The
existing JSON file is experimental test data only. Atomic file replacement is not
a claim of rollback resistance, multi-process safety, or consensus durability.
