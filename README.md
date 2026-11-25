# ANA Blockchain — experimental RandomX testnet

## Consensus parameters
- Network: ANA-TESTNET-1
- Proof of Work: RandomX (light mode)
- Testnet RandomX key: ANA-TESTNET-RANDOMX-SEED-v1
- Initial testnet difficulty: 8 leading zero bits
- Dynamic difficulty: retarget every 10 completed blocks toward a 30-second block interval; adjust by at most 1 bit per window; clamp to 4–24 bits
- Maximum supply target: 21,000,000 ANA
- Block subsidy: up to 50 ANA per block, clamped to remaining supply at the 21,000,000 ANA cap
- Genesis premine: none; the genesis ledger starts with zero minted ANA
- Transaction fees: debited from senders and credited to the block miner; fees do not count as newly minted supply
- Atomic units: 100,000,000 per ANA

These parameters are experimental and must not be reused for a public mainnet without a formal consensus specification and security review.

## Build
Install stable Rust, CMake and a C/C++ compiler. Then:
```sh
cargo test --all-targets
cargo build --release
```

## Create a miner wallet
```sh
cargo run --release --bin ana-wallet -- new miner.json
cargo run --release --bin ana-wallet -- address miner.json
cargo run --release --bin ana-wallet -- balance <ANA-address> 127.0.0.1:19001
```

## Run two local nodes
Use the address printed by the wallet as the miner address. Start the first node:
```sh
cargo run --release --bin ana-node -- 127.0.0.1:19001 node-a.json miner-address
```
Start a second node in another terminal:
```sh
cargo run --release --bin ana-node -- 127.0.0.1:19002 node-b.json none 127.0.0.1:19001
```
The nodes request the peer chain at startup, validate received blocks, compare cumulative work, reorganize to a higher-work valid chain, persist accepted state, and gossip new blocks. Mining runs against a snapshot so peer messages are not blocked during RandomX work. The first node mines; the second is an observer (`none`) to avoid two local miners creating competing tips. Configure peers in both directions for resilient propagation.

## Current testnet-alpha limitations
- Nodes maintain an in-memory transaction mempool, validate sender signatures/nonces/balances, include eligible pending transactions in mined blocks, and update balances/nonces when blocks are accepted. Pending transactions are removed after confirmation. The mempool is not persisted across restarts.
- Nodes validate full candidate chains from genesis and select by cumulative proof-of-work; equal-work ties use the smaller tip hash. Reorganizations replay blocks to rebuild balances/nonces. Displaced transactions are revalidated in the local mempool. This is a minimal testnet rule, not adversarially hardened consensus.
- Difficulty starts at 8 bits and retargets every 10 completed blocks using the elapsed time across that window. Each retarget changes difficulty by at most one bit, with experimental bounds of 4–24 bits and a 30-second target interval.
- RandomX uses one fixed testnet seed; no epoch seed schedule exists.
- The node protocol has no authentication, rate limits, peer discovery, message size limits, or DoS protection.
- The JSON-based consensus header encoding is deterministic for this Rust struct today but is not yet a formally versioned canonical wire format.
- Wallet can query available balance and next nonce from a node before sending. The keystore is still unencrypted, and the mempool is not persisted.
- Do not use for real funds. This is not mainnet-ready software.


## Fork choice and reorganization (testnet alpha)
Each non-genesis block contributes work equal to 2^difficulty. Nodes validate a candidate chain from the fixed genesis before replacing local state. Greater cumulative work wins; equal-work chains use the lexicographically smaller hexadecimal tip hash as a deterministic tie-break. Balances, nonces, and minted supply are rebuilt by replaying the selected chain. Transactions found only on a displaced branch are returned to the local mempool and revalidated.

This is a minimal testnet rule. The simple timestamp-based retarget rule, unauthenticated peers, unbounded chain messages, and the absence of checkpoints/finality mean it is not safe for public adversarial deployment.

## Block rewards and supply accounting

For every accepted non-genesis block, consensus derives the miner subsidy from the ledger state immediately before that block:

`subsidy = min(50 ANA, 21,000,000 ANA - total_minted)`

The subsidy is credited to the block's `miner` address and added to the ledger's `minted` counter atomically with the block's transactions. The block's miner address is part of the RandomX proof-of-work input, so changing the reward recipient changes the block hash. Transaction fees are transferred from senders to the miner in addition to the subsidy; fees are transfers, not new issuance. Once the supply cap is reached, later blocks receive no subsidy, though valid transaction fees can still be collected.

There is no genesis premine. The genesis block is a fixed bootstrap block and the initial ledger has zero minted supply. Every node independently recomputes subsidy and fees while validating/replaying blocks, including during chain synchronization and reorganization. A block that would overflow balances or exceed the supply cap is rejected without partially changing ledger state.

The implementation uses an implicit protocol-defined block subsidy rather than a user-supplied coinbase transaction, preventing miners from choosing an arbitrary mint amount. This is still experimental testnet consensus and has not received an independent security audit.
