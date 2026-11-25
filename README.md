# ANA Blockchain — experimental RandomX testnet

## Consensus parameters
- Network: ANA-TESTNET-1
- Proof of Work: RandomX (light mode)
- Testnet RandomX key: ANA-TESTNET-RANDOMX-SEED-v1
- Fixed testnet difficulty: 8 leading zero bits
- Maximum supply target: 21,000,000 ANA
- Block subsidy: up to 50 ANA per block
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
The nodes request the peer chain at startup, validate received blocks, persist accepted state, and gossip new blocks. The first node mines; the second is an observer (`none`) to avoid two local miners creating competing tips. Configure peers in both directions for resilient propagation.

## Current testnet-alpha limitations
- Nodes maintain an in-memory transaction mempool, validate sender signatures/nonces/balances, include eligible pending transactions in mined blocks, and update balances/nonces when blocks are accepted. Pending transactions are removed after confirmation. The mempool is not persisted across restarts.
- Chain selection is append-only: no fork choice, reorganization, cumulative-work comparison, or robust adversarial sync.
- Difficulty is fixed at 8 bits and is only suitable for local experimentation.
- RandomX uses one fixed testnet seed; no epoch seed schedule exists.
- The node protocol has no authentication, rate limits, peer discovery, message size limits, or DoS protection.
- The JSON-based consensus header encoding is deterministic for this Rust struct today but is not yet a formally versioned canonical wire format.
- Wallet can query available balance and next nonce from a node before sending. The keystore is still unencrypted, and the mempool is not persisted.
- Do not use for real funds. This is not mainnet-ready software.
