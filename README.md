# ANA Blockchain — experimental testnet alpha

ANA targets Rust, Proof of Work and RandomX CPU mining.

## Fixed project targets
- Maximum supply target: 21,000,000 ANA
- Atomic units: 100,000,000 per ANA
- Initial subsidy proposal: 50 ANA
- Network label for wallet/transaction signatures: ANA-TESTNET-1

## Build
Install stable Rust, CMake and a C/C++ compiler. On Debian/Ubuntu:
```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake
cargo test --all-targets
cargo build --release
```

## Wallet alpha
```sh
cargo run --release --bin ana-wallet -- new ana-wallet.json
cargo run --release --bin ana-wallet -- address ana-wallet.json
```
The wallet creates an Ed25519 keypair and a local JSON key file. On Unix, file permissions are set to 0600. This file is **not encrypted**. Amounts are parsed as exact 8-decimal fixed-point values; floating-point rounding is avoided. Do not use a wallet containing real value; back it up securely and never share it.

## Start two transaction-relay nodes
Terminal 1:
```sh
cargo run --release --bin ana-node -- 127.0.0.1:19001 127.0.0.1:19002
```
Terminal 2:
```sh
cargo run --release --bin ana-node -- 127.0.0.1:19002 127.0.0.1:19001
```
This alpha relays and signature-checks signed transaction messages between configured peers. It is not yet a full P2P blockchain node.

## Transaction and ledger alpha
The library provides Ed25519-signed transactions, sender/public-key matching, network separation, nonce and balance checks, and a subsidy calculation that stops issuance at 21,000,000 ANA. Ledger transaction and block application are atomic: a failed state transition leaves the previous ledger unchanged.

## Important limitations — NOT mainnet ready
- The current `ana-node` is a transaction relay only. It does not mine, validate or propagate blocks, persist a ledger, or provide confirmed balances.
- Wallet sends currently use nonce 0; sequential wallet nonce/balance discovery and fee estimation are not implemented.
- The ledger is a consensus-state foundation, not yet wired into a full block-validation/chain-selection loop.
- The earlier RandomX miner remains a separate demonstration and still uses a development seed and JSON header encoding.
- No encrypted keystore, RPC authentication, peer discovery, DoS protection, difficulty retarget, canonical binary consensus encoding, chain reorganization, or audited network protocol exists.
- Never use this software for real funds. Treat all testnet coins as valueless.

A public testnet launch requires deterministic RandomX epoch rules, full block validation, mining and block gossip, durable state, nonce-aware wallet operations, integration tests across multiple nodes, fuzzing, and independent security review.
