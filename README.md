# ANA Blockchain

ANA is an experimental independent-chain project targeting Rust, Proof of Work, and RandomX CPU mining.

## Target network parameters

- Project: ANA
- Consensus target: Proof of Work
- Intended mining algorithm: RandomX
- Implementation language: Rust
- Maximum supply target: 21,000,000 ANA
- Initial block reward proposal: 50 ANA
- Atomic units: 100,000,000 per ANA
- Initial mining focus: CPU

## Current status — experimental prototype

The miner now calls the **RandomX** hashing library through the Rust `randomx-bindings` crate and uses RandomX light mode. Light mode needs roughly 256 MiB of memory for the cache. The first initialization can take time.

This is only a single-process proof-of-work demonstration. It is **not a complete blockchain**, does not yet enforce the 21 million supply cap, and must not be used for real funds or described as a launched cryptocurrency.

The current development key is a placeholder:
`ANA-DEVNET-RANDOMX-SEED-v1`.
It is not a finalized consensus seed schedule. All nodes in a real network must derive identical RandomX keys from a formally specified epoch/seed rule.

## Build requirements

- Stable Rust toolchain
- CMake
- A C/C++ compiler toolchain

On Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake git
```

Install Rust from https://rustup.rs, then run:

```sh
cargo test
cargo run --release -- 8
```

The argument is the number of leading zero bits required in the RandomX hash. This is a demonstration target only, not a calibrated network difficulty.

## What is implemented

- RandomX light-mode cache and VM initialization
- RandomX hash calculation for candidate block headers
- Nonce search until a simple leading-zero target is met
- Fixed prototype genesis block
- Basic target-check unit tests

## Critical work before a public testnet

1. Specify canonical binary block-header encoding and official RandomX test vectors.
2. Define a deterministic, network-specific RandomX seed epoch schedule and genesis constants.
3. Implement full block validation independently of the miner.
4. Implement signed transactions, wallet key management, mempool, and ledger state.
5. Enforce the 21,000,000 ANA cap in consensus state, including subsidy schedule and fees.
6. Implement difficulty retargeting, timestamp rules, chain selection, and reorganization handling.
7. Add durable storage, P2P networking, peer discovery, and RPC.
8. Add multi-node integration tests, fuzzing, dependency audits, and independent security review.

**Do not launch mainnet or distribute coins until consensus rules are complete, deterministic, and independently reviewed.**
