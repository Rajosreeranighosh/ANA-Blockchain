# ANA Blockchain

ANA is an experimental independent-chain project targeting Rust + Proof of Work + RandomX CPU mining.

## Target network parameters

- Project: ANA
- Consensus target: Proof of Work
- Intended mining algorithm: RandomX
- Implementation language: Rust
- Maximum supply target: 21,000,000 ANA
- Initial block reward proposal: 50 ANA
- Atomic units: 100,000,000 per ANA
- Initial mining focus: CPU

## Current status — prototype only

The current repository contains a small, buildable block-header and mining-loop demonstration using **temporary SHA-256 development PoW**. It is **not RandomX**, does not implement a complete blockchain, and must not be presented as a live coin or used for real funds.

RandomX integration is a required next engineering milestone. The project must select and pin a maintained Rust binding or audited FFI wrapper, verify its API and native build requirements, and add official RandomX test vectors before enabling RandomX consensus.

## Build and run

Install stable Rust from https://rustup.rs.

```sh
cargo test
cargo run --release -- 1
```

The numeric argument is a low demo difficulty (0–6), not a production network difficulty.

## Planned repository layout

```text
ana-blockchain/
├── .github/workflows/ci.yml
├── src/main.rs
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
└── .gitignore
```

## Required milestones before public testnet

1. Integrate RandomX correctly and test against official vectors.
2. Define canonical genesis data and a network-specific RandomX seed/epoch schedule.
3. Implement signed transactions, wallet key management, mempool, and ledger state.
4. Enforce the 21,000,000 ANA cap in deterministic consensus state, including subsidy schedule and fees.
5. Implement retargeting, timestamp rules, chain selection, and reorganization handling.
6. Add durable storage, P2P networking, peer discovery, and RPC.
7. Add multi-node integration tests, fuzzing, dependency audits, and independent security review.

**Do not launch mainnet or distribute coins until consensus rules are complete, deterministic, and independently reviewed.**
