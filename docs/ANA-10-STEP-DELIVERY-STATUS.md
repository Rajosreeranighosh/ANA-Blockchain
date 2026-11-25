# ANA Blockchain — 10-step delivery and release gate

Status reviewed 2026-11-26. This file distinguishes implemented prototypes from release blockers.

## 1. Desktop GUI build verification — IN PROGRESS
- The egui QR image type error was corrected.
- Ubuntu CI passed for that GUI-only correction.
- A later Windows run failed inside `randomx-bindings-sys` while generating RandomX assembly under the `windows-latest` Visual Studio 2026 image.
- CI has been pinned to `windows-2022` / Visual Studio 2022. A fresh successful run on the latest combined branch is still required.
- The paginated-history test initially exposed a faulty test fixture; the fixture was corrected and pagination coverage expanded. Latest code still requires a fresh green CI run.

## 2. Transaction-history API — IMPLEMENTED, LIMITED
- The node exposes a bounded history page for confirmed transparent transactions.
- Records include transaction ID, direction, amount, fee, block height, timestamp and confirmations.
- Maximum page size is 1,000 records.

## 3. Reorganization-aware history — IMPLEMENTED, LIMITED
- Pages are pinned to the canonical tip hash.
- A changed tip invalidates the cursor and tells the client to restart.
- History is rebuilt from the current canonical chain; pending transactions are not included.

## 4. Wallet history screen — IMPLEMENTED, LIMITED
- ANA Wallet GUI displays confirmed incoming/outgoing/self transactions and pagination.
- This is not a stealth-output scanner and does not provide Monero-style privacy.

## 5. Backup and recovery — PARTIAL
- Existing encrypted wallet backup command copies and verifies the encrypted keystore.
- Restore is by restoring the encrypted backup file and unlocking with the original passphrase.
- There is no mnemonic seed format or seed-based recovery. Do not invent one or claim that a BIP39 phrase restores the existing ANA key.

## 6. Wallet security — PARTIAL
- Existing keystore encryption uses Argon2id and XChaCha20-Poly1305.
- GUI now auto-locks after 15 minutes without input and retains manual close-wallet.
- This is not an independent wallet security audit; OS-level secret handling and recovery still need review.

## 7. Address book — IMPLEMENTED, LIMITED
- Local labels and validated ANA public addresses can be added, updated, removed and selected for sending.
- The address-book JSON is plaintext and contains no private keys. Treat it as private user data.

## 8. Node networking — BLOCKED FOR PUBLIC DEPLOYMENT
- Current node/client protocol is plaintext TCP with a shared bearer token.
- A token sent over plaintext is not transport encryption or cryptographic peer identity.
- Do not expose node ports to the public internet. TLS or another reviewed authenticated encrypted transport, key rotation, replay protection, rate limits and adversarial tests are required.

## 9. Monero-inspired privacy — EXPERIMENTAL ONLY
- Existing stealth-address, Pedersen commitment, range-proof and balance-check modules are prototypes.
- There is no production CLSAG implementation, complete key-image/UTXO consensus state, authenticated amount encryption, privacy mempool, or private transaction consensus integration.
- Privacy transactions must remain disabled in consensus until complete cryptographic implementation, adversarial testing and independent audit.

## 10. Multi-node testnet and release validation — PARTIAL / NOT MAINNET READY
- The repository contains local TCP-level two-node propagation tests.
- A public, multi-operator, long-running testnet with hostile-peer testing, monitoring, reproducible builds, recovery drills and independent review has not been completed.

## Consensus invariants that must not change
- Maximum supply: 21,000,000 ANA.
- Atomic units: 100,000,000 per ANA.
- No premine and no tail emission.
- Block subsidy: up to 50 ANA, capped by remaining supply.
- Fees are transfers to miners, not newly minted supply.
- Keep CPU-first RandomX mining.

## Mainnet go/no-go
**NO-GO.** Do not launch mainnet or accept real funds until every security, consensus, networking, wallet-recovery, privacy and operational release gate has been independently verified. Green CI alone is not a security audit.
