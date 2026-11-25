# ANA Wallet GUI (experimental)

ANA Wallet GUI is a native desktop application built with Rust and egui/eframe. It is intended to run on Windows 10/11 and Linux desktop environments, including Ubuntu.

## Build

Install Rust stable and the platform's native build prerequisites from the repository README. On Ubuntu/Debian, install:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libgl1-mesa-dev libx11-dev libx11-xcb-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libxkbcommon-x11-dev
```

Build and run:

```sh
cargo build --release --bin ana-wallet-gui
cargo run --release --bin ana-wallet-gui
```

The same Cargo commands work in Windows PowerShell after installing Rust MSVC, Visual Studio C++ Build Tools, and CMake.

## Current screens

- Overview: local wallet address, balance and next nonce queried from an ANA node.
- Send: recipient, ANA amount, fee, transaction review and explicit confirmation before signing/submitting.
- Receive: address and QR code.
- Transactions: bounded, paginated confirmed-chain history for the wallet address, plus transaction-ID status lookup.
- Address book: validated local contacts that can populate the Send recipient field.
- Security: automatic wallet lock after 15 minutes without input; manual close-wallet control remains available.
- Settings: node endpoint and close-wallet control.

## Current limitations and security notes

- The local address book is a separate, unencrypted JSON file containing labels and public addresses only; it is ignored by Git and should still be treated as private user data.
- The GUI reuses the existing encrypted wallet keystore. For an encrypted backup, use `cargo run --release --bin ana-wallet -- backup wallet.encrypted.json wallet-backup.encrypted.json`; the command verifies the copy. Restoring requires copying the encrypted backup back to a wallet file and unlocking it with the original passphrase.
- This first GUI version uses the existing encrypted ANA keystore (Argon2id + XChaCha20-Poly1305). It does not implement a mnemonic seed, hardware wallet support, subaddresses, multisig, or wallet restore from a seed phrase.
- Wallet history currently scans confirmed transparent transactions from the node's canonical chain. Pages are bounded to at most 1,000 records and pinned to a tip hash; if the tip changes during pagination, restart the scan. Pending transactions are not yet included in the history list.
- History is transparent-account history, not private-output scanning. A future stealth wallet scanner requires key-image/output-index integration and cannot be inferred from this API.
- Node communication is the existing plaintext TCP protocol. Use localhost, or a trusted VPN/private network with the configured peer token. Never expose the node port directly to the public internet.
- Private transactions are not enabled in consensus. The GUI does not imply that ANA currently offers Monero-level transaction privacy.
- This is experimental testnet software. Do not use real funds; do not treat it as audited wallet software.
