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

The test suite includes a TCP-level node protocol smoke test that starts a local listener and verifies a real `get_status` request/response using the configured peer-authentication envelope.

```
```

## Create an encrypted miner wallet
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
- Nodes maintain a persistent local transaction mempool, validate sender signatures/nonces/balances, include eligible pending transactions in mined blocks, and update balances/nonces when blocks are accepted. Pending transactions are removed after confirmation and restored entries are revalidated at restart. Mempools are local node state, not consensus data.
- Nodes validate full candidate chains from genesis and select by cumulative proof-of-work; equal-work ties use the smaller tip hash. Reorganizations replay blocks to rebuild balances/nonces. Displaced transactions are revalidated in the local mempool. This is a minimal testnet rule, not adversarially hardened consensus.
- Difficulty starts at 8 bits and retargets every 10 completed blocks using the elapsed time across that window. Each retarget changes difficulty by at most one bit, with experimental bounds of 4–24 bits and a 30-second target interval. New blocks must have timestamps strictly greater than the median of up to the previous 11 block timestamps (median-time-past); miners choose a timestamp at least one second beyond both the previous tip and that median.
- RandomX uses one fixed testnet seed; no epoch seed schedule exists.
- Peer messages use an optional shared ANA_PEER_TOKEN; without it, inbound connections are loopback-only. The node limits concurrent inbound connections, message size, and socket timeouts. The token is sent over plaintext TCP, so use a trusted private network or VPN. There is no TLS, peer identity system, rate limiting, or peer discovery.
- The JSON-based consensus header encoding is deterministic for this Rust struct today but is not yet a formally versioned canonical wire format.
- Wallet keystores use Argon2id and XChaCha20-Poly1305 encryption, support legacy-key migration and encrypted backups, and can query a node for balance/nonce before sending. Transaction admission acknowledgements indicate mempool acceptance, not block confirmation.
- Transaction status is node-local. Confirmations count the inclusion block as 1 and may decrease to zero after a chain reorganization; this prototype has no deterministic finality.
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


### Persistent mempool (experimental)

Each node stores pending transactions in a sibling file named `<chain-data-file>.mempool.json`. The node writes snapshots through a temporary file and atomic rename, then restores the pool at startup. Restored entries must have a valid signature, matching transaction ID, and be executable against the currently validated ledger; stale, malformed, or unexecutable entries are discarded. Confirmed transactions are removed, and the pool is revalidated after chain updates and reorganizations. This is local node state, not consensus data, and peers may have different mempools.


### Peer network safeguards (experimental)

The node limits inbound work to 64 concurrent connections, caps each newline-delimited JSON message at 8 MiB, and applies 10-second socket read/write timeouts and outbound connect timeouts. Malformed, incomplete, oversized, and unauthenticated messages are rejected.

For nodes communicating across machines, set the same high-entropy `ANA_PEER_TOKEN` environment variable on every node before starting it. The token is sent as a shared bearer secret over the existing TCP transport. **This transport is not encrypted**: use a trusted private network or VPN, and do not expose the peer port to the public internet without a TLS/VPN layer. If the token is unset, inbound connections are accepted only from loopback addresses, so remote peers cannot connect. These controls reduce basic resource abuse but do not replace TLS, rate limiting, authenticated key identities, or protocol-level sync pagination.


## Wallet security v1 (experimental)
New wallets created by `ana-wallet new` are encrypted at rest with Argon2id key derivation and XChaCha20-Poly1305 authenticated encryption. The CLI prompts for the passphrase without echoing it; passphrases must be at least 12 characters. The wallet file is written atomically and restricted to owner read/write permissions on Unix. The passphrase is never stored in the file or accepted as a command-line argument.

**Back up the encrypted wallet file and store the passphrase separately.** Losing either means losing access; there is no password reset or recovery service. Anyone who obtains both can spend the wallet. Keep backups offline and never upload wallet files or passphrases to GitHub. Existing plaintext wallet files from earlier versions are not automatically imported by this CLI; preserve them securely until a separately reviewed migration tool exists. This is experimental software, not audited custody software.


## Legacy wallet migration and encrypted backup
To migrate a pre-v1 plaintext wallet without changing its address or private key:
```sh
cargo run --release --bin ana-wallet -- migrate old-wallet.json new-wallet.encrypted.json
```
The command prompts twice for a new passphrase, refuses to overwrite the destination, and leaves the original wallet untouched. Verify the new wallet address and backup before securely removing any plaintext copy.

To create and verify a copy of an encrypted wallet:
```sh
cargo run --release --bin ana-wallet -- backup wallet.encrypted.json wallet-backup.encrypted.json
```
The backup command first unlocks the source, refuses to overwrite an existing destination, writes an owner-only file on Unix, then verifies that the copied keystore can be unlocked. Store the passphrase separately from both wallet copies. Keep at least two backups in separate secure locations. Never commit wallet files or passphrases to source control. A forgotten passphrase cannot be reset.


## Reusable wallet library API (v1)

Applications can use the public `Wallet` type from the `ana_blockchain` crate instead of shelling out to the CLI:

```rust
use ana_blockchain::Wallet;
use std::path::Path;

let wallet = Wallet::open(
    Path::new("wallet.encrypted.json"),
    b"your wallet passphrase",
)?;
println!("Address: {}", wallet.address());

let tx = wallet.sign_transaction(
    "ana1<recipient-public-key-hex>",
    1_000_000, // 0.01 ANA in atomic units
    10_000,    // 0.0001 ANA fee
    0,         // nonce obtained from the node
)?;
println!("Signed transaction: {}", tx.id()?);
```

The API supports encrypted wallet creation, unlocking, public address/key access, and transaction signing. It does not store passphrases, query node balances, broadcast transactions, or manage nonce state; applications must obtain the current nonce from a trusted node and submit the returned signed transaction using the node protocol. Keep unlocked wallet handles short-lived. This API is experimental and has not been independently audited.


## Node query API v1 (experimental)

The node accepts authenticated newline-delimited JSON requests on its configured TCP port. These read-only queries use the same peer authentication policy as the node protocol: set the same `ANA_PEER_TOKEN` on both sides, and use a trusted private network or VPN because this TCP transport is not encrypted. With no token configured, inbound connections are loopback-only.

- `{"kind":"get_status"}` returns `kind: "node_status"` with network, current height, tip hash, minted atomic units, and pending transaction count.
- `{"kind":"get_account","address":"ana1..."}` returns projected balance and next nonce, including valid locally pending transactions. Invalid addresses are ignored.
- `{"kind":"get_transaction","transaction_id":"<transaction-id>"}` returns `confirmed` plus block height, `pending`, or `not_found`.

Transaction status is the responding node's local view; pending transactions are not consensus-final and nodes can temporarily disagree. A transaction marked confirmed can still be affected by a later chain reorganization. This is the existing bounded TCP protocol, not a separate public HTTP/REST service. Do not expose it directly to the public internet.


## Wallet-to-node integration v1

The wallet CLI uses the reusable `ana_blockchain::rpc::NodeClient` for authenticated node queries and transaction submission. Configure the same `ANA_PEER_TOKEN` on the wallet and node when token authentication is enabled. Without a token, the node accepts loopback connections only. The TCP connection is plaintext: use a trusted private network or VPN, never expose it directly to the public internet.

New commands:

- `ana-wallet status <node-ip:port>` — network, height, tip hash, minted supply, pending count.
- `ana-wallet tx-status <transaction-id> <node-ip:port>` — node-local pending/confirmed/not-found view.
- `ana-wallet balance <address> <node-ip:port>` — validated address balance and next nonce.
- `ana-wallet send ...` — uses the same authenticated client for balance lookup and signed transaction submission.

The current transaction-submit protocol has no admission acknowledgement. A successful send command means the request was written to the TCP connection, not that the node accepted it; query `tx-status` afterward. A `not_found` result may be temporary or indicate rejection. Status is node-local and confirmations can be reorganized.


## Transaction admission acknowledgements v1

When a wallet submits a signed transaction, the node now replies with a `transaction_result` message containing the transaction ID and an admission state:

- `accepted` — verified and admitted to this node's mempool.
- `already_known` — the node has already seen this transaction ID.
- `rejected` — invalid signature, nonce, balance, or ordering, or an internal admission failure.

The wallet verifies that the acknowledgement ID matches the submitted transaction and reports rejection rather than treating a successful TCP write as acceptance. Admission is not confirmation: continue using `ana-wallet tx-status` until the transaction is included in a block. Node status remains local and a later reorganization can change confirmation status.


## Waiting for transaction confirmations

The wallet can poll a node until a transaction reaches a requested confirmation count or a timeout expires:

```sh
cargo run --release --bin ana-wallet -- wait-confirmations <transaction-id> 127.0.0.1:19001 6 600
```

The example waits for 6 confirmations for up to 600 seconds, checking every 5 seconds. The command reports the node's current local status and fails on timeout; it does not cancel or reverse the transaction. A reorganization can reduce the confirmation count, so reaching a threshold is not deterministic finality. Use a trusted node and the same `ANA_PEER_TOKEN` configuration as other wallet RPC commands.
