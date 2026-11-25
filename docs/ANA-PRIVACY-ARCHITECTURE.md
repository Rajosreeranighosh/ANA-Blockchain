# ANA Privacy Transaction Architecture (Draft v1)

## Status

Design and wire-model groundwork only. The current ANA consensus still uses
transparent Ed25519 account transactions. The new `privacy` module is not
connected to block validation, mempool admission, mining, wallets, or RPC.

**Nothing in this draft currently provides transaction privacy or cryptographic
spend validation.** The structural validator checks serialization bounds only.

## Fixed ANA economics

- Maximum supply remains **21,000,000 ANA**.
- Existing atomic unit remains 1 ANA = 100,000,000 atomic units.
- Existing initial block subsidy remains 50 ANA, subject to the existing cap.
- Fees are transferred to miners and are not newly minted.
- Privacy work must preserve the supply cap and reward accounting.

## Intended transaction model

The intended private transaction has:

1. Inputs referencing rings of previously created outputs.
2. A unique key image per real spent output to prevent double spends without
   revealing which ring member was spent.
3. Pseudo-output commitments and output Pedersen commitments.
4. One-time destination keys and encrypted amounts.
5. A range proof proving output amounts are in range.
6. A linkable ring signature (CLSAG-family design) proving ownership of one
   ring member without revealing which one.
7. Explicit fees, so the consensus layer can account for miner revenue.

The initial wire-model ring size is 16. This is a protocol draft parameter,
not a privacy guarantee. Ring member selection, maturity, decoy distribution,
and fork/version rules remain to be specified and tested.

## Consensus verification requirements

Before any private transaction is accepted by a node, consensus must verify:

- Every referenced output exists and is eligible for spending.
- Ring members are valid, distinct, and selected under deterministic rules.
- Key images are valid curve points, correctly derived, and globally unique.
- CLSAG signatures are cryptographically valid.
- Pedersen commitments are valid and balance:
  sum(input commitments) = sum(output commitments) + fee commitment.
- Range proofs verify and prevent negative or overflowing amounts.
- Fees and miner reward obey the 21-million ANA supply cap.
- Reorg handling restores spent-output and key-image state consistently.

The node must reject unknown transaction versions and malformed cryptographic
encodings. Consensus rules must be deterministic across implementations.

## Wallet requirements

A future privacy wallet needs separate spend and view keys, subaddress support,
one-time output derivation, blockchain scanning, encrypted amount recovery,
output selection, decoy selection, key-image generation, and secure backups.
The current Ed25519 account wallet is not a substitute for this design.

## Implementation sequence

1. Freeze this versioned data model and add serialization/structural tests.
2. Select and independently review a maintained curve/cryptography stack.
3. Implement stealth-address derivation and wallet scanning.
4. Implement commitments, authenticated amount encryption, and range proofs.
5. Implement CLSAG-compatible signing and verification plus key-image checks.
6. Add a separate privacy UTXO/key-image state and reorg-safe persistence.
7. Integrate private transactions into mempool, blocks, wallet and RPC.
8. Add adversarial tests, cross-node test vectors, independent audit, then a
   dedicated privacy testnet. Do not activate on the existing testnet by
   silently changing consensus.

## Security references

- Monero source: https://github.com/monero-project/monero
- Monero developer library: https://web.getmonero.org/library/
- Zero to Monero, second edition: https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
- Monero RingCT overview: https://web.getmonero.org/resources/moneropedia/bulletproofs.html

Do not copy Monero's code without reviewing its license and dependency
requirements. Do not invent cryptographic primitives or treat placeholder
bytes as proofs.
