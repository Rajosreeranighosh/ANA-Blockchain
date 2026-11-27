# Security Policy

## Scope and status

ANA is experimental testnet software. It is not audited, does not provide deterministic transaction finality, and must not be used to store or transfer real funds. A successful CI run is not a security audit or a mainnet-readiness claim.

## Reporting a vulnerability

Do not publish exploit details or private keys in public issues. Report suspected vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting feature, if enabled. Include:
- affected commit or release;
- affected component and platform;
- reproducible steps and expected impact;
- a minimal proof of concept that does not target third-party systems.

Allow maintainers time to investigate and prepare a fix before public disclosure. Never include seed phrases, wallet files, passphrases, or live peer tokens in a report.

## Security invariants

Changes to consensus or cryptography must preserve and test:
- maximum supply of 21,000,000 ANA and 100,000,000 atomic units per ANA;
- no premine or tail emission;
- block subsidy is derived by consensus and fees are transfers, not issuance;
- transaction signatures, sender ownership, nonce ordering, and checked arithmetic;
- deterministic block validation and chain replay;
- no enabling experimental private-transaction code without complete verification and independent review.

## Contributor requirements

- Prefer established, maintained cryptographic libraries; do not invent cryptographic primitives.
- Do not change proof-of-work, serialization, signature rules, genesis, or other consensus behavior without vectors, migration/fork analysis, and explicit review.
- Add adversarial tests for every consensus validation change.
- Never commit wallet files, passphrases, peer tokens, or production secrets.
- Treat all peer data as untrusted and bound parsing, memory, CPU, and connection use.
- A green CI badge is necessary but not sufficient for release.
