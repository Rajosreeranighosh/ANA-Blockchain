# ANA Peer Transport Design — mTLS 1.0 (Proposal)

**Status:** design only; not implemented or approved for public deployment  
**Scope:** replace the current plaintext TCP peer channel without changing consensus, transaction encoding, or chain-selection rules.

## 1. Security goals

The peer transport must provide:

- TLS 1.3 confidentiality and integrity for every peer message.
- Mutual authentication: both endpoints prove possession of a node certificate private key.
- Explicit trust policy: a node accepts only certificates issued by its configured ANA network CA, or explicitly pinned peer identities.
- Network separation: a certificate trusted for one ANA network must not automatically authenticate on another.
- Bounded resource use before, during, and after TLS handshakes.
- Certificate rotation and revocation procedures that do not require sharing one network-wide secret.

TLS protects the channel; it does not make peer-provided blocks or transactions valid. Consensus validation remains authoritative.

## 2. Proposed implementation

Use a maintained Rust TLS 1.3 implementation (rustls) and its maintained platform-independent crypto provider. Pin compatible versions in Cargo.toml and commit Cargo.lock before implementation. Do not write custom cryptography or silently fall back to plaintext.

Keep the current synchronous TCP architecture initially. Wrap accepted and outbound sockets in rustls server/client connections. Configure TLS 1.3 only, disable obsolete protocol versions and insecure cipher suites, and use a dedicated ALPN identifier such as ana-peer/1.

The listener must continue rejecting non-loopback binds until the complete TLS implementation, configuration validation, and negative tests are merged. There must be no environment-variable or command-line option that bypasses TLS for a remote bind.

## 3. Node identity and trust

Each node has a distinct certificate and private key. The private key is generated and stored locally with restrictive filesystem permissions; it is never transmitted, committed, logged, or copied to another node.

The initial deployment model should use an operator-managed private CA per network:

- The CA certificate is distributed out-of-band and configured as a trust anchor.
- Each node certificate contains a network-scoped identity in a URI SAN, for example ana://<network-id>/<node-id>.
- <node-id> is derived from a documented hash of the certificate public key (the exact algorithm and encoding must be fixed in the implementation spec).
- Both client and server certificate verifiers validate the certificate chain, validity period, allowed key usage, expected network identity, and SAN format.
- A certificate trusted by the CA but carrying a different network ID is rejected.
- Unknown certificates and missing client certificates are rejected by default.

Do not treat a shared ANA_PEER_TOKEN as peer identity. Remove it from the wire protocol only after migration behavior is specified. Do not accept an empty trust store or silently trust any self-signed certificate.

A future pinned-peer mode may be added, but it must use explicit public-key fingerprints and the same network-identity checks. It must not weaken CA verification by default.

## 4. Rotation and revocation

Define an operator procedure before production use:

1. Issue a replacement certificate while the old certificate remains valid.
2. Distribute updated trust/revocation material to peers.
3. Confirm peers recognize the replacement identity.
4. Rotate the node certificate and verify successful mutual authentication.
5. Revoke the old certificate and verify it is rejected.

Define how revocation is distributed and how stale revocation data is handled. If reliable revocation cannot be guaranteed, short-lived certificates and explicit operator pin updates are required; this is an operational risk, not something TLS alone solves.

## 5. Protocol and replay considerations

- Keep application messages inside the authenticated TLS stream.
- Preserve strict frame-size limits and read/write deadlines after the TLS handshake.
- Authenticate the peer before deserializing application JSON.
- Bind the negotiated ALPN and expected network ID to the connection configuration.
- TLS 1.3 record protection prevents undetected modification and ordinary network replay across independent sessions. Application-level commands must still be idempotent or validated against current chain/mempool state.
- If future sessions carry resumable state or privileged commands, specify session binding and replay semantics separately; do not assume a TLS connection authenticates a particular transaction.
- Do not change JSON serialization, transaction IDs, block hashes, signatures, or consensus rules as part of this transport change.

## 6. Resource controls

Retain and test the existing maximum connection count, socket timeouts, and message-size limits. Add:

- A handshake deadline and a cap on concurrent handshakes.
- A bounded certificate-chain size and certificate parsing budget.
- Per-peer and per-IP connection/request rate limits.
- A policy for duplicate connections from the same authenticated node identity.
- Clean shutdown and deterministic release of connection slots after handshake failure, timeout, or I/O error.
- Metrics that expose counts and error categories but never private key material, tokens, or sensitive payloads.

TLS handshakes consume CPU and memory; the existing TCP connection cap alone is insufficient against handshake exhaustion.

## 7. Required tests

### Positive tests
- Two nodes with certificates issued by the same test CA and matching network identity can exchange status and transaction messages.
- The same tests pass on Windows and Ubuntu.
- A rotated certificate works during the documented overlap window.

### Negative tests
- Missing client certificate is rejected.
- Unknown CA, expired certificate, wrong network SAN, malformed SAN, and wrong key usage are rejected.
- A client connecting to an impostor server is rejected.
- TLS 1.2 and plaintext connections are rejected.
- Wrong ALPN is rejected.
- Oversized certificate chains and stalled handshakes are bounded and do not exhaust connection slots.
- Revoked certificates are rejected according to the documented revocation policy.
- No remote bind is possible when TLS or trust configuration is absent or invalid.

### Regression tests
- Existing message-size, connection-count, chain-sync, mempool, and duplicate-cache tests remain green.
- A malformed or malicious peer message still cannot bypass consensus validation.
- No consensus known-answer vector changes.

## 8. Rollout gates

Do not enable public peer binds until all of the following are true:

1. The design is reviewed and the exact certificate identity and revocation formats are specified.
2. TLS 1.3 mutual authentication is implemented with a maintained library and no plaintext fallback.
3. Positive, negative, resource-exhaustion, and cross-platform tests pass in CI.
4. The operator certificate provisioning, backup, rotation, and revocation guide is published.
5. Independent security review covers the TLS configuration and identity-verification code.
6. A multi-operator testnet demonstrates recovery from certificate expiry, rotation, and revocation.

Even after these gates, transport security does not establish consensus safety or mainnet readiness.
