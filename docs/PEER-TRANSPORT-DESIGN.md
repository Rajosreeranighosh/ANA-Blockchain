# ANA Peer Transport Design — mTLS 1.0 (Proposal)

**Status:** partially implemented on `ana-mtls-transport-v1`; not yet CI-validated or approved for public deployment  
**Scope:** replace the current plaintext TCP peer channel without changing consensus, transaction encoding, or chain-selection rules.

## Implementation status (2026-11-27)

The feature branch now contains TLS 1.3 client/server configuration, CA and CRL loading, ANA URI-SAN and SPKI identity checks, ALPN enforcement, strict outbound pins and inbound allowlists, test-only mutual-TLS fixtures, and a live-node transaction integration. The TLS handshake has an absolute 10-second deadline on both client and server paths. A duplicate authenticated inbound node ID is rejected while its first connection remains active; a real two-connection TLS integration test exercises rejection and identity release. The existing newline-delimited JSON framing is preserved.

The node enables this mode only when all seven variables are present:

- `ANA_PEER_CA`: PEM network CA bundle.
- `ANA_PEER_CRL`: PEM CRL bundle; required and fail-closed.
- `ANA_PEER_CERT`: this node's PEM certificate chain.
- `ANA_PEER_KEY`: this node's private key (keep outside the repository and protect filesystem permissions).
- `ANA_PEER_SERVER_NAME`: DNS name used for TLS server-name validation; the remote server certificate must contain the matching DNS SAN.
- `ANA_PEER_PINS`: exact `endpoint=node-id` mapping for every configured outbound peer.
- `ANA_PEER_ALLOWED_NODE_IDS`: explicit inbound allowlist of lowercase 64-character SPKI fingerprints.

If none of these variables is set, the node remains in loopback-only plaintext compatibility mode. If only some are set, startup fails. There is no plaintext fallback after TLS mode is selected. The legacy shared peer token remains an optional application-layer check and is not treated as node identity.

**Not yet complete:** final Windows/Ubuntu CI for the newest duplicate-connection integration, exhaustive expiry/CRL/ALPN/plaintext negative tests, a concurrent-handshake cap and bounded certificate-chain parsing budget, a multi-node block-and-transaction gossip test, certificate provisioning/rotation guidance, and independent security review. The duplicate-identity test covers the reservation lifecycle over real TLS sessions. An eight-slot inbound TLS-handshake cap is implemented with an RAII guard; a test verifies the ninth concurrent acquisition is rejected and a released slot becomes available. Accepted connections now also enforce a maximum of eight certificates and 256 KiB aggregate DER (64 KiB per certificate) before ANA identity parsing. These chain limits are post-handshake: rustls has already processed the TLS Certificate message, so they do not constitute a hard pre-handshake memory/parser-work bound. Connection-slot release is owned by an RAII guard across both TLS and plaintext handler paths, with a unit test for release. Do not expose public peer listeners or treat this branch as production-secure until all rollout gates below pass.

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

An additional per-peer SPKI pinning authorization layer is implemented after standard CA/WebPKI and CRL validation. Outbound endpoints require exact configured node-ID pins, and inbound connections require an explicit node-ID allowlist. Pinning does not replace or weaken CA verification, TLS 1.3, ALPN, or ANA network-identity checks.

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

- An absolute 10-second handshake deadline is implemented on inbound and outbound TLS handshakes. Inbound TLS handshakes are capped at eight concurrent attempts using an RAII slot guard; excess attempts are rejected, and a unit test verifies cap enforcement and slot release.
- Post-handshake certificate-chain policy is implemented: at most eight certificates, 256 KiB aggregate DER, and 64 KiB per certificate before ANA identity parsing. A hard pre-handshake TLS Certificate-message memory/parser-work bound remains outstanding and requires a rustls-supported mechanism or separately reviewed design.
- Per-peer and per-IP connection/request rate limits.
- A duplicate-identity policy is implemented with a process-wide inbound identity reservation; a real TLS integration test verifies rejection while the first connection is live and acceptance after it closes.
- Connection-slot ownership is now RAII-based from handler entry through transport processing; TLS rejection and early-return paths release the slot exactly once. Timeout and I/O-error release still need dedicated end-to-end tests.
- Metrics that expose counts and error categories but never private key material, tokens, or sensitive payloads.

TLS handshakes consume CPU and memory; the existing TCP connection cap alone is insufficient against handshake exhaustion. The eight-slot inbound cap reduces concurrent handshake pressure. Post-handshake chain-size limits constrain accepted chains but do not stop rustls from processing an oversized Certificate message before ANA can inspect it; a pre-handshake parser-work/memory bound and adversarial load testing remain outstanding.

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

## 9. Fixed node certificate profile (proposal)

The following profile removes ambiguity from the initial implementation. It remains a proposal until the implementation and test vectors exist.

- Certificates use X.509 v3, ECDSA P-256 keys, SHA-256 signatures, and a maximum validity of 90 days. Private keys are generated per node and must never be shared.
- The issuing CA certificate is a dedicated ANA network CA with `basicConstraints = critical, CA:TRUE` and `keyCertSign,cRLSign` key usage. The CA private key is kept offline.
- A node certificate has `basicConstraints = critical, CA:FALSE`, critical `digitalSignature` key usage, and both `clientAuth` and `serverAuth` extended key usages. RSA, Ed25519, wildcard DNS identities, and certificates without the required extensions are rejected in the first profile.
- The node identity is the lowercase hex SHA-256 digest of the DER-encoded SubjectPublicKeyInfo (SPKI). The URI SAN is exactly `ana://<network-id>/<node-id>`, with no query, fragment, port, percent-encoding, or additional path segment.
- `network-id` is the lowercase hex SHA-256 digest of UTF-8 bytes `ANA-NETWORK-ID-v1\0<network-name>`. The configured network name must exactly equal the chain's compiled network identifier; it is not accepted from the peer message.
- Verification must compare the URI SAN network ID to the local configured network ID and recompute the node ID from the certificate public key. It must reject missing, duplicate, malformed, or mismatched URI SANs. DNS names and common names are not identity fallbacks.
- Certificate validity is checked against the system clock with no more than 60 seconds of clock skew. The certificate chain must terminate at the explicitly configured network CA.

### Revocation profile

The first implementation must use an operator-distributed, signed X.509 CRL for the network CA. Nodes must require a configured CRL, verify its signature and issuer, enforce its `thisUpdate` and `nextUpdate` window, and reject certificates listed as revoked. A missing, invalid, or expired CRL is a fail-closed configuration error for remote peer mode. CRL refresh and emergency distribution are operator responsibilities and must be documented. Until this mechanism is implemented and tested, remote peer mode remains disabled.

### Required identity test vectors

Commit generated test-only CA, valid node certificates, and CRLs under a test-fixtures directory; never use production private keys. Tests must cover:
- SPKI-to-node-ID and network-name-to-network-ID known-answer vectors.
- Correct URI SAN acceptance and wrong-network / wrong-key / malformed / duplicate SAN rejection.
- Wrong EKU, wrong key usage, expired/not-yet-valid certificate, untrusted issuer, revoked serial, expired CRL, and wrong-issuer CRL rejection.
- A valid certificate issued for one network being rejected by another network.



## 8. Pinned rustls 0.23.46 implementation notes

The current dependency pins are recorded in `Cargo.toml` and `Cargo.lock`:

- `rustls = 0.23.46`, with the `ring` and `std` features and default features disabled.
- `rustls-pemfile = 2.2.0` for PEM decoding only.
- `x509-parser = 0.17.0` for parsing and enforcing the ANA URI subject-alternative-name identity after normal certificate-chain validation.

The implementation must use rustls' standard WebPKI verifiers on both sides. The server must construct a `rustls::server::WebPkiClientVerifier` from the explicitly configured CA root store and install it with `ServerConfig::builder().with_client_cert_verifier(...)`. The client must construct a `rustls::client::WebPkiServerVerifier` from its explicit CA root store and install it with `ClientConfig::builder().with_webpki_verifier(...)`. Do not use `allow_unauthenticated`, `no_client_auth`, a custom accept-all verifier, or an empty trust store.

Where CRLs are configured, load and parse the complete configured CRL set and pass it to both verifier builders using `with_crls`. Missing, unreadable, malformed, or empty-required CRL configuration must prevent the transport from starting. The deployment policy must explicitly choose revocation depth and unknown-status behavior; unknown status is a rejection, not an implicit allow. CRL freshness/expiry must be tested with a fixed test clock or generated fixtures and must fail closed. Do not assume that merely calling `with_crls` implements every operational freshness policy.

After chain validation, parse the authenticated peer certificate and require exactly the configured ANA network identity in the URI SAN. Reject absent, malformed, duplicate, or mismatched ANA URI SANs. Do not infer identity from the common name, DNS SAN, IP SAN, socket address, or the legacy shared token. Define and test the canonical network/node URI encoding before enabling peers.

## 9. Required negative-test matrix

The transport test suite must exercise both client and server verification paths. Tests now cover wrong outbound SPKI pins and inbound identities outside the allowlist after a valid TLS handshake; these are authorization rejections, not TLS certificate-chain handshake failures. The suite must assert TLS handshake failure (not merely an application-layer rejection) for:

1. No client certificate when the server requires mTLS.
2. No server certificate / plaintext peer attempting to speak the JSON protocol.
3. Certificate signed by an untrusted CA.
4. Expired and not-yet-valid leaf certificate.
5. Revoked leaf certificate.
6. Missing, expired, malformed, or unusable CRL configuration when revocation is mandatory.
7. Unknown revocation status under the configured fail-closed policy.
8. Correctly CA-signed certificate with missing, malformed, duplicate, wrong-network, or wrong-node URI SAN.
9. Certificate valid for a different ANA network.
10. Wrong ALPN and TLS versions below TLS 1.3.

Positive tests must prove two distinct node certificates issued by the configured test CA can establish TLS 1.3 in both directions, negotiate only `ana-peer/1`, and exchange the existing newline-delimited messages without changing their serialization. Include a multi-node gossip integration test and run all tests on Windows and Ubuntu.

These tests are a release gate. Until the lockfile is committed, the implementation compiles on both CI platforms, and this matrix passes, the loopback-only restrictions remain mandatory and the design remains unapproved for public testnet use.

## 10. Per-peer identity pin configuration (implementation contract)

The live mTLS transport must not accept an arbitrary certificate merely because it chains to the network CA. CA/WebPKI validation, CRL validation, TLS 1.3, ALPN, and the ANA URI-SAN/SPKI consistency check remain mandatory; node pins add an authorization check after certificate validation.

The operator configuration contract for the implementation is:

- `ANA_PEER_PINS`: comma-separated `endpoint=node-id` entries, where endpoint is exactly the peer endpoint string supplied on the node command line and node-id is the expected lowercase 64-character SHA-256 SPKI fingerprint.
- `ANA_PEER_ALLOWED_NODE_IDS`: comma-separated lowercase 64-character SHA-256 SPKI fingerprints permitted to initiate inbound connections.
- Empty entries, whitespace-padded entries, duplicate endpoints, duplicate node IDs, malformed fingerprints, and unrecognized endpoints are configuration errors. No wildcard, implicit trust, or default allow-all behavior is permitted.
- When mTLS is enabled, both variables are required. Every configured outbound endpoint must have exactly one pin. Inbound authentication must match the explicit allowlist.
- The endpoint mapping is an operator-managed address-to-identity association, not a cryptographic identity itself. DNS/IP changes require updating the endpoint entry without changing the certificate identity.
- Inbound mTLS handshakes are capped at 8 concurrent attempts; excess attempts are rejected and the slot is released on every exit path. The node also retains its 10-second absolute handshake deadline.
- ANA's post-handshake identity parser rejects an individual end-entity certificate larger than 64 KiB DER before invoking the X.509 parser. This is not yet a total certificate-chain/handshake-message memory budget: rustls performs chain processing during the handshake, so a separately reviewed bound on aggregate chain size and parsing work remains outstanding.
- The same node ID must not be admitted through multiple simultaneous inbound connections. The current inbound path reserves identity only after successful TLS, network-identity, and allowlist verification; the guard releases it when the connection handler exits. A real TLS integration test verifies duplicate rejection and subsequent reuse after the first session closes.
- These variables are parsed and validated at startup and enforced by the live outbound/inbound handshake paths. Do not deploy mTLS on public interfaces until all remaining rollout gates are satisfied.

This configuration is intentionally explicit and fail-closed. Do not silently derive expected node IDs from the presented certificate, since that would make pinning meaningless.

