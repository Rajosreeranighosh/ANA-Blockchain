# ANA Peer Certificate Operations (Draft)

**Status:** operator runbook draft; not approved for production or public testnet.  
**Applies to:** the mTLS transport on `ana-mtls-transport-v1`.

This document describes the operational sequence only. It does not create keys, issue certificates, distribute secrets, or enable remote listeners. Have an independent security reviewer validate the CA, certificate, CRL, and deployment procedures before use.

## 1. Security invariants

- Maintain a separate offline issuing CA for each ANA network. Never place the CA private key in this repository or on a peer node.
- Generate each node's private key on that node. Do not reuse keys between nodes or send private keys over chat, email, or source control.
- Use the certificate profile in [PEER-TRANSPORT-DESIGN.md](PEER-TRANSPORT-DESIGN.md): X.509 v3, ECDSA P-256, SHA-256, node certificate validity no longer than 90 days, required client/server EKUs and key usage, and exactly one URI SAN.
- The URI SAN must be exactly `ana://<network-id>/<node-id>`. The network ID is derived from the compiled network name; the node ID is SHA-256 of DER SubjectPublicKeyInfo. Do not invent or manually type either fingerprint.
- Distribute the CA certificate, signed CRL, and peer pin/allowlist changes through an authenticated out-of-band operator channel.
- A missing, unreadable, empty, invalid, or expired required CRL is a deployment stop condition. Do not bypass it.
- Keep the listener loopback-only until all transport rollout gates, cross-platform CI, multi-node tests, and independent review are complete.

## 2. Issue a node identity

1. Confirm the target network name and its compiled identifier with the release being deployed.
2. Generate a fresh private key on the target node using the approved cryptographic tooling and restrictive filesystem permissions.
3. Generate a certificate signing request from that node. The private key must remain on the node.
4. Have the offline network CA operator validate the node owner, endpoint, network, requested key profile, and intended node ID before issuing.
5. Issue a certificate with the required extensions and a validity period of at most 90 days.
6. Independently verify the certificate chain, key usage, EKUs, validity, exact single URI SAN, network ID, and SPKI-derived node ID.
7. Record the node ID and endpoint-to-node mapping in the operator's access-controlled inventory. Never record private key bytes.

## 3. Configure a node

Provide the following paths and values through the node's protected service environment, not through command-line arguments or committed files:

- `ANA_PEER_CA`: trusted network CA PEM bundle.
- `ANA_PEER_CRL`: current signed network CRL PEM.
- `ANA_PEER_CERT`: this node's certificate chain.
- `ANA_PEER_KEY`: this node's private key.
- `ANA_PEER_SERVER_NAME`: DNS name that matches the remote server certificate DNS SAN.
- `ANA_PEER_PINS`: exact comma-separated `endpoint=node-id` entries for every configured outbound peer.
- `ANA_PEER_ALLOWED_NODE_IDS`: explicit comma-separated lowercase 64-hex SPKI IDs allowed inbound.

Before starting, verify that every outbound endpoint has exactly one pin, every intended inbound peer is allowlisted, and no unknown or duplicate entries exist. Keep CA trust and CRL validation enabled; pins are an additional authorization layer, not a replacement.

Protect key files with owner-only permissions appropriate to the operating system. Ensure backups are encrypted and access-controlled. Never log environment values, private keys, or certificate contents.

## 4. Stage and validate a rotation

1. Issue a replacement certificate using a newly generated node key. Keep the old certificate active during the planned overlap.
2. Compute and independently verify the replacement SPKI node ID.
3. Distribute the replacement node ID to every peer's outbound pin configuration and inbound allowlist where applicable.
4. Distribute the refreshed CA/CRL material through the operator channel and confirm all nodes have loaded it.
5. Start or restart the replacement identity only on the isolated test network. Verify TLS 1.3, ALPN `ana-peer/1`, network URI SAN, CA chain, CRL status, and both pin directions.
6. Confirm block and transaction gossip and monitor connection rejection counters.
7. After all peers have migrated, revoke the old certificate, publish a newly signed CRL, and distribute it to every node.
8. Verify the old certificate is rejected and the replacement remains accepted. Retain an auditable record of approvals and timestamps.

Do not revoke the old certificate until the replacement has been proven across the full peer set, unless responding to a key compromise.

## 5. Emergency compromise procedure

If a node private key is suspected compromised:

1. Isolate the affected node and stop its peer service.
2. Revoke the certificate through the offline CA process and publish a newly signed CRL.
3. Remove the compromised node ID from inbound allowlists and outbound pin maps.
4. Distribute the updated CRL and pin/allowlist configuration through the authenticated operator channel.
5. Generate a new private key on the recovered node and issue a new certificate with a new SPKI node ID.
6. Verify that every peer rejects the old identity and accepts only the replacement identity.
7. Preserve incident records without retaining exposed private key material.

## 6. CRL freshness and monitoring

- Track each CRL's issuer, signature validity, `thisUpdate`, and `nextUpdate`.
- Schedule refresh early enough to distribute and verify the new CRL before the current CRL expires.
- Treat an expired or unavailable CRL as a fail-closed outage, not a reason to disable revocation checks.
- Alert on certificate expiry, CRL expiry, unexpected node IDs, pin mismatches, allowlist rejections, handshake timeouts, and handshake-cap rejections.
- Never include private keys, tokens, or full sensitive peer payloads in logs.

## 7. Release checklist

A deployment is not approved merely because certificates can connect. Require all of the following:

- [ ] Operator CA generation, custody, issuance, backup, and recovery procedures independently reviewed.
- [ ] Certificate profile and node/network ID test vectors verified.
- [ ] Rotation and emergency revocation rehearsed with multiple operators.
- [ ] Windows and Ubuntu CI pass on the exact release commit.
- [ ] Negative tests cover unknown CA, missing/revoked/expired certificate, wrong network, wrong pin, inbound not-allowlisted identity, wrong ALPN, and TLS below 1.3.
- [ ] Handshake timeout, connection-slot release, and resource-exhaustion tests pass.
- [ ] Multi-node block and transaction gossip passes with distinct node identities.
- [ ] Aggregate TLS Certificate-message memory/parser-work bounds are reviewed; post-handshake ANA chain limits alone are not a pre-handshake DoS defense.
- [ ] Independent security review completed and findings resolved.
- [ ] Public networking explicitly approved by maintainers after all rollout gates pass.

Until every item is complete, use only isolated loopback test environments. This runbook does not authorize public peer binds or mainnet deployment.
