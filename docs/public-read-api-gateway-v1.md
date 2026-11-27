# ANA Public Read API Gateway — v1 design

**Status: design only. Not implemented. Not a launch or deployment guarantee.**

This document defines the next safe boundary between the ANA node and the separate ANA Website. The browser must never speak the node's internal TCP protocol directly.

## Existing node capabilities

The development node has a newline-delimited JSON TCP protocol and persistent local chain state. Its internal query operations include:

- `get_status`: network identifier, local chain height, tip hash, minted amount, and pending transaction count.
- `get_account`: account balance and nonce for a validated ANA address.
- `get_transaction`: local transaction state (`confirmed`, `pending`, or `not_found`), with confirmation metadata when confirmed.

The Rust `NodeClient` also supports transaction submission. That is a write operation and is explicitly out of scope for this public read API. The current peer transport is not a public HTTP service; do not expose its TCP port to the internet.

## Proposed HTTP contract

The gateway should expose only these read-only routes initially:

| Route | Purpose | Data source |
|---|---|---|
| `GET /api/v1/status` | Node/network status | `get_status` |
| `GET /api/v1/accounts/{address}` | Public account balance and nonce | `get_account` |
| `GET /api/v1/transactions/{transaction_id}` | Local transaction lookup | `get_transaction` |

No block-list or block-detail endpoint is promised in v1 until the canonical block response schema, pagination, and reorganization semantics have dedicated tests.

### Response rules

- Return JSON with a stable `schema_version` field and explicit `network` identity.
- Preserve integer values as JSON integers; never convert balances to floating-point.
- Return `Cache-Control: no-store` for account and transaction lookups. Status may use a short, documented cache only after monitoring exists.
- Distinguish a node's local view from network-wide finality. A `confirmed` transaction response is the queried node's local chain view, not a finality guarantee.
- Use consistent errors: `400` invalid input, `404` unknown route/resource where appropriate, `429` rate limit, `502` upstream node unavailable/invalid response, and `503` gateway not ready.
- Bound request-line, header, response, concurrency, and upstream timeouts. Validate address and transaction-ID syntax before contacting the node.

## Mandatory security boundary

1. Bind the gateway to loopback or a private interface during development. Public exposure requires a separately reviewed deployment design.
2. Connect only to an explicitly configured local node address. Never accept a node address from a browser request.
3. Keep peer tokens, TLS private keys, CA/CRL files, and node credentials server-side. Never embed them in website assets, JavaScript, HTML, source maps, or API responses.
4. Do not enable transaction submission, wallet signing, mining controls, peer administration, or arbitrary RPC forwarding through this gateway.
5. Apply request rate limits, strict CORS allowlists, security headers, structured redacted logs, and health checks. Do not log credentials or sensitive request headers.
6. Fail closed on a wrong network identifier, malformed JSON, oversized responses, invalid node status, or upstream timeout.
7. Run the gateway as a separate least-privilege process. It must not have access to wallet seed phrases or node private keys beyond the minimum client credential material it requires.

## Required tests before website integration

- Unit tests for every response schema, integer boundary, invalid address, malformed transaction ID, and error mapping.
- Integration tests against a disposable local node proving the HTTP result matches the node's internal query result.
- Negative tests for wrong network, upstream disconnect, timeout, oversized response, malformed JSON, rate limiting, and disallowed browser origin.
- Security tests proving there are no write routes, arbitrary upstream targets, credential leaks, or unauthenticated access to the node TCP listener.
- End-to-end website tests against a controlled test endpoint. The explorer must remain in its unavailable state if the endpoint is missing or fails validation.

## Delivery sequence

1. Implement the gateway as a separate binary/service; do not add HTTP handling to the peer protocol.
2. Add the tests above and run Windows and Ubuntu CI for the node plus gateway.
3. Deploy only to a private test environment and verify metrics and logs.
4. Publish a monitored, read-only testnet endpoint after review.
5. Then connect the separate `ANA-Website` explorer to that fixed endpoint. Keep the wallet concept nonfunctional until a separately reviewed wallet architecture exists.

Until these steps are complete, the website must continue to state that live explorer data is unavailable.
