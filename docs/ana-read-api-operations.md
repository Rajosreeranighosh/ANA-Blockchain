# Running the experimental ANA read API

**Experimental local service only. Do not expose it to the public internet.**

The `ana-read-api` binary is a small HTTP adapter around the existing `NodeClient`. It is deliberately restricted to loopback addresses because the upstream node protocol is newline-delimited TCP and is not a public HTTP interface.

## Build and configure

Run the node on a loopback address, for example:

```sh
cargo run --bin ana-node -- 127.0.0.1:3030 ./ana-chain.json none
```

In a second process, configure the gateway:

```sh
ANA_NODE_ADDR=127.0.0.1:3030
ANA_READ_API_BIND=127.0.0.1:8080
# Optional exact browser origin; omit to send no CORS permission:
ANA_READ_API_CORS_ORIGIN=https://rajosreeranighosh.github.io
cargo run --bin ana-read-api
```

On Windows PowerShell, set the same variables with `$env:NAME="value"` before running `cargo run --bin ana-read-api`.

If the node is configured with `ANA_PEER_TOKEN`, start the gateway with the same token in its environment. Do not put the token in website files or browser requests.

The gateway rejects non-literal or non-loopback upstream addresses and non-loopback bind addresses. It supports only GET requests, bounded request headers, a fixed route set, bounded concurrent connections, and no request body. Responses use JSON integers, include the schema and network identity, and set `Cache-Control: no-store`.

## Routes

- `GET /api/v1/status`
- `GET /api/v1/accounts/{ana_address}`
- `GET /api/v1/transactions/{64_hex_transaction_id}`

This first implementation has no block endpoints, no write routes, no arbitrary RPC forwarding, no OPTIONS/preflight support, and no public deployment configuration. Browser access is permitted only for the exact configured CORS origin; same-origin or server-side clients can call it without an Origin header.

## Before any public testnet deployment

The service still needs full integration tests against a disposable node, request-rate limiting, stronger HTTP parser tests, operational metrics and health checks, TLS termination/reverse-proxy design, deployment secrets handling, independent security review, and Windows/Ubuntu CI. It is not yet a supported public API. The separate ANA Website must not be pointed at this loopback address; a hosted monitored endpoint is required first.
