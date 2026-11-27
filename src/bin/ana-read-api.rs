//! Loopback-only, read-only HTTP adapter for the ANA node query client.
//!
//! This is an experimental local gateway, not a public production endpoint.
//! The upstream node protocol is plaintext TCP and must remain on a trusted
//! loopback/private network. Never bind this process to a public interface.

use ana_blockchain::{rpc::NodeClient, NETWORK};
use serde::Serialize;
use std::{
    env,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    thread,
    time::Duration,
};

const MAX_ACTIVE: usize = 32;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_LINE: usize = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Serialize)]
struct ApiError<'a> {
    schema_version: &'static str,
    network: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
struct StatusResponse<'a> {
    schema_version: &'static str,
    network: &'a str,
    height: u64,
    tip_hash: &'a str,
    minted: u64,
    pending_transactions: usize,
}

#[derive(Serialize)]
struct AccountResponse<'a> {
    schema_version: &'static str,
    network: &'static str,
    address: &'a str,
    balance: u64,
    nonce: u64,
}

#[derive(Serialize)]
struct TransactionResponse<'a> {
    schema_version: &'static str,
    network: &'static str,
    transaction_id: &'a str,
    state: &'a str,
    confirmed_height: Option<u64>,
    confirmations: u64,
}

fn response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    origin: Option<&str>,
    allowed_origin: Option<&str>,
) -> std::io::Result<()> {
    let cors = match (origin, allowed_origin) {
        (Some(requested), Some(allowed)) if requested == allowed =>
            format!("Access-Control-Allow-Origin: {allowed}\r\nVary: Origin\r\n"),
        _ => String::new(),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nConnection: close\r\n{cors}\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn send_json<T: Serialize>(
    stream: &mut TcpStream,
    status: &str,
    value: &T,
    origin: Option<&str>,
    allowed_origin: Option<&str>,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"serialization failure\"}".to_vec());
    response(stream, status, &body, origin, allowed_origin)
}

fn parse_request(stream: &mut TcpStream) -> std::io::Result<(String, Option<String>)> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    (&mut reader).take((MAX_REQUEST_LINE + 1) as u64).read_line(&mut request_line)?;
    if request_line.len() > MAX_REQUEST_LINE || !request_line.ends_with("\r\n") {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request line"));
    }
    let mut parts = request_line.trim_end().split_ascii_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method != "GET" || !(version == "HTTP/1.1" || version == "HTTP/1.0") || parts.next().is_some() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported request"));
    }
    if !path.starts_with("/api/v1/") || path.contains('?') || path.contains('#') || path.contains('%') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"));
    }
    let mut total = request_line.len();
    let mut origin = None;
    loop {
        let mut line = String::new();
        let count = reader.read_line(&mut line)?;
        total = total.saturating_add(count);
        if count == 0 || total > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "incomplete or oversized headers"));
        }
        if line == "\r\n" { break; }
        if line.starts_with("Origin:") {
            let value = line[7..].trim();
            if value.len() > 512 || value.contains('\r') || value.contains('\n') {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid origin"));
            }
            origin = Some(value.to_owned());
        }
        if line.to_ascii_lowercase().starts_with("content-length:") &&
            line.split_once(':').map(|(_, value)| value.trim() != "0").unwrap_or(true) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "request bodies are not supported"));
        }
        if line.to_ascii_lowercase().starts_with("transfer-encoding:") {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "request bodies are not supported"));
        }
    }
    Ok((path.to_owned(), origin))
}

fn handle(mut stream: TcpStream, node: Arc<NodeClient>, allowed_origin: Option<Arc<String>>) {
    let origin_for_error = None;
    let (path, origin) = match parse_request(&mut stream) {
        Ok(value) => value,
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::InvalidInput { "400 Bad Request" } else { "400 Bad Request" };
            let _ = send_json(&mut stream, status, &ApiError {
                schema_version: "1", network: NETWORK, error: "invalid_request"
            }, origin_for_error, allowed_origin.as_deref().map(String::as_str));
            return;
        }
    };
    let origin_ref = origin.as_deref();
    let allowed = allowed_origin.as_deref().map(String::as_str);

    if path == "/api/v1/status" {
        match node.status() {
            Ok(status) if status.network == NETWORK => {
                let value = StatusResponse {
                    schema_version: "1", network: NETWORK, height: status.height,
                    tip_hash: &status.tip_hash, minted: status.minted,
                    pending_transactions: status.pending_transactions,
                };
                let _ = send_json(&mut stream, "200 OK", &value, origin_ref, allowed);
            }
            _ => {
                let _ = send_json(&mut stream, "502 Bad Gateway", &ApiError {
                    schema_version: "1", network: NETWORK, error: "upstream_unavailable_or_invalid"
                }, origin_ref, allowed);
            }
        }
        return;
    }

    if let Some(address) = path.strip_prefix("/api/v1/accounts/") {
        match node.account(address) {
            Ok((balance, nonce)) => {
                let value = AccountResponse { schema_version: "1", network: NETWORK, address, balance, nonce };
                let _ = send_json(&mut stream, "200 OK", &value, origin_ref, allowed);
            }
            Err(_) => {
                let _ = send_json(&mut stream, "400 Bad Request", &ApiError {
                    schema_version: "1", network: NETWORK, error: "invalid_address_or_upstream_error"
                }, origin_ref, allowed);
            }
        }
        return;
    }

    if let Some(id) = path.strip_prefix("/api/v1/transactions/") {
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let _ = send_json(&mut stream, "400 Bad Request", &ApiError {
                schema_version: "1", network: NETWORK, error: "invalid_transaction_id"
            }, origin_ref, allowed);
            return;
        }
        match node.transaction_status(id) {
            Ok(status) => {
                let value = TransactionResponse {
                    schema_version: "1", network: NETWORK, transaction_id: &status.transaction_id,
                    state: &status.state, confirmed_height: status.confirmed_height,
                    confirmations: status.confirmations,
                };
                let _ = send_json(&mut stream, "200 OK", &value, origin_ref, allowed);
            }
            Err(_) => {
                let _ = send_json(&mut stream, "502 Bad Gateway", &ApiError {
                    schema_version: "1", network: NETWORK, error: "upstream_unavailable_or_invalid"
                }, origin_ref, allowed);
            }
        }
        return;
    }

    let _ = send_json(&mut stream, "404 Not Found", &ApiError {
        schema_version: "1", network: NETWORK, error: "not_found"
    }, origin_ref, allowed);
}

fn main() -> anyhow::Result<()> {
    let bind: SocketAddr = env::var("ANA_READ_API_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse()?;
    if !bind.ip().is_loopback() {
        anyhow::bail!("refusing non-loopback HTTP bind; public exposure requires a separately reviewed deployment");
    }
    let node_address = env::var("ANA_NODE_ADDR")
        .map_err(|_| anyhow::anyhow!("ANA_NODE_ADDR must explicitly identify the local ANA node TCP address"))?;
    let node = Arc::new(NodeClient::new(node_address));
    let allowed_origin = env::var("ANA_READ_API_CORS_ORIGIN").ok().filter(|value| !value.is_empty()).map(Arc::new);
    let listener = TcpListener::bind(bind)?;
    let active = Arc::new(AtomicUsize::new(0));
    println!("ANA read API listening on {bind}; network={NETWORK}; upstream configured (credentials are not logged)");
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let count = active.fetch_add(1, Ordering::SeqCst);
                if count >= MAX_ACTIVE {
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let node = node.clone();
                let active = active.clone();
                let origin = allowed_origin.clone();
                thread::spawn(move || {
                    handle(stream, node, origin);
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(error) => eprintln!("HTTP accept error: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_are_required_by_main_configuration_policy() {
        for address in ["127.0.0.1:8080", "[::1]:8080"] {
            let parsed: SocketAddr = address.parse().unwrap();
            assert!(parsed.ip().is_loopback());
        }
        for address in ["0.0.0.0:8080", "192.0.2.10:8080"] {
            let parsed: SocketAddr = address.parse().unwrap();
            assert!(!parsed.ip().is_loopback());
        }
    }

    #[test]
    fn api_response_serializes_integer_balances_without_float_conversion() {
        let value = AccountResponse {
            schema_version: "1", network: NETWORK, address: "ana1example",
            balance: u64::MAX, nonce: u64::MAX,
        };
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json["balance"], serde_json::json!(u64::MAX));
        assert_eq!(json["nonce"], serde_json::json!(u64::MAX));
    }

    #[test]
    fn error_response_does_not_include_upstream_details() {
        let value = ApiError { schema_version: "1", network: NETWORK, error: "upstream_unavailable_or_invalid" };
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("private"));
    }
}
