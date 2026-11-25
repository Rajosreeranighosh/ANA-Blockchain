//! Authenticated client for the ANA node's bounded newline-delimited TCP query protocol.
use crate::{validate_address, Transaction, NETWORK};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStatus {
    pub network: String,
    pub height: u64,
    pub tip_hash: String,
    pub minted: u64,
    pub pending_transactions: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub transaction_id: String,
    pub state: String,
    pub confirmed_height: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    kind: String,
    #[serde(default)]
    transaction: Option<Transaction>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    balance: Option<u64>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(default)]
    transaction_state: Option<String>,
    #[serde(default)]
    confirmed_height: Option<u64>,
    #[serde(default)]
    node_status: Option<NodeStatus>,
    #[serde(default)]
    auth: Option<String>,
}

/// A client for one ANA node. If ANA_PEER_TOKEN is set, it is sent as the
/// shared authentication token. The transport is plaintext TCP; use a VPN or
/// trusted private network and never expose this protocol directly to the internet.
pub struct NodeClient {
    address: String,
    token: Option<String>,
}

impl NodeClient {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            token: env::var("ANA_PEER_TOKEN").ok().filter(|value| !value.is_empty()),
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        let socket = self.address.to_socket_addrs()
            .context("invalid ANA node address")?
            .next()
            .context("ANA node address resolved to no socket addresses")?;
        let stream = TcpStream::connect_timeout(&socket, IO_TIMEOUT)
            .context("could not connect to ANA node")?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(stream)
    }

    fn exchange(&self, mut request: WireMessage) -> Result<WireMessage> {
        request.auth = self.token.clone();
        let mut stream = self.connect()?;
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        stream.write_all(&bytes)?;
        let mut line = Vec::new();
        BufReader::new(stream).take(MAX_RESPONSE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .context("failed reading ANA node response")?;
        if line.is_empty() || line.len() as u64 > MAX_RESPONSE_BYTES || line.last() != Some(&b'\n') {
            bail!("ANA node returned an empty, oversized, or incomplete response");
        }
        serde_json::from_slice(&line).context("invalid ANA node response")
    }

    fn empty(kind: &str) -> WireMessage {
        WireMessage {
            kind: kind.into(), transaction: None, address: None, balance: None, nonce: None,
            transaction_id: None, transaction_state: None, confirmed_height: None,
            node_status: None, auth: None,
        }
    }

    pub fn account(&self, address: &str) -> Result<(u64, u64)> {
        validate_address(address)?;
        let mut request = Self::empty("get_account");
        request.address = Some(address.to_owned());
        let reply = self.exchange(request)?;
        if reply.kind != "account" {
            bail!("ANA node did not return account state");
        }
        Ok((
            reply.balance.context("missing balance in ANA node response")?,
            reply.nonce.context("missing nonce in ANA node response")?,
        ))
    }

    pub fn status(&self) -> Result<NodeStatus> {
        let reply = self.exchange(Self::empty("get_status"))?;
        if reply.kind != "node_status" {
            bail!("ANA node did not return node status");
        }
        let status = reply.node_status.context("missing node status payload")?;
        if status.network != NETWORK {
            bail!("connected node reports a different ANA network");
        }
        Ok(status)
    }

    pub fn transaction_status(&self, id: &str) -> Result<TransactionStatus> {
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("transaction ID must be 64 hexadecimal characters");
        }
        let mut request = Self::empty("get_transaction");
        request.transaction_id = Some(id.to_ascii_lowercase());
        let reply = self.exchange(request)?;
        if reply.kind != "transaction_status" {
            bail!("ANA node did not return transaction status");
        }
        let state = reply.transaction_state.context("missing transaction state")?;
        if !matches!(state.as_str(), "confirmed" | "pending" | "not_found") {
            bail!("ANA node returned an unknown transaction state");
        }
        Ok(TransactionStatus {
            transaction_id: id.to_ascii_lowercase(),
            state,
            confirmed_height: reply.confirmed_height,
        })
    }

    /// Submit a signed transaction and wait for the node's explicit admission result.
    /// "accepted" means admitted to this node's mempool, not mined or confirmed.
    pub fn submit_transaction(&self, transaction: Transaction) -> Result<String> {
        transaction.verify()?;
        let id = transaction.id()?;
        let mut request = Self::empty("transaction");
        request.transaction = Some(transaction);
        let reply = self.exchange(request)?;
        if reply.kind != "transaction_result" {
            bail!("ANA node did not acknowledge transaction submission");
        }
        if reply.transaction_id.as_deref() != Some(id.as_str()) {
            bail!("ANA node acknowledgement transaction ID mismatch");
        }
        match reply.transaction_state.as_deref() {
            Some("accepted") | Some("already_known") => Ok(id),
            Some("rejected") => bail!("ANA node rejected the transaction"),
            _ => bail!("ANA node returned an unknown transaction admission status"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_status_response_deserializes() {
        let message = r#"{"kind":"node_status","node_status":{"network":"ANA-TESTNET-1","height":7,"tip_hash":"abc","minted":5000000000,"pending_transactions":2}}"#;
        let reply: WireMessage = serde_json::from_str(message).unwrap();
        let status = reply.node_status.unwrap();
        assert_eq!(status.network, NETWORK);
        assert_eq!(status.height, 7);
        assert_eq!(status.pending_transactions, 2);
    }

    #[test]
    fn transaction_status_response_deserializes() {
        let message = r#"{"kind":"transaction_status","transaction_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","transaction_state":"confirmed","confirmed_height":12}"#;
        let reply: WireMessage = serde_json::from_str(message).unwrap();
        assert_eq!(reply.transaction_state.as_deref(), Some("confirmed"));
        assert_eq!(reply.confirmed_height, Some(12));
    }

    #[test]
    fn auth_field_is_flattened_compatible() {
        let mut request = NodeClient::empty("get_status");
        request.auth = Some("secret".into());
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["kind"], "get_status");
        assert_eq!(json["auth"], "secret");
    }
}
