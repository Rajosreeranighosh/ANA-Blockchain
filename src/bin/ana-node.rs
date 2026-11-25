use ana_blockchain::{validate_address, Block, ChainState, Ledger, Transaction};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
struct Message {
    kind: String,
    #[serde(default)]
    transaction: Option<Transaction>,
    #[serde(default)]
    block: Option<Block>,
    #[serde(default)]
    blocks: Option<Vec<Block>>,
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
    confirmations: Option<u64>,
    #[serde(default)]
    node_status: Option<NodeStatus>,
    #[serde(default)]
    history_page: Option<HistoryPage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct HistoryEntry { transaction_id: String, direction: String, amount: u64, fee: u64, height: u64, timestamp: u64, confirmations: u64 }
#[derive(Serialize, Deserialize, Clone, Debug)]
struct HistoryPage { tip_hash: String, entries: Vec<HistoryEntry>, next_height: u64, next_transaction_index: usize, has_more: bool }
#[derive(Serialize, Deserialize, Clone, Debug)]
struct NodeStatus {
    network: String,
    height: u64,
    tip_hash: String,
    minted: u64,
    pending_transactions: usize,
}

type SharedChain = Arc<Mutex<ChainState>>;
type Peers = Arc<Vec<String>>;
type Seen = Arc<Mutex<HashSet<String>>>;
type Mempool = Arc<Mutex<BTreeMap<String, Transaction>>>;
type SyncSessions = Arc<Mutex<BTreeMap<String, SyncSession>>>;
struct SyncSession { blocks: Vec<Block>, last_updated: Instant }
const SYNC_SESSION_TTL: Duration = Duration::from_secs(60);
const MAX_BLOCKS_PER_PAGE: usize = 128;
const MAX_SYNC_SESSIONS: usize = 16;
const MAX_SYNC_BLOCKS: usize = 1_000_000;

// Backward-compatible chain-sync metadata uses legacy optional fields:
// request.address=start height, transaction_id=expected tip hash, nonce=page size;
// response.address=page start, transaction_id=snapshot tip hash, nonce=next height,
// confirmations=1 when more pages follow and 0 on the final page.
fn store_sync_page(
    sessions: &SyncSessions,
    sync_id: String,
    start: usize,
    page: Vec<Block>,
    next: usize,
    more: bool,
) -> Result<Option<Vec<Block>>> {
    if page.is_empty()
        || page.len() > MAX_BLOCKS_PER_PAGE
        || next != start.checked_add(page.len()).context("chain-sync page height overflow")?
    {
        bail!("invalid chain-sync page bounds or page exceeds the configured limit");
    }
    let mut sessions = sessions.lock().map_err(|_| anyhow::anyhow!("sync-session lock poisoned"))?;
    let now = Instant::now();
    sessions.retain(|_, session| now.duration_since(session.last_updated) <= SYNC_SESSION_TTL);

    if start == 0 {
        if sessions.len() >= MAX_SYNC_SESSIONS && !sessions.contains_key(&sync_id) {
            if let Some(oldest_key) = sessions.iter()
                .min_by_key(|(_, session)| session.last_updated)
                .map(|(key, _)| key.clone()) {
                sessions.remove(&oldest_key);
            }
        }
        sessions.insert(sync_id.clone(), SyncSession { blocks: page, last_updated: now });
    } else {
        let candidate = sessions.get_mut(&sync_id).context("unknown or expired chain-sync session")?;
        if candidate.blocks.len() != start || candidate.blocks.len().saturating_add(page.len()) > MAX_SYNC_BLOCKS {
            sessions.remove(&sync_id);
            bail!("chain-sync page is out of sequence or exceeds the block limit");
        }
        candidate.blocks.extend(page);
        candidate.last_updated = now;
    }
    let candidate_len = sessions.get(&sync_id).map(|session| session.blocks.len()).unwrap_or(0);
    if candidate_len > MAX_SYNC_BLOCKS {
        sessions.remove(&sync_id);
        bail!("chain-sync session exceeds the block limit");
    }
    if more { Ok(None) } else { Ok(sessions.remove(&sync_id).map(|session| session.blocks)) }
}

fn chain_request(start: u64, sync_id: Option<String>) -> Message {
    Message { kind: "get_chain".into(), transaction: None, block: None, blocks: None,
        address: Some(start.to_string()), balance: None, nonce: Some(MAX_BLOCKS_PER_PAGE as u64),
        transaction_id: sync_id, transaction_state: None, confirmed_height: None,
        confirmations: None, node_status: None, history_page: None }
}

const MAX_CONNECTIONS: usize = 64;
const MAX_MESSAGE_BYTES: u64 = 8 * 1024 * 1024;
const SOCKET_TIMEOUT_SECS: u64 = 10;

/// Refuse accidental remote exposure: this prototype has no TLS, so remote
/// binds require both the shared token and an explicit insecure-transport opt-in.
fn validate_bind_security(bind: &str, has_token: bool, allow_insecure_remote: bool) -> Result<()> {
    let addresses: Vec<_> = bind.to_socket_addrs()
        .context("could not resolve node bind address")?
        .collect();
    if addresses.is_empty() {
        bail!("node bind address resolved to no socket addresses");
    }
    if addresses.iter().all(|address| address.ip().is_loopback()) {
        return Ok(());
    }
    if !has_token {
        bail!("refusing non-loopback bind without ANA_PEER_TOKEN; bind to loopback or configure peer authentication");
    }
    if !allow_insecure_remote {
        bail!("refusing remote bind over plaintext TCP; use a VPN/SSH tunnel or set ANA_ALLOW_INSECURE_REMOTE_BIND=1 only on a trusted private network");
    }
    eprintln!("SECURITY WARNING: remote node transport is plaintext TCP; the shared peer token is not encrypted");
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct AuthenticatedMessage {
    #[serde(flatten)]
    message: Message,
    #[serde(default)]
    auth: Option<String>,
}

fn peer_token() -> Option<String> {
    env::var("ANA_PEER_TOKEN").ok().filter(|token| !token.is_empty())
}

fn authenticated_wire(message: &Message) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&AuthenticatedMessage {
        message: Message {
            kind: message.kind.clone(),
            transaction: message.transaction.clone(),
            block: message.block.clone(),
            blocks: message.blocks.clone(),
            address: message.address.clone(),
            balance: message.balance,
            nonce: message.nonce,
            transaction_id: message.transaction_id.clone(),
            transaction_state: message.transaction_state.clone(),
            confirmed_height: message.confirmed_height,
            confirmations: message.confirmations,
            node_status: message.node_status.clone(), history_page: message.history_page.clone(),
        },
        auth: peer_token(),
    })?)
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}


fn send(peer: &str, message: &Message) {
    let address = match peer.to_socket_addrs().ok().and_then(|mut values| values.next()) {
        Some(value) => value,
        None => return,
    };
    if let Ok(mut stream) = TcpStream::connect_timeout(
        &address,
        Duration::from_secs(SOCKET_TIMEOUT_SECS),
    ) {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
        if let Ok(mut wire) = authenticated_wire(message) {
            wire.push(b'\n');
            let _ = stream.write_all(&wire);
        }
    }
}
fn broadcast(peers: &Peers, message: &Message) {
    for peer in peers.iter() {
        send(peer, message);
    }
}

fn persist(chain: &SharedChain, path: &Path) {
    if let Ok(state) = chain.lock() {
        if let Err(error) = state.save(path) {
            eprintln!("chain persistence error: {error}");
        }
    }
}

/// Derive a separate durable mempool file next to the node's chain file.
fn mempool_path(data_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.mempool.json", data_file.to_string_lossy()))
}

/// Atomically persist pending transactions. The temporary file is renamed only
/// after the complete JSON snapshot has been written.
fn persist_mempool(pool: &Mempool, path: &Path) -> Result<()> {
    let snapshot = pool.lock()
        .map_err(|_| anyhow::anyhow!("mempool lock poisoned"))?
        .clone();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(&snapshot)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

/// Load only correctly keyed, correctly signed, currently executable transactions.
fn load_mempool(path: &Path, chain: &ChainState) -> Result<BTreeMap<String, Transaction>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let stored: BTreeMap<String, Transaction> = serde_json::from_slice(&fs::read(path)?)?;
    let mut candidates = BTreeMap::new();
    for (id, tx) in stored {
        if tx.verify().is_ok() && matches!(tx.id(), Ok(ref actual_id) if actual_id == &id) {
            candidates.insert(id, tx);
        }
    }
    let pool = Arc::new(Mutex::new(candidates));
    let accepted: HashSet<String> = select_transactions(chain, &pool)
        .iter().filter_map(|tx| tx.id().ok()).collect();
    let mut values = pool.lock()
        .map_err(|_| anyhow::anyhow!("mempool lock poisoned"))?.clone();
    values.retain(|id, _| accepted.contains(id));
    Ok(values)
}

fn persist_mempool_after_change(pool: &Mempool, data_file: &Path) {
    let path = mempool_path(data_file);
    if let Err(error) = persist_mempool(pool, &path) {
        eprintln!("mempool persistence error: {error}");
    }
}

fn transaction_ack(id: &str, state: &str) -> Message {
    Message {
        kind: "transaction_result".into(), transaction: None, block: None, blocks: None,
        address: None, balance: None, nonce: None, transaction_id: Some(id.to_owned()),
        transaction_state: Some(state.to_owned()), confirmed_height: None, confirmations: None, node_status: None, history_page: None,
    }
}

fn response(stream: &mut TcpStream, message: &Message) {
    if let Ok(mut wire) = authenticated_wire(message) {
        wire.push(b'\n');
        let _ = stream.write_all(&wire);
    }
}
fn select_transactions(chain: &ChainState, pool: &Mempool) -> Vec<Transaction> {
    let mut candidates: Vec<(String, Transaction)> = match pool.lock() {
        Ok(pool) => pool.iter().map(|(id, tx)| (id.clone(), tx.clone())).collect(),
        Err(_) => return Vec::new(),
    };
    candidates.sort_by(|a, b| {
        a.1.from.cmp(&b.1.from)
            .then(a.1.nonce.cmp(&b.1.nonce))
            .then(a.0.cmp(&b.0))
    });
    let mut projected = chain.ledger.clone();
    let mut accepted = Vec::new();
    for (_, tx) in candidates {
        if projected.apply_transaction(&tx).is_ok() {
            accepted.push(tx);
        }
    }
    accepted
}

fn prune_mempool(chain: &SharedChain, pool: &Mempool) {
    let accepted_ids: HashSet<String> = match chain.lock() {
        Ok(state) => select_transactions(&state, pool)
            .iter().filter_map(|tx| tx.id().ok()).collect(),
        Err(_) => return,
    };
    if let Ok(mut values) = pool.lock() {
        values.retain(|id, _| accepted_ids.contains(id));
    }
}

fn projected_ledger(chain: &SharedChain, pool: &Mempool) -> Option<Ledger> {
    let state = chain.lock().ok()?;
    let mut ledger = state.ledger.clone();
    for tx in select_transactions(&state, pool) {
        if ledger.apply_transaction(&tx).is_err() {
            continue;
        }
    }
    Some(ledger)
}


/// Return the responding node's local view of a transaction.
fn transaction_status(blocks: &[Block], pool: &Mempool, id: &str) -> (String, Option<u64>) {
    for block in blocks {
        if block.transactions.iter().any(|tx| tx.id().ok().as_deref() == Some(id)) {
            return ("confirmed".into(), Some(block.height));
        }
    }
    if pool.lock().map(|values| values.contains_key(id)).unwrap_or(false) {
        return ("pending".into(), None);
    }
    ("not_found".into(), None)
}

fn confirmation_count(tip_height: u64, confirmed_height: u64) -> Option<u64> {
    tip_height.checked_sub(confirmed_height)?.checked_add(1)
}


fn build_history_page(blocks: &[Block], address: &str, start_height: u64, start_index: usize, limit: usize) -> Result<HistoryPage> {
    validate_address(address)?;
    if limit == 0 || limit > 1000 { bail!("history page size must be between 1 and 1000"); }
    let tip = blocks.last().context("chain has no genesis block")?;
    if start_height > tip.height.saturating_add(1) { bail!("history cursor is beyond the current chain tip"); }
    let mut entries = Vec::new();
    for height in start_height..=tip.height {
        let block = blocks.get(height as usize).context("chain height index is inconsistent")?;
        let first = if height == start_height { start_index } else { 0 };
        if first > block.transactions.len() { bail!("history transaction cursor is outside the block"); }
        for (index, tx) in block.transactions.iter().enumerate().skip(first) {
            if tx.from != address && tx.to != address { continue; }
            let direction = if tx.from == address && tx.to == address { "self" } else if tx.from == address { "outgoing" } else { "incoming" };
            entries.push(HistoryEntry { transaction_id: tx.id()?, direction: direction.into(), amount: tx.amount, fee: tx.fee, height, timestamp: block.timestamp, confirmations: tip.height.saturating_sub(height).saturating_add(1) });
            if entries.len() == limit {
                let next_index = index.saturating_add(1);
                let within = next_index < block.transactions.len();
                return Ok(HistoryPage { tip_hash: tip.hash.clone(), entries, next_height: if within { height } else { height.saturating_add(1) }, next_transaction_index: if within { next_index } else { 0 }, has_more: within || height < tip.height });
            }
        }
    }
    Ok(HistoryPage { tip_hash: tip.hash.clone(), entries, next_height: tip.height.saturating_add(1), next_transaction_index: 0, has_more: false })
}
fn handle(
    mut stream: TcpStream,
    chain: SharedChain,
    peers: Peers,
    seen: Seen,
    pool: Mempool,
    data_file: PathBuf,
    active_connections: Arc<AtomicUsize>,
    sync_sessions: SyncSessions,
) {
    let _connection_guard = ConnectionGuard(active_connections);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
    let mut line = Vec::new();
    let read_result = {
        let cloned = match stream.try_clone() { Ok(value) => value, Err(_) => return };
        let mut reader = BufReader::new(cloned);
        reader.by_ref().take(MAX_MESSAGE_BYTES + 1).read_until(b'\n', &mut line)
    };
    if read_result.is_err() || line.len() as u64 > MAX_MESSAGE_BYTES || line.last() != Some(&b'\n') {
        eprintln!("Rejected oversized, incomplete, or unreadable peer message");
        return;
    }
    let envelope: AuthenticatedMessage = match serde_json::from_slice(&line) {
        Ok(value) => value,
        Err(_) => { eprintln!("Rejected malformed peer message"); return; }
    };
    match peer_token() {
        Some(expected) if envelope.auth.as_deref() != Some(expected.as_str()) => {
            eprintln!("Rejected peer with invalid authentication token");
            return;
        }
        None if !stream.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false) => {
            eprintln!("Rejected non-loopback peer: set ANA_PEER_TOKEN on every node");
            return;
        }
        _ => {}
    }
    let message = envelope.message;

    match message.kind.as_str() {
        "get_chain" => {
            if let Ok(state) = chain.lock() {
                let start = message.address.as_deref().and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
                let tip_hash = state.tip().hash.clone();
                if message.transaction_id.as_deref().is_some_and(|expected| expected != tip_hash) { return; }
                if start >= state.blocks.len() { return; }
                let requested = message.nonce.unwrap_or(MAX_BLOCKS_PER_PAGE as u64) as usize;
                let mut end = start.saturating_add(requested.min(MAX_BLOCKS_PER_PAGE)).min(state.blocks.len());
                loop {
                    let reply = Message { kind: "blocks".into(), transaction: None, block: None,
                        blocks: Some(state.blocks[start..end].to_vec()), address: Some(start.to_string()),
                        balance: None, nonce: Some(end as u64), transaction_id: Some(tip_hash.clone()),
                        transaction_state: None, confirmed_height: None,
                        confirmations: Some(u64::from(end < state.blocks.len())), node_status: None, history_page: None };
                    if authenticated_wire(&reply).map(|bytes| bytes.len() < MAX_MESSAGE_BYTES as usize).unwrap_or(false) {
                        response(&mut stream, &reply); break;
                    }
                    if end <= start + 1 { break; }
                    end = start + (end - start) / 2;
                }
            }
        }
        "get_account" => {
            if let Some(address) = message.address {
                if validate_address(&address).is_ok() {
                    if let Some(ledger) = projected_ledger(&chain, &pool) {
                        response(&mut stream, &Message {
                            kind: "account".into(), transaction: None, block: None, blocks: None,
                            address: Some(address.clone()), balance: Some(ledger.balance(&address)),
                            nonce: Some(ledger.nonce(&address)),
                            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None,
                            node_status: None, history_page: None,
                        });
                    }
                }
            }
        }
        "get_status" => {
            if let (Ok(state), Ok(pending)) = (chain.lock(), pool.lock()) {
                let tip = state.tip();
                response(&mut stream, &Message {
                    kind: "node_status".into(), transaction: None, block: None, blocks: None,
                    address: None, balance: None, nonce: None,
                    transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None,
                    node_status: Some(NodeStatus {
                        network: ana_blockchain::NETWORK.into(),
                        height: tip.height,
                        tip_hash: tip.hash.clone(),
                        minted: state.ledger.minted,
                        pending_transactions: pending.len(),
                    }),
                    history_page: None,
                });
            }
        }
        "get_history" => {
            if let Some(address) = message.address.as_deref() {
                if let Ok(state) = chain.lock() {
                    let start_height = message.balance.unwrap_or(0);
                    let start_index = message.confirmed_height.unwrap_or(0) as usize;
                    let limit = message.nonce.unwrap_or(100) as usize;
                    let tip_hash = state.tip().hash.clone();
                    if message.transaction_id.as_deref().is_some_and(|expected| expected != tip_hash) {
                        response(&mut stream, &Message { kind: "history_stale".into(), transaction: None, block: None, blocks: None, address: None, balance: None, nonce: None, transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: None });
                    } else if let Ok(page) = build_history_page(&state.blocks, address, start_height, start_index, limit) {
                        response(&mut stream, &Message { kind: "history_page".into(), transaction: None, block: None, blocks: None, address: None, balance: None, nonce: None, transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: Some(page) });
                    }
                }
            }
        }
        "get_transaction" => {
            if let Some(id) = message.transaction_id {
                if let Ok(state) = chain.lock() {
                    let (status, height) = transaction_status(&state.blocks, &pool, &id);
                    let confirmations = height.and_then(|confirmed| confirmation_count(state.tip().height, confirmed));
                    response(&mut stream, &Message {
                        kind: "transaction_status".into(), transaction: None, block: None, blocks: None,
                        address: None, balance: None, nonce: None,
                        transaction_id: Some(id), transaction_state: Some(status),
                        confirmed_height: height, confirmations, node_status: None, history_page: None,
                    });
                }
            }
        }
        "blocks" => {
            if let (Some(page), Some(sync_id), Some(next_height), Some(start_text)) =
                (message.blocks, message.transaction_id, message.nonce, message.address)
            {
                let start = match start_text.parse::<usize>() { Ok(v) => v, Err(_) => return };
                let next = next_height as usize;
                if page.is_empty() || next != start.saturating_add(page.len()) { return; }
                let complete = match store_sync_page(
                    &sync_sessions, sync_id.clone(), start, page, next,
                    message.confirmations.unwrap_or(0) != 0,
                ) {
                    Ok(value) => value,
                    Err(error) => { eprintln!("Rejected chain-sync page: {error}"); return; }
                };
                if let Some(blocks) = complete {
                    let (changed, displaced) = if let Ok(mut state) = chain.lock() {
                        let old_blocks = state.blocks.clone();
                        match state.replace_if_more_work(blocks) {
                            Ok(true) => {
                                let canonical: HashSet<String> = state.blocks.iter().flat_map(|b| b.transactions.iter())
                                    .filter_map(|tx| tx.id().ok()).collect();
                                let displaced = old_blocks.iter().flat_map(|b| b.transactions.iter().cloned())
                                    .filter(|tx| tx.id().map(|id| !canonical.contains(&id)).unwrap_or(false)).collect();
                                (true, displaced)
                            }
                            Ok(false) => (false, Vec::new()),
                            Err(error) => { eprintln!("Rejected candidate chain: {error}"); (false, Vec::new()) }
                        }
                    } else { (false, Vec::new()) };
                    if changed {
                        if let Ok(mut values) = pool.lock() { for tx in displaced { if let Ok(id) = tx.id() { values.insert(id, tx); } } }
                        prune_mempool(&chain, &pool);
                        persist_mempool_after_change(&pool, &data_file);
                        persist(&chain, &data_file);
                        println!("Switched to higher-work chain at height {}", chain.lock().map(|s| s.tip().height).unwrap_or(0));
                    }
                } else {
                    broadcast(&peers, &chain_request(next_height, Some(sync_id)));
                }
            }
        }
        "block" => {
            if let Some(block) = message.block {
                let id = block.hash.clone();
                let first_seen = seen.lock().map(|mut values| values.insert(id)).unwrap_or(false);
                if !first_seen { return; }
                let result = chain.lock()
                    .map_err(|_| anyhow::anyhow!("chain lock poisoned"))
                    .and_then(|mut state| state.append(block.clone()));
                if result.is_ok() {
                    println!("Confirmed block #{} with {} transaction(s)",
                        block.height, block.transactions.len());
                    if let Ok(mut values) = pool.lock() {
                        for tx in &block.transactions {
                            if let Ok(id) = tx.id() { values.remove(&id); }
                        }
                    }
                    prune_mempool(&chain, &pool);
                    persist_mempool_after_change(&pool, &data_file);
                    persist(&chain, &data_file);
                    broadcast(&peers, &Message {
                        kind: "block".into(), transaction: None, block: Some(block),
                        blocks: None, address: None, balance: None, nonce: None,
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: None,
                    });
                } else {
                    eprintln!("Block does not extend local tip; requesting peer chain");
                    broadcast(&peers, &chain_request(0, None));
                }
            }
        }
        "transaction" => {
            if let Some(tx) = message.transaction {
                let id = match tx.id() { Ok(id) => id, Err(_) => return };
                if tx.verify().is_err() {
                    eprintln!("Rejected invalid transaction {id}");
                    response(&mut stream, &transaction_ack(&id, "rejected"));
                    return;
                }
                if seen.lock().map(|values| values.contains(&id)).unwrap_or(true) {
                    response(&mut stream, &transaction_ack(&id, "already_known"));
                    return;
                }
                if let Ok(mut values) = pool.lock() {
                    values.insert(id.clone(), tx.clone());
                } else {
                    response(&mut stream, &transaction_ack(&id, "rejected"));
                    return;
                }
                let accepted = chain.lock().ok()
                    .map(|state| select_transactions(&state, &pool).iter()
                        .any(|candidate| candidate.id().ok().as_deref() == Some(&id)))
                    .unwrap_or(false);
                if !accepted {
                    if let Ok(mut values) = pool.lock() { values.remove(&id); }
                    eprintln!("Rejected transaction: nonce, balance, or ordering invalid");
                    response(&mut stream, &transaction_ack(&id, "rejected"));
                    return;
                }
                if let Ok(mut values) = seen.lock() { values.insert(id.clone()); }
                println!("Accepted pending transaction {id}");
                persist_mempool_after_change(&pool, &data_file);
                response(&mut stream, &transaction_ack(&id, "accepted"));
                broadcast(&peers, &Message {
                    kind: "transaction".into(), transaction: Some(tx), block: None,
                    blocks: None, address: None, balance: None, nonce: None,
                    transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: None,
                });
            }
        }
        _ => {}
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        bail!("Usage: ana-node <bind-ip:port> <data-file> <miner-address|none> [peer-ip:port ...]");
    }
    let bind = &args[1];
    let data_file = PathBuf::from(&args[2]);
    let miner = if args[3] == "none" {
        None
    } else {
        validate_address(&args[3])?;
        Some(args[3].clone())
    };
    let peers: Peers = Arc::new(args.iter().skip(4).cloned().collect());
    let allow_remote = env::var("ANA_ALLOW_INSECURE_REMOTE_BIND").as_deref() == Ok("1");
    validate_bind_security(bind, peer_token().is_some(), allow_remote)?;
    let chain = Arc::new(Mutex::new(ChainState::load(&data_file)?));
    let mempool_file = mempool_path(&data_file);
    let restored = {
        let state = chain.lock().map_err(|_| anyhow::anyhow!("chain lock poisoned"))?;
        load_mempool(&mempool_file, &state)?
    };
    println!("Restored {} pending transaction(s) from {}", restored.len(), mempool_file.display());
    let restored_ids: HashSet<String> = restored.keys().cloned().collect();
    let seen: Seen = Arc::new(Mutex::new(restored_ids));
    let pool: Mempool = Arc::new(Mutex::new(restored));

    let listener = TcpListener::bind(bind)?;
    println!("ANA TESTNET node listening on {bind}; {} configured peers", peers.len());
    println!("Network safeguards: {MAX_CONNECTIONS} concurrent connections, {MAX_MESSAGE_BYTES} byte message cap, {SOCKET_TIMEOUT_SECS}s socket timeout.");
    if peer_token().is_none() { println!("WARNING: ANA_PEER_TOKEN is unset; inbound connections are restricted to loopback."); }
    println!("RandomX testnet difficulty: starts at 8 bits; retargets every 10 completed blocks toward a 30-second target.");
    for peer in peers.iter() {
        send(peer, &chain_request(0, None));
    }

    if let Some(miner_address) = miner {
        let mining_chain = chain.clone();
        let mining_peers = peers.clone();
        let mining_pool = pool.clone();
        let mining_file = data_file.clone();
        thread::spawn(move || loop {
            let transactions = mining_chain.lock()
                .map(|state| select_transactions(&state, &mining_pool))
                .unwrap_or_default();
            // Mine against a snapshot without holding the chain mutex during RandomX.
            let snapshot = match mining_chain.lock() {
                Ok(state) => state.clone(),
                Err(_) => { thread::sleep(Duration::from_secs(1)); continue; }
            };
            let result = snapshot.mine_next_with_transactions(miner_address.clone(), transactions);
            match result {
                Ok(block) => {
                    let accepted = mining_chain.lock()
                        .map(|mut state| state.append(block.clone()).is_ok()).unwrap_or(false);
                    if accepted {
                        println!("Mined block #{} with {} transaction(s)",
                            block.height, block.transactions.len());
                        if let Ok(mut values) = mining_pool.lock() {
                            for tx in &block.transactions {
                                if let Ok(id) = tx.id() { values.remove(&id); }
                            }
                        }
                        prune_mempool(&mining_chain, &mining_pool);
                        persist_mempool_after_change(&mining_pool, &mining_file);
                        persist(&mining_chain, &mining_file);
                        broadcast(&mining_peers, &Message {
                            kind: "block".into(), transaction: None, block: Some(block),
                            blocks: None, address: None, balance: None, nonce: None,
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: None,
                        });
                    }
                }
                Err(error) => {
                    eprintln!("mining error: {error}");
                    thread::sleep(Duration::from_secs(3));
                }
            }
        });
    } else {
        println!("Observer mode: mining disabled.");
    }

    let active_connections = Arc::new(AtomicUsize::new(0));
    let sync_sessions: SyncSessions = Arc::new(Mutex::new(BTreeMap::new()));
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let current = active_connections.fetch_add(1, Ordering::SeqCst);
                if current >= MAX_CONNECTIONS {
                    active_connections.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("Rejected connection: connection limit reached");
                    drop(stream);
                    continue;
                }
                let c = chain.clone();
                let p = peers.clone();
                let s = seen.clone();
                let m = pool.clone();
                let f = data_file.clone();
                let active = active_connections.clone();
                let sync = sync_sessions.clone();
                thread::spawn(move || handle(stream, c, p, s, m, f, active, sync));
            }
            Err(error) => eprintln!("connection error: {error}"),
        }
    }
    Ok(())
}
 
#[cfg(test)]
mod tests {
    use super::*;
    use ana_blockchain::{address, sign, COIN};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn temp_file(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ana-{label}-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn remote_bind_requires_token_and_explicit_plaintext_opt_in() {
        assert!(validate_bind_security("127.0.0.1:19001", false, false).is_ok());
        assert!(validate_bind_security("0.0.0.0:19001", false, true).is_err());
        assert!(validate_bind_security("0.0.0.0:19001", true, false).is_err());
        assert!(validate_bind_security("0.0.0.0:19001", true, true).is_ok());
    }

    #[test]
    fn chain_sync_accumulates_pages_in_order_and_completes_only_on_final_page() {
        let sessions: SyncSessions = Arc::new(Mutex::new(BTreeMap::new()));
        let genesis = ChainState::new().blocks[0].clone();
        assert!(store_sync_page(&sessions, "tip-a".into(), 0, vec![genesis.clone()], 1, true).unwrap().is_none());
        let complete = store_sync_page(&sessions, "tip-a".into(), 1, vec![genesis], 2, false).unwrap().unwrap();
        assert_eq!(complete.len(), 2);
        assert!(sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn chain_sync_expires_abandoned_sessions_before_accepting_pages() {
        let sessions: SyncSessions = Arc::new(Mutex::new(BTreeMap::new()));
        let genesis = ChainState::new().blocks[0].clone();
        sessions.lock().unwrap().insert(
            "stale-tip".into(),
            SyncSession {
                blocks: vec![genesis.clone()],
                last_updated: Instant::now() - SYNC_SESSION_TTL - Duration::from_secs(1),
            },
        );

        assert!(store_sync_page(&sessions, "stale-tip".into(), 1, vec![genesis], 2, false).is_err());
        assert!(sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn chain_sync_rejects_pages_larger_than_protocol_limit() {
        let sessions: SyncSessions = Arc::new(Mutex::new(BTreeMap::new()));
        let genesis = ChainState::new().blocks[0].clone();
        let oversized = vec![genesis; MAX_BLOCKS_PER_PAGE + 1];
        assert!(store_sync_page(
            &sessions,
            "oversized-tip".into(),
            0,
            oversized,
            (MAX_BLOCKS_PER_PAGE + 1) as usize,
            false,
        ).is_err());
        assert!(sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn chain_sync_rejects_out_of_order_and_unknown_sessions() {
        let sessions: SyncSessions = Arc::new(Mutex::new(BTreeMap::new()));
        let genesis = ChainState::new().blocks[0].clone();
        assert!(store_sync_page(&sessions, "tip-b".into(), 0, vec![genesis.clone()], 1, true).unwrap().is_none());
        assert!(store_sync_page(&sessions, "tip-b".into(), 2, vec![genesis.clone()], 3, false).is_err());
        assert!(!sessions.lock().unwrap().contains_key("tip-b"));
        assert!(store_sync_page(&sessions, "tip-c".into(), 1, vec![genesis], 2, false).is_err());
    }

    #[test]
    fn wallet_history_pages_are_address_filtered_and_reorg_snapshot_bound() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let unrelated = SigningKey::generate(&mut OsRng);
        let unrelated_address = address(&unrelated.verifying_key());
        let receiver_address = address(&receiver.verifying_key());
        let tx = sign(&sender, receiver_address.clone(), COIN, 7, 0).unwrap();
        let mut genesis = ChainState::new().blocks[0].clone();
        genesis.height = 0;
        let tx2 = sign(&sender, receiver_address.clone(), COIN / 2, 3, 1).unwrap();
        let mut block = genesis.clone();
        block.height = 1;
        block.timestamp = genesis.timestamp + 30;
        block.transactions.extend([tx.clone(), tx2.clone()]);
        let blocks = vec![genesis, block];

        let page = build_history_page(&blocks, &receiver_address, 0, 0, 1).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].transaction_id, tx.id().unwrap());
        assert_eq!(page.entries[0].direction, "incoming");
        assert_eq!(page.entries[0].amount, COIN);
        assert_eq!(page.entries[0].fee, 7);
        assert_eq!(page.entries[0].confirmations, 1);
        assert!(page.has_more);
        let page2 = build_history_page(&blocks, &receiver_address, page.next_height, page.next_transaction_index, 1).unwrap();
        assert_eq!(page2.entries.len(), 1);
        assert_eq!(page2.entries[0].transaction_id, tx2.id().unwrap());
        assert!(!page2.has_more);

        let empty = build_history_page(&blocks, &unrelated_address, 0, 0, 1).unwrap();
        assert!(empty.entries.is_empty());
        assert!(!empty.has_more);
        assert!(build_history_page(&blocks, &receiver_address, 2, 0, 1).unwrap().entries.is_empty());
        assert!(build_history_page(&blocks, &receiver_address, 0, 0, 0).is_err());
        assert!(build_history_page(&blocks, &receiver_address, 0, 0, 1001).is_err());
    }

    #[test]
    fn transaction_status_reports_pending_confirmed_and_unknown() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let tx = sign(&sender, address(&receiver.verifying_key()), 1, 0, 0).unwrap();
        let id = tx.id().unwrap();
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), tx.clone())])));
        let mut block = ChainState::new().blocks[0].clone();
        block.height = 1;
        block.transactions.push(tx);
        assert_eq!(transaction_status(&[block], &pool, &id), ("confirmed".into(), Some(1)));
        assert_eq!(transaction_status(&[], &pool, &id), ("pending".into(), None));
        assert_eq!(transaction_status(&[], &pool, "missing"), ("not_found".into(), None));
    }

    #[test]
    fn confirmation_count_includes_inclusion_block_and_handles_invalid_height() {
        assert_eq!(confirmation_count(12, 12), Some(1));
        assert_eq!(confirmation_count(15, 12), Some(4));
        assert_eq!(confirmation_count(11, 12), None);
    }

    #[test]
    fn pending_transactions_survive_restart_and_are_revalidated() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let sender_address = address(&sender.verifying_key());
        let mut chain = ChainState::new();
        chain.ledger.balances.insert(sender_address, 5 * COIN);
        let tx = sign(&sender, address(&receiver.verifying_key()), COIN, 1, 0).unwrap();
        let id = tx.id().unwrap();
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), tx)])));
        let path = temp_file("mempool-roundtrip");

        persist_mempool(&pool, &path).unwrap();
        let restored = load_mempool(&path, &chain).unwrap();

        assert!(restored.contains_key(&id));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn restart_discards_invalid_or_unexecutable_pending_transactions() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let tx = sign(
            &sender,
            address(&receiver.verifying_key()),
            COIN,
            1,
            0,
        ).unwrap();
        let mut invalid = tx;
        invalid.amount += 1;
        let id = invalid.id().unwrap();
        let stored = BTreeMap::from([(id, invalid)]);
        let path = temp_file("mempool-invalid");
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

        let restored = load_mempool(&path, &ChainState::new()).unwrap();

        assert!(restored.is_empty());
        fs::remove_file(path).unwrap();
    }
}
 
#[cfg(test)]
mod network_security_tests {
    use super::*;
    use ana_blockchain::{address, sign, COIN};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn authenticated_envelope_round_trips_message_and_token_field() {
        let message = Message {
            kind: "get_chain".into(),
            transaction: None,
            block: None,
            blocks: None,
            address: None,
            balance: None,
            nonce: None,
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None, history_page: None,
        };
        let envelope = AuthenticatedMessage {
            message,
            auth: Some("test-secret".into()),
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: AuthenticatedMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.message.kind, "get_chain");
        assert_eq!(decoded.auth.as_deref(), Some("test-secret"));
    }

    #[test]
    fn transaction_ack_has_expected_wire_shape() {
        let ack = transaction_ack("abc123", "accepted");
        assert_eq!(ack.kind, "transaction_result");
        assert_eq!(ack.transaction_id.as_deref(), Some("abc123"));
        assert_eq!(ack.transaction_state.as_deref(), Some("accepted"));
    }

    #[test]
    fn message_size_limit_is_nonzero_and_bounded() {
        assert!(MAX_MESSAGE_BYTES >= 1024);
        assert!(MAX_MESSAGE_BYTES <= 8 * 1024 * 1024);
        assert!(MAX_CONNECTIONS > 0);
    }



    #[test]
    fn peer_can_request_genesis_chain_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let chain: SharedChain = Arc::new(Mutex::new(ChainState::new()));
        let peers: Peers = Arc::new(Vec::new());
        let seen: Seen = Arc::new(Mutex::new(HashSet::new()));
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let data_file = std::env::temp_dir().join(format!("ana-tcp-chain-{}.json", std::process::id()));

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, chain, peers, seen, pool, data_file, active, Arc::new(Mutex::new(BTreeMap::new())));
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let request = Message {
            kind: "get_chain".into(),
            transaction: None, block: None, blocks: None, address: None,
            balance: None, nonce: None, transaction_id: None,
            transaction_state: None, confirmed_height: None, confirmations: None,
            node_status: None, history_page: None,
        };
        let mut wire = authenticated_wire(&request).unwrap();
        wire.push(b'\n');
        client.write_all(&wire).unwrap();

        let mut response_line = Vec::new();
        BufReader::new(client).read_until(b'\n', &mut response_line).unwrap();
        let response: AuthenticatedMessage = serde_json::from_slice(&response_line).unwrap();
        assert_eq!(response.message.kind, "blocks");
        let blocks = response.message.blocks.unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 0);

        server.join().unwrap();
    }

    #[test]
    fn signed_transaction_propagates_between_two_tcp_nodes() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let sender_address = address(&sender.verifying_key());
        let receiver_address = address(&receiver.verifying_key());
        let tx = sign(&sender, receiver_address, COIN, 1, 0).unwrap();
        let tx_id = tx.id().unwrap();

        // Start node B as a real TCP listener with the same initial ledger.
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let address_b = listener_b.local_addr().unwrap();
        let mut chain_b_state = ChainState::new();
        chain_b_state.ledger.balances.insert(sender_address.clone(), 5 * COIN);
        let chain_b: SharedChain = Arc::new(Mutex::new(chain_b_state));
        let pool_b: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        let active_b = Arc::new(AtomicUsize::new(0));
        let data_b = std::env::temp_dir().join(format!("ana-two-node-b-{}.json", std::process::id()));
        let b_chain = chain_b.clone();
        let b_pool = pool_b.clone();
        let b_active = active_b.clone();
        let b_data = data_b.clone();
        let server_b = thread::spawn(move || {
            let (stream, _) = listener_b.accept().unwrap();
            handle(
                stream,
                b_chain,
                Arc::new(Vec::new()),
                Arc::new(Mutex::new(HashSet::new())),
                b_pool,
                b_data,
                b_active,
                Arc::new(Mutex::new(BTreeMap::new())),
            );
        });

        // Node A accepts the transaction and gossips it to node B.
        let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let address_a = listener_a.local_addr().unwrap();
        let mut chain_a_state = ChainState::new();
        chain_a_state.ledger.balances.insert(sender_address, 5 * COIN);
        let chain_a: SharedChain = Arc::new(Mutex::new(chain_a_state));
        let pool_a: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        let active_a = Arc::new(AtomicUsize::new(0));
        let data_a = std::env::temp_dir().join(format!("ana-two-node-a-{}.json", std::process::id()));
        let a_chain = chain_a.clone();
        let a_pool = pool_a.clone();
        let a_active = active_a.clone();
        let a_data = data_a.clone();
        let peer_list: Peers = Arc::new(vec![address_b.to_string()]);
        let server_a = thread::spawn(move || {
            let (stream, _) = listener_a.accept().unwrap();
            handle(
                stream,
                a_chain,
                peer_list,
                Arc::new(Mutex::new(HashSet::new())),
                a_pool,
                a_data,
                a_active,
                Arc::new(Mutex::new(BTreeMap::new())),
            );
        });

        let mut client = TcpStream::connect(address_a).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let request = Message {
            kind: "transaction".into(),
            transaction: Some(tx),
            block: None,
            blocks: None,
            address: None,
            balance: None,
            nonce: None,
            transaction_id: None,
            transaction_state: None,
            confirmed_height: None,
            confirmations: None,
            node_status: None, history_page: None,
        };
        let mut wire = authenticated_wire(&request).unwrap();
        wire.push(b'\n');
        client.write_all(&wire).unwrap();
        let mut ack_line = Vec::new();
        BufReader::new(client).read_until(b'\n', &mut ack_line).unwrap();
        let ack: AuthenticatedMessage = serde_json::from_slice(&ack_line).unwrap();
        assert_eq!(ack.message.transaction_state.as_deref(), Some("accepted"));

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if pool_b.lock().unwrap().contains_key(&tx_id) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "node B did not receive the transaction");
            thread::sleep(Duration::from_millis(10));
        }

        server_a.join().unwrap();
        server_b.join().unwrap();
        let _ = fs::remove_file(data_a);
        let _ = fs::remove_file(data_b);
        let _ = fs::remove_file(mempool_path(&std::env::temp_dir().join(format!("ana-two-node-a-{}.json", std::process::id()))));
        let _ = fs::remove_file(mempool_path(&std::env::temp_dir().join(format!("ana-two-node-b-{}.json", std::process::id()))));
    }

    #[test]
    fn node_status_is_served_over_a_real_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let chain: SharedChain = Arc::new(Mutex::new(ChainState::new()));
        let peers: Peers = Arc::new(Vec::new());
        let seen: Seen = Arc::new(Mutex::new(HashSet::new()));
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let data_file = std::env::temp_dir().join(format!("ana-tcp-status-{}.json", std::process::id()));

        let server_chain = chain.clone();
        let server_peers = peers.clone();
        let server_seen = seen.clone();
        let server_pool = pool.clone();
        let server_active = active.clone();
        let server_file = data_file.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(
                stream,
                server_chain,
                server_peers,
                server_seen,
                server_pool,
                server_file,
                server_active,
                Arc::new(Mutex::new(BTreeMap::new())),
            );
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let request = Message {
            kind: "get_status".into(),
            transaction: None,
            block: None,
            blocks: None,
            address: None,
            balance: None,
            nonce: None,
            transaction_id: None,
            transaction_state: None,
            confirmed_height: None,
            confirmations: None,
            node_status: None, history_page: None,
        };
        let mut wire = authenticated_wire(&request).unwrap();
        wire.push(b'\n');
        client.write_all(&wire).unwrap();

        let mut response_line = Vec::new();
        BufReader::new(client)
            .read_until(b'\n', &mut response_line)
            .unwrap();
        let response: AuthenticatedMessage = serde_json::from_slice(&response_line).unwrap();
        assert_eq!(response.message.kind, "node_status");
        let status = response.message.node_status.unwrap();
        assert_eq!(status.network, ana_blockchain::NETWORK);
        assert_eq!(status.height, 0);
        assert_eq!(status.pending_transactions, 0);

        server.join().unwrap();
    }
}
