use ana_blockchain::{validate_address, Block, ChainState, Ledger, Transaction};
use ana_blockchain::peer_tls::{accept_authenticated, connect_authenticated, load_client_config, load_server_config};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex, OnceLock},
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
}

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
#[derive(Default)]
struct SeenCache {
    ids: HashSet<String>,
    insertion_order: VecDeque<String>,
}
type Seen = Arc<Mutex<SeenCache>>;
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
        confirmations: None, node_status: None }
}

const MAX_CONNECTIONS: usize = 64;
const MAX_CONNECTIONS_PER_WINDOW: usize = 30;
const CONNECTION_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_LIMIT_ENTRIES: usize = 256;
const MAX_MEMPOOL_TRANSACTIONS: usize = 4_096;
const MAX_SEEN_IDS: usize = 100_000;
const MAX_MEMPOOL_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MESSAGE_BYTES: u64 = 8 * 1024 * 1024;
const SOCKET_TIMEOUT_SECS: u64 = 10;


struct PeerTls {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    server_name: String,
}
static PEER_TLS: OnceLock<PeerTls> = OnceLock::new();

fn peer_tls_from_env() -> Result<Option<PeerTls>> {
    const REQUIRED: [&str; 5] = ["ANA_PEER_CA", "ANA_PEER_CRL", "ANA_PEER_CERT", "ANA_PEER_KEY", "ANA_PEER_SERVER_NAME"];
    let supplied = REQUIRED.iter().filter(|name| env::var_os(name).is_some()).count();
    if supplied == 0 { return Ok(None); }
    if supplied != REQUIRED.len() { bail!("mTLS requires all five ANA_PEER_* credential variables"); }
    let path = |name: &str| -> Result<PathBuf> { Ok(PathBuf::from(env::var(name)?)) };
    let ca = path("ANA_PEER_CA")?; let crl = path("ANA_PEER_CRL")?;
    let cert = path("ANA_PEER_CERT")?; let key = path("ANA_PEER_KEY")?;
    let server_name = env::var("ANA_PEER_SERVER_NAME")?;
    if server_name.trim().is_empty() { bail!("ANA_PEER_SERVER_NAME must not be empty"); }
    Ok(Some(PeerTls {
        server: load_server_config(&ca, &crl, &cert, &key)?,
        client: load_client_config(&ca, &crl, &cert, &key)?,
        server_name,
    }))
}

fn resolve_tls_peer(peer: &str) -> Result<std::net::SocketAddr> {
    peer.to_socket_addrs()?.next().context("TLS peer resolved to no addresses")
}
/// Bounded per-source connection-attempt limiter. Entries expire after one
/// window; the map itself is capped so source churn cannot grow memory forever.
#[derive(Default)]
struct ConnectionRateLimiter {
    attempts: HashMap<IpAddr, VecDeque<Instant>>,
}

impl ConnectionRateLimiter {
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let cutoff = now.checked_sub(CONNECTION_RATE_WINDOW).unwrap_or(now);
        for attempts in self.attempts.values_mut() {
            while attempts.front().is_some_and(|time| *time <= cutoff) {
                attempts.pop_front();
            }
        }
        self.attempts.retain(|_, attempts| !attempts.is_empty());
        if !self.attempts.contains_key(&ip) && self.attempts.len() >= MAX_RATE_LIMIT_ENTRIES {
            return false;
        }
        let attempts = self.attempts.entry(ip).or_default();
        if attempts.len() >= MAX_CONNECTIONS_PER_WINDOW {
            return false;
        }
        attempts.push_back(now);
        true
    }
}

/// The current peer protocol is plaintext TCP and carries no authenticated
/// transport identity. Restrict listeners to loopback until mTLS is implemented.
fn validate_bind_security(bind: &str) -> Result<()> {
    let addresses: Vec<_> = bind.to_socket_addrs()
        .context("could not resolve node bind address")?
        .collect();
    if addresses.is_empty() {
        bail!("node bind address resolved to no socket addresses");
    }
    if addresses.iter().all(|address| address.ip().is_loopback()) {
        return Ok(());
    }
    bail!("refusing non-loopback bind: peer transport is plaintext and unauthenticated; use loopback with a trusted VPN/SSH tunnel until encrypted peer transport is implemented");
}

/// Resolve an outbound peer immediately before connecting and enforce the
/// loopback-only boundary on the exact socket address used. Rechecking at send
/// time prevents DNS changes after startup validation from bypassing the guard.
fn resolve_loopback_peer(peer: &str) -> Result<std::net::SocketAddr> {
    let addresses: Vec<_> = peer.to_socket_addrs()
        .with_context(|| format!("could not resolve configured peer {peer}"))?
        .collect();
    if addresses.is_empty() {
        bail!("configured peer {peer} resolved to no socket addresses");
    }
    if !addresses.iter().all(|address| address.ip().is_loopback()) {
        bail!("refusing non-loopback peer {peer}: outbound peer transport is plaintext and unauthenticated; use loopback with a trusted VPN/SSH tunnel until encrypted peer transport is implemented");
    }
    Ok(addresses[0])
}

/// Validate configured peers at startup so invalid remote addresses fail fast.
fn validate_peer_security(peer: &str) -> Result<()> {
    resolve_loopback_peer(peer).map(|_| ())
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
            node_status: message.node_status.clone(),
        },
        auth: peer_token(),
    })?)
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}


fn send(peer: &str, message: &Message) {
    let tls = PEER_TLS.get();
    let address = match if tls.is_some() { resolve_tls_peer(peer) } else { resolve_loopback_peer(peer) } {
        Ok(value) => value,
        Err(error) => { eprintln!("Refusing outbound peer connection: {error}"); return; }
    };
    if let Ok(mut tcp) = TcpStream::connect_timeout(&address, Duration::from_secs(SOCKET_TIMEOUT_SECS)) {
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
        if let Ok(mut wire) = authenticated_wire(message) {
            wire.push(b'\n');
            if let Some(tls) = tls {
                match connect_authenticated(tcp, tls.client.clone(), &tls.server_name, ana_blockchain::NETWORK) {
                    Ok(mut stream) => { let _ = stream.write_all(&wire); }
                    Err(error) => eprintln!("Outbound ANA mTLS authentication failed: {error}"),
                }
            } else { let _ = tcp.write_all(&wire); }
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
    if snapshot.len() > MAX_MEMPOOL_TRANSACTIONS {
        bail!("mempool exceeds the configured transaction limit");
    }
    let serialized = serde_json::to_vec_pretty(&snapshot)?;
    if serialized.len() as u64 > MAX_MEMPOOL_FILE_BYTES {
        bail!("mempool snapshot exceeds the configured file-size limit");
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    // NamedTempFile creates a unique file in the destination directory and
    // persist() performs platform-specific replacement, including on Windows.
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .context("could not create temporary mempool snapshot")?;
    temp.write_all(&serialized)?;
    temp.as_file().sync_all().context("could not sync temporary mempool snapshot")?;
    temp.persist(path).map_err(|error| {
        anyhow::anyhow!("could not atomically replace mempool snapshot {}: {}", path.display(), error.error)
    })?;
    Ok(())
}

/// Read a file without trusting a prior metadata() size check. The extra byte
/// detects oversized files even if they grow while being read.
fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("file exceeds the configured size limit");
    }
    Ok(bytes)
}

/// Load only correctly keyed, correctly signed, currently executable transactions.
fn load_mempool(path: &Path, chain: &ChainState) -> Result<BTreeMap<String, Transaction>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = read_bounded_file(path, MAX_MEMPOOL_FILE_BYTES)
        .context("could not safely read mempool file")?;
    let stored: BTreeMap<String, Transaction> = serde_json::from_slice(&bytes)?;
    if stored.len() > MAX_MEMPOOL_TRANSACTIONS {
        bail!("mempool file exceeds the configured transaction limit");
    }
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

/// Bounded FIFO duplicate cache. Eviction is safe because ledger nonce, block
/// linkage, and transaction validity checks remain authoritative on acceptance.
fn remember_seen(seen: &Seen, id: String) -> bool {
    let Ok(mut cache) = seen.lock() else { return false; };
    if !cache.ids.insert(id.clone()) { return false; }
    cache.insertion_order.push_back(id);
    if cache.ids.len() > MAX_SEEN_IDS {
        if let Some(oldest) = cache.insertion_order.pop_front() {
            cache.ids.remove(&oldest);
        }
    }
    true
}

fn transaction_ack(id: &str, state: &str) -> Message {
    Message {
        kind: "transaction_result".into(), transaction: None, block: None, blocks: None,
        address: None, balance: None, nonce: None, transaction_id: Some(id.to_owned()),
        transaction_state: Some(state.to_owned()), confirmed_height: None, confirmations: None, node_status: None,
    }
}

fn response<S: Write>(stream: &mut S, message: &Message) {
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
    let peer_is_loopback = stream.peer_addr().map(|address| address.ip().is_loopback()).unwrap_or(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
    handle_transport(stream, peer_is_loopback, chain, peers, seen, pool, data_file, active_connections, sync_sessions);
}

/// Process newline-delimited peer messages over any Read + Write transport.
/// This keeps protocol framing independent from the underlying TCP/TLS stream.
fn handle_transport<S: Read + Write>(
    mut stream: S,
    peer_is_loopback: bool,
    chain: SharedChain,
    peers: Peers,
    seen: Seen,
    pool: Mempool,
    data_file: PathBuf,
    active_connections: Arc<AtomicUsize>,
    sync_sessions: SyncSessions,
) {
    let _connection_guard = ConnectionGuard(active_connections);
    let mut line = Vec::new();
    let read_result = {
        let mut reader = BufReader::new(&mut stream);
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
        None if !peer_is_loopback => {
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
                        confirmations: Some(u64::from(end < state.blocks.len())), node_status: None };
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
                            node_status: None,
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
                });
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
                        confirmed_height: height, confirmations, node_status: None,
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
                let first_seen = remember_seen(&seen, id);
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
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None,
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
                if seen.lock().map(|cache| cache.ids.contains(&id)).unwrap_or(true) {
                    response(&mut stream, &transaction_ack(&id, "already_known"));
                    return;
                }
                if let Ok(mut values) = pool.lock() {
                    if values.len() >= MAX_MEMPOOL_TRANSACTIONS {
                        response(&mut stream, &transaction_ack(&id, "mempool_full"));
                        return;
                    }
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
                let _ = remember_seen(&seen, id.clone());
                println!("Accepted pending transaction {id}");
                persist_mempool_after_change(&pool, &data_file);
                response(&mut stream, &transaction_ack(&id, "accepted"));
                broadcast(&peers, &Message {
                    kind: "transaction".into(), transaction: Some(tx), block: None,
                    blocks: None, address: None, balance: None, nonce: None,
                    transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None,
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
    let configured_peers: Vec<String> = args.iter().skip(4).cloned().collect();
    validate_bind_security(bind)?;
    for peer in &configured_peers {
        validate_peer_security(peer)?;
    }
    let peers: Peers = Arc::new(configured_peers);
    let chain = Arc::new(Mutex::new(ChainState::load(&data_file)?));
    let mempool_file = mempool_path(&data_file);
    let restored = {
        let state = chain.lock().map_err(|_| anyhow::anyhow!("chain lock poisoned"))?;
        load_mempool(&mempool_file, &state)?
    };
    println!("Restored {} pending transaction(s) from {}", restored.len(), mempool_file.display());
    let mut restored_seen = SeenCache::default();
    for id in restored.keys().take(MAX_SEEN_IDS) {
        restored_seen.ids.insert(id.clone());
        restored_seen.insertion_order.push_back(id.clone());
    }
    let seen: Seen = Arc::new(Mutex::new(restored_seen));
    let pool: Mempool = Arc::new(Mutex::new(restored));

    let listener = TcpListener::bind(bind)?;
    println!("ANA TESTNET node listening on {bind}; {} configured peers", peers.len());
    println!("Network safeguards: {MAX_CONNECTIONS} concurrent connections, {MAX_MESSAGE_BYTES} byte message cap, {MAX_MEMPOOL_TRANSACTIONS} pending transaction cap, {MAX_SEEN_IDS} duplicate-cache cap, {SOCKET_TIMEOUT_SECS}s socket timeout.");
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
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None,
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
    let mut connection_rate = ConnectionRateLimiter::default();
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let source_ip = match stream.peer_addr() {
                    Ok(address) => address.ip(),
                    Err(error) => {
                        eprintln!("Rejected connection with unavailable peer address: {error}");
                        drop(stream);
                        continue;
                    }
                };
                if !connection_rate.allow(source_ip, Instant::now()) {
                    eprintln!("Rejected connection: source rate limit reached");
                    drop(stream);
                    continue;
                }
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

    // Thread names contain ':' on Rust's Windows test runner, which is not
    // valid in Windows filenames. A process-local counter also keeps parallel
    // tests from colliding when they use the same label.
    static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_file(label: &str) -> PathBuf {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ana-{label}-{}-{sequence}.json",
            std::process::id()
        ))
    }

    #[test]
    fn connection_rate_limiter_enforces_window_and_expires_old_attempts() {
        let mut limiter = ConnectionRateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let start = Instant::now();
        for _ in 0..MAX_CONNECTIONS_PER_WINDOW {
            assert!(limiter.allow(ip, start));
        }
        assert!(!limiter.allow(ip, start));
        assert!(limiter.allow(ip, start + CONNECTION_RATE_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn connection_rate_limiter_caps_source_tracking() {
        let mut limiter = ConnectionRateLimiter::default();
        let start = Instant::now();
        for value in 1..=MAX_RATE_LIMIT_ENTRIES {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(value as u32));
            assert!(limiter.allow(ip, start));
        }
        let extra = IpAddr::V4(std::net::Ipv4Addr::from((MAX_RATE_LIMIT_ENTRIES + 1) as u32));
        assert!(!limiter.allow(extra, start));
        assert!(limiter.attempts.len() <= MAX_RATE_LIMIT_ENTRIES);
    }

    #[test]
    fn mempool_persistence_replaces_existing_snapshot() {
        let path = temp_file("mempool-replace");
        fs::write(&path, b"stale snapshot").unwrap();
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        persist_mempool(&pool, &path).unwrap();
        let restored: BTreeMap<String, Transaction> =
            serde_json::from_slice(&read_bounded_file(&path, MAX_MEMPOOL_FILE_BYTES).unwrap()).unwrap();
        assert!(restored.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn mempool_persistence_uses_unique_temp_files_and_leaves_no_temp_file() {
        let path = temp_file("mempool-atomic");
        let pool: Mempool = Arc::new(Mutex::new(BTreeMap::new()));
        persist_mempool(&pool, &path).unwrap();
        assert!(path.exists());
        let parent = path.parent().unwrap();
        let prefix = format!("{}.tmp.", path.file_name().unwrap().to_string_lossy());
        let leftovers = fs::read_dir(parent).unwrap().filter_map(|entry| entry.ok())
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix));
        assert!(!leftovers);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn bounded_file_reader_rejects_growth_past_limit() {
        let path = temp_file("bounded-read");
        fs::write(&path, b"12345").unwrap();
        assert_eq!(read_bounded_file(&path, 5).unwrap(), b"12345");
        assert!(read_bounded_file(&path, 4).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn seen_cache_is_bounded_and_reports_duplicates() {
        let seen: Seen = Arc::new(Mutex::new(SeenCache::default()));
        assert!(remember_seen(&seen, "first".into()));
        assert!(!remember_seen(&seen, "first".into()));
        for index in 0..=MAX_SEEN_IDS {
            let _ = remember_seen(&seen, format!("id-{index}"));
        }
        assert!(seen.lock().unwrap().ids.len() <= MAX_SEEN_IDS);
    }

    #[test]
    fn seen_cache_evicts_oldest_inserted_id_first() {
        let seen: Seen = Arc::new(Mutex::new(SeenCache::default()));
        assert!(remember_seen(&seen, "oldest".into()));
        for index in 0..MAX_SEEN_IDS {
            let _ = remember_seen(&seen, format!("new-{}", index));
        }
        let cache = seen.lock().unwrap();
        assert!(!cache.ids.contains("oldest"));
        assert!(cache.ids.contains(&format!("new-{}", MAX_SEEN_IDS - 1)));
    }

    #[test]
    fn outbound_peer_transport_allows_loopback_only() {
        assert!(validate_peer_security("127.0.0.1:18080").is_ok());
        assert!(validate_peer_security("[::1]:18080").is_ok());
        assert!(validate_peer_security("localhost:18080").is_ok());
        assert!(validate_peer_security("0.0.0.0:18080").is_err());
        assert!(validate_peer_security("[::]:18080").is_err());
        assert!(validate_peer_security("192.0.2.1:18080").is_err());
        assert!(resolve_loopback_peer("192.0.2.1:18080").is_err());
    }

    #[test]
    fn plaintext_transport_allows_loopback_only() {
        assert!(validate_bind_security("127.0.0.1:19001").is_ok());
        assert!(validate_bind_security("[::1]:19001").is_ok());
        assert!(validate_bind_security("0.0.0.0:19001").is_err());
        assert!(validate_bind_security("[::]:19001").is_err());
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
            transaction_id: None, transaction_state: None, confirmed_height: None, confirmations: None, node_status: None,
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
        let seen: Seen = Arc::new(Mutex::new(SeenCache::default()));
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
            node_status: None,
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
                Arc::new(Mutex::new(SeenCache::default())),
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
                Arc::new(Mutex::new(SeenCache::default())),
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
            node_status: None,
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
        let seen: Seen = Arc::new(Mutex::new(SeenCache::default()));
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
            node_status: None,
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
