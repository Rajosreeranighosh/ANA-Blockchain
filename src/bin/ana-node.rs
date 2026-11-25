use ana_blockchain::{validate_address, Block, ChainState, Ledger, Transaction};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
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
}

type SharedChain = Arc<Mutex<ChainState>>;
type Peers = Arc<Vec<String>>;
type Seen = Arc<Mutex<HashSet<String>>>;
type Mempool = Arc<Mutex<BTreeMap<String, Transaction>>>;

fn send(peer: &str, message: &Message) {
    if let Ok(mut stream) = TcpStream::connect(peer) {
        if let Ok(mut wire) = serde_json::to_vec(message) {
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

fn response(stream: &mut TcpStream, message: &Message) {
    if let Ok(mut wire) = serde_json::to_vec(message) {
        wire.push(b'\n');
        let _ = stream.write_all(&wire);
    }
}

/// Return transactions that can be applied in deterministic sender/nonce order.
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

fn handle(
    mut stream: TcpStream,
    chain: SharedChain,
    peers: Peers,
    seen: Seen,
    pool: Mempool,
    data_file: PathBuf,
) {
    let mut line = String::new();
    if BufReader::new(match stream.try_clone() { Ok(s) => s, Err(_) => return })
        .read_line(&mut line).is_err() {
        return;
    }
    let message: Message = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(_) => return,
    };

    match message.kind.as_str() {
        "get_chain" => {
            if let Ok(state) = chain.lock() {
                response(&mut stream, &Message {
                    kind: "blocks".into(), transaction: None, block: None,
                    blocks: Some(state.blocks.clone()), address: None, balance: None, nonce: None,
                });
            }
        }
        "get_account" => {
            if let Some(address) = message.address {
                if let Some(ledger) = projected_ledger(&chain, &pool) {
                    response(&mut stream, &Message {
                        kind: "account".into(), transaction: None, block: None, blocks: None,
                        address: Some(address.clone()), balance: Some(ledger.balance(&address)),
                        nonce: Some(ledger.nonce(&address)),
                    });
                }
            }
        }
        "blocks" => {
            if let Some(blocks) = message.blocks {
                let (changed, displaced) = if let Ok(mut state) = chain.lock() {
                    let old_blocks = state.blocks.clone();
                    match state.replace_if_more_work(blocks) {
                        Ok(true) => {
                            let canonical: HashSet<String> = state.blocks.iter()
                                .flat_map(|b| b.transactions.iter())
                                .filter_map(|tx| tx.id().ok()).collect();
                            let displaced: Vec<Transaction> = old_blocks.iter()
                                .flat_map(|b| b.transactions.iter().cloned())
                                .filter(|tx| tx.id().map(|id| !canonical.contains(&id)).unwrap_or(false))
                                .collect();
                            (true, displaced)
                        }
                        Ok(false) => (false, Vec::new()),
                        Err(error) => { eprintln!("Rejected candidate chain: {error}"); (false, Vec::new()) }
                    }
                } else { (false, Vec::new()) };
                if changed {
                    if let Ok(mut values) = pool.lock() {
                        for tx in displaced { if let Ok(id) = tx.id() { values.insert(id, tx); } }
                    }
                    prune_mempool(&chain, &pool);
                    persist(&chain, &data_file);
                    println!("Switched to higher-work chain at height {}",
                        chain.lock().map(|s| s.tip().height).unwrap_or(0));
                    broadcast(&peers, &Message {
                        kind: "get_chain".into(), transaction: None, block: None,
                        blocks: None, address: None, balance: None, nonce: None,
                    });
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
                    persist(&chain, &data_file);
                    broadcast(&peers, &Message {
                        kind: "block".into(), transaction: None, block: Some(block),
                        blocks: None, address: None, balance: None, nonce: None,
                    });
                } else {
                    eprintln!("Block does not extend local tip; requesting peer chain");
                    broadcast(&peers, &Message {
                        kind: "get_chain".into(), transaction: None, block: None,
                        blocks: None, address: None, balance: None, nonce: None,
                    });
                }
            }
        }
        "transaction" => {
            if let Some(tx) = message.transaction {
                if tx.verify().is_err() {
                    eprintln!("Rejected invalid transaction");
                    return;
                }
                let id = match tx.id() { Ok(id) => id, Err(_) => return };
                if seen.lock().map(|values| values.contains(&id)).unwrap_or(true) {
                    return;
                }
                if let Ok(mut values) = pool.lock() {
                    values.insert(id.clone(), tx.clone());
                } else { return; }
                let accepted = chain.lock().ok()
                    .map(|state| select_transactions(&state, &pool).iter()
                        .any(|candidate| candidate.id().ok().as_deref() == Some(&id)))
                    .unwrap_or(false);
                if !accepted {
                    if let Ok(mut values) = pool.lock() { values.remove(&id); }
                    eprintln!("Rejected transaction: nonce, balance, or ordering invalid");
                    return;
                }
                if let Ok(mut values) = seen.lock() { values.insert(id.clone()); }
                println!("Accepted pending transaction {id}");
                broadcast(&peers, &Message {
                    kind: "transaction".into(), transaction: Some(tx), block: None,
                    blocks: None, address: None, balance: None, nonce: None,
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
    let chain = Arc::new(Mutex::new(ChainState::load(&data_file)?));
    let seen: Seen = Arc::new(Mutex::new(HashSet::new()));
    let pool: Mempool = Arc::new(Mutex::new(BTreeMap::new()));

    let listener = TcpListener::bind(bind)?;
    println!("ANA TESTNET node listening on {bind}; {} configured peers", peers.len());
    println!("RandomX testnet difficulty: 8 bits; mining pending transactions.");
    for peer in peers.iter() {
        send(peer, &Message {
            kind: "get_chain".into(), transaction: None, block: None,
            blocks: None, address: None, balance: None, nonce: None,
        });
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
                        persist(&mining_chain, &mining_file);
                        broadcast(&mining_peers, &Message {
                            kind: "block".into(), transaction: None, block: Some(block),
                            blocks: None, address: None, balance: None, nonce: None,
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

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let c = chain.clone();
                let p = peers.clone();
                let s = seen.clone();
                let m = pool.clone();
                let f = data_file.clone();
                thread::spawn(move || handle(stream, c, p, s, m, f));
            }
            Err(error) => eprintln!("connection error: {error}"),
        }
    }
    Ok(())
}
