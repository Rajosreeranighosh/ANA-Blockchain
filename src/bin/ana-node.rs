use ana_blockchain::{validate_address, Block, ChainState, Transaction};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
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
}

type SharedChain = Arc<Mutex<ChainState>>;
type Peers = Arc<Vec<String>>;
type Seen = Arc<Mutex<HashSet<String>>>;

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

fn handle(
    stream: TcpStream,
    chain: SharedChain,
    peers: Peers,
    seen: Seen,
    data_file: PathBuf,
) {
    let mut line = String::new();
    let cloned = match stream.try_clone() {
        Ok(value) => value,
        Err(_) => return,
    };
    if BufReader::new(cloned).read_line(&mut line).is_err() {
        return;
    }
    let message: Message = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(_) => return,
    };

    match message.kind.as_str() {
        "get_chain" => {
            if let Ok(state) = chain.lock() {
                let response = Message {
                    kind: "blocks".into(),
                    transaction: None,
                    block: None,
                    blocks: Some(state.blocks.clone()),
                };
                if let Ok(mut wire) = serde_json::to_vec(&response) {
                    wire.push(b'\n');
                    let mut stream = stream;
                    let _ = stream.write_all(&wire);
                }
            }
        }
        "blocks" => {
            if let Some(blocks) = message.blocks {
                let mut changed = false;
                if let Ok(mut state) = chain.lock() {
                    for block in blocks {
                        if state.append(block).is_ok() {
                            changed = true;
                        }
                    }
                }
                if changed {
                    persist(&chain, &data_file);
                    broadcast(&peers, &Message {
                        kind: "get_chain".into(),
                        transaction: None,
                        block: None,
                        blocks: None,
                    });
                }
            }
        }
        "block" => {
            if let Some(block) = message.block {
                let id = block.hash.clone();
                let first_seen = seen.lock().map(|mut values| values.insert(id)).unwrap_or(false);
                if !first_seen {
                    return;
                }
                let accepted = chain.lock().map(|mut state| state.append(block.clone()).is_ok()).unwrap_or(false);
                if accepted {
                    println!("Accepted block #{} {}", block.height, block.hash);
                    persist(&chain, &data_file);
                    broadcast(&peers, &Message {
                        kind: "block".into(),
                        transaction: None,
                        block: Some(block),
                        blocks: None,
                    });
                } else {
                    eprintln!("Rejected invalid, stale, or non-extending block");
                }
            }
        }
        "transaction" => {
            if let Some(tx) = message.transaction {
                if tx.verify().is_err() {
                    eprintln!("Rejected invalid transaction");
                    return;
                }
                let id = match tx.id() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if !seen.lock().map(|mut values| values.insert(id.clone())).unwrap_or(false) {
                    return;
                }
                println!("Relayed unconfirmed transaction {id}");
                broadcast(&peers, &Message {
                    kind: "transaction".into(),
                    transaction: Some(tx),
                    block: None,
                    blocks: None,
                });
            }
        }
        _ => {}
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        bail!("Usage: ana-node <bind-ip:port> <data-file> <miner-address> [peer-ip:port ...]");
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

    let listener = TcpListener::bind(bind)?;
    println!("ANA TESTNET node listening on {bind}; {} configured peers", peers.len());
    println!("RandomX testnet difficulty: 8 bits; mining empty blocks only.");
    for peer in peers.iter() {
        send(peer, &Message {
            kind: "get_chain".into(),
            transaction: None,
            block: None,
            blocks: None,
        });
    }

    if let Some(miner_address) = miner {
        let mining_chain = chain.clone();
        let mining_peers = peers.clone();
        let mining_file = data_file.clone();
        thread::spawn(move || loop {
            let result = mining_chain.lock().map_err(|_| anyhow::anyhow!("chain lock poisoned"))
                .and_then(|state| state.mine_next(miner_address.clone()));
            match result {
                Ok(block) => {
                    let accepted = mining_chain.lock().map(|mut state| state.append(block.clone()).is_ok()).unwrap_or(false);
                    if accepted {
                        println!("Mined block #{} {}", block.height, block.hash);
                        persist(&mining_chain, &mining_file);
                        broadcast(&mining_peers, &Message {
                            kind: "block".into(),
                            transaction: None,
                            block: Some(block),
                            blocks: None,
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
                let f = data_file.clone();
                thread::spawn(move || handle(stream, c, p, s, f));
            }
            Err(error) => eprintln!("connection error: {error}"),
        }
    }
    Ok(())
}
