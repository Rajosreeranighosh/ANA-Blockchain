use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const COIN: u64 = 100_000_000;
const MAX_SUPPLY: u64 = 21_000_000 * COIN;
const INITIAL_BLOCK_REWARD: u64 = 50 * COIN;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockHeader {
    height: u64,
    timestamp: u64,
    previous_hash: String,
    nonce: u64,
    difficulty: u8,
    reward: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Block {
    header: BlockHeader,
    hash: String,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

// Development-only hash function. This is NOT RandomX.
// RandomX must replace this behind a tested PoW interface before testnet launch.
fn development_hash(header: &BlockHeader) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(header)?;
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn meets_demo_target(hash: &[u8; 32], difficulty: u8) -> bool {
    hash.iter().take((difficulty / 2) as usize).all(|b| *b == 0)
        && (difficulty % 2 == 0 || hash[(difficulty / 2) as usize] < 16)
}

fn genesis() -> Block {
    let header = BlockHeader {
        height: 0,
        timestamp: 1_764_096_000,
        previous_hash: "0".repeat(64),
        nonce: 0,
        difficulty: 0,
        reward: 0,
    };
    let hash = development_hash(&header).expect("static genesis header serializes");
    Block { header, hash: hex::encode(hash) }
}

fn mine_demo_block(previous: &Block, difficulty: u8) -> Result<Block> {
    if difficulty > 6 {
        bail!("demo difficulty must be between 0 and 6");
    }

    let mut header = BlockHeader {
        height: previous.header.height + 1,
        timestamp: now()?,
        previous_hash: previous.hash.clone(),
        nonce: 0,
        difficulty,
        reward: INITIAL_BLOCK_REWARD.min(MAX_SUPPLY),
    };

    loop {
        let hash = development_hash(&header)?;
        if meets_demo_target(&hash, difficulty) {
            return Ok(Block { header, hash: hex::encode(hash) });
        }
        header.nonce = header.nonce.checked_add(1).ok_or_else(|| anyhow::anyhow!("nonce overflow"))?;
    }
}

fn main() -> Result<()> {
    let difficulty = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1".to_string())
        .parse::<u8>()?;

    let previous = genesis();
    let block = mine_demo_block(&previous, difficulty)?;

    println!("ANA development-chain demo");
    println!("WARNING: SHA-256 demo PoW only; NOT RandomX and NOT mainnet-ready.");
    println!("{}", serde_json::to_string_pretty(&block)?);
    println!("Reward: {} ANA", block.header.reward as f64 / COIN as f64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic() {
        assert_eq!(genesis().hash, genesis().hash);
    }

    #[test]
    fn demo_block_links_to_genesis() {
        let g = genesis();
        let b = mine_demo_block(&g, 0).unwrap();
        assert_eq!(b.header.height, 1);
        assert_eq!(b.header.previous_hash, g.hash);
    }
}
