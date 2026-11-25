use anyhow::{bail, Context, Result};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const COIN: u64 = 100_000_000;
const MAX_SUPPLY: u64 = 21_000_000 * COIN;
const INITIAL_BLOCK_REWARD: u64 = 50 * COIN;

// DEVELOPMENT ONLY. This is not a finalized network seed schedule.
// A real network must specify deterministic seed epochs in its consensus rules.
const DEV_RANDOMX_KEY: &[u8] = b"ANA-DEVNET-RANDOMX-SEED-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockHeader {
    height: u64,
    timestamp: u64,
    previous_hash: String,
    nonce: u64,
    difficulty: u16,
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

fn header_bytes(header: &BlockHeader) -> Result<Vec<u8>> {
    // Struct field order is stable in serde_json, but production consensus should
    // use a formally specified canonical binary header encoding.
    Ok(serde_json::to_vec(header)?)
}

fn meets_target(hash: &[u8; 32], difficulty: u16) -> bool {
    let full_zero_bytes = (difficulty / 8) as usize;
    let remaining_bits = (difficulty % 8) as u8;

    if !hash.iter().take(full_zero_bytes).all(|byte| *byte == 0) {
        return false;
    }

    remaining_bits == 0 || (hash[full_zero_bytes] >> (8 - remaining_bits)) == 0
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
    // Genesis is a fixed bootstrap constant in this prototype. It is not mined.
    let bytes = serde_json::to_vec(&header).expect("genesis header serializes");
    let hash = Sha256::digest(bytes);
    Block {
        header,
        hash: hex::encode(hash),
    }
}

fn mine_randomx_block(previous: &Block, difficulty: u16) -> Result<Block> {
    if difficulty > 255 {
        bail!("difficulty must be between 0 and 255 leading zero bits");
    }

    println!("Initializing RandomX light-mode cache (about 256 MiB)...");
    let flags = RandomXFlag::default();
    let cache = RandomXCache::new(flags, DEV_RANDOMX_KEY)
        .context("failed to initialize RandomX cache")?;
    let vm = RandomXVM::new(flags, Some(cache), None)
        .context("failed to initialize RandomX VM")?;

    let mut header = BlockHeader {
        height: previous.header.height + 1,
        timestamp: now()?,
        previous_hash: previous.hash.clone(),
        nonce: 0,
        difficulty,
        reward: INITIAL_BLOCK_REWARD,
    };

    loop {
        let input = header_bytes(&header)?;
        let digest = vm.calculate_hash(&input)
            .context("RandomX hash calculation failed")?;
        let hash: [u8; 32] = digest.try_into()
            .map_err(|_| anyhow::anyhow!("RandomX returned an invalid digest length"))?;
        if meets_target(&hash, difficulty) {
            return Ok(Block {
                header,
                hash: hex::encode(hash),
            });
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce overflow"))?;
    }
}

fn main() -> Result<()> {
    let difficulty = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "8".to_string())
        .parse::<u16>()?;

    let previous = genesis();
    let block = mine_randomx_block(&previous, difficulty)?;

    println!("ANA RandomX development mining prototype");
    println!("WARNING: experimental dev seed and incomplete chain rules; NOT mainnet-ready.");
    println!("{}", serde_json::to_string_pretty(&block)?);
    println!(
        "Reward proposal: {} ANA",
        block.header.reward as f64 / COIN as f64
    );
    println!(
        "Supply cap target: {} ANA (not yet enforced by ledger state)",
        MAX_SUPPLY / COIN
    );
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
    fn target_checks_leading_bits() {
        let mut hash = [0u8; 32];
        assert!(meets_target(&hash, 8));
        assert!(meets_target(&hash, 13));
        hash[0] = 0x08;
        assert!(!meets_target(&hash, 5));
        assert!(meets_target(&hash, 4));
    }
}
