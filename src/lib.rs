use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::{SystemTime, UNIX_EPOCH}};

pub const COIN: u64 = 100_000_000;
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;
pub const BLOCK_REWARD: u64 = 50 * COIN;
pub const NETWORK: &str = "ANA-TESTNET-1";
pub const TESTNET_DIFFICULTY: u16 = 8;
pub const DIFFICULTY_RETARGET_INTERVAL: u64 = 10;
pub const TARGET_BLOCK_SECONDS: u64 = 30;
pub const MIN_TESTNET_DIFFICULTY: u16 = 4;
pub const MAX_TESTNET_DIFFICULTY: u16 = 24;
pub const MEDIAN_TIME_WINDOW: usize = 11;
pub const RANDOMX_SEED: &[u8] = b"ANA-TESTNET-RANDOMX-SEED-v1";

/// Parse a human ANA amount without floating-point rounding.
pub fn parse_amount(input: &str) -> Result<u64> {
    if input.is_empty() || input.starts_with('-') || input.starts_with('+') {
        bail!("amount must be a non-negative decimal number");
    }
    let mut parts = input.split('.');
    let whole = parts.next().context("missing amount")?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 8
    {
        bail!("amount must use digits and at most 8 decimal places");
    }
    let whole: u64 = whole.parse().context("amount is too large")?;
    let scale = 10u64.pow((8 - fraction.len()) as u32);
    let fractional: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().context("invalid fractional amount")?
    };
    whole
        .checked_mul(COIN)
        .and_then(|v| v.checked_add(fractional.checked_mul(scale)?))
        .context("amount is too large")
}

#[derive(Serialize, Deserialize)]
pub struct WalletFile {
    pub network: String,
    pub secret_key: String,
}

pub fn address(k: &VerifyingKey) -> String {
    format!("ana1{}", hex::encode(k.to_bytes()))
}

pub fn validate_address(value: &str) -> Result<()> {
    if !value.starts_with("ana1") || value.len() != 68 {
        bail!("invalid ANA address");
    }
    let bytes: [u8; 32] = hex::decode(&value[4..])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ANA address key"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid ANA public key")?;
    Ok(())
}

pub fn create_wallet(path: &Path) -> Result<String> {
    if path.exists() {
        bail!("refusing to overwrite wallet");
    }
    let k = SigningKey::generate(&mut OsRng);
    let w = WalletFile {
        network: NETWORK.into(),
        secret_key: hex::encode(k.to_bytes()),
    };
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&w)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(address(&k.verifying_key()))
}

pub fn open_wallet(path: &Path) -> Result<SigningKey> {
    let w: WalletFile = serde_json::from_slice(&fs::read(path)?)?;
    if w.network != NETWORK {
        bail!("wallet network mismatch");
    }
    let b: [u8; 32] = hex::decode(w.secret_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key"))?;
    Ok(SigningKey::from_bytes(&b))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub network: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
struct Payload<'a> {
    network: &'a str,
    from: &'a str,
    to: &'a str,
    amount: u64,
    fee: u64,
    nonce: u64,
    public_key: &'a str,
}

impl Transaction {
    fn payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Payload {
            network: &self.network,
            from: &self.from,
            to: &self.to,
            amount: self.amount,
            fee: self.fee,
            nonce: self.nonce,
            public_key: &self.public_key,
        })?)
    }

    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn verify(&self) -> Result<()> {
        if self.network != NETWORK || self.amount == 0 {
            bail!("invalid network or amount");
        }
        validate_address(&self.to)?;
        let p: [u8; 32] = hex::decode(&self.public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad public key"))?;
        let k = VerifyingKey::from_bytes(&p)?;
        if address(&k) != self.from {
            bail!("sender key mismatch");
        }
        let s: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature"))?;
        k.verify(&self.payload()?, &Signature::from_bytes(&s))
            .context("bad transaction signature")?;
        Ok(())
    }
}

pub fn sign(
    k: &SigningKey,
    to: String,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Result<Transaction> {
    let mut t = Transaction {
        network: NETWORK.into(),
        from: address(&k.verifying_key()),
        to,
        amount,
        fee,
        nonce,
        public_key: hex::encode(k.verifying_key().to_bytes()),
        signature: String::new(),
    };
    t.signature = hex::encode(k.sign(&t.payload()?).to_bytes());
    t.verify()?;
    Ok(t)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub height: u64,
    pub previous: String,
    pub timestamp: u64,
    pub miner: String,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
    pub difficulty: u16,
    pub hash: String,
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Ledger {
    pub balances: BTreeMap<String, u64>,
    pub nonces: BTreeMap<String, u64>,
    pub minted: u64,
}

impl Ledger {
    pub fn balance(&self, a: &str) -> u64 {
        *self.balances.get(a).unwrap_or(&0)
    }

    pub fn nonce(&self, a: &str) -> u64 {
        *self.nonces.get(a).unwrap_or(&0)
    }

    fn credit(&mut self, a: &str, n: u64) -> Result<()> {
        let v = self.balance(a).checked_add(n).context("balance overflow")?;
        self.balances.insert(a.into(), v);
        Ok(())
    }

    pub fn apply_transaction(&mut self, t: &Transaction) -> Result<()> {
        let mut candidate = self.clone();
        candidate.apply_transaction_inner(t)?;
        *self = candidate;
        Ok(())
    }

    fn apply_transaction_inner(&mut self, t: &Transaction) -> Result<()> {
        t.verify()?;
        if t.nonce != self.nonce(&t.from) {
            bail!("bad nonce");
        }
        let cost = t.amount.checked_add(t.fee).context("amount overflow")?;
        if self.balance(&t.from) < cost {
            bail!("insufficient balance");
        }
        let next_nonce = t.nonce.checked_add(1).context("nonce overflow")?;
        self.balances.insert(t.from.clone(), self.balance(&t.from) - cost);
        self.credit(&t.to, t.amount)?;
        self.nonces.insert(t.from.clone(), next_nonce);
        Ok(())
    }

    /// Apply an entire block atomically: on any error, the original ledger is untouched.
    pub fn apply_block(&mut self, b: &Block) -> Result<()> {
        let mut candidate = self.clone();
        candidate.apply_block_inner(b)?;
        *self = candidate;
        Ok(())
    }

    fn apply_block_inner(&mut self, b: &Block) -> Result<()> {
        validate_address(&b.miner)?;
        let mut fees = 0u64;
        for t in &b.transactions {
            self.apply_transaction_inner(t)?;
            fees = fees.checked_add(t.fee).context("fees overflow")?;
        }
        let subsidy = BLOCK_REWARD.min(MAX_SUPPLY.saturating_sub(self.minted));
        self.credit(
            &b.miner,
            subsidy.checked_add(fees).context("reward overflow")?,
        )?;
        self.minted = self.minted.checked_add(subsidy).context("supply overflow")?;
        if self.minted > MAX_SUPPLY {
            bail!("supply cap exceeded");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_time_past_uses_the_upper_median_of_recent_blocks() {
        let mut blocks = vec![genesis_block()];
        for (height, timestamp) in [100, 110, 120, 130].iter().enumerate() {
            let mut block = genesis_block();
            block.height = height as u64 + 1;
            block.timestamp = *timestamp;
            blocks.push(block);
        }
        assert_eq!(median_time_past(&blocks).unwrap(), 120);
    }

    #[test]
    fn block_timestamp_must_be_greater_than_median_time_past() {
        let mut blocks = vec![genesis_block()];
        for height in 1..=5 {
            let mut block = genesis_block();
            block.height = height;
            block.timestamp = 1_764_096_000 + height * 10;
            blocks.push(block);
        }
        let median = median_time_past(&blocks).unwrap();
        assert!(validate_block_timestamp(&blocks, median).is_err());
        assert!(validate_block_timestamp(&blocks, median + 1).is_ok());
    }

    fn retarget_history(elapsed: u64, tip_difficulty: u16) -> Vec<Block> {
        let genesis = genesis_block();
        let mut blocks = vec![genesis.clone()];
        for height in 1..=DIFFICULTY_RETARGET_INTERVAL {
            blocks.push(Block {
                height,
                previous: String::new(),
                timestamp: genesis.timestamp + elapsed * height / DIFFICULTY_RETARGET_INTERVAL,
                miner: genesis.miner.clone(),
                transactions: Vec::new(),
                nonce: 0,
                difficulty: if height == DIFFICULTY_RETARGET_INTERVAL { tip_difficulty } else { TESTNET_DIFFICULTY },
                hash: String::new(),
            });
        }
        blocks
    }

    #[test]
    fn difficulty_retargets_up_when_blocks_are_too_fast() {
        let blocks = retarget_history(10, TESTNET_DIFFICULTY);
        assert_eq!(expected_next_difficulty(&blocks).unwrap(), TESTNET_DIFFICULTY + 1);
    }

    #[test]
    fn difficulty_retargets_down_when_blocks_are_too_slow() {
        let blocks = retarget_history(1_000, TESTNET_DIFFICULTY);
        assert_eq!(expected_next_difficulty(&blocks).unwrap(), TESTNET_DIFFICULTY - 1);
    }

    #[test]
    fn difficulty_retarget_is_bounded_and_waits_for_full_window() {
        let fast = retarget_history(1, MAX_TESTNET_DIFFICULTY);
        assert_eq!(expected_next_difficulty(&fast).unwrap(), MAX_TESTNET_DIFFICULTY);
        let slow = retarget_history(1_000, MIN_TESTNET_DIFFICULTY);
        assert_eq!(expected_next_difficulty(&slow).unwrap(), MIN_TESTNET_DIFFICULTY);
        let mut partial = retarget_history(10, TESTNET_DIFFICULTY);
        partial.pop();
        assert_eq!(expected_next_difficulty(&partial).unwrap(), TESTNET_DIFFICULTY);
    }

    #[test]
    fn signatures_detect_tampering() {
        let a = SigningKey::generate(&mut OsRng);
        let b = address(&SigningKey::generate(&mut OsRng).verifying_key());
        let mut t = sign(&a, b, 10, 1, 0).unwrap();
        t.verify().unwrap();
        t.amount += 1;
        assert!(t.verify().is_err());
    }

    fn empty_block(miner: &SigningKey, height: u64) -> Block {
        Block {
            height,
            previous: String::new(),
            timestamp: height,
            miner: address(&miner.verifying_key()),
            transactions: vec![],
            nonce: 0,
            difficulty: TESTNET_DIFFICULTY,
            hash: String::new(),
        }
    }

    #[test]
    fn first_block_mints_exactly_50_ana_to_miner() {
        let miner = SigningKey::generate(&mut OsRng);
        let miner_address = address(&miner.verifying_key());
        let mut ledger = Ledger::default();

        ledger.apply_block(&empty_block(&miner, 1)).unwrap();

        assert_eq!(ledger.minted, BLOCK_REWARD);
        assert_eq!(ledger.balance(&miner_address), BLOCK_REWARD);
        assert_eq!(ledger.minted, 50 * COIN);
    }

    #[test]
    fn each_block_mints_subsidy_once_and_only_once() {
        let miner = SigningKey::generate(&mut OsRng);
        let miner_address = address(&miner.verifying_key());
        let mut ledger = Ledger::default();

        ledger.apply_block(&empty_block(&miner, 1)).unwrap();
        ledger.apply_block(&empty_block(&miner, 2)).unwrap();

        assert_eq!(ledger.minted, 2 * BLOCK_REWARD);
        assert_eq!(ledger.balance(&miner_address), 2 * BLOCK_REWARD);
    }

    #[test]
    fn transaction_fees_go_to_miner_without_increasing_minted_supply() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let miner = SigningKey::generate(&mut OsRng);
        let sender_address = address(&sender.verifying_key());
        let receiver_address = address(&receiver.verifying_key());
        let miner_address = address(&miner.verifying_key());
        let amount = 2 * COIN;
        let fee = COIN / 10;
        let mut ledger = Ledger::default();
        ledger.balances.insert(sender_address.clone(), 5 * COIN);
        let tx = sign(&sender, receiver_address.clone(), amount, fee, 0).unwrap();
        let mut block = empty_block(&miner, 1);
        block.transactions.push(tx);

        ledger.apply_block(&block).unwrap();

        assert_eq!(ledger.balance(&receiver_address), amount);
        assert_eq!(ledger.balance(&sender_address), 5 * COIN - amount - fee);
        assert_eq!(ledger.balance(&miner_address), BLOCK_REWARD + fee);
        assert_eq!(ledger.minted, BLOCK_REWARD);
    }

    #[test]
    fn issuance_stops_exactly_at_supply_cap() {
        let miner = SigningKey::generate(&mut OsRng);
        let miner_address = address(&miner.verifying_key());
        let mut ledger = Ledger::default();
        ledger.minted = MAX_SUPPLY - 1;

        ledger.apply_block(&empty_block(&miner, 1)).unwrap();
        assert_eq!(ledger.minted, MAX_SUPPLY);
        assert_eq!(ledger.balance(&miner_address), 1);

        ledger.apply_block(&empty_block(&miner, 2)).unwrap();
        assert_eq!(ledger.minted, MAX_SUPPLY);
        assert_eq!(ledger.balance(&miner_address), 1);
    }

    #[test]
    fn ledger_rejects_preexisting_supply_above_cap_atomically() {
        let miner = SigningKey::generate(&mut OsRng);
        let mut ledger = Ledger::default();
        ledger.minted = MAX_SUPPLY + 1;
        let before = ledger.clone();

        assert!(ledger.apply_block(&empty_block(&miner, 1)).is_err());
        assert_eq!(ledger.minted, before.minted);
        assert_eq!(ledger.balances, before.balances);
        assert_eq!(ledger.nonces, before.nonces);
    }

    #[test]
    fn failed_block_does_not_partially_change_ledger() {
        let sender = SigningKey::generate(&mut OsRng);
        let receiver = SigningKey::generate(&mut OsRng);
        let miner = SigningKey::generate(&mut OsRng);
        let sender_address = address(&sender.verifying_key());
        let receiver_address = address(&receiver.verifying_key());
        let mut ledger = Ledger::default();
        ledger.balances.insert(sender_address.clone(), 100);
        ledger.balances.insert(receiver_address.clone(), u64::MAX);
        let tx = sign(&sender, receiver_address, 10, 1, 0).unwrap();
        let block = Block {
            height: 1,
            previous: String::new(),
            timestamp: 1,
            miner: address(&miner.verifying_key()),
            transactions: vec![tx],
            nonce: 0,
            difficulty: TESTNET_DIFFICULTY,
            hash: String::new(),
        };
        let before = ledger.clone();
        assert!(ledger.apply_block(&block).is_err());
        assert_eq!(ledger.balances, before.balances);
        assert_eq!(ledger.nonces, before.nonces);
        assert_eq!(ledger.minted, before.minted);
    }

    #[test]
    fn parses_amounts_exactly() {
        assert_eq!(parse_amount("1").unwrap(), COIN);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        assert_eq!(parse_amount("12.34000000").unwrap(), 1_234_000_000);
        assert!(parse_amount("0.000000001").is_err());
        assert!(parse_amount("1e-3").is_err());
    }
}


#[derive(Serialize)]
struct PowHeader<'a> {
    network: &'a str,
    height: u64,
    previous: &'a str,
    timestamp: u64,
    miner: &'a str,
    transactions: &'a [Transaction],
    nonce: u64,
    difficulty: u16,
}

fn pow_input(block: &Block) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&PowHeader {
        network: NETWORK,
        height: block.height,
        previous: &block.previous,
        timestamp: block.timestamp,
        miner: &block.miner,
        transactions: &block.transactions,
        nonce: block.nonce,
        difficulty: block.difficulty,
    })?)
}

fn meets_pow_target(hash: &[u8; 32], bits: u16) -> bool {
    let bytes = (bits / 8) as usize;
    let remainder = (bits % 8) as u8;
    hash.iter().take(bytes).all(|b| *b == 0)
        && (remainder == 0 || (hash[bytes] >> (8 - remainder)) == 0)
}

fn randomx_vm_for_key(key: &[u8]) -> Result<RandomXVM> {
    let flags = RandomXFlag::default();
    let cache = RandomXCache::new(flags, key)
        .context("RandomX cache initialization failed")?;
    RandomXVM::new(flags, Some(cache), None)
        .context("RandomX VM initialization failed")
}

fn randomx_vm() -> Result<RandomXVM> {
    randomx_vm_for_key(RANDOMX_SEED)
}

fn randomx_vm_hash(vm: &RandomXVM, input: &[u8]) -> Result<[u8; 32]> {
    let digest = vm.calculate_hash(input)
        .context("RandomX hash calculation failed")?;
    digest.try_into()
        .map_err(|_| anyhow::anyhow!("RandomX returned an invalid digest length"))
}

fn randomx_hash(input: &[u8]) -> Result<[u8; 32]> {
    let vm = randomx_vm()?;
    randomx_vm_hash(&vm, input)
}

#[cfg(test)]
mod randomx_known_answer_tests {
    use super::*;

    #[test]
    fn randomx_matches_upstream_known_answer() {
        let vm = randomx_vm_for_key(b"test key 000").unwrap();
        let digest = randomx_vm_hash(&vm, b"This is a test").unwrap();
        assert_eq!(
            hex::encode(digest),
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        );
    }
}

pub fn block_hash(block: &Block) -> Result<String> {
    Ok(hex::encode(randomx_hash(&pow_input(block)?)?))
}

pub fn genesis_block() -> Block {
    let digest = Sha256::digest(b"ANA-TESTNET-1:GENESIS:v1");
    Block {
        height: 0,
        previous: "0".repeat(64),
        timestamp: 1_764_096_000,
        miner: "ana1".to_owned() + &"0".repeat(64),
        transactions: Vec::new(),
        nonce: 0,
        difficulty: 0,
        hash: hex::encode(digest),
    }
}

/// Median of up to the last 11 timestamps in the existing chain.
pub fn median_time_past(blocks: &[Block]) -> Result<u64> {
    if blocks.is_empty() {
        bail!("chain is empty");
    }
    let start = blocks.len().saturating_sub(MEDIAN_TIME_WINDOW);
    let mut timestamps: Vec<u64> = blocks[start..].iter().map(|block| block.timestamp).collect();
    timestamps.sort_unstable();
    Ok(timestamps[timestamps.len() / 2])
}

/// A new block must be strictly later than the median of recent block timestamps.
pub fn validate_block_timestamp(blocks: &[Block], timestamp: u64) -> Result<()> {
    let median = median_time_past(blocks)?;
    if timestamp <= median {
        bail!("block timestamp must be greater than median-time-past ({median})");
    }
    Ok(())
}

/// Derive the next block difficulty using only the validated chain history.
/// Retargets every 10 completed blocks, moving at most one bit per window.
pub fn expected_next_difficulty(blocks: &[Block]) -> Result<u16> {
    let tip = blocks.last().context("chain is empty")?;
    let next_height = tip.height.checked_add(1).context("height overflow")?;
    if next_height <= DIFFICULTY_RETARGET_INTERVAL
        || (next_height - 1) % DIFFICULTY_RETARGET_INTERVAL != 0
    {
        return Ok(if tip.height == 0 { TESTNET_DIFFICULTY } else { tip.difficulty });
    }

    let ancestor_index = blocks.len().checked_sub(1 + DIFFICULTY_RETARGET_INTERVAL as usize)
        .context("insufficient retarget history")?;
    let ancestor = &blocks[ancestor_index];
    let elapsed = tip.timestamp.saturating_sub(ancestor.timestamp);
    let target = TARGET_BLOCK_SECONDS * DIFFICULTY_RETARGET_INTERVAL;
    let current = if tip.height == 0 { TESTNET_DIFFICULTY } else { tip.difficulty };

    if elapsed < target / 2 {
        Ok(current.saturating_add(1).min(MAX_TESTNET_DIFFICULTY))
    } else if elapsed > target.saturating_mul(2) {
        Ok(current.saturating_sub(1).max(MIN_TESTNET_DIFFICULTY))
    } else {
        Ok(current.clamp(MIN_TESTNET_DIFFICULTY, MAX_TESTNET_DIFFICULTY))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChainState {
    pub blocks: Vec<Block>,
    pub ledger: Ledger,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    pub fn new() -> Self {
        Self { blocks: vec![genesis_block()], ledger: Ledger::default() }
    }

    pub fn tip(&self) -> &Block {
        self.blocks.last().expect("chain always contains genesis")
    }

    /// Compare a fully validated candidate chain using cumulative proof-of-work.
    /// Equal-work ties use the lexicographically smaller tip hash for convergence.
    pub fn replace_if_more_work(&mut self, blocks: Vec<Block>) -> Result<bool> {
        let expected_genesis = genesis_block();
        let supplied_genesis = blocks.first().context("candidate chain is empty")?;
        if serde_json::to_vec(supplied_genesis)? != serde_json::to_vec(&expected_genesis)? {
            bail!("candidate chain has an unknown genesis");
        }
        let mut candidate = Self::new();
        for block in blocks.into_iter().skip(1) { candidate.append(block)?; }
        let candidate_work = candidate.cumulative_work()?;
        let current_work = self.cumulative_work()?;
        let wins_tie = candidate_work == current_work && candidate.tip().hash < self.tip().hash;
        if candidate_work > current_work || wins_tie { *self = candidate; return Ok(true); }
        Ok(false)
    }

    /// Sum per-block work (2^difficulty); checked to prevent accumulator overflow.
    pub fn cumulative_work(&self) -> Result<u128> {
        self.blocks.iter().skip(1).try_fold(0u128, |total, block| {
            let work = 1u128.checked_shl(u32::from(block.difficulty))
                .context("block difficulty exceeds work accumulator")?;
            total.checked_add(work).context("cumulative chain work overflow")
        })
    }
    pub fn append(&mut self, block: Block) -> Result<()> {
        let previous = self.tip();
        if block.height != previous.height.checked_add(1).context("height overflow")? {
            bail!("incorrect block height");
        }
        if block.previous != previous.hash {
            bail!("previous block hash mismatch");
        }
        validate_block_timestamp(&self.blocks, block.timestamp)?;
        let expected_difficulty = expected_next_difficulty(&self.blocks)?;
        if block.difficulty != expected_difficulty {
            bail!("unexpected block difficulty: expected {expected_difficulty}, got {}", block.difficulty);
        }
        validate_address(&block.miner)?;
        let actual = block_hash(&block)?;
        if actual != block.hash {
            bail!("block RandomX hash mismatch");
        }
        let raw: [u8; 32] = hex::decode(&actual)?.try_into()
            .map_err(|_| anyhow::anyhow!("invalid RandomX digest"))?;
        if !meets_pow_target(&raw, block.difficulty) {
            bail!("block does not meet proof-of-work target");
        }
        let mut candidate_ledger = self.ledger.clone();
        candidate_ledger.apply_block(&block)?;
        self.ledger = candidate_ledger;
        self.blocks.push(block);
        Ok(())
    }

    pub fn mine_next(&self, miner: String) -> Result<Block> {
        self.mine_next_with_transactions(miner, Vec::new())
    }

    /// Mine a block containing the supplied transactions. Transactions are
    /// consensus-checked again by append() before the block is committed.
    pub fn mine_next_with_transactions(
        &self,
        miner: String,
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        validate_address(&miner)?;
        let mut projected = self.ledger.clone();
        for transaction in &transactions {
            projected.apply_transaction(transaction)?;
        }
        let previous = self.tip();
        let height = previous.height.checked_add(1).context("height overflow")?;
        let median = median_time_past(&self.blocks)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            .max(previous.timestamp.checked_add(1).context("timestamp overflow")?)
            .max(median.checked_add(1).context("median timestamp overflow")?);
        let mut block = Block {
            height,
            previous: previous.hash.clone(),
            timestamp,
            miner,
            transactions,
            nonce: 0,
            difficulty: expected_next_difficulty(&self.blocks)?,
            hash: String::new(),
        };
        let vm = randomx_vm()?;
        loop {
            let input = pow_input(&block)?;
            let digest = randomx_vm_hash(&vm, &input)?;
            if meets_pow_target(&digest, block.difficulty) {
                block.hash = hex::encode(digest);
                return Ok(block);
            }
            block.nonce = block.nonce.checked_add(1).context("nonce overflow")?;
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        fs::write(&temp, serde_json::to_vec(self)?)?;
        fs::rename(temp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let state: Self = serde_json::from_slice(&fs::read(path)?)?;
        if state.blocks.is_empty() || state.blocks[0].hash != genesis_block().hash {
            bail!("stored chain has an unknown genesis");
        }
        let mut rebuilt = Self::new();
        for block in state.blocks.iter().skip(1) {
            rebuilt.append(block.clone())?;
        }
        if rebuilt.ledger.minted != state.ledger.minted
            || rebuilt.ledger.balances != state.ledger.balances
            || rebuilt.ledger.nonces != state.ledger.nonces
        {
            bail!("stored ledger does not match validated blocks");
        }
        Ok(rebuilt)
    }
}


// Encrypted wallet keystore v1. Uses Argon2id + XChaCha20-Poly1305.
#[derive(Serialize, Deserialize)]
struct EncryptedWalletFile {
    version: u32,
    network: String,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn wallet_kek(passphrase: &[u8], salt: &[u8; 16]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|_| anyhow::anyhow!("invalid wallet KDF parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("wallet key derivation failed: {e}"))?;
    Ok(key)
}

/// Create an encrypted wallet. Existing files are never overwritten.
pub fn create_encrypted_wallet(path: &Path, passphrase: &[u8]) -> Result<String> {
    let signing = SigningKey::generate(&mut OsRng);
    let addr = address(&signing.verifying_key());
    encrypt_wallet_key(path, &signing, passphrase)?;
    Ok(addr)
}

/// Encrypt an existing signing key into a new v1 keystore without modifying the source.
pub fn encrypt_wallet_key(path: &Path, signing: &SigningKey, passphrase: &[u8]) -> Result<()> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
    use rand::RngCore;
    use std::{fs::OpenOptions, io::Write};
    if passphrase.len() < 12 {
        bail!("wallet passphrase must be at least 12 bytes");
    }
    if path.exists() { bail!("refusing to overwrite wallet"); }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = wallet_kek(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("invalid wallet encryption key"))?;
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), signing.to_bytes().as_ref())
        .map_err(|_| anyhow::anyhow!("wallet encryption failed"))?;
    let file = EncryptedWalletFile {
        version: 1, network: NETWORK.into(), kdf: "argon2id-19m-2-1".into(),
        salt: hex::encode(salt), nonce: hex::encode(nonce), ciphertext: hex::encode(ciphertext),
    };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) { fs::create_dir_all(parent)?; }
    let temp = path.with_extension("wallet-tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut output = options.open(&temp).context("could not create temporary wallet file")?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }
    output.write_all(&serde_json::to_vec_pretty(&file)?)?;
    output.sync_all()?;
    fs::rename(&temp, path).context("could not atomically install wallet file")?;
    Ok(())
}

/// Unlock a v1 encrypted wallet. Legacy plaintext wallets are intentionally not accepted here.
pub fn open_encrypted_wallet(path: &Path, passphrase: &[u8]) -> Result<SigningKey> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, XChaCha20Poly1305, XNonce};
    let file: EncryptedWalletFile = serde_json::from_slice(&fs::read(path)?)
        .context("invalid encrypted ANA wallet file")?;
    if file.version != 1 || file.network != NETWORK || file.kdf != "argon2id-19m-2-1" {
        bail!("unsupported wallet version, network, or KDF");
    }
    let salt: [u8; 16] = hex::decode(file.salt)?.try_into()
        .map_err(|_| anyhow::anyhow!("invalid wallet salt"))?;
    let nonce: [u8; 24] = hex::decode(file.nonce)?.try_into()
        .map_err(|_| anyhow::anyhow!("invalid wallet nonce"))?;
    let ciphertext = hex::decode(file.ciphertext)?;
    let key = wallet_kek(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut plaintext = zeroize::Zeroizing::new(
        cipher.decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("wrong passphrase or damaged wallet"))?
    );
    use zeroize::Zeroize;
    let secret = zeroize::Zeroizing::new(<[u8; 32]>::try_from(plaintext.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid decrypted private key"))?);
    plaintext.zeroize();
    Ok(SigningKey::from_bytes(&secret))
}


#[cfg(test)]
mod encrypted_wallet_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encrypted_wallet_round_trip_and_rejects_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let expected = create_encrypted_wallet(&path, b"correct horse battery").unwrap();
        let key = open_encrypted_wallet(&path, b"correct horse battery").unwrap();
        assert_eq!(address(&key.verifying_key()), expected);
        assert!(open_encrypted_wallet(&path, b"incorrect passphrase").is_err());
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("correct horse"));
        assert!(!contents.contains("secret_key"));
    }

    #[test]
    fn encrypted_wallet_refuses_short_passphrase_and_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        assert!(create_encrypted_wallet(&path, b"short").is_err());
        create_encrypted_wallet(&path, b"a sufficiently long passphrase").unwrap();
        assert!(create_encrypted_wallet(&path, b"another sufficiently long passphrase").is_err());
    }
}


#[cfg(test)]
mod wallet_migration_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn legacy_wallet_can_be_encrypted_without_changing_its_key() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join("legacy.json");
        let encrypted = dir.path().join("encrypted.json");
        let original_address = create_wallet(&legacy).unwrap();
        let key = open_wallet(&legacy).unwrap();
        encrypt_wallet_key(&encrypted, &key, b"a sufficiently long passphrase").unwrap();
        let restored = open_encrypted_wallet(&encrypted, b"a sufficiently long passphrase").unwrap();
        assert_eq!(address(&restored.verifying_key()), original_address);
        assert!(legacy.exists());
        assert!(encrypt_wallet_key(&encrypted, &key, b"another sufficiently long passphrase").is_err());
    }
}


/// An unlocked encrypted ANA wallet handle.
///
/// The private signing key is kept inside this type; callers receive the public
/// address and signed transactions, not raw private-key bytes. Keep this handle
/// short-lived and do not log or serialize it.
pub struct Wallet {
    signing_key: SigningKey,
}

impl Wallet {
    /// Create a new encrypted wallet and return its ANA address.
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<String> {
        create_encrypted_wallet(path, passphrase)
    }

    /// Unlock an existing encrypted wallet.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let signing_key = open_encrypted_wallet(path, passphrase)?;
        Ok(Self { signing_key })
    }

    /// Return this wallet's public ANA address.
    pub fn address(&self) -> String {
        address(&self.signing_key.verifying_key())
    }

    /// Return the public Ed25519 key as lowercase hexadecimal.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign and locally verify a transaction for submission to an ANA node.
    /// Amount and fee are atomic units (1 ANA = 100,000,000 atomic units).
    pub fn sign_transaction(
        &self,
        recipient: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Result<Transaction> {
        sign(&self.signing_key, recipient.to_owned(), amount, fee, nonce)
    }
}

#[cfg(test)]
mod wallet_api_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wallet_api_creates_unlocks_and_signs_without_exposing_secret_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("api-wallet.json");
        let expected_address = Wallet::create(&path, b"a sufficiently long API passphrase").unwrap();
        let wallet = Wallet::open(&path, b"a sufficiently long API passphrase").unwrap();

        assert_eq!(wallet.address(), expected_address);
        assert_eq!(wallet.public_key_hex().len(), 64);

        let recipient = address(&SigningKey::generate(&mut OsRng).verifying_key());
        let tx = wallet.sign_transaction(&recipient, COIN, COIN / 100, 0).unwrap();
        tx.verify().unwrap();
        assert_eq!(tx.from, expected_address);
        assert_eq!(tx.to, recipient);
        assert_eq!(tx.amount, COIN);
        assert_eq!(tx.fee, COIN / 100);
        assert_eq!(tx.nonce, 0);
        assert!(Wallet::open(&path, b"wrong passphrase").is_err());
    }

    #[test]
    fn wallet_api_rejects_invalid_recipient_and_zero_amount() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("api-wallet.json");
        Wallet::create(&path, b"a sufficiently long API passphrase").unwrap();
        let wallet = Wallet::open(&path, b"a sufficiently long API passphrase").unwrap();
        assert!(wallet.sign_transaction("not-an-address", 1, 0, 0).is_err());
        let recipient = address(&SigningKey::generate(&mut OsRng).verifying_key());
        assert!(wallet.sign_transaction(&recipient, 0, 0, 0).is_err());
    }
}


pub mod privacy;
pub mod privacy_commitments;
pub mod privacy_rangeproofs;
pub mod rpc;
