use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use randomx_bindings::{RandomxCache, RandomxFlags, RandomxVm};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::{SystemTime, UNIX_EPOCH}};

pub const COIN: u64 = 100_000_000;
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;
pub const BLOCK_REWARD: u64 = 50 * COIN;
pub const NETWORK: &str = "ANA-TESTNET-1";
pub const TESTNET_DIFFICULTY: u16 = 8;
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

fn randomx_hash(input: &[u8]) -> Result<[u8; 32]> {
    let flags = RandomxFlags::default();
    let cache = RandomxCache::new(flags, RANDOMX_SEED)
        .context("RandomX cache initialization failed")?;
    let vm = RandomxVm::new(flags, &cache)
        .context("RandomX VM initialization failed")?;
    Ok(vm.hash(input))
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
        if block.timestamp < previous.timestamp {
            bail!("block timestamp moved backwards");
        }
        if block.difficulty != TESTNET_DIFFICULTY {
            bail!("unexpected testnet difficulty");
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            .max(previous.timestamp);
        let mut block = Block {
            height,
            previous: previous.hash.clone(),
            timestamp,
            miner,
            transactions,
            nonce: 0,
            difficulty: TESTNET_DIFFICULTY,
            hash: String::new(),
        };
        let flags = RandomxFlags::default();
        let cache = RandomxCache::new(flags, RANDOMX_SEED)
            .context("RandomX cache initialization failed")?;
        let vm = RandomxVm::new(flags, &cache)
            .context("RandomX VM initialization failed")?;
        loop {
            let digest = vm.hash(&pow_input(&block)?);
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
