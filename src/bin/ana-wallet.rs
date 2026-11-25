use ana_blockchain::{address, encrypt_wallet_key, open_encrypted_wallet, open_wallet, parse_amount, sign, Transaction};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    path::Path,
};

#[derive(Serialize, Deserialize)]
struct Message {
    kind: String,
    #[serde(default)] transaction: Option<Transaction>,
    #[serde(default)] address: Option<String>,
    #[serde(default)] balance: Option<u64>,
    #[serde(default)] nonce: Option<u64>,
    #[serde(default)] block: Option<serde_json::Value>,
    #[serde(default)] blocks: Option<Vec<serde_json::Value>>,
}

fn account(node: &str, address: &str) -> Result<(u64, u64)> {
    let mut stream = TcpStream::connect(node).context("could not connect to ANA node")?;
    let request = serde_json::to_string(&Message {
        kind: "get_account".into(), transaction: None, address: Some(address.into()),
        balance: None, nonce: None, block: None, blocks: None,
    })? + "\n";
    stream.write_all(request.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let reply: Message = serde_json::from_str(&line).context("invalid account response")?;
    if reply.kind != "account" { bail!("node did not return account state"); }
    Ok((reply.balance.context("missing balance")?, reply.nonce.context("missing nonce")?))
}

fn submit(node: &str, tx: Transaction) -> Result<()> {
    let mut stream = TcpStream::connect(node).context("could not connect to ANA node")?;
    let wire = serde_json::to_string(&Message {
        kind: "transaction".into(), transaction: Some(tx), address: None,
        balance: None, nonce: None, block: None, blocks: None,
    })? + "\n";
    stream.write_all(wire.as_bytes())?;
    Ok(())
}

fn unlock(path: &str) -> Result<ed25519_dalek::SigningKey> {
    let passphrase = rpassword::prompt_password("Wallet passphrase: ")?;
    open_encrypted_wallet(Path::new(path), passphrase.as_bytes())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("new") => {
            let path = args.get(2).map(String::as_str).unwrap_or("ana-wallet.json");
            let pass = rpassword::prompt_password("Create wallet passphrase (12+ characters): ")?;
            let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
            if pass != confirm { bail!("passphrases do not match"); }
            let addr = ana_blockchain::create_encrypted_wallet(Path::new(path), pass.as_bytes())?;
            println!("New ANA address: {addr}");
            println!("Wallet encrypted. Back up this file and keep the passphrase separately.");
        }
        Some("migrate") => {
            if args.len() != 4 { bail!("Usage: ana-wallet migrate <legacy-plaintext-wallet> <new-encrypted-wallet>"); }
            let legacy = open_wallet(Path::new(&args[2])).context("could not open legacy wallet")?;
            let pass = rpassword::prompt_password("New wallet passphrase (12+ characters): ")?;
            let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
            if pass != confirm { bail!("passphrases do not match"); }
            encrypt_wallet_key(Path::new(&args[3]), &legacy, pass.as_bytes())?;
            println!("Migrated address: {}", address(&legacy.verifying_key()));
            println!("The original plaintext wallet was not changed. Securely archive it, then remove it only after verifying your backup.");
        }
        Some("backup") => {
            if args.len() != 4 { bail!("Usage: ana-wallet backup <encrypted-wallet> <backup-file>"); }
            let pass = rpassword::prompt_password("Wallet passphrase: ")?;
            open_encrypted_wallet(Path::new(&args[2]), pass.as_bytes()).context("wallet unlock failed; backup not created")?;
            let source = Path::new(&args[2]);
            let destination = Path::new(&args[3]);
            if destination.exists() { bail!("refusing to overwrite backup"); }
            let bytes = fs::read(source)?;
            let temp = destination.with_extension("backup-tmp");
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut out = options.open(&temp)?;
            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?; }
            out.write_all(&bytes)?;
            out.sync_all()?;
            fs::rename(&temp, destination)?;
            open_encrypted_wallet(destination, pass.as_bytes()).context("backup verification failed")?;
            println!("Encrypted backup created and verified. Store the passphrase separately.");
        }
        Some("address") => {
            let path = args.get(2).map(String::as_str).unwrap_or("ana-wallet.json");
            println!("{}", address(&unlock(path)?.verifying_key()));
        }
        Some("balance") => {
            if args.len() != 4 { bail!("Usage: ana-wallet balance <address> <node-ip:port>"); }
            let (balance, nonce) = account(&args[3], &args[2])?;
            println!("Balance: {}.{:08} ANA", balance / 100_000_000, balance % 100_000_000);
            println!("Next nonce: {nonce}");
        }
        Some("send") => {
            if args.len() != 7 { bail!("Usage: ana-wallet send <wallet-file> <recipient> <amount-ANA> <fee-ANA> <node-ip:port>"); }
            let key = unlock(&args[2])?;
            let from = address(&key.verifying_key());
            let (balance, nonce) = account(&args[6], &from)?;
            let amount = parse_amount(&args[4])?;
            let fee = parse_amount(&args[5])?;
            if balance < amount.checked_add(fee).context("amount overflow")? { bail!("insufficient available balance"); }
            let tx = sign(&key, args[3].clone(), amount, fee, nonce)?;
            let id = tx.id()?;
            submit(&args[6], tx)?;
            println!("Submitted transaction: {id}");
            println!("The node will relay it; it is not confirmed until included in a mined block.");
        }
        _ => println!("ANA wallet: new [file] | migrate <legacy-file> <encrypted-file> | backup <wallet-file> <backup-file> | address [file] | balance <address> <node> | send <file> <recipient> <amount> <fee> <node>"),
    }
    Ok(())
}
