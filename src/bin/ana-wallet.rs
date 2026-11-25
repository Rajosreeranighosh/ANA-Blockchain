use ana_blockchain::{address, open_wallet, parse_amount, sign, Transaction};
use anyhow::{bail, Result};
use serde::Serialize;
use std::{env, io::Write, net::TcpStream, path::Path};

#[derive(Serialize)]
struct Message {
    kind: String,
    transaction: Option<Transaction>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("new") => {
            let path = args.get(2).map(String::as_str).unwrap_or("ana-wallet.json");
            println!(
                "New ANA address: {}",
                ana_blockchain::create_wallet(Path::new(path))?
            );
            println!("Keep the wallet file private and backed up.");
        }
        Some("address") => {
            let path = args.get(2).map(String::as_str).unwrap_or("ana-wallet.json");
            println!("{}", address(&open_wallet(Path::new(path))?.verifying_key()));
        }
        Some("send") => {
            if args.len() != 7 {
                bail!("Usage: ana-wallet send <wallet-file> <recipient> <amount-ANA> <fee-ANA> <node-ip:port>");
            }
            let key = open_wallet(Path::new(&args[2]))?;
            let amount = parse_amount(&args[4])?;
            let fee = parse_amount(&args[5])?;
            let tx = sign(&key, args[3].clone(), amount, fee, 0)?;
            let wire = serde_json::to_string(&Message {
                kind: "transaction".into(),
                transaction: Some(tx),
            })? + "\n";
            TcpStream::connect(&args[6])?.write_all(wire.as_bytes())?;
            println!("Signed transaction submitted to {}", args[6]);
            println!("Note: this alpha sender still uses nonce 0; only the first spend can be accepted.");
        }
        _ => println!(
            "ANA wallet alpha: new [file] | address [file] | send <file> <recipient> <amount> <fee> <node>"
        ),
    }
    Ok(())
}
