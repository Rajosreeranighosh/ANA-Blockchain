use anyhow::{bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use serde::{Serialize,Deserialize};
use sha2::{Sha256,Digest};
use std::{collections::BTreeMap,fs,path::Path};

pub const COIN:u64=100_000_000;
pub const MAX_SUPPLY:u64=21_000_000*COIN;
pub const BLOCK_REWARD:u64=50*COIN;
pub const NETWORK:&str="ANA-TESTNET-1";

#[derive(Serialize,Deserialize)] pub struct WalletFile { pub network:String, pub secret_key:String }
pub fn address(k:&VerifyingKey)->String { format!("ana1{}",hex::encode(k.to_bytes())) }
pub fn create_wallet(path:&Path)->Result<String>{
 if path.exists(){bail!("refusing to overwrite wallet")}
 let k=SigningKey::generate(&mut OsRng);
 let w=WalletFile{network:NETWORK.into(),secret_key:hex::encode(k.to_bytes())};
 if let Some(p)=path.parent(){fs::create_dir_all(p)?}
 fs::write(path,serde_json::to_vec_pretty(&w)?)?;
 #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(path,fs::Permissions::from_mode(0o600))?;}
 Ok(address(&k.verifying_key()))
}
pub fn open_wallet(path:&Path)->Result<SigningKey>{
 let w:WalletFile=serde_json::from_slice(&fs::read(path)?)?;
 if w.network!=NETWORK{bail!("wallet network mismatch")}
 let b:[u8;32]=hex::decode(w.secret_key)?.try_into().map_err(|_|anyhow::anyhow!("invalid private key"))?;
 Ok(SigningKey::from_bytes(&b))
}
#[derive(Clone,Serialize,Deserialize,Debug)]
pub struct Transaction {pub network:String,pub from:String,pub to:String,pub amount:u64,pub fee:u64,pub nonce:u64,pub public_key:String,pub signature:String}
#[derive(Serialize)] struct Payload<'a>{network:&'a str,from:&'a str,to:&'a str,amount:u64,fee:u64,nonce:u64,public_key:&'a str}
impl Transaction{
 fn payload(&self)->Result<Vec<u8>>{Ok(serde_json::to_vec(&Payload{network:&self.network,from:&self.from,to:&self.to,amount:self.amount,fee:self.fee,nonce:self.nonce,public_key:&self.public_key})?)}
 pub fn verify(&self)->Result<()>{
  if self.network!=NETWORK||self.amount==0||!self.to.starts_with("ana1")||self.to.len()!=68{bail!("invalid network, recipient or amount")}
  let p:[u8;32]=hex::decode(&self.public_key)?.try_into().map_err(|_|anyhow::anyhow!("bad public key"))?;
  let k=VerifyingKey::from_bytes(&p)?;if address(&k)!=self.from{bail!("sender key mismatch")}
  let s:[u8;64]=hex::decode(&self.signature)?.try_into().map_err(|_|anyhow::anyhow!("bad signature"))?;
  k.verify(&self.payload()?,&Signature::from_bytes(&s)).context("bad transaction signature")?;Ok(())
 }
}
pub fn sign(k:&SigningKey,to:String,amount:u64,fee:u64,nonce:u64)->Result<Transaction>{
 let mut t=Transaction{network:NETWORK.into(),from:address(&k.verifying_key()),to,amount,fee,nonce,public_key:hex::encode(k.verifying_key().to_bytes()),signature:String::new()};
 t.signature=hex::encode(k.sign(&t.payload()?).to_bytes());t.verify()?;Ok(t)
}
#[derive(Clone,Serialize,Deserialize,Debug)] pub struct Block {pub height:u64,pub previous:String,pub timestamp:u64,pub miner:String,pub transactions:Vec<Transaction>,pub nonce:u64,pub hash:String}
#[derive(Clone,Serialize,Deserialize,Default,Debug)] pub struct Ledger {pub balances:BTreeMap<String,u64>,pub nonces:BTreeMap<String,u64>,pub minted:u64}
impl Ledger{
 pub fn balance(&self,a:&str)->u64{*self.balances.get(a).unwrap_or(&0)}
 pub fn nonce(&self,a:&str)->u64{*self.nonces.get(a).unwrap_or(&0)}
 fn credit(&mut self,a:&str,n:u64)->Result<()>{let v=self.balance(a).checked_add(n).context("balance overflow")?;self.balances.insert(a.into(),v);Ok(())}
 pub fn apply_transaction(&mut self,t:&Transaction)->Result<()>{
  t.verify()?;if t.nonce!=self.nonce(&t.from){bail!("bad nonce")}
  let cost=t.amount.checked_add(t.fee).context("amount overflow")?;
  if self.balance(&t.from)<cost{bail!("insufficient balance")}
  self.balances.insert(t.from.clone(),self.balance(&t.from)-cost);self.credit(&t.to,t.amount)?;
  self.nonces.insert(t.from.clone(),t.nonce.checked_add(1).context("nonce overflow")?);Ok(())
 }
 pub fn apply_block(&mut self,b:&Block)->Result<()>{
  let mut fees=0u64;for t in &b.transactions{self.apply_transaction(t)?;fees=fees.checked_add(t.fee).context("fees overflow")?}
  let subsidy=BLOCK_REWARD.min(MAX_SUPPLY.saturating_sub(self.minted));
  self.credit(&b.miner,subsidy.checked_add(fees).context("reward overflow")?)?;
  self.minted=self.minted.checked_add(subsidy).context("supply overflow")?;
  if self.minted>MAX_SUPPLY{bail!("supply cap exceeded")}Ok(())
 }
}
pub fn hash_block(b:&Block)->Result<String>{let mut x=b.clone();x.hash.clear();Ok(hex::encode(Sha256::digest(serde_json::to_vec(&x)?)))}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn signatures_detect_tampering(){let a=SigningKey::generate(&mut OsRng);let b=address(&SigningKey::generate(&mut OsRng).verifying_key());let mut t=sign(&a,b,10,1,0).unwrap();t.verify().unwrap();t.amount+=1;assert!(t.verify().is_err());}
 #[test]fn issuance_is_capped(){let mut l=Ledger::default();l.minted=MAX_SUPPLY-1;let k=SigningKey::generate(&mut OsRng);let b=Block{height:1,previous:String::new(),timestamp:1,miner:address(&k.verifying_key()),transactions:vec![],nonce:0,hash:String::new()};l.apply_block(&b).unwrap();assert_eq!(l.minted,MAX_SUPPLY);}
}