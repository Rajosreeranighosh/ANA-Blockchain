use ana_blockchain::{parse_amount, rpc::NodeClient, Wallet};
use eframe::egui;
use std::{path::Path,};
use zeroize::Zeroize;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Page { Overview, Send, Receive, Transactions, Settings }

struct AnaWalletApp {
    page: Page,
    wallet_path: String,
    passphrase: String,
    confirm_passphrase: String,
    wallet: Option<Wallet>,
    address: String,
    node_address: String,
    balance: Option<u64>,
    nonce: Option<u64>,
    node_height: Option<u64>,
    node_network: String,
    recipient: String,
    amount: String,
    fee: String,
    transaction_id: String,
    transaction_state: String,
    message: String,
    qr_texture: Option<egui::TextureHandle>,
    confirm_send: bool,
}

impl Default for AnaWalletApp {
    fn default() -> Self {
        Self {
            page: Page::Overview,
            wallet_path: "ana-wallet.json".into(),
            passphrase: String::new(),
            confirm_passphrase: String::new(),
            wallet: None,
            address: String::new(),
            node_address: "127.0.0.1:19001".into(),
            balance: None,
            nonce: None,
            node_height: None,
            node_network: String::new(),
            recipient: String::new(),
            amount: String::new(),
            fee: "0.001".into(),
            transaction_id: String::new(),
            transaction_state: String::new(),
            message: "Create a new wallet or open an encrypted ANA wallet file.".into(),
            qr_texture: None,
            confirm_send: false,
        }
    }
}

impl AnaWalletApp {
    fn unlock(&mut self) {
        let result = Wallet::open(Path::new(&self.wallet_path), self.passphrase.as_bytes());
        self.passphrase.zeroize();
        match result {
            Ok(wallet) => {
                self.address = wallet.address();
                self.wallet = Some(wallet);
                self.message = "Wallet opened. Connect to an ANA node to refresh your balance.".into();
                self.balance = None;
                self.nonce = None;
                self.qr_texture = None;
            }
            Err(error) => self.message = format!("Could not open wallet: {error:#}"),
        }
    }

    fn create(&mut self) {
        if self.passphrase != self.confirm_passphrase {
            self.passphrase.zeroize();
            self.confirm_passphrase.zeroize();
            self.message = "Passphrases did not match. Please enter them again.".into();
            return;
        }
        let result = Wallet::create(Path::new(&self.wallet_path), self.passphrase.as_bytes());
        let opened = if result.is_ok() {
            Wallet::open(Path::new(&self.wallet_path), self.passphrase.as_bytes())
        } else {
            Err(anyhow::anyhow!("wallet creation failed"))
        };
        self.passphrase.zeroize();
        self.confirm_passphrase.zeroize();
        match (result, opened) {
            (Ok(address), Ok(wallet)) => {
                self.address = address;
                self.wallet = Some(wallet);
                self.qr_texture = None;
                self.message = "Encrypted wallet created. Back up the wallet file and store its passphrase separately.".into();
            }
            (Err(error), _) => self.message = format!("Could not create wallet: {error:#}"),
            (_, Err(error)) => self.message = format!("Wallet was created but could not be reopened: {error:#}"),
        }
    }

    fn refresh(&mut self) {
        if self.wallet.is_none() {
            self.message = "Open a wallet first.".into();
            return;
        }
        let client = NodeClient::new(&self.node_address);
        match client.status() {
            Ok(status) => {
                self.node_network = status.network;
                self.node_height = Some(status.height);
                match client.account(&self.address) {
                    Ok((balance, nonce)) => {
                        self.balance = Some(balance);
                        self.nonce = Some(nonce);
                        self.message = "Wallet balance updated from the connected node.".into();
                    }
                    Err(error) => self.message = format!("Node connected, but account query failed: {error:#}"),
                }
            }
            Err(error) => self.message = format!("Could not connect to ANA node: {error:#}"),
        }
    }

    fn send(&mut self) {
        let Some(wallet) = self.wallet.as_ref() else {
            self.message = "Open a wallet before sending.".into();
            return;
        };
        let amount = match parse_amount(self.amount.trim()) {
            Ok(value) if value > 0 => value,
            Ok(_) => { self.message = "Amount must be greater than zero.".into(); return; }
            Err(error) => { self.message = format!("Invalid amount: {error:#}"); return; }
        };
        let fee = match parse_amount(self.fee.trim()) {
            Ok(value) => value,
            Err(error) => { self.message = format!("Invalid fee: {error:#}"); return; }
        };
        let Some(nonce) = self.nonce else {
            self.message = "Refresh the wallet balance before sending so the current nonce is known.".into();
            return;
        };
        if self.balance.is_some_and(|balance| balance < amount.saturating_add(fee)) {
            self.message = "Insufficient balance for amount plus fee.".into();
            return;
        }
        let tx = match wallet.sign_transaction(self.recipient.trim(), amount, fee, nonce) {
            Ok(tx) => tx,
            Err(error) => { self.message = format!("Could not prepare transaction: {error:#}"); return; }
        };
        match NodeClient::new(&self.node_address).submit_transaction(tx) {
            Ok(id) => {
                self.transaction_id = id.clone();
                self.transaction_state = "submitted to node mempool (not confirmed)".into();
                self.message = format!("Node accepted transaction {id}. Refresh later to check balance.");
                self.balance = None;
                self.nonce = None;
            }
            Err(error) => self.message = format!("Transaction was not accepted: {error:#}"),
        }
    }

    fn check_transaction(&mut self) {
        if self.transaction_id.trim().is_empty() {
            self.message = "Enter a transaction ID first.".into();
            return;
        }
        match NodeClient::new(&self.node_address).transaction_status(self.transaction_id.trim()) {
            Ok(status) => {
                self.transaction_state = format!("{} — {} confirmation(s)", status.state, status.confirmations);
                self.message = "Status is the connected node's local view; reorganizations can change it.".into();
            }
            Err(error) => self.message = format!("Could not check transaction: {error:#}"),
        }
    }

    fn ensure_qr(&mut self, ctx: &egui::Context) {
        if self.address.is_empty() || self.qr_texture.is_some() { return; }
        if let Ok(code) = qrcode::QrCode::new(self.address.as_bytes()) {
            let width = code.width();
            let pixels: Vec<egui::Color32> = code.to_colors().iter().map(|color| match color {
                qrcode::Color::Dark => egui::Color32::BLACK,
                qrcode::Color::Light => egui::Color32::WHITE,
            }).collect();
            let image = egui::ColorImage::new([width, width], pixels);
            self.qr_texture = Some(ctx.load_texture("ana-receive-address", image, egui::TextureOptions::NEAREST));
        }
    }

    fn amount_label(value: Option<u64>) -> String {
        value.map(|v| format!("{}.{:08} ANA", v / 100_000_000, v % 100_000_000))
            .unwrap_or_else(|| "—".into())
    }
}

impl eframe::App for AnaWalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("ANA Wallet");
                ui.label("Experimental testnet");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(if self.wallet.is_some() { "Wallet unlocked" } else { "No wallet open" });
                });
            });
        });

        egui::SidePanel::left("navigation").resizable(false).default_width(175.0).show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("Wallet");
            ui.add_space(10.0);
            for (page, label) in [
                (Page::Overview, "Overview"), (Page::Send, "Send"), (Page::Receive, "Receive"),
                (Page::Transactions, "Transactions"), (Page::Settings, "Settings"),
            ] {
                if ui.selectable_label(self.page == page, label).clicked() { self.page = page; }
            }
            ui.add_space(20.0);
            if ui.button("Refresh balance").clicked() { self.refresh(); }
            ui.separator();
            ui.label("Network");
            ui.label(if self.node_network.is_empty() { "Not connected" } else { &self.node_network });
            if let Some(height) = self.node_height { ui.label(format!("Height: {height}")); }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.wallet.is_none() {
                ui.heading("Welcome to ANA Wallet");
                ui.label("Create a new encrypted wallet or open an existing wallet file.");
                ui.add_space(16.0);
                ui.label("Wallet file path");
                ui.text_edit_singleline(&mut self.wallet_path);
                ui.label("Passphrase (minimum 12 characters)");
                ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                ui.horizontal(|ui| {
                    if ui.button("Create new wallet").clicked() { self.create(); }
                    if ui.button("Open wallet").clicked() { self.unlock(); }
                });
            } else {
                match self.page {
                    Page::Overview => {
                        ui.heading("Overview");
                        ui.add_space(12.0);
                        ui.group(|ui| {
                            ui.label("Total balance");
                            ui.heading(Self::amount_label(self.balance));
                            ui.label("Balance is read from the connected node.");
                        });
                        ui.horizontal(|ui| {
                            ui.group(|ui| {
                                ui.label("Next transaction nonce");
                                ui.heading(self.nonce.map(|n| n.to_string()).unwrap_or_else(|| "—".into()));
                            });
                            ui.group(|ui| {
                                ui.label("Node height");
                                ui.heading(self.node_height.map(|n| n.to_string()).unwrap_or_else(|| "—".into()));
                            });
                        });
                        ui.add_space(12.0);
                        ui.label("Your ANA address");
                        ui.add(egui::TextEdit::singleline(&mut self.address).interactive(false));
                        if ui.button("Copy address").clicked() {
                            ctx.copy_text(self.address.clone());
                            self.message = "Address copied.".into();
                        }
                        if ui.button("Refresh from node").clicked() { self.refresh(); }
                    }
                    Page::Send => {
                        ui.heading("Send ANA");
                        ui.label("Recipient address");
                        ui.text_edit_singleline(&mut self.recipient);
                        ui.label("Amount (ANA)");
                        ui.text_edit_singleline(&mut self.amount);
                        ui.label("Network fee (ANA)");
                        ui.text_edit_singleline(&mut self.fee);
                        ui.label(format!("Available balance: {}", Self::amount_label(self.balance)));
                        if ui.button("Review transaction").clicked() { self.confirm_send = true; }
                        ui.label("The wallet signs locally. The node connection currently uses plaintext TCP.");
                    }
                    Page::Receive => {
                        ui.heading("Receive ANA");
                        ui.label("Share this address with the sender.");
                        ui.add_space(8.0);
                        self.ensure_qr(ctx);
                        if let Some(texture) = &self.qr_texture {
                            ui.image((texture.id(), egui::vec2(220.0, 220.0)));
                        }
                        ui.add(egui::TextEdit::singleline(&mut self.address).interactive(false));
                        if ui.button("Copy receive address").clicked() {
                            ctx.copy_text(self.address.clone());
                            self.message = "Receive address copied.".into();
                        }
                    }
                    Page::Transactions => {
                        ui.heading("Transaction lookup");
                        ui.label("The current node API supports lookup by transaction ID, not full wallet history.");
                        ui.text_edit_singleline(&mut self.transaction_id);
                        if ui.button("Check transaction").clicked() { self.check_transaction(); }
                        if !self.transaction_state.is_empty() { ui.label(&self.transaction_state); }
                    }
                    Page::Settings => {
                        ui.heading("Settings");
                        ui.label("ANA node address (host:port)");
                        ui.text_edit_singleline(&mut self.node_address);
                        if ui.button("Connect and refresh").clicked() { self.refresh(); }
                        ui.separator();
                        ui.label("Wallet file");
                        ui.text_edit_singleline(&mut self.wallet_path);
                        if ui.button("Close wallet").clicked() {
                            self.wallet = None;
                            self.address.clear();
                            self.balance = None;
                            self.nonce = None;
                            self.qr_texture = None;
                            self.message = "Wallet locked in this application session.".into();
                        }
                        ui.label("Encrypted with Argon2id and XChaCha20-Poly1305. Keep the passphrase separate from backups.");
                        ui.label("Remote-node traffic is plaintext TCP. Use loopback or a trusted VPN/private network only.");
                    }
                }
            }

            if self.confirm_send {
                let mut do_send = false;
                let mut cancel = false;
                egui::Window::new("Confirm ANA transaction").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label(format!("Recipient: {}", self.recipient));
                    ui.label(format!("Amount: {} ANA", self.amount));
                    ui.label(format!("Fee: {} ANA", self.fee));
                    ui.separator();
                    ui.label("Check the address and amount carefully. Sending cannot be undone.");
                    ui.horizontal(|ui| {
                        if ui.button("Confirm and send").clicked() { do_send = true; }
                        if ui.button("Cancel").clicked() { cancel = true; }
                    });
                });
                if do_send { self.confirm_send = false; self.send(); }
                if cancel { self.confirm_send = false; }
            }

            ui.add_space(18.0);
            ui.separator();
            ui.label(&self.message);
            ui.small("ANA is experimental testnet software. Do not use real funds. Private transactions are not enabled in consensus.");
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("ANA Wallet", options, Box::new(|_cc| Ok(Box::new(AnaWalletApp::default()))))
}
