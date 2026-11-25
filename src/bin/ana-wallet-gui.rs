use ana_blockchain::{parse_amount, rpc::NodeClient, Wallet};
use eframe::egui;
use std::{fs, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Page { Overview, Send, Receive, Transactions, Contacts, Settings }

#[derive(Clone, Serialize, Deserialize)]
struct AddressBookEntry { label: String, address: String }

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
    history: Vec<ana_blockchain::rpc::HistoryEntry>,
    history_tip_hash: Option<String>,
    history_next_height: u64,
    history_next_index: usize,
    history_has_more: bool,
    history_limit: usize,
    contacts: Vec<AddressBookEntry>,
    contact_label: String,
    contact_address: String,
    last_activity: f64,
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
            history: Vec::new(),
            history_tip_hash: None,
            history_next_height: 0,
            history_next_index: 0,
            history_has_more: false,
            history_limit: 100,
            contacts: Vec::new(),
            contact_label: String::new(),
            contact_address: String::new(),
            last_activity: 0.0,
        }
    }
}

impl AnaWalletApp {

    fn address_book_path() -> PathBuf { PathBuf::from("ana-address-book.json") }

    fn load_address_book(&mut self) {
        let path = Self::address_book_path();
        if !path.exists() { self.contacts.clear(); return; }
        match fs::read(&path).and_then(|bytes| serde_json::from_slice::<Vec<AddressBookEntry>>(&bytes).map_err(std::io::Error::other)) {
            Ok(entries) => {
                self.contacts = entries.into_iter()
                    .filter(|entry| !entry.label.trim().is_empty() && ana_blockchain::validate_address(&entry.address).is_ok())
                    .take(500).collect();
            }
            Err(error) => self.message = format!("Could not load address book: {error}"),
        }
    }

    fn save_address_book(&mut self) {
        let path = Self::address_book_path();
        let temp = path.with_extension("json.tmp");
        let result = serde_json::to_vec_pretty(&self.contacts)
            .map_err(std::io::Error::other)
            .and_then(|bytes| fs::write(&temp, bytes))
            .and_then(|_| {
                #[cfg(windows)]
                if path.exists() { fs::remove_file(&path)?; }
                fs::rename(&temp, &path)
            });
        match result {
            Ok(()) => self.message = "Address book saved locally.".into(),
            Err(error) => self.message = format!("Could not save address book: {error}"),
        }
    }

    fn add_contact(&mut self) {
        let label = self.contact_label.trim();
        let address = self.contact_address.trim();
        if label.is_empty() || label.len() > 64 {
            self.message = "Contact label must contain 1–64 characters.".into();
            return;
        }
        if ana_blockchain::validate_address(address).is_err() {
            self.message = "Enter a valid ANA address.".into();
            return;
        }
        if let Some(existing) = self.contacts.iter_mut().find(|entry| entry.address == address) {
            existing.label = label.to_owned();
        } else if self.contacts.len() < 500 {
            self.contacts.push(AddressBookEntry { label: label.to_owned(), address: address.to_owned() });
        } else {
            self.message = "Address book limit reached (500 contacts).".into();
            return;
        }
        self.contact_label.clear();
        self.contact_address.clear();
        self.save_address_book();
    }

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
                self.load_address_book();
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
                self.load_address_book();
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


    fn load_history(&mut self, reset: bool) {
        if self.wallet.is_none() { self.message = "Open a wallet first.".into(); return; }
        if reset {
            self.history.clear();
            self.history_tip_hash = None;
            self.history_next_height = 0;
            self.history_next_index = 0;
            self.history_has_more = false;
        }
        let client = NodeClient::new(&self.node_address);
        match client.history_page(
            &self.address,
            self.history_next_height,
            self.history_next_index,
            self.history_limit,
            self.history_tip_hash.as_deref(),
        ) {
            Ok(page) => {
                self.history_tip_hash = Some(page.tip_hash);
                self.history_next_height = page.next_height;
                self.history_next_index = page.next_transaction_index;
                self.history_has_more = page.has_more;
                self.history.extend(page.entries);
                self.message = format!("Loaded {} confirmed wallet transaction(s).", self.history.len());
            }
            Err(error) => {
                self.history.clear();
                self.history_tip_hash = None;
                self.history_next_height = 0;
                self.history_next_index = 0;
                self.history_has_more = false;
                self.message = format!("History scan stopped; refresh from the beginning: {error:#}");
            }
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
            let mut image = egui::ColorImage::new([width, width], egui::Color32::WHITE);
            image.pixels = pixels;
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
        let (now, has_input) = ctx.input(|input| (input.time, !input.raw.events.is_empty()));
        if self.last_activity == 0.0 { self.last_activity = now; }
        if has_input { self.last_activity = now; }
        if self.wallet.is_some() && now - self.last_activity >= 900.0 {
            self.wallet = None;
            self.address.clear();
            self.balance = None;
            self.nonce = None;
            self.qr_texture = None;
            self.history.clear();
            self.history_tip_hash = None;
            self.passphrase.zeroize();
            self.confirm_passphrase.zeroize();
            self.message = "Wallet automatically locked after 15 minutes of inactivity.".into();
            self.last_activity = now;
        }
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
                (Page::Transactions, "Transactions"), (Page::Contacts, "Address book"), (Page::Settings, "Settings"),
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
                        ui.heading("Transaction history");
                        ui.label("Confirmed transactions on the current canonical chain. Refresh if the chain reorganizes.");
                        ui.horizontal(|ui| {
                            if ui.button("Refresh history").clicked() { self.load_history(true); }
                            if ui.add_enabled(self.history_has_more, egui::Button::new("Load more")).clicked() { self.load_history(false); }
                        });
                        ui.label(format!("{} confirmed record(s) loaded", self.history.len()));
                        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                            egui::Grid::new("ana-history-grid").striped(true).show(ui, |ui| {
                                ui.strong("Direction"); ui.strong("Amount"); ui.strong("Height"); ui.strong("Confirmations"); ui.end_row();
                                for entry in &self.history {
                                    ui.label(&entry.direction);
                                    ui.label(Self::amount_label(Some(entry.amount)));
                                    ui.label(entry.height.to_string());
                                    ui.label(entry.confirmations.to_string());
                                    ui.end_row();
                                }
                            });
                        });
                        ui.separator();
                        ui.heading("Transaction ID lookup");
                        ui.text_edit_singleline(&mut self.transaction_id);
                        if ui.button("Check transaction").clicked() { self.check_transaction(); }
                        if !self.transaction_state.is_empty() { ui.label(&self.transaction_state); }
                    }
                    Page::Contacts => {
                        ui.heading("Address book");
                        ui.label("Contacts are stored locally in ana-address-book.json. They are not encrypted.");
                        ui.label("Contact label");
                        ui.text_edit_singleline(&mut self.contact_label);
                        ui.label("ANA address");
                        ui.text_edit_singleline(&mut self.contact_address);
                        if ui.button("Add / update contact").clicked() { self.add_contact(); }
                        ui.separator();
                        let contacts = self.contacts.clone();
                        for contact in contacts {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.strong(&contact.label);
                                    ui.small(&contact.address);
                                });
                                if ui.button("Use for send").clicked() {
                                    self.recipient = contact.address.clone();
                                    self.page = Page::Send;
                                }
                                if ui.button("Remove").clicked() {
                                    self.contacts.retain(|entry| entry.address != contact.address);
                                    self.save_address_book();
                                }
                            });
                        }
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
                        ui.label("The wallet automatically locks after 15 minutes without input.");
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
