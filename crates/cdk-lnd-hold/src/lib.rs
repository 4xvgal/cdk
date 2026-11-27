#![doc = include_str!("../README.md")]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use cdk_common::bitcoin::consensus::deserialize;
use cdk_common::bitcoin::hashes::{sha256, Hash};
use cdk_common::bitcoin::Transaction;
use cdk_common::payment::{
    self, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse,
    MintPayment, OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse, SettingsResponse,
    SettleIncomingPaymentResponse, WaitPaymentResponse,
};
use cdk_common::util::hex;
use cdk_common::{Amount, Bolt11Invoice, CurrencyUnit, MintQuoteState};
use cdk_lnd::{chainrpc, client, invoicesrpc, lnrpc};
use futures::{Stream, StreamExt};
use hold::{
    follow_action, lockup_attempt, lockup_stop, past_deadline, settle_decision, FollowAction,
    HoldRecord, HoldState, HoldStatus, HoldTracker, LockupAttempt, Reserve, SettleDecision,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use store::SettleStore;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request};
use tracing::instrument;

/// Hold state of `bolt11_hold` invoices
///
/// LND invoices are mapped to records, the settle deadline is derived from them,
/// and the cancel decision is a comparison with the current block height. This
/// module has no I/O.
pub mod hold;

/// On-chain lockup scripts a `bolt11_hold` quote can be settled from
///
/// The mint watches the lockup of the quote and settles the held HTLCs once the
/// preimage is revealed on-chain. This module has no I/O.
pub mod lockup;

/// SQLite store of the preimages and hold states of this processor
pub mod store;

const EVENT_CHANNEL_CAPACITY: usize = 64;
const RECOVERY_PAGE_SIZE: u64 = 1_000;
const BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(5);
const SUBSCRIPTION_RETRY_DELAY: Duration = Duration::from_secs(5);
const SETTLE_RETRY_DELAY: Duration = Duration::from_secs(5);
const LOCKUP_SETTLE_ROUNDS: u32 = 12;

/// Custom payment method served by this backend
pub const METHOD: &str = "bolt11_hold";

/// LND hold invoice backend settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// LND gRPC address
    pub address: String,
    /// LND TLS certificate file
    pub cert_file: PathBuf,
    /// LND macaroon file
    pub macaroon_file: PathBuf,
    /// Lowest final CLTV delta a wallet may request
    pub min_final_cltv_expiry_delta: u32,
    /// Highest final CLTV delta a wallet may request
    pub max_final_cltv_expiry_delta: u32,
    /// Blocks subtracted from the lowest accepted HTLC expiry to get the settle
    /// deadline
    pub settle_margin_blocks: u32,
    /// Blocks before that same expiry at which LND cancels the hold invoice by
    /// itself (`invoices.holdexpirydelta`)
    pub lnd_hold_expiry_delta: u32,
    /// Maximum number of unpaid and held quotes
    pub max_pending_quotes: u32,
    /// Hold invoice expiry in seconds
    pub invoice_expiry_secs: i32,
    /// SQLite file holding the persisted preimages and hold states
    pub settle_db_path: PathBuf,
    /// Watch the on-chain lockup of a quote and settle it from the revealed
    /// preimage
    pub auto_settle_onchain: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            address: String::new(),
            cert_file: PathBuf::new(),
            macaroon_file: PathBuf::new(),
            min_final_cltv_expiry_delta: 144,
            max_final_cltv_expiry_delta: 576,
            settle_margin_blocks: 22,
            lnd_hold_expiry_delta: 18,
            max_pending_quotes: 100,
            invoice_expiry_secs: 3600,
            settle_db_path: PathBuf::from("cdk-lnd-hold-settle.sqlite"),
            auto_settle_onchain: true,
        }
    }
}

impl Settings {
    /// Method options advertised to the mint for `bolt11_hold`
    pub fn options_json(&self) -> Value {
        json!({
            "min_final_cltv_expiry_delta": self.min_final_cltv_expiry_delta,
            "max_final_cltv_expiry_delta": self.max_final_cltv_expiry_delta,
            "settle_margin_blocks": self.settle_margin_blocks,
            "max_pending_quotes": self.max_pending_quotes,
            "auto_settle_onchain": self.auto_settle_onchain,
        })
    }
}

#[derive(Debug)]
struct HoldInvoiceRequest {
    payment_hash: [u8; 32],
    amount_sat: u64,
    cltv_expiry_delta: u32,
    lockup_script: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct ExtraFields {
    payment_hash: Option<String>,
    #[serde(default)]
    min_final_cltv_expiry_delta: Option<u32>,
    #[serde(default)]
    lockup: Option<LockupFields>,
}

#[derive(Debug, Deserialize)]
struct LockupFields {
    script: String,
}

fn invalid(message: &str) -> payment::Error {
    payment::Error::Custom(message.to_string())
}

fn validate_settings(settings: &Settings) -> Result<(), payment::Error> {
    if settings.settle_margin_blocks <= settings.lnd_hold_expiry_delta {
        return Err(invalid(&format!(
            "settle_margin_blocks ({}) must exceed lnd_hold_expiry_delta ({})",
            settings.settle_margin_blocks, settings.lnd_hold_expiry_delta,
        )));
    }

    Ok(())
}

fn validate_request(
    amount: Option<Amount<CurrencyUnit>>,
    extra_json: Option<&str>,
    settings: &Settings,
) -> Result<HoldInvoiceRequest, payment::Error> {
    let amount = amount.ok_or_else(|| invalid("bolt11_hold requires an amount"))?;

    if amount.unit() != &CurrencyUnit::Sat {
        return Err(payment::Error::UnsupportedUnit);
    }

    if amount.value() == 0 {
        return Err(invalid("bolt11_hold requires a non-zero amount"));
    }

    let fields: ExtraFields = serde_json::from_str(
        extra_json.ok_or_else(|| invalid("bolt11_hold requires extra_json"))?,
    )?;

    let payment_hash = fields
        .payment_hash
        .ok_or_else(|| invalid("bolt11_hold requires payment_hash"))?;

    let payment_hash: [u8; 32] = hex::decode(&payment_hash)
        .map_err(|_| payment::Error::InvalidHash)?
        .try_into()
        .map_err(|_| payment::Error::InvalidHash)?;

    let cltv_expiry_delta = fields
        .min_final_cltv_expiry_delta
        .unwrap_or(settings.min_final_cltv_expiry_delta);

    if !(settings.min_final_cltv_expiry_delta..=settings.max_final_cltv_expiry_delta)
        .contains(&cltv_expiry_delta)
    {
        return Err(payment::Error::InvalidCltvDelta);
    }

    Ok(HoldInvoiceRequest {
        payment_hash,
        amount_sat: amount.value(),
        cltv_expiry_delta,
        lockup_script: parse_lockup(fields.lockup, &payment_hash, settings)?,
    })
}

fn parse_lockup(
    lockup: Option<LockupFields>,
    payment_hash: &[u8; 32],
    settings: &Settings,
) -> Result<Option<Vec<u8>>, payment::Error> {
    let Some(lockup) = lockup else {
        return Ok(None);
    };

    if !settings.auto_settle_onchain {
        return Err(payment::Error::InvalidLockupScript);
    }

    let script = hex::decode(&lockup.script).map_err(|_| payment::Error::InvalidLockupScript)?;

    if !lockup::commits_to_payment_hash(&script, payment_hash) {
        return Err(payment::Error::InvalidLockupScript);
    }

    Ok(Some(script))
}

fn payment_hash_from_identifier(
    payment_identifier: &PaymentIdentifier,
) -> Result<[u8; 32], payment::Error> {
    hex::decode(payment_identifier.to_string())
        .map_err(|_| payment::Error::InvalidHash)?
        .try_into()
        .map_err(|_| payment::Error::InvalidHash)
}

fn parse_preimage(preimage: &str, payment_hash: &[u8; 32]) -> Result<[u8; 32], payment::Error> {
    let preimage: [u8; 32] = hex::decode(preimage)
        .map_err(|_| payment::Error::PreimageMismatch)?
        .try_into()
        .map_err(|_| payment::Error::PreimageMismatch)?;

    if &sha256::Hash::hash(&preimage).to_byte_array() != payment_hash {
        return Err(payment::Error::PreimageMismatch);
    }

    Ok(preimage)
}

fn is_already_cancelled(status: &tonic::Status) -> bool {
    status.message().to_lowercase().contains("already cancel")
}

fn is_hash_already_used(status: &tonic::Status) -> bool {
    let message = status.message().to_lowercase();

    message.contains("invoice with payment hash already exists")
        || message.contains("invoice with that hash already exists")
}

fn is_already_settled(status: &tonic::Status) -> bool {
    status.message().to_lowercase().contains("already settled")
}

fn settle_extra_json(record: HoldRecord, preimage_persisted: bool) -> Value {
    let mut extra = record.extra_json();

    if let Value::Object(fields) = &mut extra {
        fields.insert("preimage_persisted".to_string(), json!(preimage_persisted));
    }

    extra
}

fn created_extra(request: &HoldInvoiceRequest, settle_margin_blocks: u32) -> Value {
    let mut extra =
        HoldRecord::from_status(HoldStatus::unpaid(), settle_margin_blocks).extra_json();

    if let Value::Object(fields) = &mut extra {
        fields.insert(
            "payment_hash".to_string(),
            json!(hex::encode(request.payment_hash)),
        );
        fields.insert(
            "min_final_cltv_expiry_delta".to_string(),
            json!(request.cltv_expiry_delta),
        );
    }

    extra
}

fn add_hold_invoice_request(
    request: &HoldInvoiceRequest,
    memo: String,
    settings: &Settings,
) -> invoicesrpc::AddHoldInvoiceRequest {
    invoicesrpc::AddHoldInvoiceRequest {
        memo,
        hash: request.payment_hash.to_vec(),
        value: request.amount_sat as i64,
        expiry: i64::from(settings.invoice_expiry_secs),
        cltv_expiry: u64::from(request.cltv_expiry_delta),
    }
}

/// LND hold invoice backend serving the `bolt11_hold` custom payment method
pub struct LndHold {
    settings: Settings,
    watcher: Watcher,
    event_stream_active: Arc<AtomicBool>,
    event_cancel: CancellationToken,
}

impl std::fmt::Debug for LndHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndHold")
            .field("address", &self.settings.address)
            .finish_non_exhaustive()
    }
}

impl LndHold {
    /// Connect to LND
    #[instrument(skip_all)]
    pub async fn new(settings: Settings) -> Result<Self, payment::Error> {
        validate_settings(&settings)?;

        let client = client::connect(
            &settings.address,
            &settings.cert_file,
            &settings.macaroon_file,
        )
        .await
        .map_err(|err| invalid(&format!("LND connection error: {err}")))?;

        let store = Arc::new(SettleStore::open(&settings.settle_db_path)?);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

        let watcher = Watcher {
            client,
            tracker: Arc::new(HoldTracker::new(settings.settle_margin_blocks)),
            store,
            events,
            watched: Arc::new(Mutex::new(HashSet::new())),
            lockups: Arc::new(Mutex::new(HashSet::new())),
            height: Arc::new(Mutex::new(None)),
        };

        tokio::spawn(poll_block_height(watcher.clone()));
        tokio::spawn(recover_pending_invoices(watcher.clone()));
        tokio::spawn(resume_pending_settles(watcher.clone()));
        tokio::spawn(resume_lockup_watches(watcher.clone()));

        Ok(Self {
            settings,
            watcher,
            event_stream_active: Arc::new(AtomicBool::new(false)),
            event_cancel: CancellationToken::new(),
        })
    }

    async fn create_reserved_quote(
        &self,
        request: &HoldInvoiceRequest,
        description: String,
    ) -> Result<CreateIncomingPaymentResponse, payment::Error> {
        let add_request = add_hold_invoice_request(request, description, &self.settings);

        let mut client = self.watcher.client.clone();
        let response = client
            .invoices()
            .add_hold_invoice(Request::new(add_request))
            .await
            .map_err(|status| {
                if is_hash_already_used(&status) {
                    return payment::Error::PaymentHashAlreadyUsed;
                }

                invalid(&format!("LND AddHoldInvoice failed: {status}"))
            })?
            .into_inner();

        let bolt11 = Bolt11Invoice::from_str(&response.payment_request)?;

        if bolt11.payment_hash().as_byte_array() != &request.payment_hash {
            return Err(payment::Error::InvalidHash);
        }

        self.watcher.ensure_watching(&request.payment_hash);

        if let Some(script) = &request.lockup_script {
            let height_hint = self.watcher.block_height().await?;
            self.watcher
                .store
                .watch_lockup(&request.payment_hash, script, height_hint)?;
            self.watcher.ensure_lockup_watch(&request.payment_hash);

            tracing::info!(
                payment_hash = %hex::encode(request.payment_hash),
                height_hint,
                "watching the on-chain lockup of the quote",
            );
        }

        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: PaymentIdentifier::PaymentHash(request.payment_hash),
            expiry: bolt11.expires_at().map(|time| time.as_secs()),
            request: bolt11.to_string(),
            extra_json: Some(created_extra(request, self.settings.settle_margin_blocks)),
        })
    }
}

/// Effect of acting on the spend of a watched lockup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockupSettle {
    /// The quote needs no further watching
    Resolved,
    /// Keep watching, but leave the subscription so the spend is replayed
    Reregister,
}

#[derive(Clone)]
struct Watcher {
    client: client::Client,
    tracker: Arc<HoldTracker>,
    store: Arc<SettleStore>,
    events: broadcast::Sender<WaitPaymentResponse>,
    watched: Arc<Mutex<HashSet<[u8; 32]>>>,
    lockups: Arc<Mutex<HashSet<[u8; 32]>>>,
    height: Arc<Mutex<Option<u32>>>,
}

impl Watcher {
    async fn lookup_invoice(
        &self,
        payment_hash: &[u8; 32],
    ) -> Result<Option<lnrpc::Invoice>, payment::Error> {
        let mut client = self.client.clone();
        let lookup_request = lnrpc::PaymentHash {
            r_hash: payment_hash.to_vec(),
            ..Default::default()
        };

        match client
            .lightning()
            .lookup_invoice(Request::new(lookup_request))
            .await
        {
            Ok(invoice) => Ok(Some(invoice.into_inner())),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(invalid(&format!("LND LookupInvoice failed: {status}"))),
        }
    }

    async fn record(&self, payment_hash: &[u8; 32]) -> Result<HoldRecord, payment::Error> {
        Ok(match self.lookup_invoice(payment_hash).await? {
            Some(invoice) => self
                .tracker
                .observe(payment_hash, HoldStatus::from_invoice(&invoice)),
            None => match self.tracker.get(payment_hash) {
                Some(record) => record,
                None => self.tracker.observe(payment_hash, HoldStatus::unpaid()),
            },
        })
    }

    async fn block_height(&self) -> Result<u32, payment::Error> {
        let mut client = self.client.clone();

        let height = client
            .lightning()
            .get_info(Request::new(lnrpc::GetInfoRequest {}))
            .await
            .map(|response| response.into_inner().block_height)
            .map_err(|status| invalid(&format!("LND GetInfo failed: {status}")))?;

        *self.height.lock().unwrap_or_else(PoisonError::into_inner) = Some(height);
        Ok(height)
    }

    fn tip_height(&self) -> Option<u32> {
        *self.height.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn settle_invoice(&self, preimage: &[u8; 32]) -> Result<(), tonic::Status> {
        let request = invoicesrpc::SettleInvoiceMsg {
            preimage: preimage.to_vec(),
        };

        self.client
            .clone()
            .invoices()
            .settle_invoice(Request::new(request))
            .await
            .map(|_| ())
    }

    fn mark_settled(&self, payment_hash: &[u8; 32]) -> Result<(), payment::Error> {
        self.tracker.mark_settled(payment_hash);
        self.store.set_state(payment_hash, HoldState::Settled)
    }

    fn mark_cancelled(&self, payment_hash: &[u8; 32]) -> Result<(), payment::Error> {
        self.tracker.mark_cancelled(payment_hash);
        self.store.set_state(payment_hash, HoldState::Cancelled)
    }

    fn ensure_watching(&self, payment_hash: &[u8; 32]) {
        let inserted = self
            .watched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*payment_hash);

        if !inserted {
            return;
        }

        tokio::spawn(follow_hold_invoice(
            self.client.clone(),
            Arc::clone(&self.tracker),
            self.events.clone(),
            *payment_hash,
        ));
    }

    fn ensure_lockup_watch(&self, payment_hash: &[u8; 32]) {
        let inserted = self
            .lockups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*payment_hash);

        if !inserted {
            return;
        }

        tokio::spawn(follow_lockup(self.clone(), *payment_hash));
    }

    fn lockups_count(&self) -> usize {
        self.lockups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn stop_lockup_watch(&self, payment_hash: &[u8; 32]) {
        self.lockups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(payment_hash);

        if let Err(err) = self.store.unwatch_lockup(payment_hash) {
            tracing::warn!(error = %err, "could not forget the lockup watch");
        }
    }

    async fn lockup_resolved(&self, payment_hash: &[u8; 32]) -> bool {
        if let Some(record) = self.tracker.get(payment_hash) {
            match lockup_stop(record) {
                Some(resolved) => return resolved,
                None => return self.past_deadline(record).await,
            }
        }

        match self.lookup_invoice(payment_hash).await {
            Ok(Some(invoice)) => {
                let record = self
                    .tracker
                    .observe(payment_hash, HoldStatus::from_invoice(&invoice));

                match lockup_stop(record) {
                    Some(resolved) => resolved,
                    None => self.past_deadline(record).await,
                }
            }
            Ok(None) => true,
            Err(err) => {
                tracing::warn!(error = %err, "could not look up the hold invoice");
                false
            }
        }
    }

    async fn past_deadline(&self, record: HoldRecord) -> bool {
        let height = match self.tip_height() {
            Some(height) => Some(height),
            None => self.block_height().await.ok(),
        };

        past_deadline(record, height)
    }

    async fn settle_lockup(
        &self,
        payment_hash: &[u8; 32],
        spending: &chainrpc::SpendDetails,
    ) -> LockupSettle {
        let Ok(tx) = deserialize::<Transaction>(&spending.raw_spending_tx) else {
            tracing::warn!(
                payment_hash = %hex::encode(payment_hash),
                "could not parse the transaction spending the lockup; retrying the watch",
            );
            return LockupSettle::Reregister;
        };

        let Some(input) = tx.input.get(spending.spending_input_index as usize) else {
            tracing::warn!(
                payment_hash = %hex::encode(payment_hash),
                "the transaction spending the lockup has no such input; retrying the watch",
            );
            return LockupSettle::Reregister;
        };
        let witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();

        let Some(preimage) = lockup::extract_preimage(&witness, payment_hash) else {
            tracing::info!(
                payment_hash = %hex::encode(payment_hash),
                spending_height = spending.spending_height,
                "the lockup was spent without the preimage; nothing to settle",
            );
            return LockupSettle::Resolved;
        };

        tracing::info!(
            payment_hash = %hex::encode(payment_hash),
            spending_height = spending.spending_height,
            "the lockup revealed the preimage; settling the held HTLCs",
        );

        for round in 0..LOCKUP_SETTLE_ROUNDS {
            let record = match self.record(payment_hash).await {
                Ok(record) => record,
                Err(err) => {
                    tracing::warn!(error = %err, "could not read the hold record");
                    tokio::time::sleep(SETTLE_RETRY_DELAY).await;
                    continue;
                }
            };

            let height = match self.block_height().await {
                Ok(height) => Some(height),
                Err(err) => {
                    tracing::warn!(error = %err, "could not read the block height");
                    None
                }
            };

            match lockup_attempt(
                settle_decision(record, false, height),
                LOCKUP_SETTLE_ROUNDS - round - 1,
            ) {
                LockupAttempt::Settle => {
                    if let Err(err) =
                        self.store
                            .persist_preimage(payment_hash, &preimage, HoldState::Held)
                    {
                        tracing::warn!(error = %err, "could not persist the revealed preimage");
                        tokio::time::sleep(SETTLE_RETRY_DELAY).await;
                        continue;
                    }

                    settle_until_settled(self.clone(), *payment_hash, preimage).await;
                    return LockupSettle::Resolved;
                }
                LockupAttempt::Resolved => return LockupSettle::Resolved,
                LockupAttempt::Retry => tokio::time::sleep(SETTLE_RETRY_DELAY).await,
                LockupAttempt::Defer => break,
            }
        }

        tracing::warn!(
            payment_hash = %hex::encode(payment_hash),
            "the hold invoice is not held yet; keeping the watch so it can still settle",
        );

        LockupSettle::Reregister
    }
}

async fn recover_pending_invoices(watcher: Watcher) {
    let mut client = watcher.client.clone();
    let mut index_offset = 0;

    loop {
        let request = lnrpc::ListInvoiceRequest {
            pending_only: true,
            index_offset,
            num_max_invoices: RECOVERY_PAGE_SIZE,
            ..Default::default()
        };

        let page = loop {
            match client
                .lightning()
                .list_invoices(Request::new(request))
                .await
            {
                Ok(response) => break response.into_inner(),
                Err(status) => {
                    tracing::warn!(
                        error = %status,
                        index_offset,
                        "LND ListInvoices failed; retrying pending hold invoice recovery",
                    );
                    tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
                }
            }
        };

        if page.invoices.is_empty() || page.last_index_offset <= index_offset {
            return;
        }

        for invoice in &page.invoices {
            let Ok(payment_hash) = <[u8; 32]>::try_from(invoice.r_hash.as_slice()) else {
                tracing::warn!("LND returned a pending invoice without a 32-byte hash");
                continue;
            };

            let record = watcher
                .tracker
                .observe(&payment_hash, HoldStatus::from_invoice(invoice));

            tracing::info!(
                payment_hash = %hex::encode(payment_hash),
                hold_state = record.state.as_str(),
                settle_deadline = ?record.settle_deadline,
                "recovered a pending LND invoice",
            );

            watcher.ensure_watching(&payment_hash);
        }

        index_offset = page.last_index_offset;
    }
}

async fn follow_hold_invoice(
    mut client: client::Client,
    tracker: Arc<HoldTracker>,
    events: broadcast::Sender<WaitPaymentResponse>,
    payment_hash: [u8; 32],
) {
    loop {
        let request = invoicesrpc::SubscribeSingleInvoiceRequest {
            r_hash: payment_hash.to_vec(),
        };

        match client
            .invoices()
            .subscribe_single_invoice(Request::new(request))
            .await
        {
            Ok(response) => {
                if follow_invoice(response.into_inner(), &tracker, &events, payment_hash).await {
                    return;
                }
            }
            Err(status) if status.code() == Code::NotFound => {
                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    "LND does not know the hold invoice; stopping the subscription",
                );
                return;
            }
            Err(status) => {
                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    error = %status,
                    "LND SubscribeSingleInvoice failed; retrying",
                );
            }
        }

        tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
    }
}

async fn follow_invoice(
    mut stream: tonic::Streaming<lnrpc::Invoice>,
    tracker: &HoldTracker,
    events: &broadcast::Sender<WaitPaymentResponse>,
    payment_hash: [u8; 32],
) -> bool {
    while let Some(message) = stream.next().await {
        let invoice = match message {
            Ok(invoice) => invoice,
            Err(status) => {
                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    error = %status,
                    "LND hold invoice subscription closed; resubscribing",
                );
                return false;
            }
        };

        match follow_action(tracker.observe(&payment_hash, HoldStatus::from_invoice(&invoice))) {
            FollowAction::Settle => {
                tracing::info!(
                    payment_hash = %hex::encode(payment_hash),
                    amount_msat = invoice.amt_paid_msat,
                    "LND hold invoice settled",
                );
                let _ = events.send(WaitPaymentResponse {
                    payment_identifier: PaymentIdentifier::PaymentHash(payment_hash),
                    payment_amount: Amount::new(invoice.amt_paid_msat as u64, CurrencyUnit::Msat),
                    payment_id: hex::encode(payment_hash),
                });
                return true;
            }
            FollowAction::Stop => {
                tracing::info!(
                    payment_hash = %hex::encode(payment_hash),
                    "LND hold invoice cancelled",
                );
                return true;
            }
            FollowAction::Continue => {}
        }
    }

    false
}

async fn poll_block_height(watcher: Watcher) {
    let mut client = watcher.client.clone();

    loop {
        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;

        let held = watcher.tracker.held();

        if held.is_empty() && watcher.lockups_count() == 0 {
            continue;
        }

        let block_height = match watcher.block_height().await {
            Ok(block_height) => block_height,
            Err(err) => {
                tracing::warn!(error = %err, "LND GetInfo failed; skipping the cancel round");
                continue;
            }
        };

        for (payment_hash, record) in held {
            let preimage_persisted = match watcher.store.preimage(&payment_hash) {
                Ok(preimage) => preimage.is_some(),
                Err(err) => {
                    tracing::warn!(
                        payment_hash = %hex::encode(payment_hash),
                        error = %err,
                        "could not read the persisted preimage; skipping the cancel round",
                    );
                    continue;
                }
            };

            if !hold::should_cancel(record, preimage_persisted, block_height) {
                continue;
            }

            let request = invoicesrpc::CancelInvoiceMsg {
                payment_hash: payment_hash.to_vec(),
            };

            match client
                .invoices()
                .cancel_invoice(Request::new(request))
                .await
            {
                Ok(_) => {
                    if let Err(err) = watcher.mark_cancelled(&payment_hash) {
                        tracing::warn!(error = %err, "could not persist the cancelled hold state");
                    }
                    tracing::info!(
                        payment_hash = %hex::encode(payment_hash),
                        block_height,
                        settle_deadline = ?record.settle_deadline,
                        "LND hold invoice cancelled after the settle deadline",
                    );
                }
                Err(status) => {
                    tracing::warn!(
                        payment_hash = %hex::encode(payment_hash),
                        block_height,
                        error = %status,
                        "LND CancelInvoice failed; retrying on the next round",
                    );
                }
            }
        }
    }
}

async fn settle_until_settled(watcher: Watcher, payment_hash: [u8; 32], preimage: [u8; 32]) {
    loop {
        match watcher.settle_invoice(&preimage).await {
            Ok(()) => {
                if let Err(err) = watcher.mark_settled(&payment_hash) {
                    tracing::warn!(error = %err, "could not persist the settled hold state");
                }

                tracing::info!(
                    payment_hash = %hex::encode(payment_hash),
                    "LND hold invoice settled with the persisted preimage",
                );
                return;
            }
            Err(status) if is_already_settled(&status) => {
                if let Err(err) = watcher.mark_settled(&payment_hash) {
                    tracing::warn!(error = %err, "could not persist the settled hold state");
                }

                tracing::info!(
                    payment_hash = %hex::encode(payment_hash),
                    "LND hold invoice was already settled",
                );
                return;
            }
            Err(status) if is_already_cancelled(&status) => {
                if let Err(err) = watcher.mark_cancelled(&payment_hash) {
                    tracing::warn!(error = %err, "could not persist the cancelled hold state");
                }

                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    error = %status,
                    "LND hold invoice was already cancelled; not settling",
                );
                return;
            }
            Err(status) if status.code() == Code::NotFound => {
                if let Err(err) = watcher.mark_cancelled(&payment_hash) {
                    tracing::warn!(error = %err, "could not persist the cancelled hold state");
                }

                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    "LND does not know the hold invoice; stopping the settle retry",
                );
                return;
            }
            Err(status) => {
                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    error = %status,
                    "LND SettleInvoice failed; retrying",
                );
                tokio::time::sleep(SETTLE_RETRY_DELAY).await;
            }
        }
    }
}

async fn resume_pending_settles(watcher: Watcher) {
    let records = loop {
        match watcher.store.pending_settles() {
            Ok(records) => break records,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "could not read the pending settles; retrying the resume",
                );
                tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
            }
        }
    };

    for record in records {
        tracing::info!(
            payment_hash = %hex::encode(record.payment_hash),
            "resuming the settle retry of a persisted preimage",
        );
        watcher.ensure_watching(&record.payment_hash);
        tokio::spawn(settle_until_settled(
            watcher.clone(),
            record.payment_hash,
            record.preimage,
        ));
    }
}

async fn resume_lockup_watches(watcher: Watcher) {
    let watches = loop {
        match watcher.store.pending_lockups() {
            Ok(watches) => break watches,
            Err(err) => {
                tracing::warn!(error = %err, "could not read the pending lockup watches; retrying");
                tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
            }
        }
    };

    for watch in watches {
        tracing::info!(
            payment_hash = %hex::encode(watch.payment_hash),
            "resuming the lockup watch of a pending quote",
        );
        watcher.ensure_lockup_watch(&watch.payment_hash);
    }
}

async fn follow_lockup(watcher: Watcher, payment_hash: [u8; 32]) {
    loop {
        if watcher.lockup_resolved(&payment_hash).await {
            watcher.stop_lockup_watch(&payment_hash);
            return;
        }

        let watch = match watcher.store.lockup_watch(&payment_hash) {
            Ok(Some(watch)) => watch,
            Ok(None) => {
                watcher.stop_lockup_watch(&payment_hash);
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "could not read the lockup watch");
                tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
                continue;
            }
        };

        let request = chainrpc::SpendRequest {
            outpoint: None,
            script: lockup::p2wsh_script_pubkey(&watch.script),
            height_hint: watch.height_hint,
        };

        let mut client = watcher.client.clone();
        let registration = client.chain().register_spend_ntfn(Request::new(request));
        tokio::pin!(registration);

        let response = loop {
            tokio::select! {
                () = tokio::time::sleep(BLOCK_POLL_INTERVAL) => {
                    if watcher.lockup_resolved(&payment_hash).await {
                        watcher.stop_lockup_watch(&payment_hash);
                        return;
                    }
                }
                response = &mut registration => break response,
            }
        };

        match response {
            Ok(response) => {
                if follow_lockup_spends(&watcher, &payment_hash, response.into_inner()).await {
                    watcher.stop_lockup_watch(&payment_hash);
                    return;
                }
            }
            Err(status) => {
                tracing::warn!(
                    payment_hash = %hex::encode(payment_hash),
                    error = %status,
                    "LND RegisterSpendNtfn failed; retrying the lockup watch",
                );
            }
        }

        tokio::time::sleep(SUBSCRIPTION_RETRY_DELAY).await;
    }
}

async fn follow_lockup_spends(
    watcher: &Watcher,
    payment_hash: &[u8; 32],
    mut stream: tonic::Streaming<chainrpc::SpendEvent>,
) -> bool {
    loop {
        tokio::select! {
            () = tokio::time::sleep(BLOCK_POLL_INTERVAL) => {
                if watcher.lockup_resolved(payment_hash).await {
                    return true;
                }
            }
            event = stream.next() => match event {
                Some(Ok(event)) => match event.event {
                    Some(chainrpc::spend_event::Event::Spend(spending)) => {
                        match watcher.settle_lockup(payment_hash, &spending).await {
                            LockupSettle::Resolved => return true,
                            LockupSettle::Reregister => return false,
                        }
                    }
                    Some(chainrpc::spend_event::Event::Reorg(_)) | None => {}
                },
                Some(Err(status)) => {
                    tracing::warn!(
                        payment_hash = %hex::encode(payment_hash),
                        error = %status,
                        "LND spend subscription closed; resubscribing",
                    );
                    return false;
                }
                None => return false,
            }
        }
    }
}

#[async_trait]
impl MintPayment for LndHold {
    type Err = payment::Error;

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        Ok(SettingsResponse {
            unit: CurrencyUnit::Sat.to_string(),
            bolt11: None,
            bolt12: None,
            onchain: None,
            custom: HashMap::from([(METHOD.to_string(), self.settings.options_json().to_string())]),
        })
    }

    #[instrument(skip_all)]
    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        let IncomingPaymentOptions::Custom(options) = options else {
            return Err(payment::Error::UnsupportedPaymentOption);
        };

        let request = validate_request(
            options.amount,
            options.extra_json.as_deref(),
            &self.settings,
        )?;

        match self
            .watcher
            .tracker
            .reserve(&request.payment_hash, self.settings.max_pending_quotes)
        {
            Reserve::Reserved => {}
            Reserve::AlreadyTracked => return Err(payment::Error::PaymentHashAlreadyUsed),
            Reserve::Full => {
                tracing::warn!(
                    payment_hash = %hex::encode(request.payment_hash),
                    max_pending_quotes = self.settings.max_pending_quotes,
                    "rejecting the quote: the processor holds the maximum number of pending quotes",
                );

                return Err(payment::Error::TooManyPendingQuotes);
            }
        }

        let created = self
            .create_reserved_quote(&request, options.description.unwrap_or_default())
            .await;

        if created.is_err() {
            self.watcher.tracker.release(&request.payment_hash);
        }

        created
    }

    async fn get_payment_quote(
        &self,
        _unit: &CurrencyUnit,
        _options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        Err(payment::Error::UnsupportedPaymentOption)
    }

    async fn make_payment(
        &self,
        _unit: &CurrencyUnit,
        _options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        Err(payment::Error::UnsupportedPaymentOption)
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let receiver = self.watcher.events.subscribe();
        let cancel = self.event_cancel.clone();
        let is_active = Arc::clone(&self.event_stream_active);

        let stream = futures::stream::unfold(
            (receiver, cancel, is_active),
            |(mut receiver, cancel, is_active)| async move {
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => {
                            is_active.store(false, Ordering::SeqCst);
                            return None;
                        }
                        received = receiver.recv() => match received {
                            Ok(response) => {
                                is_active.store(true, Ordering::SeqCst);
                                return Some((
                                    Event::PaymentReceived(response),
                                    (receiver, cancel, is_active),
                                ));
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::warn!(skipped, "payment event stream lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                is_active.store(false, Ordering::SeqCst);
                                return None;
                            }
                        }
                    }
                }
            },
        );

        self.event_stream_active.store(true, Ordering::SeqCst);
        Ok(Box::pin(stream))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.event_stream_active.load(Ordering::SeqCst)
    }

    fn cancel_payment_event_stream(&self) {
        self.event_cancel.cancel();
    }

    #[instrument(skip(self))]
    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        let payment_hash = payment_hash_from_identifier(payment_identifier)?;
        self.watcher.ensure_watching(&payment_hash);

        let Some(invoice) = self.watcher.lookup_invoice(&payment_hash).await? else {
            return Ok(Vec::new());
        };

        let record = self
            .watcher
            .tracker
            .observe(&payment_hash, HoldStatus::from_invoice(&invoice));

        tracing::debug!(
            payment_hash = %payment_identifier,
            hold_state = record.state.as_str(),
            min_htlc_expiry_height = ?record.min_htlc_expiry_height,
            settle_deadline = ?record.settle_deadline,
            "checked LND hold invoice",
        );

        if record.state != HoldState::Settled {
            return Ok(Vec::new());
        }

        Ok(vec![WaitPaymentResponse {
            payment_identifier: payment_identifier.clone(),
            payment_amount: Amount::new(invoice.amt_paid_msat as u64, CurrencyUnit::Msat),
            payment_id: hex::encode(payment_hash),
        }])
    }

    #[instrument(skip(self))]
    async fn check_incoming_payment_extra(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Option<Value>, Self::Err> {
        let payment_hash = payment_hash_from_identifier(payment_identifier)?;
        self.watcher.ensure_watching(&payment_hash);

        Ok(Some(self.watcher.record(&payment_hash).await?.extra_json()))
    }

    #[instrument(skip(self))]
    async fn settle_incoming_payment(
        &self,
        method: &str,
        payment_identifier: &PaymentIdentifier,
        preimage: &str,
    ) -> Result<SettleIncomingPaymentResponse, Self::Err> {
        if method != METHOD {
            return Err(payment::Error::UnsupportedPaymentOption);
        }

        let payment_hash = payment_hash_from_identifier(payment_identifier)?;
        let preimage = parse_preimage(preimage, &payment_hash)?;

        self.watcher.ensure_watching(&payment_hash);

        let record = self.watcher.record(&payment_hash).await?;
        let preimage_persisted = self.watcher.store.preimage(&payment_hash)?.is_some();
        let block_height = if record.state == HoldState::Held {
            Some(self.watcher.block_height().await?)
        } else {
            None
        };

        let state = match settle_decision(record, preimage_persisted, block_height)? {
            SettleDecision::AlreadySettled => {
                self.watcher.mark_settled(&payment_hash)?;
                MintQuoteState::Paid
            }
            SettleDecision::Settle => {
                self.watcher
                    .store
                    .persist_preimage(&payment_hash, &preimage, HoldState::Held)?;

                match self.watcher.settle_invoice(&preimage).await {
                    Ok(()) => {
                        self.watcher.mark_settled(&payment_hash)?;
                        MintQuoteState::Paid
                    }
                    Err(status) if is_already_settled(&status) => {
                        self.watcher.mark_settled(&payment_hash)?;
                        MintQuoteState::Paid
                    }
                    Err(status) if is_already_cancelled(&status) => {
                        self.watcher.mark_cancelled(&payment_hash)?;
                        return Err(payment::Error::HoldCancelled);
                    }
                    Err(status) if status.code() == Code::NotFound => {
                        self.watcher.mark_cancelled(&payment_hash)?;
                        return Err(payment::Error::HoldNotHeld);
                    }
                    Err(status) => {
                        tracing::warn!(
                            payment_hash = %hex::encode(payment_hash),
                            error = %status,
                            "LND SettleInvoice failed; retrying in the background",
                        );

                        tokio::spawn(settle_until_settled(
                            self.watcher.clone(),
                            payment_hash,
                            preimage,
                        ));

                        MintQuoteState::Unpaid
                    }
                }
            }
        };

        let record = self.watcher.tracker.get(&payment_hash).unwrap_or(record);
        let preimage_persisted = self.watcher.store.preimage(&payment_hash)?.is_some();

        Ok(SettleIncomingPaymentResponse {
            request_lookup_id: payment_identifier.clone(),
            state,
            extra_json: Some(settle_extra_json(record, preimage_persisted)),
        })
    }

    async fn check_outgoing_payment(
        &self,
        _payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        Err(payment::Error::UnsupportedPaymentOption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount() -> Option<Amount<CurrencyUnit>> {
        Some(Amount::new(10_000, CurrencyUnit::Sat))
    }

    fn validate(extra_json: &str) -> Result<HoldInvoiceRequest, payment::Error> {
        validate_request(amount(), Some(extra_json), &Settings::default())
    }

    fn validate_with(
        settings: &Settings,
        extra_json: &str,
    ) -> Result<HoldInvoiceRequest, payment::Error> {
        validate_request(amount(), Some(extra_json), settings)
    }

    const SWAP_SCRIPT: &str = "8201208763a914ea4beb47def8492389a1e16634795441e1b8724588210311111111111111111111111111111111111111111111111111111111111111116775022003b1752102222222222222222222222222222222222222222222222222222222222222222268ac";
    const SWAP_PAYMENT_HASH: &str =
        "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";

    fn hash_hex() -> String {
        hex::encode([7u8; 32])
    }

    #[test]
    fn settings_expose_hold_options() {
        let options = Settings::default().options_json();

        assert_eq!(options["min_final_cltv_expiry_delta"], 144);
        assert_eq!(options["max_final_cltv_expiry_delta"], 576);
        assert_eq!(options["settle_margin_blocks"], 22);
        assert_eq!(options["max_pending_quotes"], 100);
        assert_eq!(options["auto_settle_onchain"], true);

        let disabled = Settings {
            auto_settle_onchain: false,
            ..Settings::default()
        };
        assert_eq!(disabled.options_json()["auto_settle_onchain"], false);
    }

    fn lockup_request(script: &str, payment_hash: &str) -> String {
        format!(r#"{{"payment_hash":"{payment_hash}","lockup":{{"script":"{script}"}}}}"#)
    }

    #[test]
    fn request_accepts_a_lockup_script_of_the_payment_hash() {
        let request =
            validate(&lockup_request(SWAP_SCRIPT, SWAP_PAYMENT_HASH)).expect("valid lockup");

        assert_eq!(
            request.lockup_script,
            Some(hex::decode(SWAP_SCRIPT).expect("fixture script"))
        );
    }

    #[test]
    fn request_without_a_lockup_watches_nothing() {
        let request =
            validate(&format!(r#"{{"payment_hash":"{}"}}"#, hash_hex())).expect("valid request");

        assert_eq!(request.lockup_script, None);
    }

    #[test]
    fn request_rejects_an_invalid_lockup_script() {
        for script in [
            String::new(),
            "zz".to_string(),
            "00".to_string(),
            SWAP_SCRIPT[..SWAP_SCRIPT.len() - 2].to_string(),
        ] {
            assert!(
                matches!(
                    validate(&lockup_request(&script, SWAP_PAYMENT_HASH)),
                    Err(payment::Error::InvalidLockupScript)
                ),
                "{script}"
            );
        }
    }

    #[test]
    fn request_rejects_a_lockup_script_of_another_payment_hash() {
        let other = hex::encode([7u8; 32]);

        assert!(matches!(
            validate(&lockup_request(SWAP_SCRIPT, &other)),
            Err(payment::Error::InvalidLockupScript)
        ));
    }

    #[test]
    fn request_rejects_a_lockup_when_auto_settle_is_disabled() {
        let settings = Settings {
            auto_settle_onchain: false,
            ..Settings::default()
        };

        assert!(matches!(
            validate_with(&settings, &lockup_request(SWAP_SCRIPT, SWAP_PAYMENT_HASH)),
            Err(payment::Error::InvalidLockupScript)
        ));
        assert!(validate_with(
            &settings,
            &format!(r#"{{"payment_hash":"{}"}}"#, hash_hex())
        )
        .is_ok());
    }

    #[test]
    fn settings_reject_margin_at_or_below_lnd_hold_expiry_delta() {
        assert!(validate_settings(&Settings::default()).is_ok());

        for settle_margin_blocks in [18, 17, 0] {
            let settings = Settings {
                settle_margin_blocks,
                ..Settings::default()
            };

            assert!(
                matches!(validate_settings(&settings), Err(payment::Error::Custom(_))),
                "{settle_margin_blocks}"
            );
        }
    }

    #[test]
    fn default_margin_cancels_before_lnd_hold_expiry() {
        let settings = Settings::default();
        let min_htlc_expiry_height = 1_000_i32;
        let lnd_cancel_height =
            u32::try_from(min_htlc_expiry_height).unwrap() - settings.lnd_hold_expiry_delta;

        let record = hold::HoldRecord::from_status(
            hold::HoldStatus {
                state: hold::HoldState::Held,
                min_htlc_expiry_height: Some(min_htlc_expiry_height),
            },
            settings.settle_margin_blocks,
        );
        let deadline = record.settle_deadline.expect("held invoice has a deadline");

        assert!(deadline < lnd_cancel_height);
        assert!(record.should_cancel(lnd_cancel_height - 1));
    }

    #[test]
    fn request_uses_requested_cltv() {
        let request = validate(&format!(
            r#"{{"payment_hash":"{}","min_final_cltv_expiry_delta":432}}"#,
            hash_hex()
        ))
        .expect("valid request");

        assert_eq!(request.payment_hash, [7u8; 32]);
        assert_eq!(request.amount_sat, 10_000);
        assert_eq!(request.cltv_expiry_delta, 432);
    }

    #[test]
    fn request_defaults_cltv_to_minimum() {
        let request =
            validate(&format!(r#"{{"payment_hash":"{}"}}"#, hash_hex())).expect("valid request");

        assert_eq!(request.cltv_expiry_delta, 144);
    }

    #[test]
    fn request_rejects_cltv_outside_range() {
        for cltv in [0, 143, 577] {
            let error = validate(&format!(
                r#"{{"payment_hash":"{}","min_final_cltv_expiry_delta":{cltv}}}"#,
                hash_hex()
            ))
            .expect_err("cltv outside range");

            assert!(matches!(error, payment::Error::InvalidCltvDelta), "{cltv}");
        }
    }

    #[test]
    fn duplicate_hash_status_maps_to_payment_hash_already_used() {
        let status = tonic::Status::unknown("invoice with that hash already exists (hash=07)");
        let lnd_status = tonic::Status::unknown("invoice with payment hash already exists");

        assert!(is_hash_already_used(&status));
        assert!(is_hash_already_used(&lnd_status));
        assert!(!is_hash_already_used(&tonic::Status::unknown("other")));
    }

    #[test]
    fn add_hold_invoice_request_carries_amount_and_cltv() {
        let request = validate(&format!(
            r#"{{"payment_hash":"{}","min_final_cltv_expiry_delta":432}}"#,
            hash_hex()
        ))
        .expect("valid request");

        let add_request =
            add_hold_invoice_request(&request, "swap".to_string(), &Settings::default());

        assert_eq!(add_request.hash, [7u8; 32]);
        assert_eq!(add_request.value, 10_000);
        assert_eq!(add_request.memo, "swap");
        assert_eq!(add_request.expiry, 3600);
        assert_eq!(add_request.cltv_expiry, 432);
    }

    #[test]
    fn created_extra_reports_unpaid_hold_and_request_fields() {
        let request = validate(&format!(
            r#"{{"payment_hash":"{}","min_final_cltv_expiry_delta":432}}"#,
            hash_hex()
        ))
        .expect("valid request");

        let extra = created_extra(&request, 22);

        assert_eq!(extra["hold_state"], "UNPAID");
        assert_eq!(extra["settle_deadline"], Value::Null);
        assert_eq!(extra["payment_hash"], hash_hex());
        assert_eq!(extra["min_final_cltv_expiry_delta"], 432);
    }

    #[test]
    fn request_rejects_missing_payment_hash() {
        assert!(matches!(
            validate(r#"{"min_final_cltv_expiry_delta":144}"#),
            Err(payment::Error::Custom(_))
        ));
    }

    #[test]
    fn request_rejects_bad_payment_hash() {
        assert!(matches!(
            validate(r#"{"payment_hash":"00"}"#),
            Err(payment::Error::InvalidHash)
        ));
        assert!(matches!(
            validate(&format!(r#"{{"payment_hash":"{}"}}"#, "zz".repeat(32))),
            Err(payment::Error::InvalidHash)
        ));
    }

    #[test]
    fn request_rejects_missing_extra_json() {
        assert!(matches!(
            validate_request(amount(), None, &Settings::default()),
            Err(payment::Error::Custom(_))
        ));
    }

    #[test]
    fn request_rejects_missing_amount() {
        assert!(matches!(
            validate_request(None, Some(r#"{"payment_hash":"00"}"#), &Settings::default()),
            Err(payment::Error::Custom(_))
        ));
    }

    #[test]
    fn request_rejects_zero_and_non_sat_amount() {
        let extra = format!(r#"{{"payment_hash":"{}"}}"#, hash_hex());

        assert!(matches!(
            validate_request(
                Some(Amount::new(0, CurrencyUnit::Sat)),
                Some(&extra),
                &Settings::default()
            ),
            Err(payment::Error::Custom(_))
        ));
        assert!(matches!(
            validate_request(
                Some(Amount::new(10_000, CurrencyUnit::Msat)),
                Some(&extra),
                &Settings::default()
            ),
            Err(payment::Error::UnsupportedUnit)
        ));
    }

    fn preimage_hash(preimage: [u8; 32]) -> [u8; 32] {
        sha256::Hash::hash(&preimage).to_byte_array()
    }

    fn record(state: HoldState, settle_deadline: Option<u32>) -> HoldRecord {
        HoldRecord {
            state,
            min_htlc_expiry_height: settle_deadline.map(|deadline| deadline as i32),
            settle_deadline,
        }
    }

    #[test]
    fn preimage_must_match_the_payment_hash() {
        let preimage = [1u8; 32];
        let payment_hash = preimage_hash(preimage);

        assert_eq!(
            parse_preimage(&hex::encode(preimage), &payment_hash).expect("matching preimage"),
            preimage
        );

        for wrong in [
            hex::encode([2u8; 32]),
            hex::encode([1u8; 31]),
            hex::encode([1u8; 33]),
            "zz".repeat(32),
            String::new(),
        ] {
            assert!(
                matches!(
                    parse_preimage(&wrong, &payment_hash),
                    Err(payment::Error::PreimageMismatch)
                ),
                "{wrong}"
            );
        }
    }

    #[test]
    fn settle_requires_a_held_record() {
        assert!(matches!(
            settle_decision(record(HoldState::Unpaid, None), false, None),
            Err(payment::Error::HoldNotHeld)
        ));
        assert!(matches!(
            settle_decision(record(HoldState::Cancelled, Some(100)), false, None),
            Err(payment::Error::HoldCancelled)
        ));
    }

    #[test]
    fn settle_accepts_up_to_the_deadline_height() {
        let held = record(HoldState::Held, Some(100));

        assert_eq!(
            settle_decision(held, false, Some(99)).ok(),
            Some(SettleDecision::Settle)
        );
        assert_eq!(
            settle_decision(held, false, Some(100)).ok(),
            Some(SettleDecision::Settle)
        );
        assert!(matches!(
            settle_decision(held, false, Some(101)),
            Err(payment::Error::SettleDeadlinePassed)
        ));
    }

    #[test]
    fn settle_of_a_persisted_preimage_is_not_late() {
        let held = record(HoldState::Held, Some(100));

        assert_eq!(
            settle_decision(held, true, Some(101)).ok(),
            Some(SettleDecision::Settle)
        );
        assert_eq!(
            settle_decision(held, true, None).ok(),
            Some(SettleDecision::Settle)
        );
    }

    #[test]
    fn settle_of_a_settled_record_is_idempotent() {
        assert_eq!(
            settle_decision(record(HoldState::Settled, Some(100)), false, Some(101)).ok(),
            Some(SettleDecision::AlreadySettled)
        );
        assert_eq!(
            settle_decision(record(HoldState::Settled, None), false, None).ok(),
            Some(SettleDecision::AlreadySettled)
        );
    }

    #[test]
    fn settled_record_reports_settled_and_persisted_preimage() {
        let store = SettleStore::in_memory().expect("in-memory store");
        let payment_hash = [7u8; 32];
        store
            .persist_preimage(&payment_hash, &[1u8; 32], HoldState::Settled)
            .expect("persist");

        let extra = settle_extra_json(record(HoldState::Settled, Some(100)), true);

        assert_eq!(extra["hold_state"], "SETTLED");
        assert_eq!(extra["settle_deadline"], 100);
        assert_eq!(extra["preimage_persisted"], true);
        assert_eq!(
            store.preimage(&payment_hash).expect("read"),
            Some([1u8; 32])
        );
    }

    #[test]
    fn poller_skips_records_with_a_persisted_preimage() {
        let held = record(HoldState::Held, Some(100));

        assert!(hold::should_cancel(held, false, 101));
        assert!(!hold::should_cancel(held, true, 101));
        assert!(!hold::should_cancel(held, false, 100));
        assert!(!hold::should_cancel(
            record(HoldState::Cancelled, Some(100)),
            false,
            101
        ));
    }

    #[test]
    fn cancelled_settle_errors_are_recognised() {
        assert!(is_already_cancelled(&tonic::Status::failed_precondition(
            "invoice is already canceled"
        )));
        assert!(is_already_cancelled(&tonic::Status::failed_precondition(
            "invoice already cancelled"
        )));
        assert!(!is_already_cancelled(&tonic::Status::cancelled(
            "operation cancelled"
        )));
        assert!(!is_already_cancelled(&tonic::Status::not_found(
            "unable to settle invoice: invoice not found"
        )));
        assert!(!is_already_cancelled(&tonic::Status::internal(
            "connection refused"
        )));
    }

    #[test]
    fn settled_settle_errors_are_recognised() {
        assert!(is_already_settled(&tonic::Status::failed_precondition(
            "invoice is already settled"
        )));
        assert!(!is_already_settled(&tonic::Status::failed_precondition(
            "invoice is already canceled"
        )));
        assert!(!is_already_settled(&tonic::Status::cancelled(
            "operation cancelled"
        )));
        assert!(!is_already_settled(&tonic::Status::internal(
            "connection refused"
        )));
    }

    #[test]
    fn default_settings_persist_to_a_file() {
        assert_eq!(
            Settings::default().settle_db_path,
            PathBuf::from("cdk-lnd-hold-settle.sqlite")
        );
    }
}
