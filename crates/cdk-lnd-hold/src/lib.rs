#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;

use async_trait::async_trait;
use cdk_common::bitcoin::hashes::Hash;
use cdk_common::payment::{
    self, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse,
    MintPayment, OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse, SettingsResponse,
    WaitPaymentResponse,
};
use cdk_common::util::hex;
use cdk_common::{Amount, Bolt11Invoice, CurrencyUnit};
use cdk_lnd::{client, invoicesrpc, lnrpc};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tonic::{Code, Request};
use tracing::instrument;

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
    /// Maximum number of unpaid and held quotes
    pub max_pending_quotes: u32,
    /// Hold invoice expiry in seconds
    pub invoice_expiry_secs: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            address: String::new(),
            cert_file: PathBuf::new(),
            macaroon_file: PathBuf::new(),
            min_final_cltv_expiry_delta: 144,
            max_final_cltv_expiry_delta: 576,
            settle_margin_blocks: 12,
            max_pending_quotes: 100,
            invoice_expiry_secs: 3600,
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
        })
    }
}

/// NUT-XX hold state of a quote
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    /// No HTLCs, or HTLCs not summing to the amount, have been accepted
    Unpaid,
    /// HTLCs summing to the amount are accepted and not resolved
    Held,
    /// The HTLCs were settled with the preimage
    Settled,
    /// The held HTLCs were cancelled
    Cancelled,
}

impl HoldState {
    /// NUT-XX string form
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unpaid => "UNPAID",
            Self::Held => "HELD",
            Self::Settled => "SETTLED",
            Self::Cancelled => "CANCELLED",
        }
    }

    fn from_invoice_state(state: lnrpc::invoice::InvoiceState) -> Self {
        match state {
            lnrpc::invoice::InvoiceState::Open => Self::Unpaid,
            lnrpc::invoice::InvoiceState::Accepted => Self::Held,
            lnrpc::invoice::InvoiceState::Settled => Self::Settled,
            lnrpc::invoice::InvoiceState::Canceled => Self::Cancelled,
        }
    }
}

/// Hold state and timing of an LND hold invoice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldStatus {
    /// NUT-XX hold state
    pub state: HoldState,
    /// Lowest `expiry_height` over accepted HTLCs
    pub min_htlc_expiry_height: Option<i32>,
}

impl HoldStatus {
    /// Map an LND invoice to a hold status
    pub fn from_invoice(invoice: &lnrpc::Invoice) -> Self {
        Self {
            state: HoldState::from_invoice_state(invoice.state()),
            min_htlc_expiry_height: invoice
                .htlcs
                .iter()
                .filter(|htlc| htlc.state() == lnrpc::InvoiceHtlcState::Accepted)
                .map(|htlc| htlc.expiry_height)
                .min(),
        }
    }

    /// Extra JSON fields describing the hold
    pub fn extra_json(self) -> Value {
        json!({
            "hold_state": self.state.as_str(),
            "min_htlc_expiry_height": self.min_htlc_expiry_height,
        })
    }

    /// `true` once LND has settled the invoice
    pub fn is_settled(self) -> bool {
        self.state == HoldState::Settled
    }
}

#[derive(Debug)]
struct HoldInvoiceRequest {
    payment_hash: [u8; 32],
    amount_sat: u64,
    cltv_expiry_delta: u32,
}

#[derive(Debug, Deserialize)]
struct ExtraFields {
    payment_hash: Option<String>,
    #[serde(default)]
    min_final_cltv_expiry_delta: Option<u32>,
}

fn invalid(message: &str) -> payment::Error {
    payment::Error::Custom(message.to_string())
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
        return Err(invalid(
            "min_final_cltv_expiry_delta outside of allowed range",
        ));
    }

    Ok(HoldInvoiceRequest {
        payment_hash,
        amount_sat: amount.value(),
        cltv_expiry_delta,
    })
}

fn payment_hash_from_identifier(
    payment_identifier: &PaymentIdentifier,
) -> Result<[u8; 32], payment::Error> {
    hex::decode(payment_identifier.to_string())
        .map_err(|_| payment::Error::InvalidHash)?
        .try_into()
        .map_err(|_| payment::Error::InvalidHash)
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
    client: client::Client,
    settings: Settings,
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
        let client = client::connect(
            &settings.address,
            &settings.cert_file,
            &settings.macaroon_file,
        )
        .await
        .map_err(|err| invalid(&format!("LND connection error: {err}")))?;

        Ok(Self { client, settings })
    }

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

        let add_request = add_hold_invoice_request(
            &request,
            options.description.unwrap_or_default(),
            &self.settings,
        );

        let mut client = self.client.clone();
        let response = client
            .invoices()
            .add_hold_invoice(Request::new(add_request))
            .await
            .map_err(|status| invalid(&format!("LND AddHoldInvoice failed: {status}")))?
            .into_inner();

        let bolt11 = Bolt11Invoice::from_str(&response.payment_request)?;

        if bolt11.payment_hash().as_byte_array() != &request.payment_hash {
            return Err(payment::Error::InvalidHash);
        }

        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: PaymentIdentifier::PaymentHash(request.payment_hash),
            expiry: bolt11.expires_at().map(|time| time.as_secs()),
            request: bolt11.to_string(),
            extra_json: Some(json!({
                "payment_hash": hex::encode(request.payment_hash),
                "min_final_cltv_expiry_delta": request.cltv_expiry_delta,
            })),
        })
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
        Err(payment::Error::UnsupportedPaymentOption)
    }

    fn is_payment_event_stream_active(&self) -> bool {
        false
    }

    fn cancel_payment_event_stream(&self) {}

    #[instrument(skip(self))]
    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        let payment_hash = payment_hash_from_identifier(payment_identifier)?;

        let Some(invoice) = self.lookup_invoice(&payment_hash).await? else {
            return Ok(Vec::new());
        };

        let status = HoldStatus::from_invoice(&invoice);

        tracing::debug!(
            payment_hash = %payment_identifier,
            hold_state = status.state.as_str(),
            min_htlc_expiry_height = ?status.min_htlc_expiry_height,
            "checked LND hold invoice",
        );

        if !status.is_settled() {
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

        let status = match self.lookup_invoice(&payment_hash).await? {
            Some(invoice) => HoldStatus::from_invoice(&invoice),
            None => HoldStatus {
                state: HoldState::Unpaid,
                min_htlc_expiry_height: None,
            },
        };

        Ok(Some(status.extra_json()))
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

    fn hash_hex() -> String {
        hex::encode([7u8; 32])
    }

    fn invoice(
        state: lnrpc::invoice::InvoiceState,
        htlcs: Vec<lnrpc::InvoiceHtlc>,
    ) -> lnrpc::Invoice {
        lnrpc::Invoice {
            state: state as i32,
            htlcs,
            ..Default::default()
        }
    }

    fn htlc(state: lnrpc::InvoiceHtlcState, expiry_height: i32) -> lnrpc::InvoiceHtlc {
        lnrpc::InvoiceHtlc {
            state: state as i32,
            expiry_height,
            ..Default::default()
        }
    }

    #[test]
    fn settings_expose_hold_options() {
        let options = Settings::default().options_json();

        assert_eq!(options["min_final_cltv_expiry_delta"], 144);
        assert_eq!(options["max_final_cltv_expiry_delta"], 576);
        assert_eq!(options["settle_margin_blocks"], 12);
        assert_eq!(options["max_pending_quotes"], 100);
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

            assert!(
                matches!(error, payment::Error::Custom(ref message) if message.contains("allowed range")),
                "{cltv}"
            );
        }
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

    #[test]
    fn open_invoice_is_unpaid() {
        let status =
            HoldStatus::from_invoice(&invoice(lnrpc::invoice::InvoiceState::Open, Vec::new()));

        assert_eq!(status.state, HoldState::Unpaid);
        assert_eq!(status.state.as_str(), "UNPAID");
        assert_eq!(status.min_htlc_expiry_height, None);
        assert!(!status.is_settled());
    }

    #[test]
    fn accepted_invoice_is_held_with_lowest_accepted_expiry() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Accepted,
            vec![
                htlc(lnrpc::InvoiceHtlcState::Accepted, 120),
                htlc(lnrpc::InvoiceHtlcState::Accepted, 100),
                htlc(lnrpc::InvoiceHtlcState::Settled, 50),
            ],
        ));

        assert_eq!(status.state, HoldState::Held);
        assert_eq!(status.state.as_str(), "HELD");
        assert_eq!(status.min_htlc_expiry_height, Some(100));
        assert!(!status.is_settled());
    }

    #[test]
    fn accepted_invoice_without_accepted_htlcs_has_no_expiry() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Accepted,
            vec![htlc(lnrpc::InvoiceHtlcState::Canceled, 100)],
        ));

        assert_eq!(status.state, HoldState::Held);
        assert_eq!(status.min_htlc_expiry_height, None);
    }

    #[test]
    fn settled_invoice_is_settled() {
        let status = HoldStatus::from_invoice(&invoice(
            lnrpc::invoice::InvoiceState::Settled,
            vec![htlc(lnrpc::InvoiceHtlcState::Settled, 100)],
        ));

        assert_eq!(status.state, HoldState::Settled);
        assert_eq!(status.state.as_str(), "SETTLED");
        assert!(status.is_settled());
    }

    #[test]
    fn canceled_invoice_is_cancelled() {
        let status =
            HoldStatus::from_invoice(&invoice(lnrpc::invoice::InvoiceState::Canceled, Vec::new()));

        assert_eq!(status.state, HoldState::Cancelled);
        assert_eq!(status.state.as_str(), "CANCELLED");
        assert!(!status.is_settled());
    }

    #[test]
    fn hold_status_extra_json_reports_state_and_expiry() {
        let status = HoldStatus {
            state: HoldState::Held,
            min_htlc_expiry_height: Some(870_420),
        };

        assert_eq!(
            status.extra_json(),
            json!({"hold_state": "HELD", "min_htlc_expiry_height": 870_420})
        );
    }
}
