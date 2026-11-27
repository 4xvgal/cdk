#![allow(missing_docs)]
#[cfg(feature = "fake")]
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
#[cfg(any(
    feature = "cln",
    feature = "lnd",
    feature = "fake",
    feature = "lnd-hold"
))]
use std::sync::Arc;

#[cfg(any(
    feature = "cln",
    feature = "lnd",
    feature = "fake",
    feature = "lnd-hold"
))]
use anyhow::bail;
#[cfg(any(feature = "cln", feature = "lnd", feature = "fake"))]
use cdk_common::common::FeeReserve;
#[cfg(any(
    feature = "cln",
    feature = "lnd",
    feature = "fake",
    feature = "lnd-hold"
))]
use cdk_common::payment::{self, MintPayment};
use cdk_common::Amount;
#[cfg(feature = "fake")]
use cdk_fake_wallet::FakeWallet;
#[cfg(feature = "cln")]
use cdk_sqlite::MintSqliteDatabase;
use clap::Parser;
use serde::{Deserialize, Serialize};
#[cfg(any(
    feature = "cln",
    feature = "lnd",
    feature = "fake",
    feature = "lnd-hold"
))]
use tokio::signal;
use tracing_subscriber::EnvFilter;

/// Common CLI arguments for CDK binaries
#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// Enable logging (default is false)
    #[arg(long, default_value_t = false)]
    pub enable_logging: bool,

    /// Logging level when enabled (default is debug)
    #[arg(long, default_value = "debug")]
    pub log_level: tracing::Level,
}

/// Initialize logging based on CLI arguments
pub fn init_logging(enable_logging: bool, log_level: tracing::Level) {
    if enable_logging {
        let default_filter = log_level.to_string();

        // Common filters to reduce noise
        let sqlx_filter = "sqlx=warn";
        let hyper_filter = "hyper=warn";
        let h2_filter = "h2=warn";
        let rustls_filter = "rustls=warn";
        let reqwest_filter = "reqwest=warn";

        let env_filter = EnvFilter::new(format!(
            "{default_filter},{sqlx_filter},{hyper_filter},{h2_filter},{rustls_filter},{reqwest_filter}"
        ));

        // Ok if successful, Err if already initialized
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .try_init();
    }
}

pub const ENV_PAYMENT_BACKEND: &str = "CDK_PAYMENT_PROCESSOR_BACKEND";
pub const ENV_LISTEN_HOST: &str = "CDK_PAYMENT_PROCESSOR_LISTEN_HOST";
pub const ENV_LISTEN_PORT: &str = "CDK_PAYMENT_PROCESSOR_LISTEN_PORT";
pub const ENV_PAYMENT_PROCESSOR_TLS_DIR: &str = "CDK_PAYMENT_PROCESSOR_TLS_DIR";

// CLN
pub const ENV_CLN_RPC_PATH: &str = "CDK_PAYMENT_PROCESSOR_CLN_RPC_PATH";
pub const ENV_CLN_BOLT12: &str = "CDK_PAYMENT_PROCESSOR_CLN_BOLT12";

pub const ENV_FEE_PERCENT: &str = "CDK_PAYMENT_PROCESSOR_FEE_PERCENT";
pub const ENV_RESERVE_FEE_MIN: &str = "CDK_PAYMENT_PROCESSOR_RESERVE_FEE_MIN";

// LND environment variables
pub const ENV_LND_ADDRESS: &str = "CDK_PAYMENT_PROCESSOR_LND_ADDRESS";
pub const ENV_LND_CERT_FILE: &str = "CDK_PAYMENT_PROCESSOR_LND_CERT_FILE";
pub const ENV_LND_MACAROON_FILE: &str = "CDK_PAYMENT_PROCESSOR_LND_MACAROON_FILE";

pub const ENV_LND_HOLD_MIN_FINAL_CLTV_EXPIRY_DELTA: &str =
    "CDK_PAYMENT_PROCESSOR_LND_HOLD_MIN_FINAL_CLTV_EXPIRY_DELTA";
pub const ENV_LND_HOLD_MAX_FINAL_CLTV_EXPIRY_DELTA: &str =
    "CDK_PAYMENT_PROCESSOR_LND_HOLD_MAX_FINAL_CLTV_EXPIRY_DELTA";
pub const ENV_LND_HOLD_SETTLE_MARGIN_BLOCKS: &str =
    "CDK_PAYMENT_PROCESSOR_LND_HOLD_SETTLE_MARGIN_BLOCKS";
pub const ENV_LND_HOLD_EXPIRY_DELTA: &str = "CDK_PAYMENT_PROCESSOR_LND_HOLD_EXPIRY_DELTA";
pub const ENV_LND_HOLD_MAX_PENDING_QUOTES: &str =
    "CDK_PAYMENT_PROCESSOR_LND_HOLD_MAX_PENDING_QUOTES";
pub const ENV_LND_HOLD_INVOICE_EXPIRY_SECS: &str =
    "CDK_PAYMENT_PROCESSOR_LND_HOLD_INVOICE_EXPIRY_SECS";
pub const ENV_LND_HOLD_SETTLE_DB_PATH: &str = "CDK_PAYMENT_PROCESSOR_LND_HOLD_SETTLE_DB_PATH";

#[derive(Parser)]
#[command(name = "payment-processor")]
#[command(about = "CDK Payment Processor", long_about = None)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging based on CLI arguments
    init_logging(args.common.enable_logging, args.common.log_level);

    #[cfg(any(
        feature = "cln",
        feature = "lnd",
        feature = "fake",
        feature = "lnd-hold"
    ))]
    {
        let backend: String = env::var(ENV_PAYMENT_BACKEND)?;
        let listen_addr: String = env::var(ENV_LISTEN_HOST)?;
        let listen_port: u16 = env::var(ENV_LISTEN_PORT)?.parse()?;
        let tls_dir: Option<PathBuf> = env::var(ENV_PAYMENT_PROCESSOR_TLS_DIR)
            .ok()
            .map(PathBuf::from);

        let payment_backend: Arc<dyn MintPayment<Err = payment::Error> + Send + Sync> =
            match backend.to_uppercase().as_str() {
                #[cfg(feature = "cln")]
                "CLN" => {
                    let cln_settings = Cln::default().from_env();
                    let fee_reserve = FeeReserve {
                        min_fee_reserve: cln_settings.reserve_fee_min,
                        percent_fee_reserve: cln_settings.fee_percent,
                    };

                    let kv_store = Arc::new(MintSqliteDatabase::new(":memory:").await?);
                    Arc::new(
                        cdk_cln::Cln::new(cln_settings.rpc_path, fee_reserve, false, kv_store)
                            .await?
                            .with_bolt12(cln_settings.bolt12),
                    )
                }
                #[cfg(feature = "fake")]
                "FAKEWALLET" => {
                    use std::collections::HashMap;
                    use std::sync::Arc;

                    let fee_reserve = FeeReserve {
                        min_fee_reserve: 1.into(),
                        percent_fee_reserve: 0.0,
                    };

                    let fake_wallet = FakeWallet::new(
                        fee_reserve,
                        HashMap::default(),
                        HashSet::default(),
                        2,
                        cashu::CurrencyUnit::Sat,
                    );

                    Arc::new(fake_wallet)
                }
                #[cfg(feature = "lnd")]
                "LND" => {
                    let lnd_settings = Lnd::default().from_env();
                    let fee_reserve = FeeReserve {
                        min_fee_reserve: lnd_settings.reserve_fee_min,
                        percent_fee_reserve: lnd_settings.fee_percent,
                    };

                    let kv_store = Arc::new(MintSqliteDatabase::new(":memory:").await?);
                    Arc::new(
                        cdk_lnd::Lnd::new(
                            lnd_settings.address,
                            lnd_settings.cert_file,
                            lnd_settings.macaroon_file,
                            fee_reserve,
                            kv_store,
                        )
                        .await?,
                    )
                }

                #[cfg(feature = "lnd-hold")]
                "LND_HOLD" => {
                    let settings = lnd_hold_settings_from_env()?;
                    Arc::new(cdk_lnd_hold::LndHold::new(settings).await?)
                }

                _ => {
                    bail!("Unknown payment backend");
                }
            };

        let mut server = cdk_payment_processor::PaymentProcessorServer::new(
            payment_backend,
            &listen_addr,
            listen_port,
        )?;

        server.start(tls_dir).await?;

        // Wait for shutdown signal
        signal::ctrl_c().await?;

        server.stop().await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cln {
    pub rpc_path: PathBuf,
    #[serde(default)]
    pub bolt12: bool,
    pub fee_percent: f32,
    pub reserve_fee_min: Amount,
}

impl Cln {
    pub fn from_env(mut self) -> Self {
        // RPC Path
        if let Ok(path) = env::var(ENV_CLN_RPC_PATH) {
            self.rpc_path = PathBuf::from(path);
        }

        // BOLT12 flag
        if let Ok(bolt12_str) = env::var(ENV_CLN_BOLT12) {
            if let Ok(bolt12) = bolt12_str.parse() {
                self.bolt12 = bolt12;
            }
        }

        // Fee percent
        if let Ok(fee_str) = env::var(ENV_FEE_PERCENT) {
            if let Ok(fee) = fee_str.parse() {
                self.fee_percent = fee;
            }
        }

        // Reserve fee minimum
        if let Ok(reserve_fee_str) = env::var(ENV_RESERVE_FEE_MIN) {
            if let Ok(reserve_fee) = reserve_fee_str.parse::<u64>() {
                self.reserve_fee_min = reserve_fee.into();
            }
        }

        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Lnd {
    pub address: String,
    pub cert_file: PathBuf,
    pub macaroon_file: PathBuf,
    pub fee_percent: f32,
    pub reserve_fee_min: Amount,
}

impl Lnd {
    pub fn from_env(mut self) -> Self {
        if let Ok(address) = env::var(ENV_LND_ADDRESS) {
            self.address = address;
        }

        if let Ok(cert_path) = env::var(ENV_LND_CERT_FILE) {
            self.cert_file = PathBuf::from(cert_path);
        }

        if let Ok(macaroon_path) = env::var(ENV_LND_MACAROON_FILE) {
            self.macaroon_file = PathBuf::from(macaroon_path);
        }

        if let Ok(fee_str) = env::var(ENV_FEE_PERCENT) {
            if let Ok(fee) = fee_str.parse() {
                self.fee_percent = fee;
            }
        }

        if let Ok(reserve_fee_str) = env::var(ENV_RESERVE_FEE_MIN) {
            if let Ok(reserve_fee) = reserve_fee_str.parse::<u64>() {
                self.reserve_fee_min = reserve_fee.into();
            }
        }

        self
    }
}

#[cfg(feature = "lnd-hold")]
fn env_parsed<T: std::str::FromStr>(name: &str) -> anyhow::Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map(Some)
            .map_err(|err| anyhow::anyhow!("Invalid value for {name}: {err}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[cfg(feature = "lnd-hold")]
pub fn lnd_hold_settings_from_env() -> anyhow::Result<cdk_lnd_hold::Settings> {
    let mut settings = cdk_lnd_hold::Settings {
        address: env::var(ENV_LND_ADDRESS).unwrap_or_default(),
        cert_file: env::var(ENV_LND_CERT_FILE)
            .map(PathBuf::from)
            .unwrap_or_default(),
        macaroon_file: env::var(ENV_LND_MACAROON_FILE)
            .map(PathBuf::from)
            .unwrap_or_default(),
        ..Default::default()
    };

    settings.min_final_cltv_expiry_delta = env_parsed(ENV_LND_HOLD_MIN_FINAL_CLTV_EXPIRY_DELTA)?
        .unwrap_or(settings.min_final_cltv_expiry_delta);
    settings.max_final_cltv_expiry_delta = env_parsed(ENV_LND_HOLD_MAX_FINAL_CLTV_EXPIRY_DELTA)?
        .unwrap_or(settings.max_final_cltv_expiry_delta);
    settings.settle_margin_blocks =
        env_parsed(ENV_LND_HOLD_SETTLE_MARGIN_BLOCKS)?.unwrap_or(settings.settle_margin_blocks);
    settings.lnd_hold_expiry_delta =
        env_parsed(ENV_LND_HOLD_EXPIRY_DELTA)?.unwrap_or(settings.lnd_hold_expiry_delta);
    settings.max_pending_quotes =
        env_parsed(ENV_LND_HOLD_MAX_PENDING_QUOTES)?.unwrap_or(settings.max_pending_quotes);
    settings.invoice_expiry_secs =
        env_parsed(ENV_LND_HOLD_INVOICE_EXPIRY_SECS)?.unwrap_or(settings.invoice_expiry_secs);
    settings.settle_db_path = env::var(ENV_LND_HOLD_SETTLE_DB_PATH)
        .map(PathBuf::from)
        .unwrap_or(settings.settle_db_path);

    Ok(settings)
}
