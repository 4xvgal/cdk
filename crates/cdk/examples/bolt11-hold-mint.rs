#![allow(missing_docs)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hex::{DisplayHex, FromHex};
use cdk::amount::SplitTarget;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{CurrencyUnit, PaymentMethod, SecretKey};
use cdk::wallet::{MintQuote, Wallet};
use cdk::{Amount, Bolt11Invoice};
use cdk_sqlite::WalletSqliteDatabase;
use rand::random;
use serde_json::{json, Value};
use ureq::Agent;

const METHOD: &str = "bolt11_hold";
const DEFAULT_CLTV: u32 = 432;

type CliResult<T> = Result<T, Box<dyn Error>>;

fn argument(args: &[String], index: usize, name: &str) -> CliResult<String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing argument {name}").into())
}

fn option(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1).cloned())
}

fn wallet_dir() -> PathBuf {
    match std::env::var_os("BOLT11_HOLD_CLI_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(".cache/cdk-bolt11-hold"),
    }
}

fn seed(dir: &Path) -> CliResult<[u8; 64]> {
    fs::create_dir_all(dir)?;
    let path = dir.join("seed");
    let hex = match fs::read_to_string(&path) {
        Ok(hex) => hex,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let hex = random::<[u8; 64]>().to_lower_hex_string();
            fs::write(&path, &hex)?;
            hex
        }
        Err(e) => return Err(format!("{}: {e}", path.display()).into()),
    };
    Ok(<[u8; 64]>::from_hex(hex.trim()).map_err(|e| e.to_string())?)
}

async fn localstore(dir: &Path) -> CliResult<Arc<WalletSqliteDatabase>> {
    fs::create_dir_all(dir)?;
    Ok(Arc::new(
        WalletSqliteDatabase::new(dir.join("wallet.sqlite")).await?,
    ))
}

async fn open_wallet(mint_url: &str, store: Arc<WalletSqliteDatabase>) -> CliResult<Wallet> {
    Ok(Wallet::new(
        mint_url,
        CurrencyUnit::Sat,
        store,
        seed(&wallet_dir())?,
        None,
    )?)
}

async fn stored_quote(quote_id: &str) -> CliResult<(MintQuote, Arc<WalletSqliteDatabase>)> {
    let store = localstore(&wallet_dir()).await?;
    let quote = store
        .get_mint_quote(quote_id)
        .await?
        .ok_or_else(|| format!("unknown quote {quote_id}"))?;
    Ok((quote, store))
}

fn quote_url(quote: &MintQuote, suffix: Option<&str>) -> CliResult<String> {
    let method = quote.payment_method.to_string();
    let mut elements = vec!["v1", "mint", "quote", method.as_str(), quote.id.as_str()];
    if let Some(suffix) = suffix {
        elements.push(suffix);
    }
    Ok(quote.mint_url.join_paths(&elements)?.to_string())
}

fn hold_fields(body: &Value, quote_id: &str) -> Value {
    json!({
        "quote": body.get("quote").cloned().unwrap_or_else(|| json!(quote_id)),
        "hold_state": body.get("hold_state"),
        "settle_deadline": body.get("settle_deadline"),
        "amount_paid": body.get("amount_paid"),
    })
}

fn agent() -> Agent {
    Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build(),
    )
}

fn read(response: ureq::http::Response<ureq::Body>) -> CliResult<Value> {
    let status = response.status().as_u16();
    let body: Value = response.into_body().read_json().unwrap_or(Value::Null);
    if status >= 400 {
        let error = json!({
            "http_status": status,
            "code": body.get("code"),
            "error": body,
        });
        return Err(error.to_string().into());
    }
    Ok(body)
}

fn get(url: &str) -> CliResult<Value> {
    let response = agent()
        .get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    read(response)
}

fn post(url: &str, body: &Value) -> CliResult<Value> {
    let response = agent()
        .post(url)
        .send_json(body)
        .map_err(|e| format!("POST {url}: {e}"))?;
    read(response)
}

fn verify_invoice(request: &str, payment_hash: &str, amount: Amount, cltv: u32) -> CliResult<()> {
    let invoice = Bolt11Invoice::from_str(request).map_err(|e| format!("invalid bolt11: {e}"))?;

    let hash = invoice.payment_hash().to_string();
    if hash != payment_hash {
        return Err(
            format!("bolt11 payment_hash {hash} does not match requested {payment_hash}").into(),
        );
    }

    let expected_msat = amount
        .to_u64()
        .checked_mul(1000)
        .ok_or("requested amount overflows millisatoshis")?;
    match invoice.amount_milli_satoshis() {
        Some(msat) if msat == expected_msat => {}
        other => {
            return Err(format!(
                "bolt11 amount {other:?} msat does not match requested {expected_msat} msat"
            )
            .into())
        }
    }

    let delta = invoice.min_final_cltv_expiry_delta();
    if delta != u64::from(cltv) {
        return Err(
            format!("bolt11 final CLTV delta {delta} does not match requested {cltv}").into(),
        );
    }

    Ok(())
}

fn quote_extra(payment_hash: &str, cltv: u32, lockup_script: Option<&str>) -> Value {
    let mut extra = json!({
        "payment_hash": payment_hash,
        "min_final_cltv_expiry_delta": cltv,
    });
    if let Some(script) = lockup_script {
        extra["lockup"] = json!({ "script": script.to_lowercase() });
    }
    extra
}

async fn quote(args: &[String]) -> CliResult<()> {
    let mint_url = argument(args, 1, "mint_url")?;
    let payment_hash = argument(args, 2, "payment_hash")?.to_lowercase();
    let amount = Amount::from(argument(args, 3, "amount")?.parse::<u64>()?);
    let cltv = match option(args, "--cltv") {
        Some(cltv) => cltv.parse::<u32>()?,
        None => DEFAULT_CLTV,
    };
    let lockup_script = option(args, "--lockup-script");

    let store = localstore(&wallet_dir()).await?;
    let wallet = open_wallet(&mint_url, store).await?;
    let extra = quote_extra(&payment_hash, cltv, lockup_script.as_deref());
    let quote = wallet
        .mint_quote(
            PaymentMethod::Custom(METHOD.to_string()),
            Some(amount),
            None,
            Some(extra.to_string()),
        )
        .await?;

    verify_invoice(&quote.request, &payment_hash, amount, cltv)?;

    println!(
        "{}",
        json!({
            "quote": quote.id,
            "bolt11": quote.request,
            "payment_hash": payment_hash,
            "expiry": quote.expiry,
        })
    );
    Ok(())
}

async fn status(args: &[String]) -> CliResult<()> {
    let quote_id = argument(args, 1, "quote")?;
    let (quote, _) = stored_quote(&quote_id).await?;
    let body = get(&quote_url(&quote, None)?)?;
    println!("{}", hold_fields(&body, &quote_id));
    Ok(())
}

async fn settle(args: &[String]) -> CliResult<()> {
    let quote_id = argument(args, 1, "quote")?;
    let preimage = argument(args, 2, "preimage")?;
    let (quote, _) = stored_quote(&quote_id).await?;
    let body = post(
        &quote_url(&quote, Some("settle"))?,
        &json!({ "preimage": preimage }),
    )?;
    println!("{}", hold_fields(&body, &quote_id));
    Ok(())
}

async fn mint(args: &[String]) -> CliResult<()> {
    let quote_id = argument(args, 1, "quote")?;
    let (quote, store) = stored_quote(&quote_id).await?;
    let wallet = open_wallet(&quote.mint_url.to_string(), store).await?;

    let proofs = wallet.mint(&quote_id, SplitTarget::default(), None).await?;
    let amount = proofs.total_amount()?;

    println!(
        "{}",
        json!({
            "quote": quote_id,
            "amount": amount.to_u64(),
            "proofs": proofs,
        })
    );
    Ok(())
}

async fn dispatch(args: &[String]) -> CliResult<()> {
    match args.first().map(String::as_str) {
        Some("pubkey") => {
            let secret_key = SecretKey::from_hex(&argument(args, 1, "secret_key")?)?;
            println!("{}", secret_key.public_key().to_hex());
            Ok(())
        }
        Some("quote") => quote(args).await,
        Some("status") => status(args).await,
        Some("settle") => settle(args).await,
        Some("mint") => mint(args).await,
        _ => Err(
            "usage: quote <mint_url> <payment_hash> <amount> [--cltv 432] \
                  [--lockup-script <hex>] | status <quote> | settle <quote> <preimage> | \
                  mint <quote> | pubkey <secret_key_hex>"
                .into(),
        ),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = dispatch(&args).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

    use super::*;

    const PAYMENT_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const AMOUNT_SAT: u64 = 10_000;
    const CLTV: u32 = 432;

    fn invoice(amount_msat: u64, cltv: u64, payment_hash: [u8; 32]) -> String {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[42; 32]).expect("static test key");
        InvoiceBuilder::new(Currency::Regtest)
            .description("bolt11 hold".to_string())
            .payment_hash(sha256::Hash::from_byte_array(payment_hash))
            .payment_secret(PaymentSecret([21; 32]))
            .duration_since_epoch(Duration::from_secs(1_700_000_000))
            .min_final_cltv_expiry_delta(cltv)
            .amount_milli_satoshis(amount_msat)
            .build_signed(|message: &Message| secp.sign_ecdsa_recoverable(message, &key))
            .expect("test invoice")
            .to_string()
    }

    fn requested_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[31] = 1;
        hash
    }

    #[test]
    fn accepts_matching_invoice() {
        let request = invoice(AMOUNT_SAT * 1000, CLTV.into(), requested_hash());
        assert!(verify_invoice(&request, PAYMENT_HASH, Amount::from(AMOUNT_SAT), CLTV).is_ok());
    }

    #[test]
    fn rejects_other_payment_hash() {
        let request = invoice(AMOUNT_SAT * 1000, CLTV.into(), [2u8; 32]);
        assert!(verify_invoice(&request, PAYMENT_HASH, Amount::from(AMOUNT_SAT), CLTV).is_err());
    }

    #[test]
    fn rejects_other_amount() {
        let request = invoice(AMOUNT_SAT * 1000 + 1000, CLTV.into(), requested_hash());
        assert!(verify_invoice(&request, PAYMENT_HASH, Amount::from(AMOUNT_SAT), CLTV).is_err());
    }

    #[test]
    fn rejects_other_cltv() {
        let request = invoice(AMOUNT_SAT * 1000, 144, requested_hash());
        assert!(verify_invoice(&request, PAYMENT_HASH, Amount::from(AMOUNT_SAT), CLTV).is_err());
    }

    #[test]
    fn extra_carries_the_lockup_script_when_given() {
        let extra = quote_extra(PAYMENT_HASH, CLTV, Some("8201AB"));
        assert_eq!(extra["lockup"]["script"], json!("8201ab"));
        assert_eq!(extra["payment_hash"], json!(PAYMENT_HASH));
        assert_eq!(extra["min_final_cltv_expiry_delta"], json!(CLTV));
    }

    #[test]
    fn extra_has_no_lockup_without_a_script() {
        let extra = quote_extra(PAYMENT_HASH, CLTV, None);
        assert!(extra.get("lockup").is_none());
    }

    #[test]
    fn rejects_invalid_invoice() {
        assert!(
            verify_invoice("lnbc1garbage", PAYMENT_HASH, Amount::from(AMOUNT_SAT), CLTV).is_err()
        );
    }
}
