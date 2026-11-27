#![allow(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;

use cdk::amount::SplitTarget;
use cdk::error::Error;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{CurrencyUnit, PaymentMethod, SecretKey};
use cdk::wallet::Wallet;
use cdk_sqlite::wallet::memory;
use rand::random;

fn argument(args: &[String], index: usize, name: &str) -> Result<String, Error> {
    args.get(index)
        .cloned()
        .ok_or_else(|| Error::Custom(format!("missing argument {name}")))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("pubkey") => {
            let secret_key = SecretKey::from_hex(argument(&args, 2, "secret_key")?)?;
            println!("{}", secret_key.public_key().to_hex());
        }
        Some("mint") => {
            let mint_url = argument(&args, 2, "mint_url")?;
            let quote_id = argument(&args, 3, "quote_id")?;
            let secret_key = SecretKey::from_hex(argument(&args, 4, "secret_key")?)?;

            let localstore = Arc::new(memory::empty().await?);
            let wallet = Wallet::new(
                &mint_url,
                CurrencyUnit::Sat,
                localstore,
                random::<[u8; 64]>(),
                None,
            )?;

            let method = PaymentMethod::Custom("bolt11_hold".to_string());
            let quote = wallet.fetch_mint_quote(&quote_id, Some(method)).await?;
            println!(
                "quote {} state {} amount_paid {}",
                quote.id, quote.state, quote.amount_paid
            );

            let proofs = wallet
                .batch_mint(
                    &[quote_id.as_str()],
                    SplitTarget::default(),
                    None,
                    Some(HashMap::from([(quote_id.clone(), secret_key)])),
                )
                .await?;
            println!(
                "minted {} sat in {} proofs",
                proofs.total_amount()?,
                proofs.len()
            );
        }
        _ => {
            return Err(Error::Custom(
                "usage: bolt11-hold-mint pubkey <secret_key_hex> | mint <mint_url> <quote_id> <secret_key_hex>"
                    .to_string(),
            ));
        }
    }

    Ok(())
}
