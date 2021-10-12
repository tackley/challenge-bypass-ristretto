use std::collections::HashMap;
use std::fs::File;
use std::io::LineWriter;
use std::io::Write;
use std::sync::mpsc;

use anyhow::{anyhow, Context, Result};
use hmac::Hmac;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use sha2::Sha512;
use structopt::StructOpt;

use challenge_bypass_ristretto::voprf::*;

type HmacSha512 = Hmac<Sha512>;

static KEYS: OnceCell<HashMap<String, SigningKey>> = OnceCell::new();

/// Process challenge bypass token redemptions from an input file and output result files
#[derive(StructOpt)]
struct Cli {
    /// The input file to read
    #[structopt(parse(from_os_str))]
    input: std::path::PathBuf,

    /// One or more issuer keys to check redemptions against
    #[structopt(short, long, env = "KEYS", use_delimiter = true, required = true)]
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialColumn {
    public_key: String,
    credential: Credential,
    value: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credential {
    t: TokenPreimage,
    payload: String,
    signature: VerificationSignature,
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    payment_id: String,
    #[serde(deserialize_with = "deserialize_json_string_credentialcolumn")]
    credential: CredentialColumn,
    timestamp: String,
}

fn deserialize_json_string_credentialcolumn<'de, D>(
    deserializer: D,
) -> Result<CredentialColumn, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
    let s = &s.replace("\\,", ",").replace("\\\\", "\\");
    serde_json::from_str(s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
struct OutRecord {
    id: String,
    payment_id: String,
    timestamp: String,
}

fn main() -> Result<()> {
    let args = Cli::from_args();

    let keys: HashMap<String, SigningKey> = args
        .keys
        .iter()
        .map::<Result<(String, SigningKey)>, _>(|k| {
            let key = SigningKey::decode_base64(k)?;
            Ok((key.public_key.encode_base64(), key))
        })
        .collect::<Result<HashMap<String, SigningKey>>>()
        .with_context(|| format!("Failed to decode all issuer keys"))?;
    KEYS.set(keys).unwrap();

    let mut success_file = args.input.clone();
    success_file.set_extension("success");
    let mut failure_file = args.input.clone();
    failure_file.set_extension("error");

    let file = File::open(args.input).with_context(|| format!("Could not read input csv"))?;
    let mut reader = csv::ReaderBuilder::new().delimiter(b';').from_reader(file);

    // Will set number of threads based on CPU count
    let pool = threadpool::Builder::new().build();
    let (tx, rx) = mpsc::channel();

    let mut num_jobs = 0;
    for line in reader.deserialize() {
        num_jobs += 1;
        let tx = tx.clone();
        let keys: &'static HashMap<String, SigningKey> =
            KEYS.get().expect("keys is not initialized");
        pool.execute(move || {
            let record: Record = line.expect("Invalid record format");
            let out = OutRecord {
                id: record.id.clone(),
                payment_id: record.payment_id.clone(),
                timestamp: record.timestamp.clone(),
            };

            let result = (move || {
                let issuer = keys
                    .get(&record.credential.public_key)
                    .with_context(|| format!("Could not find issuer"))?;

                let server_unblinded_token =
                    issuer.rederive_unblinded_token(&record.credential.credential.t);
                let server_verification_key =
                    server_unblinded_token.derive_verification_key::<Sha512>();
                if server_verification_key.verify::<HmacSha512>(
                    &record.credential.credential.signature,
                    record.credential.credential.payload.as_bytes(),
                ) {
                    Ok(())
                } else {
                    Err(anyhow!("Did not validate"))
                }
            })();
            tx.send((result, out))
                .expect("channel will be there waiting for the pool");
        });
    }

    println!("started {} jobs", num_jobs);

    let mut success_file = LineWriter::new(File::create(success_file)?);
    let mut failure_file = LineWriter::new(File::create(failure_file)?);

    for (result, record) in rx.iter().take(num_jobs) {
        let r = format!("{},{},{}\n", record.id, record.payment_id, record.timestamp);
        match result {
            Ok(_) => success_file.write_all(r.as_bytes())?,
            Err(_) => failure_file.write_all(r.as_bytes())?,
        }
    }

    println!("wrote out {} job results", num_jobs);

    Ok(())
}
