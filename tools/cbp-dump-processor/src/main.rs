use std::io;

use anyhow::Result;

use csv::StringRecord;

use challenge_bypass_ristretto::voprf::*;

/*
    very basic code to augment a issuer dump from cbp with the public key

    to create the dump:
    - in psql `\copy (SELECT * from issurs) TO dump.csv CSV DELIMITER ','`

    then
    - `cargo run <dump.csv >dump2.csv`

    ensure you remove all copies of the csv files containing the private key!
*/

fn main() -> Result<()> {
    // take the input file and parse it
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(io::stdin());

    let mut wrt = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(io::stdout());

    for result in rdr.records() {
        let record: StringRecord = result?;

        let private_key = record.get(1).expect("failed to read private key");

        let public_key = SigningKey::decode_base64(private_key)?
            .public_key
            .encode_base64();

        let mut updated_record = record.clone();
        updated_record.push_field(&public_key);
        wrt.write_record(&updated_record)?
    }
    Ok(())
}
