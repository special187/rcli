use crate::cli::OutputFormat;
use anyhow::Result;
use csv::Reader;
use serde_json::Value;
use std::fs;

pub fn process_csv(input: &str, output: String, format: OutputFormat) -> Result<()> {
    let mut reader = Reader::from_path(input)?;
    let mut ret = Vec::with_capacity(128);
    let headers = reader.headers()?.clone();
    for result in reader.records() {
        let record = result?;
        let deserialize_value = headers.iter().zip(record.iter()).collect::<Value>();
        ret.push(deserialize_value);
    }
    let content = match format {
        OutputFormat::Json => serde_json::to_string(&ret)?,
        OutputFormat::Yaml => serde_json::to_string(&ret)?,
    };
    fs::write(output, content)?;
    Ok(())
}
