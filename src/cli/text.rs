use super::verify_file;
use clap::Parser;
use std::{fmt, str::FromStr};
#[derive(Debug, Parser)]
pub enum TextSubCommand {
    #[command(about = "Sign a message with a private/shared key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a signed message")]
    Verify(TextVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser=verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, value_parser = parse_format, default_value = "blake3")]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser=verify_file, default_value = "-")]
    pub input: String,

    #[arg(long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, value_parser = parse_format, default_value = "blake3")]
    pub format: TextSignFormat,
    #[arg(short, long)]
    pub sig: String,
}
#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parse_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(Self::Blake3),
            "ed25519" => Ok(Self::Ed25519),
            _ => anyhow::bail!("Invalid format {}", s),
        }
    }
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blake3 => write!(f, "blake3"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}