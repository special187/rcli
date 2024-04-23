use clap::Parser;

#[derive(Debug, Parser)]
pub struct GenPassOpts {
    #[arg(short, long, default_value_t = 16)]
    pub length: u8,

    #[arg(long)]
    pub no_upper_case: bool,

    #[arg(long)]
    pub no_lower_case: bool,

    #[arg(long)]
    pub no_number: bool,

    #[arg(long)]
    pub no_symbol: bool,
}
