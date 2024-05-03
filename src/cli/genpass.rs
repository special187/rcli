use crate::{process_genpass, CmdExecutor};
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

impl CmdExecutor for GenPassOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let password = process_genpass(
            self.length,
            !self.no_upper_case,
            !self.no_lower_case,
            !self.no_number,
            !self.no_symbol,
        )?;
        println!("{}", password);
        let estimate = zxcvbn::zxcvbn(&password, &[])?;
        eprintln!("Password strength: {}", estimate.score());
        Ok(())
    }
}
