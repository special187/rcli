// rcli csv -i input.csv -o output.json --header -d ','
use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, Base64SubCommand, Opts,
    SubCommand,
};

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };

            process_csv(&opts.input, output, opts.format)?
        }
        SubCommand::GenPass(opts) => process_genpass(
            opts.length,
            !opts.no_upper_case,
            !opts.no_lower_case,
            !opts.no_number,
            !opts.no_symbol,
        )?,
        SubCommand::Base64(subcommand) => match subcommand {
            Base64SubCommand::Encode(opts) => process_encode(&opts.input, opts.format)?,
            Base64SubCommand::Decode(opts) => process_decode(&opts.input, opts.format)?,
        },
    }
    Ok(())
}
