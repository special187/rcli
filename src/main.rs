// rcli csv -i input.csv -o output.json --header -d ','
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use rcli::{
    get_content, get_reader, process_csv, process_decode, process_encode, process_genpass,
    process_text_key_generate, process_text_sign, process_text_verify, Base64SubCommand, Opts,
    SubCommand, TextSubCommand,
};
use std::fs;

fn main() -> Result<()> {
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
        SubCommand::GenPass(opts) => {
            let password = process_genpass(
                opts.length,
                !opts.no_upper_case,
                !opts.no_lower_case,
                !opts.no_number,
                !opts.no_symbol,
            )?;
            println!("{}", password);
            let estimate = zxcvbn::zxcvbn(&password, &[])?;
            eprintln!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(subcommand) => match subcommand {
            Base64SubCommand::Encode(opts) => {
                let encode = process_encode(&opts.input, opts.format)?;
                println!("{}", encode)
            }
            Base64SubCommand::Decode(opts) => {
                let decode = process_decode(&opts.input, opts.format)?;
                println!("{}", decode)
            }
        },
        SubCommand::Text(subcommand) => match subcommand {
            TextSubCommand::Sign(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let sign = process_text_sign(&mut reader, &key, opts.format)?;
                let encode = URL_SAFE_NO_PAD.encode(sign);
                println!("{}", encode)
            }
            TextSubCommand::Verify(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let sign = get_content(&opts.sig)?;
                let sign = URL_SAFE_NO_PAD.decode(sign)?;
                let verified = process_text_verify(&mut reader, &key, &sign, opts.format)?;
                if verified {
                    println!("✓ Signature verified");
                } else {
                    println!("⚠ Signature not verified");
                }
            }
            TextSubCommand::Generate(opts) => {
                let key = process_text_key_generate(opts.format)?;
                for (k, v) in key {
                    fs::write(opts.output_path.join(k), v)?
                }
            }
        },
    }
    Ok(())
}
