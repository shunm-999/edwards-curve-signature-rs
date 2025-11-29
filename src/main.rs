use crate::cli::Args;
use clap::Parser;
mod algorithm;
mod cli;
mod signer;

fn main() {
    let args: Args = Args::parse();

    match args.subcommand {
        cli::SubCommands::Sign { message } => {
            if let Some(msg) = message {
                println!("Signing message: {}", msg);
                // Here you would add the logic to sign the message
            } else {
                println!("No message provided to sign.");
            }
        }
    }
}
