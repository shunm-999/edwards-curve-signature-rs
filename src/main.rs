use crate::cli::{Args, ReadMessage};
use clap::Parser;
use std::io;
mod algorithm;
mod cli;
mod signer;

fn main() -> io::Result<()> {
    let args: Args = Args::parse();

    match args.subcommand {
        cli::SubCommands::Sign {
            message_file_path,
            secret_file_path,
        } => {
            let message_reader = match message_file_path {
                Some(ref path) => cli::MessageReader::File(path.clone()),
                None => cli::MessageReader::Stdin,
            };

            let message = message_reader.read_message()?;

            let message = String::from_utf8(message).unwrap();
            println!("Signing message: {}", message);
        }
    }

    Ok(())
}
