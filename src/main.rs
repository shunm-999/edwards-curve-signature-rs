use crate::cli::{Args, ReadMessage, ReadSecret};
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
            let secret_reader = if secret_file_path.ends_with(".pem") {
                cli::SecretReader::PemFile(secret_file_path)
            } else {
                unimplemented!("Only PEM secret files are supported");
            };

            let message = message_reader.read_message()?;
            let secret = secret_reader.read_secret()?;

            let message = String::from_utf8(message).unwrap();
            println!("Signing message: {}", message);
        }
    }

    Ok(())
}
