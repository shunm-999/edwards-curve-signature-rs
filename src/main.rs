use crate::cli::{
    Args, MessageReader, ReadMessage, ReadSecret, SecretReader, SignatureWriter, SubCommands,
    WriteSignature,
};
use crate::signer::{EdDsaSignature, SignatureAlgorithm, Signer};
use clap::Parser;
use std::io;

mod algorithm;
mod cli;
mod signer;

fn main() -> io::Result<()> {
    let args: Args = Args::parse();

    match args.subcommand {
        SubCommands::Sign {
            message_file_path,
            secret_file_path,
            output_file_path,
        } => {
            let signer = EdDsaSignature::new(SignatureAlgorithm::Ed25519);

            let message_reader = match message_file_path {
                Some(ref path) => MessageReader::File(path.clone()),
                None => MessageReader::Stdin,
            };
            let secret_reader = if secret_file_path.ends_with(".pem") {
                SecretReader::PemFile(secret_file_path)
            } else {
                unimplemented!("Only PEM secret files are supported");
            };
            let signature_writer = match output_file_path {
                Some(ref path) => SignatureWriter::File(path.clone()),
                None => SignatureWriter::Stdout,
            };

            let message = message_reader.read_message()?;
            let secret = secret_reader.read_secret()?;

            let signature = signer.sign(&secret, &message).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "Failed to sign the message")
            })?;

            signature_writer.write_signature(&signature)?;
        }
    }

    Ok(())
}
