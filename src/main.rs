use crate::cli::{
    Args, Base64TextReader, Base64TextWriter, PlainTextReader, ReadBase64, ReadPlainText,
    ReadSecret, SecretReader, SubCommands, WriteBase64Text, WriteSignature,
};
use crate::signer::{EdDsaSignature, GeneratePublicKey, Sign, SignatureAlgorithm, Verify};
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
            sign(message_file_path, secret_file_path, output_file_path)?;
        }
        SubCommands::GeneratePublicKey {
            secret_file_path,
            output_file_path,
        } => {
            generate_public_key(secret_file_path, output_file_path)?;
        }
        SubCommands::Verify {
            message_file_path,
            public_key_file_path,
            signature_file_path,
        } => {
            verify(message_file_path, public_key_file_path, signature_file_path)?;
        }
    }

    Ok(())
}

fn sign(
    message_file_path: Option<String>,
    secret_file_path: String,
    output_file_path: Option<String>,
) -> io::Result<()> {
    let signer = EdDsaSignature::new(SignatureAlgorithm::Ed25519);

    let message_reader = match message_file_path {
        Some(ref path) => PlainTextReader::File(path.clone()),
        None => PlainTextReader::Stdin,
    };
    let secret_reader = if secret_file_path.ends_with(".pem") {
        SecretReader::PemFile(secret_file_path)
    } else {
        unimplemented!("Only PEM secret files are supported");
    };
    let signature_writer = match output_file_path {
        Some(ref path) => Base64TextWriter::File(path.clone()),
        None => Base64TextWriter::Stdout,
    };

    let message = message_reader.read()?;
    let secret = secret_reader.read_secret()?;

    let signature = signer
        .sign(&secret, &message)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to sign the message"))?;

    signature_writer.write(&signature)?;
    Ok(())
}

fn generate_public_key(
    secret_file_path: String,
    output_public_key_path: Option<String>,
) -> io::Result<()> {
    let public_key_generator = EdDsaSignature::new(SignatureAlgorithm::Ed25519);

    let secret_reader = if secret_file_path.ends_with(".pem") {
        SecretReader::PemFile(secret_file_path)
    } else {
        unimplemented!("Only PEM secret files are supported");
    };

    let public_key_writer = match output_public_key_path {
        Some(ref path) => Base64TextWriter::File(path.clone()),
        None => Base64TextWriter::Stdout,
    };
    let secret = secret_reader.read_secret()?;

    let public_key = public_key_generator
        .generate_public_key(&secret)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to generate public key"))?;
    public_key_writer.write(&public_key)?;
    Ok(())
}

fn verify(
    message_file_path: Option<String>,
    public_key_file_path: String,
    signature_file_path: String,
) -> io::Result<()> {
    let verifier = EdDsaSignature::new(SignatureAlgorithm::Ed25519);

    let message_reader = match message_file_path {
        Some(ref path) => PlainTextReader::File(path.clone()),
        None => PlainTextReader::Stdin,
    };
    let public_key_reader = Base64TextReader::File(public_key_file_path);
    let signature_reader = Base64TextReader::File(signature_file_path);

    let message = message_reader.read()?;
    let public_key = public_key_reader.read()?;
    let signature = signature_reader.read()?;

    let is_valid = verifier.verify(&public_key, &message, &signature);
    if is_valid {
        println!("Signature is valid.");
    } else {
        eprintln!("Signature is invalid.");
    }
    Ok(())
}
