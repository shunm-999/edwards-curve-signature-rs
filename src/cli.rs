use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use regex::Regex;
use std::io::stdin;
use std::str::Lines;
use std::{fs, io};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub(crate) subcommand: SubCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubCommands {
    #[clap(name = "sign")]
    Sign {
        #[clap(long = "in", ignore_case = true)]
        message_file_path: Option<String>,
        #[clap(long = "key", ignore_case = true, required = true)]
        secret_file_path: String,
        #[clap(long = "out", ignore_case = true)]
        output_file_path: Option<String>,
    },
    #[clap(name = "gen-key")]
    GeneratePublicKey {
        #[clap(long = "key", ignore_case = true, required = true)]
        secret_file_path: String,
        #[clap(long = "out", ignore_case = true)]
        output_file_path: Option<String>,
    },
}

pub(crate) trait ReadMessage {
    fn read_message(&self) -> io::Result<Vec<u8>>;
}

pub(crate) trait ReadSecret {
    fn read_secret(&self) -> io::Result<Vec<u8>>;
}

pub(crate) trait WritePublicKey {
    fn write_public_key(&self, public_key: &[u8]) -> io::Result<()>;
}

pub(crate) trait WriteSignature {
    fn write_signature(&self, signature: &[u8]) -> io::Result<()>;
}

pub(crate) enum MessageReader {
    Stdin,
    File(String),
}

impl ReadMessage for MessageReader {
    fn read_message(&self) -> io::Result<Vec<u8>> {
        match self {
            MessageReader::Stdin => {
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                Ok(input.into_bytes())
            }
            MessageReader::File(path) => fs::read(path.to_owned()),
        }
    }
}

pub(crate) enum SecretReader {
    PemFile(String),
}

struct PemSection(Vec<u8>);

impl ReadSecret for SecretReader {
    fn read_secret(&self) -> io::Result<Vec<u8>> {
        match self {
            SecretReader::PemFile(path) => {
                let content = fs::read_to_string(path.to_owned())?;
                let pem_sections = read_pem_sections(content.lines())?;

                let pem_section = pem_sections.first().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "No PEM sections found")
                })?;

                Ok(pem_section.0.clone())
            }
        }
    }
}

fn read_pem_sections(lines: Lines<'_>) -> io::Result<Vec<PemSection>> {
    let mut sections = Vec::new();
    let mut iter = lines.peekable();

    while iter.peek().is_some() {
        let section = read_pem_section(&mut iter)?;
        sections.push(section);
    }
    Ok(sections)
}

fn read_pem_section<'a, I>(lines: &mut I) -> io::Result<PemSection>
where
    I: Iterator<Item = &'a str>,
{
    let begin_section = Regex::new(r"-----BEGIN ([A-Z ]+)-----").unwrap();
    let end_section = Regex::new(r"-----END ([A-Z ]+)-----").unwrap();

    let line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unexpected end of PEM file"))?;

    if !begin_section.is_match(line) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid PEM begin section",
        ));
    }

    let mut secret = Vec::new();
    while let Some(line) = lines.next() {
        if begin_section.is_match(line) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected BEGIN section inside PEM",
            ));
        }
        if end_section.is_match(line) {
            break;
        }

        let decoded = BASE64_STANDARD.decode(line.to_string()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid base64 in PEM section")
        })?;
        secret.extend_from_slice(&decoded);
    }
    Ok(PemSection(secret))
}

pub(crate) enum PublicKeyWriter {
    Stdout,
    File(String),
}

impl WritePublicKey for PublicKeyWriter {
    fn write_public_key(&self, public_key: &[u8]) -> io::Result<()> {
        let b64_public_key = BASE64_STANDARD.encode(public_key);
        match self {
            PublicKeyWriter::Stdout => {
                println!("{}", b64_public_key);
            }
            PublicKeyWriter::File(output_file_path) => {
                fs::write(output_file_path.to_owned(), b64_public_key)?;
            }
        }
        Ok(())
    }
}

pub(crate) enum SignatureWriter {
    Stdout,
    File(String),
}

impl WriteSignature for SignatureWriter {
    fn write_signature(&self, signature: &[u8]) -> io::Result<()> {
        let b64_signature = BASE64_STANDARD.encode(signature);
        match self {
            SignatureWriter::Stdout => {
                println!("{}", b64_signature);
            }
            SignatureWriter::File(output_file_path) => {
                fs::write(output_file_path.to_owned(), b64_signature)?;
            }
        }
        Ok(())
    }
}
