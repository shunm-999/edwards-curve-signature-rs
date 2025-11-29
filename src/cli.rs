use clap::{Parser, Subcommand};
use std::io::stdin;
use std::{fs, io};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub(crate) subcommand: SubCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubCommands {
    Sign {
        #[clap(long = "in", ignore_case = true)]
        message_file_path: Option<String>,
    },
}

pub(crate) trait ReadMessage {
    fn read_message(&self) -> io::Result<Vec<u8>>;
}

trait WriteSignature {
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
