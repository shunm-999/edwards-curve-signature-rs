use clap::{Parser, Subcommand};

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
        message: Option<String>,
    },
}

trait ReadMessage {
    fn read_message(&self) -> Option<Vec<u8>>;
}

trait WriteSignature {
    fn write_signature(&self, signature: &[u8]);
}
