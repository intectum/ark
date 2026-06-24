mod create_account;
mod crypto;
mod decrypt;
mod delete;
mod get;
mod head;
mod identity;
mod metadata;
mod put;
mod request;
mod server;
mod types;
mod util;

use clap::{Parser, Subcommand};

use crate::create_account::cmd_create_account;
use crate::decrypt::{DecryptArgs, cmd_decrypt};
use crate::delete::cmd_delete;
use crate::get::cmd_get;
use crate::head::cmd_head;
use crate::put::cmd_put;
use crate::server::cmd_server;

#[derive(Parser)]
#[command(name = "ark", about = "Ark CLI", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the file server.
    Server {
        #[arg(default_value_t = 8080)]
        port: u16,
    },
    /// Create a new account.
    CreateAccount {
        /// Address in the form <name>@<host>[:<port>].
        address: String,
    },
    /// Print response headers (HEAD request).
    Head {
        /// Ark URL or path.
        path: String,
    },
    /// Delete a file or directory.
    Delete {
        /// Ark URL or path.
        path: String,
    },
    /// Fetch a file or directory listing.
    Get {
        /// Write body to FILE instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
        /// Decrypt the response body using its metadata key.
        #[arg(short, long)]
        decrypt: bool,
        /// Ark URL or path.
        path: String,
    },
    /// Encrypt and upload a file.
    Put {
        /// Read body from FILE instead of stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<String>,
        /// Skip encryption; send body as-is.
        #[arg(long)]
        no_encrypt: bool,
        /// Ark URL or path.
        path: String,
    },
    /// Decrypt an encrypted file.
    Decrypt {
        /// Read ciphertext from FILE (otherwise stdin).
        #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
        input: Option<String>,
        /// Write plaintext to FILE (otherwise stdout).
        #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
        output: Option<String>,
        /// Decrypt the file in place (rewrites its bytes).
        #[arg(long, value_name = "FILE")]
        in_place: Option<String>,
        /// Base64url-encoded 32-byte file key (required for stdin).
        #[arg(long, value_name = "B64")]
        key: Option<String>,
        /// Override algorithm (default from metadata or aes-256-gcm).
        #[arg(long, value_name = "NAME")]
        algorithm: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let result: std::io::Result<()> = match cli.cmd {
        Cmd::Server { port } => {
            cmd_server(port);
            Ok(())
        }
        Cmd::CreateAccount { address } => cmd_create_account(&address),
        Cmd::Head { path } => cmd_head(&path),
        Cmd::Delete { path } => cmd_delete(&path),
        Cmd::Get { output, decrypt, path } => cmd_get(&path, output.as_deref(), decrypt),
        Cmd::Put { input, no_encrypt, path } => cmd_put(&path, input.as_deref(), no_encrypt),
        Cmd::Decrypt { input, output, in_place, key, algorithm } => {
            cmd_decrypt(DecryptArgs { input, output, in_place, key, algorithm })
        }
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
