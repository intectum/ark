mod client;
mod context;
mod crypto;
mod http;
mod identity;
mod metadata;
mod server;
mod types;
mod util;

use clap::{Parser, Subcommand};

use crate::client::{DecryptArgs, cmd_chmod, cmd_decrypt, cmd_delete, cmd_get, cmd_head, cmd_init, cmd_put};
use crate::context::create_client_context;
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
    /// Initialise an account in the current directory.
    Init {
        /// Address in the form <name>@<host>[:<port>].
        address: String,
    },
    /// Print response headers (HEAD request).
    Head {
        /// Ark URL or path.
        path: String,
    },
    /// Change members and permissions on a local file's metadata. Use `put` to sync.
    Chmod {
        /// Add or promote an owner (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'o', long = "owner", value_name = "ADDR")]
        owner: Vec<String>,
        /// Add or promote a writer (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'w', long = "write", value_name = "ADDR")]
        write: Vec<String>,
        /// Add or promote a reader (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'r', long = "read", value_name = "ADDR")]
        read: Vec<String>,
        /// Drop a member (repeatable).
        #[arg(short = 'd', long = "drop", value_name = "ADDR")]
        drop: Vec<String>,
        /// Local file path.
        file: String,
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
        /// Encryption algorithm; omit to send body as-is.
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
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
        #[arg(short, long, value_name = "B64")]
        key: Option<String>,
        /// Override encryption algorithm (default from metadata or aes-256-gcm).
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let result: std::io::Result<()> = match cli.cmd {
        Cmd::Server { port } => {
            cmd_server(port);
            Ok(())
        },
        Cmd::Init { address } => cmd_init(&address),
        Cmd::Chmod { owner, write, read, drop, file } => create_client_context().and_then(|c| cmd_chmod(&c, &file, &owner, &write, &read, &drop)),
        Cmd::Head { path } => create_client_context().and_then(|c| cmd_head(&c, &path)),
        Cmd::Delete { path } => create_client_context().and_then(|c| cmd_delete(&c, &path)),
        Cmd::Get { output, decrypt, path } => create_client_context().and_then(|c| cmd_get(&c, &path, output.as_deref(), decrypt)),
        Cmd::Put { input, encryption_algorithm, path } => create_client_context().and_then(|c| cmd_put(&c, &path, input.as_deref(), encryption_algorithm.as_deref())),
        Cmd::Decrypt { input, output, in_place, key, encryption_algorithm } => {
            create_client_context().and_then(|c| cmd_decrypt(&c, DecryptArgs { input, output, in_place, key, encryption_algorithm }))
        }
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
