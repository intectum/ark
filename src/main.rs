use std::env;

use clap::{Parser, Subcommand};

use ark::client::{accept_proposal_io, chmod_io, decrypt_io, delete, encrypt_io, get_io, head_io, init, list_proposals_io, put_io, reject_proposal_io, sync_io, track_io};
use ark::context::create_client_context;
use ark::server::start_server;

#[derive(Parser)]
#[command(
    name = "ark",
    about = "Ark CLI — federated, end-to-end encrypted file protocol",
    long_about = "Ark CLI. See README.md for the full guide and spec.md for the protocol.",
    version,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum ProposalsCmd {
    /// List pending share proposals.
    List,
    /// Accept a proposal by index (from `list`) or log entry id.
    Accept {
        /// Index (1-based) or log entry filename.
        id: String,
        /// Bypass metadata-change safety checks (accept fresher metadata even if
        /// members were added or self was downgraded by a non-owner).
        #[arg(short, long)]
        force: bool,
    },
    /// Reject a proposal by index (from `list`) or log entry id.
    Reject {
        /// Index (1-based) or log entry filename.
        id: String,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the file server.
    ///
    /// Serves the current working directory as the server root. Accounts land
    /// under ./ark/<name>/. Bootstraps ./ark/ark/.ark/identity.{json,key} on
    /// first start.
    Server {
        #[arg(default_value_t = 8080)]
        port: u16,
        /// Advertised host used for the auto-created ark@<host> identity.
        /// Defaults to $HOST, else localhost:<port>.
        #[arg(long)]
        host: Option<String>,
    },
    /// Initialise an account in the current directory.
    ///
    /// If the server already has an identity at ADDRESS, downloads it. If not,
    /// generates a fresh keypair locally and uploads it. Writes
    /// .ark/identity.json and (on generate) .ark/identity.key.
    ///
    /// With --password, on first init encrypts and uploads identity.key
    /// gated by a password identity; on subsequent inits from another machine,
    /// recovers identity.key using the password.
    Init {
        /// Address in the form <name>@<host>[:<port>].
        address: String,
        /// Password to gate remote access to the identity key.
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Print response headers (HEAD request).
    Head {
        /// Ark URL or path.
        path: String,
    },
    /// Change members and permissions on a local file's metadata. Use `put` to sync.
    ///
    /// Only updates the file's local xattrs. For encrypted files, adding a
    /// member re-wraps the current file key for them. Removing a member does
    /// NOT rotate the file key — the next `put` will. Follow `chmod` with
    /// `ark put -i <FILE> <PATH>` to upload the change.
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
    ///
    /// If INPUT is a directory, creates or updates a directory (empty body).
    /// A fresh file key is minted on every encrypted put and wrapped for every
    /// member. If the input file already has user.ark_local.encrypted=true
    /// (e.g. after `ark encrypt`), the body is uploaded as-is. The server
    /// relays the write to co-members' inboxes automatically.
    Put {
        /// Read body from FILE instead of stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<String>,
        /// Encryption algorithm; use "none" for plaintext. Default: reuse
        /// existing metadata's algorithm, else aes-256-gcm.
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
        /// Ark URL or path.
        path: String,
    },
    /// Reconcile local and remote state in one pass.
    ///
    /// Fetches new entries from the server's request log (`.ark/requests/`)
    /// since the checkpoint in `.ark/last_sync_request`, then walks the local tree.
    /// Per tracked file, compares local SHA-256 to `sync_body_hash`
    /// (local_modified?) and local `body_hash` to the log's `body_hash`
    /// (remote_modified?). Pure local edits push; pure remote changes pull;
    /// concurrent changes on both sides rename the local copy to
    /// `<name>.conflict-<iso>` and pull remote. Untracked local files, symlinks, and `.ark/` are left alone.
    /// With --watch, spawns the SSE watcher before the initial pass, then
    /// blocks on the local FS watcher for continuous sync.
    Sync {
        /// Watch for changes and re-sync continuously.
        #[arg(short, long)]
        watch: bool,
        /// Decrypt pulled files using their metadata key.
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Seed ark metadata on a local file or directory.
    ///
    /// Signs and writes user.ark.* xattrs. For files, also sets sync_body_hash so
    /// `sync` will consider the file. Errors if metadata already exists.
    Track {
        /// Encryption algorithm; use "none" for plaintext. Files only.
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
        /// Local file or directory path.
        path: String,
    },
    /// Decrypt an encrypted file.
    ///
    /// If the source has ark metadata, its file key and algorithm are reused
    /// and --key/--encryption-algorithm are rejected. Otherwise --key is
    /// required. Refuses to run when user.ark_local.encrypted=false.
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
    /// Review and act on pending share proposals.
    ///
    /// A proposal is any 403 PUT recorded in .ark/requests/ — another account
    /// tried to write to your server at a path where they are not yet
    /// authorized. Accepting materializes the target dir with the proposed
    /// members and pulls the file from the sender. Rejecting deletes the log
    /// entry.
    Proposals {
        #[command(subcommand)]
        cmd: ProposalsCmd,
    },
    /// Encrypt a plaintext file.
    ///
    /// If the source has ark metadata, its file key and algorithm are reused
    /// and --key/--encryption-algorithm are rejected. Otherwise --key is
    /// required. Refuses to run when user.ark_local.encrypted=true.
    Encrypt {
        /// Read plaintext from FILE (otherwise stdin).
        #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
        input: Option<String>,
        /// Write ciphertext to FILE (otherwise stdout).
        #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
        output: Option<String>,
        /// Encrypt the file in place (rewrites its bytes).
        #[arg(long, value_name = "FILE")]
        in_place: Option<String>,
        /// Base64url-encoded 32-byte file key (reuses source metadata key if absent).
        #[arg(short, long, value_name = "B64")]
        key: Option<String>,
        /// Override encryption algorithm (default from metadata or aes-256-gcm).
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
    },
}

fn main() {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let result: std::io::Result<()> = match cli.cmd {
        Cmd::Server { port, host } => {
            let resolved_host = host
                .or_else(|| env::var("HOST").ok())
                .unwrap_or_else(|| format!("localhost:{}", port));
            start_server(port, &resolved_host);
            Ok(())
        },
        Cmd::Init { address, password } => init(&address, password.as_deref()),
        Cmd::Chmod { owner, write, read, drop, file } => create_client_context().and_then(|c| chmod_io(&c, &file, &owner, &write, &read, &drop)),
        Cmd::Head { path } => create_client_context().and_then(|c| head_io(&c, &path)),
        Cmd::Delete { path } => create_client_context().and_then(|c| delete(&c, &path)),
        Cmd::Get { output, decrypt, path } => create_client_context().and_then(|c| get_io(&c, &path, output.as_deref(), decrypt)),
        Cmd::Proposals { cmd } => create_client_context().and_then(|c| match cmd {
            ProposalsCmd::List => list_proposals_io(&c),
            ProposalsCmd::Accept { id, force } => accept_proposal_io(&c, &id, force),
            ProposalsCmd::Reject { id } => reject_proposal_io(&c, &id),
        }),
        Cmd::Put { input, encryption_algorithm, path } => create_client_context().and_then(|c| put_io(&c, &path, input.as_deref(), encryption_algorithm.as_deref())),
        Cmd::Sync { watch, decrypt } => create_client_context().and_then(|c| sync_io(&c, watch, decrypt)),
        Cmd::Track { encryption_algorithm, path } => create_client_context().and_then(|c| track_io(&c, &path, encryption_algorithm.as_deref())),
        Cmd::Decrypt { input, output, in_place, key, encryption_algorithm } => {
            create_client_context().and_then(|c| decrypt_io(&c, input.as_deref(), output.as_deref(), in_place.as_deref(), key.as_deref(), encryption_algorithm.as_deref()))
        }
        Cmd::Encrypt { input, output, in_place, key, encryption_algorithm } => {
            create_client_context().and_then(|c| encrypt_io(&c, input.as_deref(), output.as_deref(), in_place.as_deref(), key.as_deref(), encryption_algorithm.as_deref()))
        }
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
