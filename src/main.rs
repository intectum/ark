use std::env;
use std::env::current_dir;
use std::io::{self, Write};
use std::path::Path;
use std::process::exit;

use clap::{Parser, Subcommand};

use ark::client::{accept_proposal, decrypt, delete, encrypt, get, head, init, list, list_proposals, put, reject_proposal, sync, watch_local, watch_remote};
use ark::types::{DirEntryKind, EntryEvent, Permissions};
use ark::context::create_client_context;
use ark::identity::parse_address;
use ark::server::start_server;
use ark::types::IdentityContext;
use ark::util::resolve_client_url;

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
enum WatchCmd {
    /// Watch a local directory tree recursively.
    Local {
        /// Local directory path.
        path: String,
    },
    /// Subscribe to remote server-sent events under a path.
    Remote {
        /// Ark URL or path.
        path: String,
    },
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
    ///
    /// With --local-only, skips the network entirely: generates a keypair and
    /// writes it locally without contacting the server.
    Init {
        /// Address in the form <name>@<host>[:<port>].
        address: String,
        /// Password to gate remote access to the identity key.
        #[arg(short, long)]
        password: Option<String>,
        /// Skip network calls; only write local identity files.
        #[arg(long)]
        local_only: bool,
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
    /// List entries of a directory.
    List {
        /// Ark URL or path.
        path: String,
    },
    /// Encrypt and upload a file.
    ///
    /// If INPUT is a directory, creates or updates a directory (empty body).
    /// Every encrypted put rotates the file key. If INPUT is already
    /// encrypted (e.g. after `ark encrypt`), the body is uploaded as-is.
    Put {
        /// Read body from FILE instead of stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<String>,
        /// Grant `owner` (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'o', long = "owner", value_name = "ADDR")]
        owner: Vec<String>,
        /// Grant `writer` (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'w', long = "writer", value_name = "ADDR")]
        writer: Vec<String>,
        /// Grant `reader` (repeatable). Use "public" for wildcard `*`.
        #[arg(short = 'r', long = "reader", value_name = "ADDR")]
        reader: Vec<String>,
        /// Drop a member (repeatable).
        #[arg(short = 'd', long = "drop", value_name = "ADDR")]
        drop: Vec<String>,
        /// Encryption algorithm; use "none" for plaintext. Default: reuse
        /// existing metadata's algorithm, else aes-256-gcm.
        #[arg(short, long, value_name = "NAME")]
        encryption_algorithm: Option<String>,
        /// Send only metadata; server keeps the existing body. Requires the
        /// file to exist on the server.
        #[arg(short, long)]
        metadata_only: bool,
        /// Ark URL or path.
        path: String,
    },
    /// Reconcile local and remote state in one pass.
    ///
    /// Per tracked file, pure local edits push; pure remote changes pull;
    /// concurrent changes on both sides write the remote copy to a
    /// `<name>.conflict-<iso>` sidecar and leave the local copy untouched.
    /// Untracked local files and symlinks are left alone. With --watch, keeps
    /// syncing continuously.
    Sync {
        /// Watch for changes and re-sync continuously.
        #[arg(short, long)]
        watch: bool,
        /// Decrypt pulled files using their metadata key.
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Watch for changes and print events as they arrive.
    Watch {
        #[command(subcommand)]
        cmd: WatchCmd,
    },
    /// Decrypt an encrypted file.
    ///
    /// If the source has ark metadata, its file key and algorithm are reused
    /// and --key/--encryption-algorithm are rejected. Otherwise --key is
    /// required. Refuses to run on files that are not currently encrypted.
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
    /// A proposal is another account attempting to share a file with you at a
    /// path where they are not yet authorized. Accepting materializes the
    /// target directory with the proposed members and pulls the file from the
    /// sender. Rejecting discards the proposal.
    Proposals {
        #[command(subcommand)]
        cmd: ProposalsCmd,
    },
    /// Encrypt a plaintext file.
    ///
    /// If the source has ark metadata, its file key and algorithm are reused
    /// and --key/--encryption-algorithm are rejected. Otherwise --key is
    /// required. Refuses to run on files that are already encrypted.
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
    let result: io::Result<()> = match cli.cmd {
        Cmd::Server { port, host } => {
            let resolved_host = host
                .or_else(|| env::var("HOST").ok())
                .unwrap_or_else(|| format!("localhost:{}", port));
            start_server(port, &resolved_host);
            Ok(())
        },
        Cmd::Init { address, password, local_only } => current_dir().and_then(|c| init(&c, &address, password.as_deref(), local_only)),
        Cmd::Head { path } => create_client_context().and_then(|c| head_cli(&c, &path)),
        Cmd::Delete { path } => create_client_context().and_then(|c| delete(&c, &path)),
        Cmd::Get { output, decrypt, path } => create_client_context().and_then(|c| get(&c, &path, output.as_deref(), decrypt)),
        Cmd::List { path } => create_client_context().and_then(|c| list_cli(&c, &path)),
        Cmd::Proposals { cmd } => create_client_context().and_then(|c| match cmd {
            ProposalsCmd::List => list_proposals_cli(&c),
            ProposalsCmd::Accept { id, force } => accept_proposal(&c, &id, force),
            ProposalsCmd::Reject { id } => reject_proposal(&c, &id),
        }),
        Cmd::Put { input, owner, writer, reader, drop, encryption_algorithm, metadata_only, path } => create_client_context().and_then(|c| put(&c, &path, input.as_deref(), &Permissions { owners: owner, writers: writer, readers: reader, drops: drop }, encryption_algorithm.as_deref(), metadata_only)),
        Cmd::Sync { watch, decrypt } => create_client_context().and_then(|c| current_dir().and_then(|d| sync(&c, &d, watch, decrypt, print_event, print_error))),
        Cmd::Watch { cmd } => match cmd {
            WatchCmd::Local { path } => watch_local(Path::new(&path), print_event, print_error),
            WatchCmd::Remote { path } => create_client_context().and_then(|c| {
                let url = resolve_client_url(&c, &path)?;
                watch_remote(&c, &url, print_event, print_error)
            }),
        },
        Cmd::Decrypt { input, output, in_place, key, encryption_algorithm } => {
            create_client_context().and_then(|c| decrypt(&c, input.as_deref(), output.as_deref(), in_place.as_deref(), key.as_deref(), encryption_algorithm.as_deref()))
        }
        Cmd::Encrypt { input, output, in_place, key, encryption_algorithm } => {
            create_client_context().and_then(|c| encrypt(&c, input.as_deref(), output.as_deref(), in_place.as_deref(), key.as_deref(), encryption_algorithm.as_deref()))
        }
    };
    if let Err(e) = result {
        eprintln!("error: {}", e);
        exit(1);
    }
}

fn head_cli(ctx: &IdentityContext, path: &str) -> io::Result<()> {
    let (headers, _) = head(ctx, path)?;

    let mut stdout = io::stdout().lock();
    for (name, value) in &headers {
        writeln!(stdout, "{}: {}", name, value)?;
    }

    Ok(())
}

fn list_cli(ctx: &IdentityContext, path: &str) -> io::Result<()> {
    let entries = list(ctx, path)?;
    let mut stdout = io::stdout().lock();
    for entry in &entries {
        let kind = match entry.kind {
            DirEntryKind::Dir => "dir",
            DirEntryKind::File => "file",
            DirEntryKind::Symlink => "symlink",
        };
        writeln!(stdout, "{}  {}", kind, entry.name)?;
    }
    Ok(())
}

fn list_proposals_cli(ctx: &IdentityContext) -> io::Result<()> {
    let proposals = list_proposals(ctx)?;
    if proposals.is_empty() {
        println!("No pending proposals.");
        return Ok(());
    }

    let (account_name, _, _) = parse_address(&ctx.identity.address)?;
    let account_prefix = format!("/ark/{}", account_name);

    for (index, proposal) in proposals.iter().enumerate() {
        let kind = proposal.metadata.body_hash.as_ref().map(|_| "file").unwrap_or("dir");
        let display_target = match proposal.target.strip_prefix(&account_prefix) {
            Some("") => "/",
            Some(rest) => rest,
            None => &proposal.target,
        };
        println!("{:>3}  {}  {}  {}  ({})", index + 1, proposal.metadata.modified_by, kind, display_target, proposal.id);
        for member in &proposal.metadata.members {
            println!("       {} = {}", member.address, member.permission.as_str());
        }
    }

    Ok(())
}

fn print_event(event: EntryEvent) -> bool {
    let kind = match event.kind {
        Some(DirEntryKind::Dir) => "dir",
        Some(DirEntryKind::File) => "file",
        Some(DirEntryKind::Symlink) => "symlink",
        None => "?",
    };
    let suffix = if event.conflict { " (conflict)" } else { "" };
    eprintln!("{} {} {}{}", kind, event.action.as_str(), event.path.display(), suffix);
    false
}

fn print_error(e: io::Error) -> bool {
    eprintln!("error: {}", e);
    false
}
