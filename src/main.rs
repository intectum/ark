mod create_account;
mod crypto;
mod decrypt;
mod get;
mod identity;
mod metadata;
mod put;
mod request;
mod server;
mod util;

use std::env;

use crate::create_account::cmd_create_account;
use crate::decrypt::{DecryptArgs, cmd_decrypt};
use crate::get::cmd_get;
use crate::put::cmd_put;
use crate::server::cmd_server;

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8080);
            cmd_server(port);
        }
        Some("create-account") => {
            let address = match args.get(2) {
                Some(a) => a,
                None => {
                    eprintln!("usage: ark create-account <name>@<host>[:<port>]");
                    std::process::exit(2);
                }
            };
            if let Err(e) = cmd_create_account(address) {
                eprintln!("create-account failed: {}", e);
                std::process::exit(1);
            }
        }
        Some("get") => {
            let mut output: Option<String> = None;
            let mut path_arg: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--output" | "-o" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => output = Some(v.clone()),
                            None => {
                                eprintln!("--output requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    p if path_arg.is_none() => path_arg = Some(p.to_string()),
                    other => {
                        eprintln!("unexpected argument: {}", other);
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            let path = match path_arg {
                Some(p) => p,
                None => {
                    eprintln!("usage: ark get [--output FILE] <path>");
                    std::process::exit(2);
                }
            };
            if let Err(e) = cmd_get(&path, output.as_deref()) {
                eprintln!("get failed: {}", e);
                std::process::exit(1);
            }
        }
        Some("put") => {
            let mut input: Option<String> = None;
            let mut path_arg: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--input" | "-i" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => input = Some(v.clone()),
                            None => {
                                eprintln!("--input requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    p if path_arg.is_none() => path_arg = Some(p.to_string()),
                    other => {
                        eprintln!("unexpected argument: {}", other);
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            let path = match path_arg {
                Some(p) => p,
                None => {
                    eprintln!("usage: ark put [--input FILE] <path>");
                    std::process::exit(2);
                }
            };
            if let Err(e) = cmd_put(&path, input.as_deref()) {
                eprintln!("put failed: {}", e);
                std::process::exit(1);
            }
        }
        Some("decrypt") => {
            let mut input: Option<String> = None;
            let mut output: Option<String> = None;
            let mut in_place: Option<String> = None;
            let mut key: Option<String> = None;
            let mut algorithm: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--input" | "-i" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => input = Some(v.clone()),
                            None => {
                                eprintln!("--input requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    "--output" | "-o" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => output = Some(v.clone()),
                            None => {
                                eprintln!("--output requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    "--in-place" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => in_place = Some(v.clone()),
                            None => {
                                eprintln!("--in-place requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    "--key" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => key = Some(v.clone()),
                            None => {
                                eprintln!("--key requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    "--algorithm" => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => algorithm = Some(v.clone()),
                            None => {
                                eprintln!("--algorithm requires a value");
                                std::process::exit(2);
                            }
                        }
                    }
                    other => {
                        eprintln!("unexpected argument: {}", other);
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            if let Err(e) = cmd_decrypt(DecryptArgs { input, output, in_place, key, algorithm }) {
                eprintln!("decrypt failed: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "usage:\n  ark server [port]\n  ark create-account <name>@<host>[:<port>]\n  ark get [--output FILE] <path>\n  ark put [--input FILE] <path>\n  ark decrypt [-i FILE | --in-place FILE] [-o FILE] [--key B64] [--algorithm NAME]"
            );
            std::process::exit(2);
        }
    }
}
