use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use crate::util::B64;

pub fn cmd_get(arg: &str, output: Option<&str>) -> std::io::Result<()> {
    let cwd = env::current_dir()?;
    let ctx = load_identity_from_tree(&cwd)?;
    let target = resolve_target(&cwd, &ctx, arg);
    let (host, port) = parse_host_port(&target.host);
    let body = http_get(&host, port, &target.host, &target.url_path, &ctx.sk)?;
    match output {
        Some(f) => fs::write(f, body)?,
        None => std::io::stdout().write_all(&body)?,
    }
    Ok(())
}

struct Target {
    host: String,
    url_path: String,
}

struct IdentityCtx {
    account_dir: PathBuf,
    account: String,
    host: String,
    sk: SigningKey,
}

fn load_identity_from_tree(start: &Path) -> std::io::Result<IdentityCtx> {
    let mut current: Option<&Path> = Some(start);
    while let Some(d) = current {
        let ark_meta = d.join(".ark");
        let id_path = ark_meta.join("identity.json");
        let key_path = ark_meta.join("identity.key");
        if id_path.is_file() && key_path.is_file() {
            let id_content = fs::read_to_string(&id_path)?;
            let id: serde_json::Value = serde_json::from_str(&id_content)
                .map_err(|e| io_err(&format!("identity.json parse: {}", e)))?;
            let address = id["address"]
                .as_str()
                .ok_or_else(|| io_err("identity.json missing address"))?;
            let (_name, host) = address
                .split_once('@')
                .ok_or_else(|| io_err("identity address has no @host"))?;
            let account = d
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| io_err("account dir name not utf-8"))?
                .to_string();

            let key_b64 = fs::read_to_string(&key_path)?;
            let decoded = B64
                .decode(key_b64.trim())
                .map_err(|e| io_err(&format!("identity.key decode: {}", e)))?;
            let seed: [u8; 32] = decoded
                .try_into()
                .map_err(|_| io_err("identity.key wrong length"))?;
            let sk = SigningKey::from_bytes(&seed);
            return Ok(IdentityCtx {
                account_dir: d.to_path_buf(),
                account,
                host: host.to_string(),
                sk,
            });
        }
        current = d.parent();
    }
    Err(io_err("no .ark/identity.json + identity.key found in cwd or any parent"))
}

fn resolve_target(cwd: &Path, ctx: &IdentityCtx, arg: &str) -> Target {
    let at_pos = arg.find('@');
    let slash_pos = arg.find('/');
    let is_address_form = match (at_pos, slash_pos) {
        (Some(a), Some(s)) => a < s,
        (Some(_), None) => true,
        _ => false,
    };
    if is_address_form {
        let (acct_part, sub) = match arg.split_once('/') {
            Some((a, b)) => (a, b),
            None => (arg, ""),
        };
        let (account, host) = acct_part.split_once('@').unwrap();
        let url_path = if sub.is_empty() {
            format!("/ark/{}/", account)
        } else {
            format!("/ark/{}/{}", account, sub)
        };
        return Target {
            host: host.to_string(),
            url_path: collapse_slashes(&url_path),
        };
    }
    if arg.starts_with('/') {
        return Target {
            host: ctx.host.clone(),
            url_path: arg.to_string(),
        };
    }
    let rel = cwd.strip_prefix(&ctx.account_dir).unwrap_or(Path::new(""));
    let rel_str = rel.to_string_lossy();
    let combined = if rel_str.is_empty() {
        format!("/ark/{}/{}", ctx.account, arg)
    } else {
        format!("/ark/{}/{}/{}", ctx.account, rel_str, arg)
    };
    Target {
        host: ctx.host.clone(),
        url_path: collapse_slashes(&combined),
    }
}

fn collapse_slashes(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut prev_slash = false;
    for c in p.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    out
}

fn parse_host_port(host: &str) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (host.to_string(), 80)
}

fn http_get(
    connect_host: &str,
    port: u16,
    host_header: &str,
    path: &str,
    sk: &SigningKey,
) -> std::io::Result<Vec<u8>> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"GET\n");
    msg.extend_from_slice(path.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(ts.to_string().as_bytes());
    msg.push(b'\n');
    let sig_b64 = B64.encode(sk.sign(&msg).to_bytes());

    let mut stream = TcpStream::connect((connect_host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: ArkAccount {}\r\nX-Ark-Timestamp: {}\r\nConnection: close\r\n\r\n",
        path, host_header, sig_b64, ts
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("malformed response (no header end)"))?;
    let header_str = std::str::from_utf8(&buf[..split]).map_err(|_| io_err("non-utf8 headers"))?;
    let status_line = header_str.lines().next().ok_or_else(|| io_err("empty response"))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io_err("no status code"))?
        .parse()
        .map_err(|_| io_err("bad status code"))?;
    let body = buf[split + 4..].to_vec();
    if code != 200 {
        return Err(io_err(&format!("HTTP {}: {}", code, String::from_utf8_lossy(&body))));
    }
    Ok(body)
}

fn io_err(s: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_account::create_account_with_seed;
    use crate::server::serve;
    use std::net::TcpListener;
    use std::thread;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let p = env::temp_dir().join(format!("ark_get_test_{}_{}", std::process::id(), nanos));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn bind_local() -> (TcpListener, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn with_cwd<R>(dir: &Path, f: impl FnOnce() -> R) -> R {
        // Tests in this module need a shared mutex on cwd since env::set_current_dir is process-wide.
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let prev = env::current_dir().unwrap();
        env::set_current_dir(dir).unwrap();
        let result = f();
        env::set_current_dir(&prev).unwrap();
        result
    }

    #[test]
    fn collapse_slashes_removes_dupes() {
        assert_eq!(collapse_slashes("/ark//gyan///x"), "/ark/gyan/x");
        assert_eq!(collapse_slashes("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn parse_host_port_with_explicit_port() {
        assert_eq!(parse_host_port("127.0.0.1:8080"), ("127.0.0.1".to_string(), 8080));
        assert_eq!(parse_host_port("example.com:443"), ("example.com".to_string(), 443));
    }

    #[test]
    fn parse_host_port_default() {
        assert_eq!(parse_host_port("example.com"), ("example.com".to_string(), 80));
    }

    fn mk_ctx(account: &str, host: &str, dir: &Path) -> IdentityCtx {
        IdentityCtx {
            account_dir: dir.to_path_buf(),
            account: account.to_string(),
            host: host.to_string(),
            sk: SigningKey::from_bytes(&[7u8; 32]),
        }
    }

    #[test]
    fn resolve_target_absolute_uses_ctx_host() {
        let cwd = Path::new("/x/ark/gyan");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "/ark/alice/foo.txt");
        assert_eq!(t.url_path, "/ark/alice/foo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_relative_at_account_root() {
        let cwd = Path::new("/x/ark/gyan");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "notes/todo.txt");
        assert_eq!(t.url_path, "/ark/gyan/notes/todo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_relative_in_subdir() {
        let cwd = Path::new("/x/ark/gyan/notes");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "todo.txt");
        assert_eq!(t.url_path, "/ark/gyan/notes/todo.txt");
        assert_eq!(t.host, "127.0.0.1:8080");
    }

    #[test]
    fn resolve_target_address_form_with_path() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com/path/to/file");
        assert_eq!(t.url_path, "/ark/alice/path/to/file");
        assert_eq!(t.host, "example.com");
    }

    #[test]
    fn resolve_target_address_form_with_port() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com:9000/foo.txt");
        assert_eq!(t.url_path, "/ark/alice/foo.txt");
        assert_eq!(t.host, "example.com:9000");
    }

    #[test]
    fn resolve_target_address_form_no_path() {
        let cwd = Path::new("/anywhere");
        let ctx = mk_ctx("gyan", "127.0.0.1:8080", Path::new("/x/ark/gyan"));
        let t = resolve_target(cwd, &ctx, "alice@example.com");
        assert_eq!(t.url_path, "/ark/alice/");
        assert_eq!(t.host, "example.com");
    }

    #[test]
    fn get_file_via_cmd_get_writes_to_output() {
        let td = TempDir::new();
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [200u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/hello.txt"), b"hi from server").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let account_dir = td.0.join("ark").join("gyan");
        let out = td.0.join("out.bin");

        with_cwd(&account_dir, || {
            cmd_get("hello.txt", Some(out.to_str().unwrap())).unwrap();
        });

        assert_eq!(fs::read(&out).unwrap(), b"hi from server");
    }

    #[test]
    fn get_from_subdir_uses_relative_path() {
        let td = TempDir::new();
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [201u8; 32]).unwrap();
        let notes = td.0.join("ark/gyan/notes");
        fs::create_dir_all(&notes).unwrap();
        fs::write(notes.join("todo.txt"), b"buy milk").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let out = td.0.join("out.bin");
        with_cwd(&notes, || {
            cmd_get("todo.txt", Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"buy milk");
    }

    #[test]
    fn get_absolute_url_path() {
        let td = TempDir::new();
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [202u8; 32]).unwrap();
        let subdir = td.0.join("ark/gyan/sub");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(subdir.join("file.txt"), b"absolute").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan/sub");
        with_cwd(&cwd, || {
            cmd_get("/ark/gyan/sub/file.txt", Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"absolute");
    }

    #[test]
    fn get_via_explicit_address_form() {
        let td = TempDir::new();
        let (listener, port) = bind_local();
        let address = format!("gyan@127.0.0.1:{}", port);
        create_account_with_seed(&td.0, &address, [203u8; 32]).unwrap();
        fs::write(td.0.join("ark/gyan/explicit.txt"), b"via address").unwrap();

        let root = td.0.clone();
        thread::spawn(move || serve(listener, root, false));

        let out = td.0.join("out.bin");
        let cwd = td.0.join("ark/gyan");
        let arg = format!("gyan@127.0.0.1:{}/explicit.txt", port);
        with_cwd(&cwd, || {
            cmd_get(&arg, Some(out.to_str().unwrap())).unwrap();
        });
        assert_eq!(fs::read(&out).unwrap(), b"via address");
    }

    #[test]
    fn get_missing_identity_errors() {
        let td = TempDir::new();
        let err = with_cwd(&td.0, || cmd_get("anything", None).unwrap_err());
        let msg = format!("{}", err);
        assert!(msg.contains("no .ark"), "msg was {}", msg);
    }
}
