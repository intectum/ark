use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::thread;

fn main() {
    let port: u16 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let root = env::current_dir().expect("cwd");
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    eprintln!("serving {} on http://0.0.0.0:{}", root.display(), port);
    serve(listener, root, true);
}

fn serve(listener: TcpListener, root: PathBuf, verbose: bool) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(s, &root, verbose) {
                        if verbose {
                            eprintln!("error: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                if verbose {
                    eprintln!("accept: {}", e);
                }
            }
        }
    }
}

fn handle(mut stream: TcpStream, root: &Path, verbose: bool) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.trim_end().split_whitespace().collect();
    if parts.len() != 3 {
        return write_status(&mut stream, 400, "Bad Request", b"bad request line");
    }
    let method = parts[0];
    let target = parts[1];

    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    if verbose {
        eprintln!("{:?} {} {}", peer, method, target);
    }

    if !is_allowed(target) {
        return write_status(&mut stream, 403, "Forbidden", b"forbidden");
    }

    if is_ark_root(target) && method != "GET" && method != "HEAD" {
        return write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed");
    }

    let path = match resolve(root, target) {
        Some(p) => p,
        None => return write_status(&mut stream, 400, "Bad Request", b"bad path"),
    };

    match method {
        "GET" => serve_get(&mut stream, &path, true),
        "HEAD" => serve_get(&mut stream, &path, false),
        "PUT" => serve_put(&mut stream, &mut reader, &path, content_length),
        "DELETE" => serve_delete(&mut stream, &path),
        _ => write_status(&mut stream, 405, "Method Not Allowed", b"method not allowed"),
    }
}

fn is_allowed(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() >= 2 && parts[0] == "ark"
}

fn is_ark_root(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() == 2 && parts[0] == "ark"
}

fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let raw = target.split('?').next().unwrap_or("");
    let decoded = percent_decode(raw)?;
    let rel = decoded.trim_start_matches('/');
    let candidate = root.join(rel);
    for comp in candidate.components() {
        if matches!(comp, Component::ParentDir) {
            return None;
        }
    }
    Some(candidate)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn serve_get(stream: &mut TcpStream, path: &Path, send_body: bool) -> std::io::Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };
    if meta.is_dir() {
        let body = list_dir(path)?;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes())?;
        if send_body {
            stream.write_all(body.as_bytes())?;
        }
        return Ok(());
    }
    let len = meta.len();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type(path),
        len
    );
    stream.write_all(headers.as_bytes())?;
    if send_body {
        let mut f = fs::File::open(path)?;
        std::io::copy(&mut f, stream)?;
    }
    Ok(())
}

fn serve_put(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    path: &Path,
    len: usize,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existed = path.exists();
    let mut f = fs::File::create(path)?;
    let mut remaining = len;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])?;
        remaining -= n;
    }
    let (code, msg) = if existed { (204, "No Content") } else { (201, "Created") };
    let response = format!("HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, msg);
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn serve_delete(stream: &mut TcpStream, path: &Path) -> std::io::Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return write_status(stream, 404, "Not Found", b"not found"),
    };
    let res = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match res {
        Ok(_) => stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").map(|_| ()),
        Err(_) => write_status(stream, 500, "Internal Server Error", b"delete failed"),
    }
}

fn list_dir(path: &Path) -> std::io::Result<String> {
    let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    let mut body = String::from("[");
    let mut first = true;
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let meta = e.metadata()?;
        let kind = if meta.is_dir() { "dir" } else if meta.is_symlink() { "symlink" } else { "file" };
        let size = meta.len();
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(&format!(
            "{{\"name\":\"{}\",\"type\":\"{}\",\"size\":{}}}",
            json_escape(&name),
            kind,
            size
        ));
    }
    body.push(']');
    Ok(body)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn write_status(stream: &mut TcpStream, code: u16, msg: &str, body: &[u8]) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        msg,
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let p = env::temp_dir().join(format!("file_server_test_{}_{}", std::process::id(), nanos));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn start_server(root: PathBuf) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || serve(listener, root, false));
        port
    }

    fn request(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let head = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            method,
            path,
            body.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        if !body.is_empty() {
            s.write_all(body).unwrap();
        }
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end");
        let header_str = std::str::from_utf8(&buf[..split]).unwrap();
        let body_bytes = buf[split + 4..].to_vec();
        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap();
        let code: u16 = status_line.split_whitespace().nth(1).unwrap().parse().unwrap();
        let headers = lines
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
            })
            .collect();
        (code, body_bytes, headers)
    }

    fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn ark(td: &Path) -> PathBuf {
        let p = td.join("ark").join("test");
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn get_file_returns_content() {
        let td = TempDir::new();
        let a = ark(&td.0);
        fs::write(a.join("hello.txt"), b"hi there").unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = request(port, "GET", "/ark/test/hello.txt", &[]);
        assert_eq!(code, 200);
        assert_eq!(body, b"hi there");
        assert_eq!(header(&headers, "content-length"), Some("8"));
    }

    #[test]
    fn get_missing_file_404() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/ark/test/nope.txt", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn get_dir_returns_json_listing() {
        let td = TempDir::new();
        let a = ark(&td.0);
        fs::write(a.join("a.txt"), b"a").unwrap();
        fs::create_dir(a.join("sub")).unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = request(port, "GET", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("\"name\":\"a.txt\""), "body was {}", s);
        assert!(s.contains("\"type\":\"file\""), "body was {}", s);
        assert!(s.contains("\"name\":\"sub\""), "body was {}", s);
        assert!(s.contains("\"type\":\"dir\""), "body was {}", s);
    }

    #[test]
    fn head_file_no_body_with_length() {
        let td = TempDir::new();
        let a = ark(&td.0);
        fs::write(a.join("x"), b"abcde").unwrap();
        let port = start_server(td.0.clone());
        let (code, body, headers) = request(port, "HEAD", "/ark/test/x", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-length"), Some("5"));
    }

    #[test]
    fn head_dir_no_body_with_json_type() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, body, headers) = request(port, "HEAD", "/ark/test/", &[]);
        assert_eq!(code, 200);
        assert!(body.is_empty());
        assert_eq!(header(&headers, "content-type"), Some("application/json"));
    }

    #[test]
    fn put_new_file_returns_201() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/ark/test/new.txt", b"payload");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/new.txt")).unwrap(), b"payload");
    }

    #[test]
    fn put_overwrite_returns_204() {
        let td = TempDir::new();
        let a = ark(&td.0);
        fs::write(a.join("x"), b"old").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/ark/test/x", b"new content");
        assert_eq!(code, 204);
        assert_eq!(fs::read(td.0.join("ark/test/x")).unwrap(), b"new content");
    }

    #[test]
    fn put_nested_path_creates_dirs() {
        let td = TempDir::new();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/ark/test/a/b/c.txt", b"deep");
        assert_eq!(code, 201);
        assert_eq!(fs::read(td.0.join("ark/test/a/b/c.txt")).unwrap(), b"deep");
    }

    #[test]
    fn delete_file_removes_and_returns_204() {
        let td = TempDir::new();
        let a = ark(&td.0);
        let p = a.join("d.txt");
        fs::write(&p, b"bye").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "DELETE", "/ark/test/d.txt", &[]);
        assert_eq!(code, 204);
        assert!(!p.exists());
    }

    #[test]
    fn delete_dir_recursively_removes_and_returns_204() {
        let td = TempDir::new();
        let a = ark(&td.0);
        let d = a.join("sub");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("inner"), b"x").unwrap();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "DELETE", "/ark/test/sub", &[]);
        assert_eq!(code, 204);
        assert!(!d.exists());
    }

    #[test]
    fn delete_missing_404() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "DELETE", "/ark/test/nope", &[]);
        assert_eq!(code, 404);
    }

    #[test]
    fn unsupported_method_returns_405() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "POST", "/ark/test/x", b"hello");
        assert_eq!(code, 405);
    }

    #[test]
    fn path_traversal_blocked() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/ark/test/../../../etc/passwd", &[]);
        assert_eq!(code, 400);
    }

    #[test]
    fn root_blocked_403() {
        let td = TempDir::new();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn non_ark_path_blocked_403() {
        let td = TempDir::new();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "GET", "/something/else", &[]);
        assert_eq!(code, 403);
    }

    #[test]
    fn ark_without_subdir_blocked_403() {
        let td = TempDir::new();
        let port = start_server(td.0.clone());
        let (code1, _, _) = request(port, "GET", "/ark", &[]);
        let (code2, _, _) = request(port, "GET", "/ark/", &[]);
        assert_eq!(code1, 403);
        assert_eq!(code2, 403);
    }

    #[test]
    fn put_at_ark_root_405() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/ark/test", b"x");
        assert_eq!(code, 405);
    }

    #[test]
    fn delete_at_ark_root_405() {
        let td = TempDir::new();
        ark(&td.0);
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "DELETE", "/ark/test", &[]);
        assert_eq!(code, 405);
        assert!(td.0.join("ark/test").exists());
    }

    #[test]
    fn put_outside_ark_blocked_403() {
        let td = TempDir::new();
        let port = start_server(td.0.clone());
        let (code, _, _) = request(port, "PUT", "/oops.txt", b"x");
        assert_eq!(code, 403);
        assert!(!td.0.join("oops.txt").exists());
    }
}
