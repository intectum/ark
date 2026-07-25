use std::io::{BufRead, BufReader, Read, Result, Write};

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use url::Url;

use crate::types::StreamEvent;
use crate::util::io_err;

const PATH_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>').add(b'?').add(b'`').add(b'{').add(b'}');

pub fn read_request(stream: &mut dyn Read, skip_body: bool) -> Result<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let (first_line, headers, body) = read_message(stream, skip_body)?;

    let request_line_parts: Vec<&str> = first_line.trim_end().split_whitespace().collect();
    if request_line_parts.len() != 3 {
        return Err(io_err("bad request line"));
    }

    let method = request_line_parts[0].to_string();

    let target = percent_decode_str(request_line_parts[1])
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| io_err("invalid percent-encoded path"))?;

    Ok((method, target, headers, body))
}

pub fn write_request(stream: &mut dyn Write, url: &Url, method: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
    let host = url.host_str().ok_or_else(|| io_err("URL missing host"))?;
    let request_line = format!("{} {} HTTP/1.1\r\n", method, utf8_percent_encode(url.path(), PATH_ENCODE_SET));

    let mut final_headers = headers.to_vec();

    let hostname = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };
    final_headers.push(("Host", &hostname));

    write_message(stream, &request_line, &final_headers, body)
}

pub fn read_response(stream: &mut dyn Read, skip_body: bool) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let (first_line, headers, body) = read_message(stream, skip_body)?;

    let code: u16 = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io_err("no status code"))?
        .parse()
        .map_err(|_| io_err("bad status code"))?;

    Ok((code, headers, body))
}

pub fn write_response(stream: &mut dyn Write, status_code: u16, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
    let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, status_msg(status_code));

    write_message(stream, &status_line, headers, body)
}

pub fn write_text(stream: &mut dyn Write, status_code: u16, body: &[u8]) -> Result<()> {
    write_response(stream, status_code, &[("Content-Type", "text/plain"), ("Connection", "close")], body)
}

pub fn write_stream_start(stream: &mut dyn Write) -> std::io::Result<()> {
    stream.write_all(b"HTTP/1.1 200 OK\r\n")?;
    stream.write_all(b"Content-Type: text/event-stream\r\n")?;
    stream.write_all(b"Cache-Control: no-cache\r\n")?;
    stream.write_all(b"Connection: keep-alive\r\n")?;
    stream.write_all(b"X-Accel-Buffering: no\r\n")?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

pub fn read_stream_events<F>(stream: &mut dyn Read, on_event: &mut F) -> std::io::Result<()>
where
    F: FnMut(&StreamEvent) -> std::io::Result<()>,
{
    let mut reader = BufReader::new(stream);

    let mut status = String::new();
    if reader.read_line(&mut status)? == 0 {
        return Err(io_err("connection closed before status"));
    }

    if !status.starts_with("HTTP/1.1 200") {
        return Err(io_err(&format!("stream open failed: {}", status.trim_end())));
    }

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io_err("connection closed in headers"));
        }
        if line.trim_end_matches(&['\r', '\n'][..]).is_empty() { break; }
    }

    let mut event = StreamEvent::default();

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io_err("stream closed"));
        }
        let line = line.trim_end_matches(&['\r', '\n'][..]);

        if line.is_empty() {
            if !event.data.is_empty() {
                on_event(&event)?;
            }
            event = StreamEvent::default();
            continue;
        }

        if line.starts_with(':') { continue; }

        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };

        match field {
            "id" => event.id = value.to_string(),
            "event" => event.event = value.to_string(),
            "data" => {
                if !event.data.is_empty() { event.data.push('\n'); }
                event.data.push_str(value);
            }
            _ => {}
        }
    }
}

pub fn write_stream_event(stream: &mut dyn Write, id: &str, event: &str, data: &str) -> std::io::Result<()> {
    write!(stream, "id: {}\nevent: {}\ndata: {}\n\n", id, event, data)?;
    stream.flush()
}

pub fn write_stream_keepalive(stream: &mut dyn Write) -> std::io::Result<()> {
    stream.write_all(b": keepalive\n\n")?;
    stream.flush()
}

fn read_message(stream: &mut dyn Read, skip_body: bool) -> Result<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut reader = BufReader::new(stream);

    let mut first_line = String::new();
    if reader.read_line(&mut first_line)? == 0 {
        return Err(io_err("empty message"));
    }

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let content_length = headers.iter().find_map(|(name, value)| if name.eq_ignore_ascii_case("content-length") { Some(value) } else { None });

    let mut body = Vec::new();
    if !skip_body {
        let content_length_value: usize = match content_length {
            Some(t) => t.parse().unwrap_or(0),
            None => 0,
        };

        if content_length_value > 0 {
            body.resize(content_length_value, 0);
            reader.read_exact(&mut body)?;
        }
    }

    Ok((first_line, headers, body))
}

pub fn write_message(stream: &mut dyn Write, first_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
    stream.write_all(first_line.as_bytes())?;

    let mut final_headers = headers.to_vec();

    let len = body.len().to_string();
    if !final_headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("Content-Length")) {
        final_headers.push(("Content-Length", &len));
    }

    final_headers.sort_by_key(|h| h.0);

    for (name, value) in final_headers {
        stream.write_all(format!("{}: {}\r\n", name, value).as_bytes())?;
    }

    stream.write_all("\r\n".as_bytes())?;

    if !body.is_empty() {
        stream.write_all(body)?;
    }

    Ok(())
}

fn status_msg(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}
