use std::io::{BufRead, BufReader, Read, Result, Write};
use std::net::TcpStream;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use url::Url;

use crate::util::io_err;

const PATH_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>').add(b'?').add(b'`').add(b'{').add(b'}');

pub fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let (first_line, headers, body) = read_message(stream, false)?;

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

pub fn write_request(stream: &mut TcpStream, url: &Url, method: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
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

pub fn read_response(stream: &mut TcpStream, method: &str) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let (first_line, headers, body) = read_message(stream, method == "HEAD")?;

    let code: u16 = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io_err("no status code"))?
        .parse()
        .map_err(|_| io_err("bad status code"))?;

    Ok((code, headers, body))
}

pub fn write_response(stream: &mut TcpStream, status_code: u16, status_msg: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
    let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, status_msg);

    write_message(stream, &status_line, headers, body)
}

fn read_message(stream: &mut TcpStream, skip_body: bool) -> Result<(String, Vec<(String, String)>, Vec<u8>)> {
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
            None => return Err(io_err("Content-Length required")),
        };

        if content_length_value > 0 {
            body.resize(content_length_value, 0);
            reader.read_exact(&mut body)?;
        }
    }

    Ok((first_line, headers, body))
}

pub fn write_message(stream: &mut TcpStream, first_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<()> {
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
