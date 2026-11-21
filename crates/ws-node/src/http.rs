//! The smallest HTTP/1.1 that the gateway and the node-to-node calls need: one request per connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub type Reply = (u16, &'static str, Vec<u8>);

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Req {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn q(&self, k: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).map(|(_, v)| v.to_string()))
    }
}

pub fn serve<F>(listen: &str, f: F)
where
    F: Fn(&Req) -> Reply + Send + Sync + 'static,
{
    let l = TcpListener::bind(listen).unwrap_or_else(|e| panic!("bind {listen}: {e}"));
    let f = Arc::new(f);
    for s in l.incoming().flatten() {
        let f = f.clone();
        std::thread::spawn(move || {
            let _ = one(s, &*f);
        });
    }
}

fn one(mut s: TcpStream, f: &dyn Fn(&Req) -> Reply) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("/").to_string());
    let mut len = 0usize;
    let mut headers = vec![];
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if len > 64 << 20 {
        return Ok(());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let req = Req { method, path: path.to_string(), query: query.to_string(), headers, body: String::from_utf8_lossy(&body).into_owned() };
    let (code, ctype, out) = f(&req);
    let status = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Not Found",
    };
    write!(s, "HTTP/1.1 {code} {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n", out.len())?;
    s.write_all(&out)?;
    Ok(())
}

pub fn request(method: &str, url: &str, path: &str, body: &str, secs: u64) -> Result<String, String> {
    let hostport = url.trim_start_matches("http://").trim_end_matches('/');
    let addr = hostport.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("{hostport}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(secs))).ok();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out);
    let (head, rest) = text.split_once("\r\n\r\n").ok_or("bad response")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    Ok(rest.to_string())
}

pub fn static_file(dir: &str, path: &str) -> Reply {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.contains("..") {
        return (404, "text/plain", "not found".into());
    }
    let ctype = match rel.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    match std::fs::read(std::path::Path::new(dir).join(rel)) {
        Ok(b) => (200, ctype, b),
        Err(_) => (404, "text/plain", "not found".into()),
    }
}
