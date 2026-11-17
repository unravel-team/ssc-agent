//! `ssc ui`: a small local web page for the scanner, on any OS (a browser is the only thing it needs).
//!
//! Safety: it listens on 127.0.0.1 only; requests must name that host (no DNS rebinding); the page needs the random
//! token from the link `ssc ui` prints (then kept in a cookie); every /api call must also send the token in a header,
//! which other web pages can't do (no CSRF); and the page may load nothing from anywhere else (CSP).

use serde_json::{json, Value};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::{app, done, runner, util};

const INDEX: &str = include_str!("ui/index.html");
const JS: &str = include_str!("ui/app.js");
const CSS: &str = include_str!("ui/app.css");
const MAX_BODY: usize = 1 << 20;
const MAX_HEAD: usize = 32_768;

#[derive(Default)]
struct ScanState {
    running: bool,
    folder: Option<String>,
    log: Vec<String>,
    error: Option<String>,
    finished_at: Option<String>,
}

struct Ui {
    token: String,
    port: u16,
    scan: Mutex<ScanState>,
}

impl Ui {
    /// The scan state. A panic while it was held can't leave it half-written (it holds only flags, names and log lines),
    /// so a poisoned lock is still usable.
    fn scan_state(&self) -> MutexGuard<'_, ScanState> {
        self.scan.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub fn serve(port: u16, open_browser: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let ui = Arc::new(Ui {
        token: util::random_token(),
        port,
        scan: Mutex::new(ScanState::default()),
    });
    let url = format!("http://127.0.0.1:{port}/?t={}", ui.token);
    println!("ssc UI: {url}\n(open this link; it only works on this computer. Ctrl+C to stop.)");
    if open_browser {
        app::open_path(&url);
    }
    for stream in listener.incoming().flatten() {
        let ui = ui.clone();
        std::thread::spawn(move || {
            let _ = handle(&ui, stream);
        });
    }
    Ok(())
}

struct Req {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn param(&self, name: &str) -> Option<String> {
        self.query
            .split('&')
            .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| decode(v)))
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(json!({}))
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            // two hex digits exactly (from_str_radix alone would also take "+1")
            b'%' if i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("0");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok()?;
    parse_request(stream.try_clone().ok()?)
}

/// Read one request. At most `MAX_HEAD` bytes of request line and headers and `MAX_BODY` of body are read: the
/// reader itself is capped, so a line that never ends can't fill the memory.
fn parse_request(stream: impl Read) -> Option<Req> {
    let mut r = BufReader::new(stream.take((MAX_HEAD + MAX_BODY) as u64));
    let mut line = String::new();
    let mut total = r.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next()?.to_string(), parts.next()?.to_string());
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        let n = r.read_line(&mut h).ok()?;
        total += n;
        if n == 0 || total > MAX_HEAD {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    let (path, query) = target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((target, String::new()));
    Some(Req {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    ctype: &str,
    body: &[u8],
    extra: &[(&str, String)],
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\
        Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n\
        Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; \
        base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n", body.len());
    for (k, v) in extra {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    stream.write_all(head.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.write_all(body)
}

fn json_resp(stream: &mut TcpStream, status: &str, v: &Value) -> std::io::Result<()> {
    respond(stream, status, "application/json", v.to_string().as_bytes(), &[])
}

/// The request must be for this server by name: a page on another site can't rebind its name to 127.0.0.1.
fn host_ok(host: Option<&str>, port: u16) -> bool {
    host.is_some_and(|h| h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"))
}

/// Whether the Cookie header carries this session's token.
fn cookie_has_token(cookie: Option<&str>, token: &str) -> bool {
    cookie.is_some_and(|c| {
        c.split(';')
            .filter_map(|p| p.trim().strip_prefix("ssc_ui="))
            .any(|v| same_secret(v, token))
    })
}

/// Compare a secret in constant time (for the given length), so the token can't be guessed byte by byte from timing.
fn same_secret(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn handle(ui: &Arc<Ui>, mut stream: TcpStream) -> std::io::Result<()> {
    let Some(req) = read_request(&mut stream) else {
        return Ok(());
    };
    if !host_ok(req.header("Host"), ui.port) {
        return respond(&mut stream, "421 Misdirected Request", "text/plain", b"wrong host", &[]);
    }
    let cookie_ok = cookie_has_token(req.header("Cookie"), &ui.token);
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => {
            if req.param("t").is_some_and(|t| same_secret(&t, &ui.token)) {
                let cookie = format!("ssc_ui={}; HttpOnly; SameSite=Strict; Path=/", ui.token);
                return respond(
                    &mut stream,
                    "303 See Other",
                    "text/plain",
                    b"",
                    &[("Set-Cookie", cookie), ("Location", "/".into())],
                );
            }
            if !cookie_ok {
                return respond(
                    &mut stream,
                    "403 Forbidden",
                    "text/plain; charset=utf-8",
                    "Open the link that `ssc ui` printed (it carries this session's key).".as_bytes(),
                    &[],
                );
            }
            let page = INDEX.replace("{{TOKEN}}", &ui.token);
            respond(&mut stream, "200 OK", "text/html; charset=utf-8", page.as_bytes(), &[])
        }
        ("GET", "/app.js") if cookie_ok => respond(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            JS.as_bytes(),
            &[],
        ),
        ("GET", "/app.css") if cookie_ok => {
            respond(&mut stream, "200 OK", "text/css; charset=utf-8", CSS.as_bytes(), &[])
        }
        (_, p) if p.starts_with("/api/") => {
            // the token in a custom header: only this page's own script can send it
            if !cookie_ok || !req.header("X-SSC-Token").is_some_and(|t| same_secret(t, &ui.token)) {
                return json_resp(&mut stream, "403 Forbidden", &json!({"error": "not this session"}));
            }
            let (status, out) = api(ui, &req);
            json_resp(&mut stream, status, &out)
        }
        _ => respond(&mut stream, "404 Not Found", "text/plain", b"not found", &[]),
    }
}

/// The folder's open action items (its latest scan's, minus the ticked ones): {total, block}. Null before a scan, or
/// for a result saved by an older version without action items.
fn open_items(label: &str, last: &Value) -> Value {
    let Some(dir) = last["dir"].as_str() else {
        return Value::Null;
    };
    let result: Value = std::fs::read_to_string(Path::new(dir).join("result.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let Some(actions) = result["actions"].as_array() else {
        return Value::Null;
    };
    let done = done::load(label);
    let open: Vec<&Value> = actions
        .iter()
        .filter(|a| !done.contains_key(a["key"].as_str().unwrap_or("")))
        .collect();
    json!({"total": open.len(), "block": open.iter().filter(|a| a["priority"] == "block").count()})
}

fn api(ui: &Arc<Ui>, req: &Req) -> (&'static str, Value) {
    let ok = |v: Value| ("200 OK", v);
    let bad = |m: String| ("400 Bad Request", json!({"error": m}));
    let mut cfg = app::load_config();
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/state") => {
            // first launch: get this computer's scan key from the server, so there is nothing to paste; the key
            // form stays as the fallback when the server hands out no keys
            if app::key_load().is_none() {
                if let Some(base) = cfg["api"].as_str() {
                    if let Err(e) = app::register(base) {
                        app::log(&e);
                    }
                }
            }
            let state = app::load_state();
            // /v1/health needs no key: check the server even before a key is entered
            let health = cfg["api"]
                .as_str()
                .map(|base| app::Api::with_key(base, &app::key_load().unwrap_or_default()))
                .map(|a| match a.and_then(|a| a.call("GET", "/v1/health", None)) {
                    Ok((200, _)) => "up".to_string(),
                    Ok((s, _)) => format!("answered {s}"),
                    Err(e) => e,
                });
            let fs: Vec<Value> = app::folders(&cfg)
                .into_iter()
                .map(|f| {
                    let label = app::folder_label(Path::new(&f));
                    json!({"path": f, "label": label, "exists": Path::new(&f).is_dir(), "last": state[&label],
                           "open": open_items(&label, &state[&label])})
                })
                .collect();
            ok(
                json!({"api": cfg["api"], "interval_minutes": cfg["interval_minutes"], "key_saved": app::key_load().is_some(),
                      "server": health, "background": app::service_state(), "folders": fs, "home": util::home().display().to_string(),
                      "env": cfg["_env"]}),
            )
        }
        ("POST", "/api/key") => {
            // first launch: the person pastes the scan key they were given; it is checked with the server before saving
            let key = req.json()["key"].as_str().map_or("", str::trim).to_string();
            if key.len() < 16 || key.len() > 200 || !key.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                return bad("that doesn't look like a scan key".into());
            }
            let Some(base) = cfg["api"].as_str() else {
                return bad("this app has no server address".into());
            };
            let probe = app::Api::with_key(base, &key).and_then(|a| a.call("GET", "/v1/scans?limit=1", None));
            match probe {
                Ok((200, _)) => match app::key_save(&key) {
                    Ok(()) => ok(json!({"saved": true})),
                    Err(e) => bad(e),
                },
                Ok((401 | 403, _)) => bad("the server doesn't accept this key; check you copied all of it".into()),
                Ok((s, r)) => bad(format!(
                    "the server answered {s}: {}",
                    r["error"].as_str().unwrap_or("")
                )),
                Err(e) => bad(e),
            }
        }
        ("POST", "/api/interval") => {
            // how often background scans run; reschedules them right away if they're on
            let m = req.json()["minutes"].as_u64().unwrap_or(0);
            if !app::INTERVALS.contains(&m) {
                return bad(format!("minutes: one of {:?}", app::INTERVALS));
            }
            cfg["interval_minutes"] = json!(m);
            if let Err(e) = app::save_config(&cfg) {
                return bad(e);
            }
            if app::service_state() == "installed" {
                if let Err(e) = app::install(m) {
                    return bad(e);
                }
            }
            ok(json!({"interval_minutes": m, "background": app::service_state()}))
        }
        ("POST", "/api/folders") => {
            let b = req.json();
            let Some(path) = b["path"].as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                return bad("path required".into());
            };
            let expanded = if let Some(rest) = path.strip_prefix("~/") {
                util::home().join(rest)
            } else {
                PathBuf::from(path)
            };
            let p = util::abspath(&expanded).display().to_string();
            let mut fs = app::folders(&cfg);
            if b["action"] == "remove"
                && cfg["_env"]["folders"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|f| f.as_str() == Some(path)))
            {
                return bad(format!(
                    "this folder is set in {} (SSC_FOLDERS): remove it there",
                    cfg["_env"]["file"].as_str().unwrap_or(".env")
                ));
            }
            match b["action"].as_str() {
                Some("add") => {
                    if !Path::new(&p).is_dir() {
                        return bad(format!("not a folder: {p}"));
                    }
                    if !fs.contains(&p) {
                        fs.push(p);
                    }
                }
                Some("remove") => fs.retain(|f| f != path && f != &p),
                _ => return bad("action: add or remove".into()),
            }
            cfg["folders"] = json!(fs);
            match app::save_config(&cfg) {
                Ok(()) => ok(json!({"folders": cfg["folders"]})),
                Err(e) => bad(e),
            }
        }
        ("POST", "/api/scan") => {
            let b = req.json();
            let targets: Vec<String> = match b["folder"].as_str() {
                Some(f) => vec![f.to_string()],
                None => app::folders(&cfg),
            };
            if targets.is_empty() {
                return bad("add a folder first".into());
            }
            let api = match app::Api::from_config(&cfg) {
                Ok(a) => a,
                Err(e) => return bad(e),
            };
            {
                let mut s = ui.scan_state();
                if s.running {
                    return ("409 Conflict", json!({"error": "a scan is already running"}));
                }
                *s = ScanState {
                    running: true,
                    folder: targets.first().cloned(),
                    ..Default::default()
                };
            }
            let ui2 = ui.clone();
            std::thread::spawn(move || {
                let say = |m: &str| {
                    ui2.scan_state().log.push(format!("{} {m}", &util::now_iso()[11..19]));
                };
                let result = match runner::lock() {
                    None => Err("another scan (the background one?) is running; try again in a minute".to_string()),
                    Some(_lock) => {
                        let rules = runner::rules(Some(&api));
                        let mut err = None;
                        for f in &targets {
                            ui2.scan_state().folder = Some(f.clone());
                            say(&format!("scanning {}", app::folder_label(Path::new(f))));
                            if let Err(e) = runner::scan_folder(&api, &rules, Path::new(f), &say) {
                                say(&format!("failed: {e}"));
                                err = Some(e);
                            }
                        }
                        err.map_or(Ok(()), Err)
                    }
                };
                let mut s = ui2.scan_state();
                s.running = false;
                s.error = result.err();
                s.finished_at = Some(util::now_iso());
            });
            ok(json!({"started": true}))
        }
        ("GET", "/api/scan") => {
            let s = ui.scan_state();
            ok(
                json!({"running": s.running, "folder": s.folder, "log": s.log, "error": s.error, "finished_at": s.finished_at}),
            )
        }
        ("GET", "/api/result") => {
            let label = req.param("label").unwrap_or_default();
            let st = app::load_state();
            let Some(dir) = st[&label]["dir"].as_str() else {
                return ("404 Not Found", json!({"error": "no result for this folder yet"}));
            };
            let read = |f: &str| std::fs::read_to_string(Path::new(dir).join(f)).unwrap_or_default();
            let result: Value = serde_json::from_str(&read("result.json")).unwrap_or(json!({}));
            ok(
                json!({"label": label, "dir": dir, "advice_md": read("ADVICE.md"), "result": result,
                      "done": done::load(&label)}),
            )
        }
        ("POST", "/api/done") => {
            // set one action item's state (done, skipped with a reason, or pending); the row is taken from the saved
            // result (or the earlier record), not from the request
            let b = req.json();
            let (label, key) = (b["label"].as_str().unwrap_or(""), b["key"].as_str().unwrap_or(""));
            let st = app::load_state();
            let Some(dir) = st[label]["dir"].as_str() else {
                return bad("no result for this folder yet".into());
            };
            let result: Value = std::fs::read_to_string(Path::new(dir).join("result.json"))
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or(json!({}));
            let earlier = done::load(label);
            let row = result["actions"]
                .as_array()
                .and_then(|a| a.iter().find(|r| r["key"] == key).cloned())
                .or_else(|| earlier.get(key).map(|d| d["row"].clone()));
            let Some(row) = row else {
                return bad("unknown action item".into());
            };
            // "state" from this app; an older page sends "done": true/false
            let state = b["state"]
                .as_str()
                .unwrap_or(if b["done"].as_bool().unwrap_or(true) { "done" } else { "pending" });
            match done::set_state(label, key, state, b["why"].as_str().unwrap_or(""), &row) {
                Ok(()) => ok(json!({"done": done::load(label)})),
                Err(e) => bad(e),
            }
        }
        ("POST", "/api/background") => {
            let b = req.json();
            match b["action"].as_str() {
                Some("install") => {
                    let m = b["interval_minutes"]
                        .as_u64()
                        .or_else(|| cfg["interval_minutes"].as_u64())
                        .unwrap_or(60)
                        .max(5);
                    if app::folders(&cfg).is_empty() {
                        return bad("add a folder first".into());
                    }
                    if app::Api::from_config(&cfg).is_err() {
                        return bad("save the server and key first".into());
                    }
                    cfg["interval_minutes"] = json!(m);
                    if let Err(e) = app::save_config(&cfg) {
                        return bad(e);
                    }
                    match app::install(m) {
                        Ok(s) => ok(json!({"message": s})),
                        Err(e) => bad(e),
                    }
                }
                Some("uninstall") => ok(json!({"message": app::uninstall()})),
                _ => bad("action: install or uninstall".into()),
            }
        }
        ("POST", "/api/open") => {
            let b = req.json();
            let st = app::load_state();
            match st[b["label"].as_str().unwrap_or("")]["dir"].as_str() {
                Some(d) => {
                    app::open_path(d);
                    ok(json!({"opened": d}))
                }
                None => bad("no result folder yet".into()),
            }
        }
        _ => ("404 Not Found", json!({"error": "unknown"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Option<Req> {
        parse_request(raw)
    }

    #[test]
    fn parses_method_path_query_headers_and_body() {
        let r = parse(
            b"POST /api/key?x=1&t=a%20b+c HTTP/1.1\r\nHost: 127.0.0.1:8790\r\nX-SSC-Token: tok\r\n\
                        Content-Length: 11\r\n\r\n{\"key\":\"k\"}",
        )
        .unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/api/key"));
        assert_eq!(r.param("t").as_deref(), Some("a b c"));
        assert_eq!(r.param("x").as_deref(), Some("1"));
        assert_eq!(r.param("missing"), None);
        assert_eq!(r.header("x-ssc-token"), Some("tok"));
        assert_eq!(r.json()["key"], "k");
    }

    #[test]
    fn a_body_that_is_not_json_reads_as_an_empty_object() {
        let r = parse(b"POST /api/scan HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(r.json(), json!({}));
    }

    #[test]
    fn refuses_oversized_or_unfinished_requests() {
        let too_big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert!(parse(too_big.as_bytes()).is_none());
        let mut huge_header = b"GET / HTTP/1.1\r\nX: ".to_vec();
        huge_header.extend(std::iter::repeat_n(b'a', MAX_HEAD + 10));
        huge_header.extend_from_slice(b"\r\n\r\n");
        assert!(parse(&huge_header).is_none());
        // a request line that never ends is cut off by the read cap instead of filling the memory
        let endless = vec![b'G'; MAX_HEAD + MAX_BODY + 100];
        assert!(parse(&endless).is_none());
        assert!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none()); // no blank line
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").is_none());
        assert!(parse(b"").is_none());
        assert!(parse(b"GARBAGE\r\n\r\n").is_none());
    }

    #[test]
    fn percent_decoding_needs_two_hex_digits() {
        assert_eq!(decode("a%2Fb%41"), "a/bA");
        assert_eq!(decode("%+1x"), "% 1x"); // not 0x01: "+1" is not two hex digits; "+" is a space
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%4"), "%4");
        assert_eq!(decode("%zz"), "%zz");
        assert_eq!(decode("%e2%9c%93"), "✓");
    }

    #[test]
    fn host_must_name_this_server() {
        assert!(host_ok(Some("127.0.0.1:8790"), 8790));
        assert!(host_ok(Some("localhost:8790"), 8790));
        for bad in [
            "evil.example:8790",
            "127.0.0.1:8791",
            "127.0.0.1",
            "localhost.evil.example:8790",
            "",
        ] {
            assert!(!host_ok(Some(bad), 8790), "{bad}");
        }
        assert!(!host_ok(None, 8790));
    }

    #[test]
    fn the_cookie_must_carry_the_exact_token() {
        let tok = "0123456789abcdef0123456789abcdef";
        assert!(cookie_has_token(Some(&format!("ssc_ui={tok}")), tok));
        assert!(cookie_has_token(Some(&format!("a=1; ssc_ui={tok}; b=2")), tok));
        assert!(!cookie_has_token(Some(&format!("ssc_ui={tok}x")), tok));
        assert!(!cookie_has_token(Some(&format!("xssc_ui={tok}")), tok));
        assert!(!cookie_has_token(Some("ssc_ui="), tok));
        assert!(!cookie_has_token(None, tok));
    }

    #[test]
    fn secrets_compare_exactly() {
        assert!(same_secret("abc", "abc"));
        assert!(!same_secret("abd", "abc"));
        assert!(!same_secret("ab", "abc"));
        assert!(!same_secret("", "abc"));
    }
}
