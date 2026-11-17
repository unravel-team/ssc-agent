//! The app around the scanner: settings, the API key, talking to the sources API (through the system's curl),
//! saving results, and background scans (launchd on macOS, a systemd user timer on Linux, Task Scheduler on Windows).

use serde_json::{json, Value};
use std::fmt::Write as _; // write!/writeln! into Strings (which can't fail)
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::{abspath, home, now_iso, run};

pub const RULES_BUILTIN: &str = include_str!("../../intel_api/config/scanner_rules.json");
/// The company server, built into the binary for distribution: `SSC_BUILD_API_URL=https://... cargo build --release`
/// (a .env file or `ssc init` can still point elsewhere).
pub const BUILT_IN_API: Option<&str> = option_env!("SSC_BUILD_API_URL");
const LABEL: &str = "local.ssc.scanner";

pub fn dir() -> PathBuf {
    std::env::var("SSC_HOME").map_or_else(|_| home().join(".ssc"), PathBuf::from)
}

// ---------------------------------------------------------------- settings and state
pub fn config_path() -> PathBuf {
    dir().join("ssc.json")
}

/// Settings saved by `ssc init` / the UI (~/.ssc/ssc.json), without the .env file.
fn load_saved() -> Value {
    let mut c = json!({"api": null, "folders": [], "interval_minutes": 60});
    if let Ok(t) = std::fs::read_to_string(config_path()) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&t) {
            for (k, v) in m {
                c[k] = v;
            }
        }
    }
    c
}

// ---------------------------------------------------------------- the .env file (server, certificate, key, folders)
pub const INTERVALS: [u64; 7] = [15, 30, 60, 120, 240, 480, 1440]; // the background-scan choices offered

/// The .env file with the scanner's settings: `$SSC_ENV` (or `--env`), else a .env holding `SSC_` settings next to the
/// binary or up to three folders above it (scanner/.env when run from the project), else ~/.ssc/.env.
pub fn env_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SSC_ENV") {
        return Some(abspath(Path::new(&p))).filter(|p| p.is_file());
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        let mut d = exe.parent().map(Path::to_path_buf);
        for _ in 0..4 {
            if let Some(dir) = d {
                candidates.push(dir.join(".env"));
                d = dir.parent().map(Path::to_path_buf);
            }
        }
    }
    candidates.push(dir().join(".env"));
    candidates
        .into_iter()
        .find(|p| p.is_file() && std::fs::read_to_string(p).is_ok_and(|t| t.contains("SSC_API_URL")))
}

/// SSC_* settings from the .env file (only keys starting with SSC_; quotes stripped). Environment variables win.
pub fn env_settings() -> (Option<PathBuf>, std::collections::BTreeMap<String, String>) {
    let mut out = std::collections::BTreeMap::new();
    let file = env_file();
    if let Some(f) = &file {
        for line in std::fs::read_to_string(f).unwrap_or_default().lines() {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim().trim_matches(|c| c == '"' || c == '\''));
                if k.starts_with("SSC_") && !v.is_empty() {
                    out.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    for k in ["SSC_API_URL", "SSC_API_KEY", "SSC_FOLDERS"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                out.insert(k.to_string(), v);
            }
        }
    }
    (file, out)
}

/// A path from the .env file: ~ is the home folder; relative paths are relative to the .env file's folder.
fn env_path(file: Option<&PathBuf>, p: &str) -> String {
    let expanded = if let Some(rest) = p.strip_prefix("~/") {
        home().join(rest)
    } else {
        PathBuf::from(p)
    };
    let base = file.and_then(|f| f.parent().map(Path::to_path_buf)).unwrap_or_default();
    abspath(&if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    })
    .display()
    .to_string()
}

/// The settings in effect: the .env file (and SSC_* environment variables) over the saved ones.
/// `_env` says which settings came from where, so they can be shown and are never written to ssc.json.
pub fn load_config() -> Value {
    let mut c = load_saved();
    if c["api"].is_null() {
        if let Some(u) = BUILT_IN_API.filter(|u| !u.is_empty()) {
            c["api"] = json!(u.trim_end_matches('/'));
        }
    }
    let (file, env) = env_settings();
    let mut from_env = Vec::new();
    if let Some(v) = env.get("SSC_API_URL") {
        c["api"] = json!(v.trim_end_matches('/'));
        from_env.push("api");
    }
    let mut env_folders = Vec::new();
    if let Some(v) = env.get("SSC_FOLDERS") {
        env_folders = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| env_path(file.as_ref(), s))
            .collect();
        let mut fs: Vec<Value> = env_folders.iter().map(|s| json!(s)).collect();
        for f in c["folders"].as_array().cloned().unwrap_or_default() {
            if !fs.contains(&f) {
                fs.push(f);
            }
        }
        c["folders"] = Value::Array(fs);
    }
    if env.contains_key("SSC_API_KEY") {
        from_env.push("key");
    }
    c["_env"] = json!({"file": file.map(|f| f.display().to_string()), "settings": from_env, "folders": env_folders});
    c
}

/// Save settings, leaving out everything that comes from the .env file.
pub fn save_config(cfg: &Value) -> Result<(), String> {
    let mut saved = load_saved();
    let env = &cfg["_env"];
    let from_env = |k: &str| env["settings"].as_array().is_some_and(|a| a.iter().any(|x| x == k));
    if !from_env("api") {
        saved["api"] = cfg["api"].clone();
    }
    saved["interval_minutes"] = cfg["interval_minutes"].clone();
    if let Some(m) = saved.as_object_mut() {
        m.remove("ca"); // a setting earlier versions had
    }
    let env_folders = env["folders"].as_array().cloned().unwrap_or_default();
    saved["folders"] = Value::Array(
        cfg["folders"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|f| !env_folders.contains(f))
            .collect(),
    );
    save_json(&config_path(), &saved)
}

pub fn save_json(path: &Path, v: &Value) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, text + "\n").map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// The folders to scan, from the settings in effect.
pub fn folders(cfg: &Value) -> Vec<String> {
    cfg["folders"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

pub fn load_state() -> Value {
    std::fs::read_to_string(dir().join("state.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(json!({}))
}

/// How a folder is named to the server: its path with the home folder as "~" (no user name), unique per folder.
pub fn folder_label(folder: &Path) -> String {
    let abs = abspath(folder);
    match abs.strip_prefix(home()) {
        Ok(r) => format!("~/{}", r.display()).replace('\\', "/"),
        Err(_) => abs.display().to_string().replace('\\', "/"),
    }
}

// ---------------------------------------------------------------- the API key: a file only this user can read
fn key_path() -> PathBuf {
    dir().join("key")
}

pub fn key_save(key: &str) -> Result<(), String> {
    crate::util::write_private(&key_path(), key).map_err(|e| format!("saving the key: {e}"))
}

pub fn key_load() -> Option<String> {
    if let Some(k) = env_settings().1.remove("SSC_API_KEY") {
        return Some(k); // from the .env file (or the environment)
    }
    std::fs::read_to_string(key_path())
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

// ---------------------------------------------------------------- the API (the system's curl; the key goes in on stdin, never on the command line)
// HTTPS certificates are checked against what the operating system trusts: no certificate setting in the app.
pub struct Api {
    pub base: String,
    key: String,
}

/// Whether the key may be sent to `url`: HTTPS, or plain HTTP only to this computer (the local test stack).
/// The host is compared exactly, so `http://localhost.example.com` is refused.
pub fn api_url_allowed(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    !authority.contains('@') && matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// A key as it can go into curl's config: printable ASCII without quotes or backslashes (curl would read those
/// as config syntax; a line break would let a key add curl options). Empty is allowed: /v1/health needs no key.
fn key_is_safe(key: &str) -> bool {
    key.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// A request body file name that no other request (this process's UI threads included) is using.
fn body_file_path() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    dir().join("tmp").join(format!("body-{}-{n}.json", std::process::id()))
}

impl Api {
    /// The API with the saved key; with no key yet, this computer gets one from the server first (register).
    pub fn from_config(cfg: &Value) -> Result<Api, String> {
        let base = cfg["api"].as_str().ok_or("no API set: ssc init --api https://...")?;
        let key = match key_load() {
            Some(k) => k,
            None => register(base)?,
        };
        Api::with_key(base, &key)
    }

    pub fn with_key(base: &str, key: &str) -> Result<Api, String> {
        let base = base.trim_end_matches('/');
        if !api_url_allowed(base) {
            return Err(format!(
                "the API must be https:// (plain http only for 127.0.0.1): {base}"
            ));
        }
        Ok(Api {
            base: base.to_string(),
            key: key.to_string(),
        })
    }

    /// One request to the API. `path` must be a path on the API's server ("/v1/..."): paths that come from the
    /// server's answers (the poll link) are checked so the key can't be sent to another host.
    pub fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        if !path.starts_with('/') || path.starts_with("//") || path.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!("refusing an API path that isn't on {}: {path:?}", self.base));
        }
        if !key_is_safe(&self.key) {
            return Err(
                "the API key has characters a key can't have (spaces, quotes, backslashes or control characters)"
                    .into(),
            );
        }
        let url = format!("{}{}", self.base, path);
        let mut args: Vec<String> = [
            "-sS",
            "--max-time",
            "90",
            "--proto",
            "=https,http",
            "-X",
            method,
            "-K",
            "-",
            "-w",
            "\n%{http_code}",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let body_file = match body {
            Some(b) => {
                let f = body_file_path();
                let text = serde_json::to_string(b).map_err(|e| e.to_string())?;
                crate::util::write_private(&f, &text).map_err(|e| e.to_string())?;
                args.extend([
                    "-H".into(),
                    "Content-Type: application/json".into(),
                    "--data-binary".into(),
                    format!("@{}", f.display()),
                ]);
                Some(f)
            }
            None => None,
        };
        args.push(url);
        // no key yet (registering, or the health check): no Authorization header at all
        let config = if self.key.is_empty() {
            String::new()
        } else {
            format!("header = \"Authorization: Bearer {}\"\n", self.key)
        };
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let curl = if cfg!(windows) { "curl.exe" } else { "curl" };
        let (ok, out, err) = run(curl, &refs, Some(config.as_bytes()));
        if let Some(f) = body_file {
            let _ = std::fs::remove_file(f);
        }
        if !ok && out.is_empty() {
            let why = if err.contains("No such file") || err.contains("not found") || err.contains("cannot find") {
                "curl is not installed (it ships with macOS and Windows 10+; on Linux install the curl package)"
                    .to_string()
            } else {
                err.trim().to_string()
            };
            return Err(format!("can't reach the sources API at {}: {}", self.base, why));
        }
        let (text, code) = out.rsplit_once('\n').unwrap_or(("", out.as_str()));
        let status: u16 = code.trim().parse().unwrap_or(0);
        let v =
            serde_json::from_str(text).unwrap_or_else(|_| json!({"error": text.chars().take(300).collect::<String>()}));
        Ok((status, v))
    }
}

/// Get a scan key for this computer from the server (POST /v1/register) and save it: nobody has to hand keys out.
/// The key can only send scans and read this computer's own results.
pub fn register(base: &str) -> Result<String, String> {
    let api = Api::with_key(base, "")?;
    let (st, r) = api.call("POST", "/v1/register", Some(&json!({"device_name": crate::util::device_name()})))?;
    if st != 200 {
        return Err(format!(
            "no scan key saved, and the server didn't hand one out ({st}): {}",
            r["error"].as_str().unwrap_or("")
        ));
    }
    let key = r["key"].as_str().unwrap_or("").to_string();
    if key.len() < 16 || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("the server's answer to /v1/register had no usable key".into());
    }
    key_save(&key)?;
    Ok(key)
}

// ---------------------------------------------------------------- results
/// One safe path component: letters, digits, "-", "." and "_" only, never "", "." or "..".
fn path_component(s: &str, fallback: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.chars().all(|c| c == '.') {
        fallback.to_string()
    } else {
        clean
    }
}

/// Where a scan's result is saved. The scan id comes from the server, so it is cleaned like the label: it can't
/// name a folder outside ~/.ssc/results.
pub fn results_dir(label: &str, scan_id: &str) -> PathBuf {
    folder_results(label).join(path_component(scan_id, "scan"))
}

/// One folder's results: a sub-folder per scan, plus done.json (the ticked action items).
pub fn folder_results(label: &str) -> PathBuf {
    dir()
        .join("results")
        .join(path_component(path_component(label, "_").trim_matches('_'), "_"))
}

/// The advisory to show: the agents' one, or (when there is none) a note with the action items from the rules.
fn advice_text(r: &Value) -> String {
    if let Some(a) = r["advice"].as_str() {
        return a.to_string();
    }
    let mut s = format!(
        "# Supply-chain check: {}\n\nNo written advisory ({}{}). Action items from the rules:\n\n",
        r["folder"].as_str().unwrap_or(""),
        r["advice_status"].as_str().unwrap_or("none"),
        r["error"].as_str().map(|e| format!(": {e}")).unwrap_or_default()
    );
    s += "| Priority | Project | Item | Where | Action |\n|---|---|---|---|---|\n";
    let cell = |v: &Value| v.as_str().unwrap_or("").replace('|', "/");
    for a in r["actions"].as_array().into_iter().flatten() {
        let wh: Vec<&str> = a["where"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} |",
            if a["priority"] == "block" { "Fix now" } else { "Review" },
            cell(&a["project"]),
            cell(&a["item"]),
            wh.join(", ").replace('|', "/"),
            cell(&a["action"])
        );
    }
    s
}

pub fn save_result(label: &str, r: &Value) -> Result<PathBuf, String> {
    let d = results_dir(label, r["id"].as_str().unwrap_or("scan"));
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    std::fs::write(d.join("ADVICE.md"), advice_text(r)).map_err(|e| e.to_string())?;
    save_json(&d.join("plan.json"), &r["plan"])?;
    save_json(&d.join("result.json"), r)?;
    Ok(d)
}

// ---------------------------------------------------------------- background scans (one installer per OS)
fn uid() -> String {
    run("id", &["-u"], None).1.trim().to_string()
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Copy this binary to ~/.ssc/bin and register it to run `scan --background` every `minutes`.
pub fn install(minutes: u64) -> Result<String, String> {
    let bin = dir().join("bin").join(if cfg!(windows) { "ssc.exe" } else { "ssc" });
    std::fs::create_dir_all(bin.parent().unwrap()).map_err(|e| e.to_string())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if abspath(&me) != abspath(&bin) {
        // a new file swapped in, never a copy over the old one: a background scan may be running from it, and
        // macOS kills a process whose binary is rewritten in place
        let tmp = bin.with_extension("new");
        std::fs::copy(&me, &tmp).map_err(|e| format!("copy to {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &bin).map_err(|e| format!("replace {}: {e}", bin.display()))?;
    }
    let log = dir().join("logs").join("scanner.log");
    std::fs::create_dir_all(log.parent().unwrap()).map_err(|e| e.to_string())?;
    let (b, l) = (bin.display().to_string(), log.display().to_string());
    let envf = env_file().map(|f| f.display().to_string());
    let env_args: Vec<String> = envf.iter().flat_map(|f| ["--env".to_string(), f.clone()]).collect();
    if cfg!(target_os = "macos") {
        let p = home().join("Library/LaunchAgents").join(format!("{LABEL}.plist"));
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{}</string>{}<string>scan</string><string>--background</string></array>
  <key>StartInterval</key><integer>{}</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
</dict>
</plist>
"#,
            xml(&b),
            env_args.iter().fold(String::new(), |mut s, a| {
                let _ = write!(s, "<string>{}</string>", xml(a));
                s
            }),
            minutes.saturating_mul(60),
            xml(&l),
            xml(&l)
        );
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&p, plist).map_err(|e| e.to_string())?;
        let target = format!("gui/{}", uid());
        let _ = run("launchctl", &["bootout", &format!("{target}/{LABEL}")], None);
        let (ok, _, err) = run("launchctl", &["bootstrap", &target, &p.display().to_string()], None);
        if !ok {
            return Err(format!("launchctl: {}", err.trim()));
        }
    } else if cfg!(windows) {
        let tr = format!(
            "\"{b}\"{} scan --background",
            envf.as_ref().map(|f| format!(" --env \"{f}\"")).unwrap_or_default()
        );
        // schtasks takes 1-1439 for MINUTE: a day (the 1440 choice) or more is a DAILY schedule
        let (sc, mo) = if minutes >= 1440 {
            ("DAILY", (minutes / 1440).to_string())
        } else {
            ("MINUTE", minutes.to_string())
        };
        let (ok, _, err) = run(
            "schtasks",
            &["/Create", "/F", "/SC", sc, "/MO", &mo, "/TN", "ssc-scanner", "/TR", &tr],
            None,
        );
        if !ok {
            return Err(format!("schtasks: {}", err.trim()));
        }
    } else {
        let d = home().join(".config/systemd/user");
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        // "%" starts a specifier in unit files: a path with one in it must say "%%"
        let unit = |s: &str| s.replace('%', "%%");
        let env_arg = envf
            .as_ref()
            .map(|f| format!(" --env \"{}\"", unit(f)))
            .unwrap_or_default();
        let service = format!(
            "[Unit]\nDescription=ssc supply-chain scan\n\n[Service]\nType=oneshot\n\
             ExecStart=\"{}\"{env_arg} scan --background\nStandardOutput=append:{l2}\nStandardError=append:{l2}\n",
            unit(&b),
            l2 = unit(&l),
        );
        std::fs::write(d.join("ssc-scanner.service"), service).map_err(|e| e.to_string())?;
        let timer = format!(
            "[Unit]\nDescription=ssc supply-chain scan every {minutes} min\n\n[Timer]\nOnBootSec=2min\n\
             OnUnitActiveSec={minutes}min\n\n[Install]\nWantedBy=timers.target\n"
        );
        std::fs::write(d.join("ssc-scanner.timer"), timer).map_err(|e| e.to_string())?;
        let _ = run("systemctl", &["--user", "daemon-reload"], None);
        let (ok, _, err) = run("systemctl", &["--user", "enable", "--now", "ssc-scanner.timer"], None);
        if !ok {
            return Err(format!("systemctl: {}", err.trim()));
        }
    }
    Ok(format!("installed {b} (scans every {minutes} min, log {l})"))
}

pub fn uninstall() -> String {
    if cfg!(target_os = "macos") {
        let _ = run("launchctl", &["bootout", &format!("gui/{}/{LABEL}", uid())], None);
        let _ = std::fs::remove_file(home().join("Library/LaunchAgents").join(format!("{LABEL}.plist")));
    } else if cfg!(windows) {
        let _ = run("schtasks", &["/Delete", "/F", "/TN", "ssc-scanner"], None);
    } else {
        let _ = run("systemctl", &["--user", "disable", "--now", "ssc-scanner.timer"], None);
        let d = home().join(".config/systemd/user");
        let _ = std::fs::remove_file(d.join("ssc-scanner.timer"));
        let _ = std::fs::remove_file(d.join("ssc-scanner.service"));
    }
    format!(
        "background scans stopped and removed; settings and results are kept in {}",
        dir().display()
    )
}

pub fn service_state() -> String {
    let installed = if cfg!(target_os = "macos") {
        run("launchctl", &["print", &format!("gui/{}/{LABEL}", uid())], None).0
    } else if cfg!(windows) {
        run("schtasks", &["/Query", "/TN", "ssc-scanner"], None).0
    } else {
        run("systemctl", &["--user", "is-enabled", "ssc-scanner.timer"], None).0
    };
    if installed {
        "installed".into()
    } else {
        "not installed".into()
    }
}

/// Open a file or URL with the system's default app.
pub fn open_path(target: &str) {
    let _ = if cfg!(target_os = "macos") {
        run("open", &[target], None)
    } else if cfg!(windows) {
        run("cmd", &["/C", "start", "", target], None)
    } else {
        run("xdg-open", &[target], None)
    };
}

pub fn log(msg: &str) {
    println!("{} {msg}", now_iso());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Component;

    #[test]
    fn the_key_only_goes_to_https_or_this_computer() {
        for ok in [
            "https://intel.example.com",
            "https://intel.example.com:8443/base",
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://localhost",
            "http://[::1]:8787",
        ] {
            assert!(api_url_allowed(ok), "{ok}");
        }
        for bad in [
            "http://intel.example.com",
            "http://localhost.evil.example", // passed the old starts_with check
            "http://127.0.0.1.evil.example", // so did this
            "http://127.0.0.1@evil.example", // user info: the host is evil.example
            "http://localhost:80@evil.example",
            "ftp://127.0.0.1",
            "",
            "intel.example.com",
        ] {
            assert!(!api_url_allowed(bad), "{bad}");
        }
        assert!(Api::with_key("http://evil.example", "k").is_err());
        assert_eq!(
            Api::with_key("https://x.example/", "k").unwrap().base,
            "https://x.example"
        );
    }

    #[test]
    fn keys_that_could_change_curls_config_are_refused() {
        assert!(key_is_safe("sk_live-abc.DEF_123"));
        assert!(key_is_safe(""));
        for bad in ["a\"b", "a\\b", "a\nurl = http://evil", "a b", "a\tb", "ключ"] {
            assert!(!key_is_safe(bad), "{bad:?}");
        }
    }

    #[test]
    fn api_paths_must_stay_on_the_server() {
        // refused before curl runs, so this needs no network
        let a = Api::with_key("https://intel.example.invalid", "k").unwrap();
        for bad in [
            "@evil.example/x",
            ".evil.example/x",
            "//evil.example/x",
            "",
            "v1/scans",
            "/v1/x y",
            "/v1/\n",
        ] {
            let e = a.call("GET", bad, None).unwrap_err();
            assert!(e.starts_with("refusing"), "{bad:?}: {e}");
        }
        let bad_key = Api::with_key("https://intel.example.invalid", "a\nb").unwrap();
        assert!(bad_key
            .call("GET", "/v1/health", None)
            .unwrap_err()
            .contains("characters"));
    }

    #[test]
    fn results_stay_inside_the_results_folder() {
        let root = dir().join("results");
        for (label, id) in [
            ("~/code", "../../../../etc"),
            ("~/code", ".."),
            ("~/code", "a/../../b"),
            ("/", ""),
            ("..", "."),
            ("~/c", "scan_20261110-01.x"),
        ] {
            let d = results_dir(label, id);
            let rest = d.strip_prefix(&root).unwrap();
            assert_eq!(rest.components().count(), 2, "{label} {id} -> {}", d.display());
            assert!(
                rest.components().all(|c| matches!(c, Component::Normal(_))),
                "{label} {id} -> {}",
                d.display()
            );
        }
        // normal ids and labels are kept as they were
        assert_eq!(
            results_dir("~/code/app", "scan_1-a.b"),
            root.join("code_app").join("scan_1-a.b")
        );
        assert_eq!(results_dir("~/code", ""), root.join("code").join("scan"));
    }

    #[test]
    fn env_paths_expand_home_and_are_relative_to_the_env_file() {
        let envf = PathBuf::from("/etc/ssc/.env");
        assert_eq!(
            env_path(Some(&envf), "projects"),
            abspath(Path::new("/etc/ssc/projects")).display().to_string()
        );
        assert_eq!(
            env_path(Some(&envf), "/abs/p"),
            abspath(Path::new("/abs/p")).display().to_string()
        );
        assert_eq!(env_path(None, "~/code"), home().join("code").display().to_string());
    }

    #[test]
    fn folder_labels_hide_the_user_name() {
        assert_eq!(folder_label(&home().join("code").join("app")), "~/code/app");
        let outside = if cfg!(windows) { "C:\\ssc-test" } else { "/ssc-test" };
        assert_eq!(folder_label(Path::new(outside)), outside.replace('\\', "/"));
    }

    #[test]
    fn folders_reads_only_strings() {
        let cfg = json!({"folders": ["/a", 3, null, "/b"]});
        assert_eq!(folders(&cfg), vec!["/a", "/b"]);
        assert_eq!(folders(&json!({})), Vec::<String>::new());
    }

    #[test]
    fn advice_falls_back_to_the_rules_result() {
        assert_eq!(advice_text(&json!({"advice": "# Written"})), "# Written");
        let r = json!({"folder": "~/c", "advice_status": "failed", "error": "agent down",
                       "actions": [{"priority": "block", "project": "p", "item": "evil 1.0", "where": ["a.txt:3"],
                                    "action": "Remove a|b"}]});
        let text = advice_text(&r);
        assert!(text.starts_with("# Supply-chain check: ~/c\n\nNo written advisory (failed: agent down)."));
        assert!(text.contains("| Fix now | p | evil 1.0 | a.txt:3 | Remove a/b |\n"));
        // an answer without any of the fields still gives a page
        assert!(advice_text(&json!({})).contains("No written advisory (none)"));
    }

    #[test]
    fn xml_escapes_markup() {
        assert_eq!(xml("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
