//! ssc: the laptop supply-chain scanner (macOS, Linux, Windows).
//!
//! Scans the folders you point it at, builds a scope (dependencies with file and line, vendors, base images,
//! CAs), sends it to the sources API, and shows the advisory and action plan the server's agents write.
//! It reads files only: nothing from the projects is installed or run, and no code or secrets leave the computer.

// The scanner must treat file names exactly like the Python scanner it is tested against, which compares
// extensions case-sensitively (f.endswith(".tf")), so the pedantic lint against that is off on purpose.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

mod app;
mod certs;
mod done;
mod manifests;
mod runner;
mod scan;
mod secrets;
mod ui;
mod usage;
mod util;
mod vendors;
mod walk;

use serde_json::json;
use std::path::{Path, PathBuf};

const USAGE: &str = "ssc: supply-chain scanner (results come from the company's sources API)

  ssc ui [--port N] [--no-browser]  open the app in your browser (settings, folders, scans, results)

  ssc init --api URL [--folder PATH ...] [--interval MIN]
                                    settings; gets a scan key from the server if none is saved
                                    (--key-stdin: use a key you were given, read from stdin)
  ssc folders [add|remove PATH]     list or change the folders to scan
  ssc scan [--folder PATH] [--background]
                                    scan now, send, wait for the advisory, save and show where it is
  ssc open [PATH]                   open the latest advisory
  ssc status                        settings, server, background scans, last result per folder
  ssc install [--interval MIN] | uninstall
                                    scan in the background every N minutes
  ssc scope PATH [--out FILE]       print the scope a scan would send (nothing is sent)

Server settings come from scanner/.env (SSC_API_URL, SSC_API_KEY, optional SSC_FOLDERS; see .env.example),
else from `ssc init`. Results: ~/.ssc/results/.
Nothing from the projects is installed or run.";

fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2).filter(|w| w[0] == flag).map(|w| w[1].clone()).collect()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    arg_values(args, flag).into_iter().next()
}

fn die(msg: &str) -> ! {
    eprintln!("ssc: {msg}");
    std::process::exit(1)
}

fn read_key() -> String {
    let mut k = String::new();
    std::io::stdin().read_line(&mut k).ok();
    k.trim().to_string()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // --env FILE (anywhere): the .env file with the server settings (background scans pass it)
    if let Some(i) = args.iter().position(|a| a == "--env") {
        if let Some(f) = args.get(i + 1).cloned() {
            std::env::set_var("SSC_ENV", f);
            args.drain(i..i + 2);
        }
    }
    // no command (e.g. double-clicked): open the app
    let cmd = args.first().map_or("ui", String::as_str);
    let mut cfg = app::load_config();
    match cmd {
        "ui" => {
            let port = arg_value(&args, "--port").and_then(|p| p.parse().ok()).unwrap_or(8790);
            ui::serve(port, !args.iter().any(|a| a == "--no-browser")).unwrap_or_else(|e| die(&e));
        }
        "init" => {
            let api = arg_value(&args, "--api")
                .or_else(|| cfg["api"].as_str().map(String::from))
                .unwrap_or_else(|| die("--api URL is required"));
            let api = api.trim_end_matches('/').to_string();
            if !app::api_url_allowed(&api) {
                die("the API must be https:// (plain http only for 127.0.0.1)");
            }
            cfg["api"] = json!(api);
            let mut fs = app::folders(&cfg);
            for f in arg_values(&args, "--folder") {
                let p = util::abspath(Path::new(&f)).display().to_string();
                if !Path::new(&p).is_dir() {
                    die(&format!("not a folder: {p}"))
                }
                if !fs.contains(&p) {
                    fs.push(p);
                }
            }
            cfg["folders"] = json!(fs);
            if let Some(m) = arg_value(&args, "--interval").and_then(|s| s.parse::<u64>().ok()) {
                cfg["interval_minutes"] = json!(m.max(5));
            }
            if args.iter().any(|a| a == "--key-stdin") {
                let key = read_key();
                if key.is_empty() {
                    die("no key given")
                }
                app::key_save(&key).unwrap_or_else(|e| die(&e));
            }
            app::save_config(&cfg).unwrap_or_else(|e| die(&e));
            // with no key saved, from_config gets one from the server
            let a = app::Api::from_config(&cfg).unwrap_or_else(|e| die(&e));
            match a.call("GET", "/v1/scans?limit=1", None) {
                Ok((200, _)) => println!(
                    "Saved. The server accepts the key. Folders: {}",
                    if fs.is_empty() {
                        "none yet (ssc folders add PATH)".into()
                    } else {
                        fs.join(", ")
                    }
                ),
                Ok((st, r)) => println!(
                    "Saved, but the server answered {st}: {}",
                    r["error"].as_str().unwrap_or("")
                ),
                Err(e) => println!("Saved, but {e}"),
            }
        }
        "folders" => {
            let mut fs = app::folders(&cfg);
            if let (Some(action), Some(path)) = (args.get(1), args.get(2)) {
                let p = util::abspath(Path::new(path)).display().to_string();
                match action.as_str() {
                    "add" => {
                        if !Path::new(&p).is_dir() {
                            die(&format!("not a folder: {p}"))
                        }
                        if !fs.contains(&p) {
                            fs.push(p);
                        }
                    }
                    "remove" => fs.retain(|f| f != &p),
                    _ => die("ssc folders [add|remove PATH]"),
                }
                cfg["folders"] = json!(fs);
                app::save_config(&cfg).unwrap_or_else(|e| die(&e));
            }
            for f in app::folders(&cfg) {
                println!("{f}");
            }
        }
        "scan" => {
            let api = app::Api::from_config(&cfg).unwrap_or_else(|e| die(&e));
            let targets: Vec<String> = arg_value(&args, "--folder").map_or_else(
                || app::folders(&cfg),
                |f| vec![util::abspath(Path::new(&f)).display().to_string()],
            );
            if targets.is_empty() {
                die("no folders to scan: ssc folders add PATH (or ssc scan --folder PATH)")
            }
            let Some(_lock) = runner::lock() else {
                app::log("another scan is still running; skipping this one");
                // a scheduled run just skips; a scan someone asked for says it didn't happen
                if args.iter().any(|a| a == "--background") {
                    return;
                }
                std::process::exit(3);
            };
            let rules = runner::rules(Some(&api));
            let mut failed = false;
            for f in targets {
                let label = app::folder_label(Path::new(&f));
                let say = |m: &str| app::log(&format!("{label}: {m}"));
                match runner::scan_folder(&api, &rules, &PathBuf::from(&f), &say) {
                    Ok(r) => {
                        let d = app::results_dir(&label, r["id"].as_str().unwrap_or(""));
                        println!(
                            "  advisory:     {}\n  action items: {} (ticks: {})",
                            d.join("ADVICE.md").display(),
                            d.join("result.json").display(),
                            done::path(&label).display()
                        );
                    }
                    Err(e) => {
                        say(&e);
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1)
            }
        }
        "open" => {
            let state = app::load_state();
            let label = args.get(1).map(|p| app::folder_label(Path::new(p)));
            let mut hits: Vec<(String, String)> = state
                .as_object()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|(k, _)| label.as_ref().is_none_or(|l| l == k))
                .filter_map(|(k, v)| v["advice"].as_str().map(|a| (k, a.to_string())))
                .collect();
            hits.sort();
            if hits.is_empty() {
                die("no advisory yet: ssc scan")
            }
            for (k, a) in hits {
                println!("{k}: {a}");
                app::open_path(&a);
            }
        }
        "status" => {
            match cfg["_env"]["file"].as_str() {
                Some(f) => println!("settings: {f} (server and key from this file)"),
                None => println!(
                    "settings: {}{}",
                    app::config_path().display(),
                    if app::config_path().exists() {
                        ""
                    } else {
                        " (not set up: scanner/.env, ssc init or ssc ui)"
                    }
                ),
            }
            // /v1/health needs no key: status never registers one
            let reach = cfg["api"]
                .as_str()
                .and_then(|base| app::Api::with_key(base, "").ok())
                .map(|a| match a.call("GET", "/v1/health", None) {
                    Ok((200, _)) => "up".to_string(),
                    Ok((s, _)) => format!("answered {s}"),
                    Err(e) => e,
                });
            println!(
                "server: {} ({}) · key saved: {}",
                cfg["api"].as_str().unwrap_or("not set"),
                reach.unwrap_or_else(|| "not checked".into()),
                if app::key_load().is_some() { "yes" } else { "no" }
            );
            println!(
                "background scans: {} (every {} min)",
                app::service_state(),
                cfg["interval_minutes"]
            );
            let state = app::load_state();
            for f in app::folders(&cfg) {
                let l = app::folder_label(Path::new(&f));
                let e = &state[&l];
                if e.is_null() {
                    println!("\n{l}\n  not scanned yet");
                    continue;
                }
                let s = &e["summary"];
                println!(
                    "\n{l}\n  last scan {}: BLOCK {} · HOLD {} · ALLOW {} · {} new · advice {}\n  {}",
                    e["at"].as_str().unwrap_or(""),
                    s["BLOCK"],
                    s["HOLD"],
                    s["ALLOW"],
                    e["new"],
                    e["advice_status"].as_str().unwrap_or(""),
                    e["advice"].as_str().unwrap_or("")
                );
            }
        }
        "install" => {
            let minutes = arg_value(&args, "--interval")
                .and_then(|s| s.parse().ok())
                .or_else(|| cfg["interval_minutes"].as_u64())
                .unwrap_or(60)
                .max(5);
            if app::folders(&cfg).is_empty() {
                die("add a folder first: ssc folders add PATH")
            }
            app::Api::from_config(&cfg).unwrap_or_else(|e| die(&e));
            cfg["interval_minutes"] = json!(minutes);
            app::save_config(&cfg).unwrap_or_else(|e| die(&e));
            println!("{}", app::install(minutes).unwrap_or_else(|e| die(&e)));
        }
        "uninstall" => println!("{}", app::uninstall()),
        "scope" => {
            let path = args.get(1).unwrap_or_else(|| die("ssc scope PATH [--out FILE]"));
            let api = app::Api::from_config(&cfg).ok();
            let (scope, projects) = scan::scan(Path::new(path), &runner::rules(api.as_ref()));
            let text = serde_json::to_string_pretty(&json!({"scope": scope, "projects": projects}))
                .unwrap_or_else(|e| die(&e.to_string()));
            match arg_value(&args, "--out") {
                Some(f) => std::fs::write(&f, text + "\n").unwrap_or_else(|e| die(&e.to_string())),
                None => println!("{text}"),
            }
        }
        "version" | "--version" => println!(
            "ssc {} (server: {})",
            env!("CARGO_PKG_VERSION"),
            app::BUILT_IN_API.unwrap_or("not built in")
        ),
        _ => println!("{USAGE}"),
    }
}
