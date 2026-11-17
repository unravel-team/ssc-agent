//! Whether a project uses a dependency: its code imports it, or a run command starts it (a Dockerfile CMD, an npm
//! script, a Procfile). Worked out here on the laptop; only a yes/no per dependency is sent, never the names found in
//! the code. The same logic as the Claude plugin's ssc_scope.py (tests compare the two).

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::util::{basename, read_text};

const PY_EXT: [&str; 1] = [".py"];
const JS_EXT: [&str; 6] = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
const LIMIT: usize = 400_000;

fn rx(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

/// A package or module name as it is compared: lower case, with "-", "_" and "." alike.
pub fn norm(name: &str) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"[-_.]+").replace_all(&name.to_lowercase(), "-").to_string()
}

/// The names a PyPI package may be imported or run as: itself, without a python-/py- prefix or -python/-py suffix.
fn pypi_names(name: &str) -> Vec<String> {
    let n = norm(name);
    let mut out = vec![n.clone()];
    for p in ["python-", "py-"] {
        if let Some(rest) = n.strip_prefix(p) {
            out.push(rest.to_string());
        }
    }
    for s in ["-python", "-py"] {
        if let Some(rest) = n.strip_suffix(s) {
            out.push(rest.to_string());
        }
    }
    out
}

/// The npm package a module specifier names: "@scope/name/sub" -> "@scope/name", "name/sub" -> "name"; none for a
/// relative path, an absolute one, or a Node built-in ("node:fs").
fn npm_package(spec: &str) -> Option<String> {
    if spec.starts_with('.') || spec.starts_with('/') || spec.starts_with("node:") || spec.contains(':') {
        return None;
    }
    let mut parts = spec.split('/');
    let first = parts.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", parts.next()?)
    } else {
        first.to_string()
    };
    (!name.is_empty()).then_some(name)
}

/// What one project uses.
#[derive(Default)]
pub struct Usage {
    has_python: bool,
    has_js: bool,
    python: BTreeSet<String>, // imported modules, normalised
    js: BTreeSet<String>,     // imported npm packages, as written
    run: BTreeSet<String>,    // words of run commands, normalised
}

impl Usage {
    /// Whether the dependency is used: Some(true/false), or None when the project has no code in its language.
    pub fn used(&self, ecosystem: &str, name: &str) -> Option<bool> {
        if ecosystem == "npm" {
            if !self.has_js {
                return None;
            }
            // type definitions belong to the package they describe: @types/node is used with node, @types/a__b with @a/b
            let target = name.strip_prefix("@types/").map_or_else(
                || name.to_string(),
                |t| t.split_once("__").map_or_else(|| t.to_string(), |(s, n)| format!("@{s}/{n}")),
            );
            let n = norm(&target);
            return Some(self.js.iter().any(|j| norm(j) == n) || self.run.contains(&n) || name.starts_with("@types/node"));
        }
        if !self.has_python {
            return None;
        }
        Some(pypi_names(name).iter().any(|n| self.python.contains(n) || self.run.contains(n)))
    }
}

/// Read a project's code and run commands. `aliases`: Python import name -> PyPI name (from the shared rules).
pub fn scan(files: &[PathBuf], aliases: &BTreeMap<String, String>) -> Usage {
    static PY_IMPORT: OnceLock<Regex> = OnceLock::new();
    static PY_FROM: OnceLock<Regex> = OnceLock::new();
    static JS_IMPORT: OnceLock<Regex> = OnceLock::new();
    static WORD: OnceLock<Regex> = OnceLock::new();
    static DOCKER_RUN: OnceLock<Regex> = OnceLock::new();
    static COMPOSE_RUN: OnceLock<Regex> = OnceLock::new();
    let py_import = rx(&PY_IMPORT, r"(?m)^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*)");
    let py_from = rx(&PY_FROM, r"(?m)^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b");
    let js_import = rx(
        &JS_IMPORT,
        r#"(?:\bfrom|\bimport|\brequire[ \t]*\(|\bimport[ \t]*\()[ \t]*["']([^"'\s]+)["']"#,
    );
    let word = rx(&WORD, r"[A-Za-z0-9@][A-Za-z0-9@/_.\-]*");
    let docker_run = rx(&DOCKER_RUN, r"(?mi)^[ \t]*(?:CMD|ENTRYPOINT|RUN)\b(.*)$");
    let compose_run = rx(&COMPOSE_RUN, r"(?m)^[ \t]*(?:command|entrypoint|cmd)[ \t]*[:=](.*)$");
    let aliases: BTreeMap<String, String> = aliases.iter().map(|(k, v)| (norm(k), norm(v))).collect();
    let mut u = Usage::default();
    let add_run = |u: &mut Usage, text: &str| {
        for w in word.find_iter(text) {
            for part in w.as_str().split('/') {
                if !part.is_empty() {
                    u.run.insert(norm(part));
                }
            }
            u.run.insert(norm(w.as_str()));
        }
    };
    for f in files {
        let b = basename(f);
        if PY_EXT.iter().any(|e| b.ends_with(e)) {
            u.has_python = true;
            let text = read_text(f, Some(LIMIT));
            let mut add = |module: &str| {
                let top = norm(module.split('.').next().unwrap_or(""));
                if !top.is_empty() {
                    u.python.insert(aliases.get(&top).cloned().unwrap_or(top));
                }
            };
            for m in py_import.captures_iter(&text) {
                for part in m[1].split(',') {
                    add(part.trim().split_whitespace().next().unwrap_or(""));
                }
            }
            for m in py_from.captures_iter(&text) {
                add(&m[1]);
            }
        } else if JS_EXT.iter().any(|e| b.ends_with(e)) {
            u.has_js = true;
            for m in js_import.captures_iter(&read_text(f, Some(LIMIT))) {
                if let Some(p) = npm_package(&m[1]) {
                    u.js.insert(p);
                }
            }
        } else if b.starts_with("Dockerfile") {
            for m in docker_run.captures_iter(&read_text(f, Some(LIMIT))) {
                add_run(&mut u, &m[1]);
            }
        } else if b == "Procfile" || b == "fly.toml" {
            add_run(&mut u, &read_text(f, Some(LIMIT)));
        } else if (b.starts_with("docker-compose") || b.starts_with("compose")) && (b.ends_with(".yml") || b.ends_with(".yaml")) {
            for m in compose_run.captures_iter(&read_text(f, Some(LIMIT))) {
                add_run(&mut u, &m[1]);
            }
        } else if b == "package.json" {
            let pj: serde_json::Value = serde_json::from_str(&read_text(f, None)).unwrap_or_default();
            for v in pj.get("scripts").and_then(|s| s.as_object()).into_iter().flat_map(|o| o.values()) {
                add_run(&mut u, v.as_str().unwrap_or(""));
            }
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn usage(files: &[(&str, &str)]) -> Usage {
        let t = TempDir::new();
        let paths: Vec<PathBuf> = files.iter().map(|(p, text)| t.write(p, text)).collect();
        let aliases = BTreeMap::from([("yaml".to_string(), "pyyaml".to_string())]);
        scan(&paths, &aliases)
    }

    #[test]
    fn python_imports_aliases_prefixes_and_run_commands() {
        let u = usage(&[
            ("app/main.py", "import os, sys\nimport yaml as y\nfrom dateutil.parser import parse\n  from flask import Flask\nfrom . import local\n"),
            ("Dockerfile", "FROM python:3.12\nCMD [\"gunicorn\", \"app:app\"]\n"),
        ]);
        for (name, want) in [("flask", true), ("PyYAML", true), ("python-dateutil", true), ("gunicorn", true), ("requests", false)] {
            assert_eq!(u.used("PyPI", name), Some(want), "{name}");
        }
        assert_eq!(u.used("npm", "react"), None); // no JavaScript in this project
    }

    #[test]
    fn javascript_imports_requires_scripts_and_types() {
        let u = usage(&[
            ("src/a.ts", "import x from 'react';\nimport '@scope/ui/button';\nconst l = require(\"lodash/fp\");\nimport('./local');\nimport fs from 'node:fs';\nexport * from \"zod\";\n"),
            ("package.json", r#"{"scripts": {"build": "next build", "lint": "eslint ."}}"#),
        ]);
        for (name, want) in [("react", true), ("@scope/ui", true), ("lodash", true), ("zod", true), ("next", true),
                             ("eslint", true), ("@types/react", true), ("axios", false), ("local", false)] {
            assert_eq!(u.used("npm", name), Some(want), "{name}");
        }
        assert_eq!(u.used("PyPI", "flask"), None);
    }
}
