//! Dependency manifests and lockfiles, parsed exactly like the Python scanner
//! (.claude/skills/supply-chain-advisor/scripts/scan_folders.py and the gatekeeper's parsers).

use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::util::{basename, lines, read_text};

/// One declared dependency, with where it was found.
#[derive(Clone, Debug)]
pub struct Dep {
    pub ecosystem: &'static str, // "PyPI" | "npm"
    pub name: String,
    pub version: Option<String>,
    pub spec: String,
    pub line: Option<usize>,
    pub text: Option<String>,
    pub pinned: bool,
    pub section: Option<String>,
}

fn rx(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

pub fn is_requirements(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"^requirements[^/]*\.txt$").is_match(name)
}

pub fn is_manifest(name: &str) -> bool {
    name == "package.json" || name == "pyproject.toml" || is_requirements(name)
}

fn starts_with_digit(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"^\d").is_match(s)
}

/// Python's `str(value)` for a package.json version value.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(b) => {
            if *b {
                "True".into()
            } else {
                "False".into()
            }
        }
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------- with line numbers (the scanner)
fn req_lines(text: &str) -> Vec<Dep> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = rx(
        &R,
        r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([^\s;,]+)|([<>=!~].*?))?\s*(?:;.*)?$",
    );
    let mut out = Vec::new();
    for (i, raw) in lines(text).into_iter().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(m) = re.captures(line) {
            let version = m.get(2).map(|v| v.as_str().to_string());
            out.push(Dep {
                ecosystem: "PyPI",
                name: m[1].to_lowercase(),
                pinned: version.is_some(),
                version,
                spec: line.to_string(),
                line: Some(i + 1),
                text: Some(raw.to_string()),
                section: None,
            });
        }
    }
    out
}

fn package_json_lines(text: &str) -> Vec<Dep> {
    static SKIP: OnceLock<Regex> = OnceLock::new();
    let skip = rx(&SKIP, r"^(workspace|file|link|portal|git\+|https?|catalog):");
    let pj: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let ls = lines(text);
    let mut out = Vec::new();
    for sect in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(obj) = pj.get(sect).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec) in obj {
            let spec = py_str(spec);
            if skip.is_match(&spec) {
                continue; // local/monorepo or URL reference, not a registry package
            }
            // the name comes from the file: a pathological one (too big for a regex) just gets no line number
            let key = Regex::new(&format!(r#""{}"\s*:"#, regex::escape(name))).ok();
            let ln = key.and_then(|k| ls.iter().position(|l| k.is_match(l))).map(|i| i + 1);
            let ver = spec
                .trim_start_matches(|c: char| "^~>=<".contains(c) || c.is_whitespace())
                .to_string();
            let version = if !ver.is_empty() && starts_with_digit(&ver) {
                Some(ver)
            } else {
                None
            };
            out.push(Dep {
                ecosystem: "npm",
                name: name.clone(),
                version,
                pinned: starts_with_digit(&spec),
                spec: spec.clone(),
                line: ln,
                text: ln.map(|n| ls[n - 1].to_string()),
                section: Some(sect.to_string()),
            });
        }
    }
    out
}

fn pyproject_lines(text: &str) -> Vec<Dep> {
    let ls = lines(text);
    let mut out = Vec::new();
    for (name, version, section) in parse_pyproject(text) {
        // "name==1.0" in a [project] list, else `name = "1.0"` in a [tool.poetry] table (same as scan_folders.py)
        let key = Regex::new(&format!(r#"(?i)["']{}(\[|[<>=!~ ;"'])"#, regex::escape(&name))).ok();
        let poetry = Regex::new(&format!(r#"(?i)^\s*["']?{}["']?\s*="#, regex::escape(&name))).ok();
        let find = |r: Option<Regex>| r.and_then(|k| ls.iter().position(|l| k.is_match(l)));
        let ln = find(key).or_else(|| find(poetry)).map(|i| i + 1);
        let spec = match ln {
            Some(n) => ls[n - 1].trim().trim_matches(',').to_string(),
            None => name.clone(),
        };
        out.push(Dep {
            ecosystem: "PyPI",
            pinned: version.is_some(),
            version,
            spec,
            line: ln,
            text: ln.map(|n| ls[n - 1].to_string()),
            section: Some(section),
            name,
        });
    }
    out
}

/// The dependencies a manifest declares, with line numbers and line text.
pub fn manifest_deps(path: &Path) -> Vec<Dep> {
    let base = basename(path);
    let text = read_text(path, None);
    if base == "package.json" {
        package_json_lines(&text)
    } else if base == "pyproject.toml" {
        pyproject_lines(&text)
    } else if is_requirements(&base) {
        req_lines(&text)
    } else {
        vec![]
    }
}

// ---------------------------------------------------------------- the gatekeeper's parsers (names for vendor detection)
fn pep508(spec: &str) -> Option<(String, Option<String>)> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = rx(&R, r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==\s*([^\s,]+))?");
    let spec = spec.split(';').next().unwrap_or("").trim();
    re.captures(spec)
        .map(|m| (m[1].to_lowercase(), m.get(3).map(|v| v.as_str().to_string())))
}

/// [project] dependencies / optional-dependencies / dependency-groups and [tool.poetry.*dependencies].
pub fn parse_pyproject_text(text: &str) -> Vec<(String, Option<String>)> {
    parse_pyproject(text).into_iter().map(|(n, v, _)| (n, v)).collect()
}

/// The same, with the section each dependency is declared in: "dependencies" (the project's own), "optional:<extra>"
/// or "group:<group>" (a dependency group: [dependency-groups], Poetry's groups and dev-dependencies).
pub fn parse_pyproject(text: &str) -> Vec<(String, Option<String>, String)> {
    static ASSIGN: OnceLock<Regex> = OnceLock::new();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static STRIP: OnceLock<Regex> = OnceLock::new();
    static POETRY: OnceLock<Regex> = OnceLock::new();
    static PVER: OnceLock<Regex> = OnceLock::new();
    static EXACT: OnceLock<Regex> = OnceLock::new();
    let assign = rx(&ASSIGN, r#"^[\w\-\."]+\s*=\s*\["#);
    let quoted = rx(&QUOTED, r#"["']([^"']+)["']"#);
    let strip = rx(&STRIP, r#""[^"]*"|'[^']*'"#);
    let poetry = rx(
        &POETRY,
        r"^(?:tool\.poetry\.(dev-)?dependencies|tool\.poetry\.group\.[\w\-]+\.dependencies)$",
    );
    let pver = rx(&PVER, r#"["']\s*(?:==)?\s*([0-9][^"',]*)["']"#);
    let exact = rx(&EXACT, r"^[0-9][\w.]*$");
    // more "[" than "]" outside quoted strings: the list goes on to the next line
    let unclosed = |t: &str| {
        let u = strip.replace_all(t, "");
        u.matches('[').count() > u.matches(']').count()
    };
    let ls = lines(text);
    let (mut deps, mut section, mut i) = (Vec::new(), String::new(), 0usize);
    while i < ls.len() {
        let line = ls[i].split('#').next().unwrap_or("").trim_end();
        let st = line.trim();
        if st.starts_with('[') {
            section = st.trim_matches(|c| c == '[' || c == ']').trim().to_string();
        } else if ["project", "project.optional-dependencies", "dependency-groups"].contains(&section.as_str())
            && assign.is_match(st)
        {
            let mut buf = st.split_once('=').map_or("", |x| x.1).to_string();
            while unclosed(&buf) && i + 1 < ls.len() {
                i += 1;
                buf.push('\n');
                buf.push_str(ls[i].split('#').next().unwrap_or(""));
            }
            if section != "project" || st.starts_with("dependencies") {
                let key = st.split_once('=').map_or("", |x| x.0).trim().trim_matches('"').to_string();
                let label = match section.as_str() {
                    "project" => "dependencies".to_string(),
                    "project.optional-dependencies" => format!("optional:{key}"),
                    _ => format!("group:{key}"),
                };
                for q in quoted.captures_iter(&buf) {
                    if let Some((n, v)) = pep508(&q[1]) {
                        deps.push((n, v, label.clone()));
                    }
                }
            }
        } else if poetry.is_match(&section) && st.contains('=') {
            let (name, val) = st.split_once('=').map_or((st, ""), |(n, v)| (n.trim(), v.trim()));
            if name.to_lowercase() != "python" {
                let ex = pver
                    .captures(val)
                    .map(|m| m[1].to_string())
                    .filter(|v| exact.is_match(v));
                let label = match section.as_str() {
                    "tool.poetry.dependencies" => "dependencies".to_string(),
                    "tool.poetry.dev-dependencies" => "group:dev".to_string(),
                    g => format!("group:{}", g.trim_start_matches("tool.poetry.group.").trim_end_matches(".dependencies")),
                };
                deps.push((name.trim_matches(|c| c == '"' || c == '\'').to_lowercase(), ex, label));
            }
        }
        i += 1;
    }
    deps
}

fn parse_requirements_names(text: &str) -> Vec<String> {
    static PIN: OnceLock<Regex> = OnceLock::new();
    static EXTRAS: OnceLock<Regex> = OnceLock::new();
    static SPLIT: OnceLock<Regex> = OnceLock::new();
    let pin = rx(&PIN, r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s;]+)");
    let extras = rx(&EXTRAS, r"\[.*\]");
    let split = rx(&SPLIT, r"[<>=!~ \[;]");
    let mut out = Vec::new();
    for l in lines(text) {
        let line = l.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        match pin.captures(line) {
            Some(m) => out.push(extras.replace(&m[1], "").to_lowercase()),
            None => out.push(split.split(line).next().unwrap_or("").to_lowercase()),
        }
    }
    out
}

/// Dependency names as the gatekeeper's `parse_deps()` sees them (for package -> vendor rules), in order, de-duplicated.
pub fn gatekeeper_names(repo: &Path, manifests: &[String]) -> Vec<String> {
    static SKIP: OnceLock<Regex> = OnceLock::new();
    let skip = rx(&SKIP, r"^(workspace|file|link|portal|git\+|https?):");
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for rel in manifests {
        let p = repo.join(rel);
        if !p.is_file() {
            continue;
        }
        let text = read_text(&p, None);
        let base = basename(&p);
        let found: Vec<(&str, String, Option<String>)> = if base == "package.json" {
            let pj: Value = serde_json::from_str(if text.is_empty() { "{}" } else { &text }).unwrap_or(Value::Null);
            let mut v = Vec::new();
            for sect in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(obj) = pj.get(sect).and_then(|x| x.as_object()) {
                    for (n, val) in obj {
                        let s = py_str(val);
                        if skip.is_match(&s) {
                            continue;
                        }
                        let ver = s
                            .trim_start_matches(|c: char| "^~>=<".contains(c) || c.is_whitespace())
                            .to_string();
                        v.push(("npm", n.clone(), if ver.is_empty() { None } else { Some(ver) }));
                    }
                }
            }
            v
        } else if base == "pyproject.toml" {
            parse_pyproject_text(&text)
                .into_iter()
                .map(|(n, v)| ("PyPI", n, v))
                .collect()
        } else if is_requirements(&base) {
            // versions only matter for de-duplication; names are what the vendor rules read
            parse_requirements_names(&text)
                .into_iter()
                .map(|n| ("PyPI", n, None))
                .collect()
        } else {
            vec![]
        };
        for (eco, name, ver) in found {
            if seen.insert((eco, name.to_lowercase(), ver)) {
                out.push(name);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- lockfiles: installed versions of direct deps
/// {(ecosystem, name lowercased): version} from uv.lock, bun.lock and package-lock.json (first file wins).
pub fn lock_versions(files: &[PathBuf]) -> HashMap<(String, String), String> {
    static UV: OnceLock<Regex> = OnceLock::new();
    static BUN: OnceLock<Regex> = OnceLock::new();
    let uv = rx(&UV, r#"\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)""#);
    // Python's pattern uses a backreference ("\1@"); Rust's regex has none, so the two names are compared here
    let bun = rx(
        &BUN,
        r#""(@?[^"@\s]+(?:/[^"@\s]+)?)": \[\s*"(@?[^"@\s]+(?:/[^"@\s]+)?)@([^"]+)""#,
    );
    let mut out = HashMap::new();
    for f in files {
        let base = basename(f);
        if !["uv.lock", "bun.lock", "package-lock.json"].contains(&base.as_str()) {
            continue;
        }
        let text = read_text(f, None);
        if base == "uv.lock" {
            for m in uv.captures_iter(&text) {
                out.entry(("PyPI".into(), m[1].to_lowercase()))
                    .or_insert_with(|| m[2].to_string());
            }
        } else if base == "bun.lock" {
            for m in bun.captures_iter(&text) {
                if m[1] == m[2] {
                    out.entry(("npm".into(), m[1].to_lowercase()))
                        .or_insert_with(|| m[3].to_string());
                }
            }
        } else if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if let Some(pk) = v.get("packages").and_then(|p| p.as_object()) {
                for (k, val) in pk {
                    let ver = val.get("version").and_then(|x| x.as_str()).filter(|s| !s.is_empty());
                    if let (Some(rest), Some(ver)) = (k.strip_prefix("node_modules/"), ver) {
                        if !rest.contains("/node_modules/") {
                            out.entry(("npm".into(), rest.to_lowercase()))
                                .or_insert_with(|| ver.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

/// Every package version a lockfile records (direct and transitive), in file order:
/// (ecosystem, name, version, lockfile). Registry packages only: the project itself, workspace members and local
/// paths are left out. Same rules as scan_folders.py's lock_entries.
pub fn lock_entries(files: &[PathBuf]) -> Vec<(String, String, String, PathBuf)> {
    static BUN: OnceLock<Regex> = OnceLock::new();
    static UV_NAME: OnceLock<Regex> = OnceLock::new();
    static UV_VERSION: OnceLock<Regex> = OnceLock::new();
    static UV_SOURCE: OnceLock<Regex> = OnceLock::new();
    static REQ: OnceLock<Regex> = OnceLock::new();
    let bun = rx(&BUN, r#""[^"]+": \[\s*"(@?[^"@\s]+(?:/[^"@\s]+)?)@([^"]+)""#);
    let uv_name = rx(&UV_NAME, r#"(?m)^name = "([^"]+)""#);
    let uv_version = rx(&UV_VERSION, r#"(?m)^version = "([^"]+)""#);
    let uv_source = rx(&UV_SOURCE, r"(?m)^source = \{ (\w+)");
    let req = rx(&REQ, r"(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)");
    let mut out = Vec::new();
    for f in files {
        let base = basename(f);
        let mut add = |eco: &str, name: &str, version: &str| {
            out.push((eco.to_string(), name.to_string(), version.to_string(), f.clone()));
        };
        match base.as_str() {
            "package-lock.json" => {
                let text = read_text(f, None);
                let Ok(v) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                for (k, val) in v.get("packages").and_then(Value::as_object).into_iter().flatten() {
                    let ver = val.get("version").and_then(Value::as_str).unwrap_or("");
                    let link = val.get("link").and_then(Value::as_bool).unwrap_or(false);
                    if let Some((_, name)) = k.rsplit_once("node_modules/") {
                        if !ver.is_empty() && !link {
                            add("npm", name, ver);
                        }
                    }
                }
            }
            "bun.lock" => {
                let text = read_text(f, None);
                for m in bun.captures_iter(&text) {
                    if !m[2].contains(':') {
                        add("npm", &m[1], &m[2]);
                    }
                }
            }
            "uv.lock" => {
                let text = read_text(f, None);
                for block in text.split("\n[[package]]\n").skip(1) {
                    let get = |r: &Regex| r.captures(block).map(|c| c[1].to_string());
                    if let (Some(n), Some(v), Some(src)) = (get(uv_name), get(uv_version), get(uv_source)) {
                        if src == "registry" {
                            add("PyPI", &n, &v);
                        }
                    }
                }
            }
            "requirements.lock" => {
                let text = read_text(f, None);
                for m in req.captures_iter(&text) {
                    add("PyPI", &m[1], &m[2]);
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn summary(deps: &[Dep]) -> Vec<(String, Option<String>, bool, Option<usize>)> {
        deps.iter()
            .map(|d| (d.name.clone(), d.version.clone(), d.pinned, d.line))
            .collect()
    }

    #[test]
    fn manifest_names() {
        for yes in [
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
        ] {
            assert!(is_manifest(yes), "{yes}");
        }
        for no in [
            "requirements.in",
            "Requirements.txt",
            "package-lock.json",
            "setup.py",
            "requirements/x.txt",
        ] {
            assert!(!is_manifest(no), "{no}");
        }
    }

    #[test]
    fn requirements_pins_ranges_extras_markers_and_comments() {
        let text =
            "-r base.txt\n--index-url https://x\nFlask==3.1.3\nsentry-sdk[flask] == 2.1.0 ; python_version > '3'\n\
                    stripe>=9\n# comment\nanthropic~=0.25  # trailing\nbare\n\n";
        let deps = req_lines(text);
        assert_eq!(
            summary(&deps),
            vec![
                ("flask".into(), Some("3.1.3".into()), true, Some(3)),
                ("sentry-sdk".into(), Some("2.1.0".into()), true, Some(4)),
                ("stripe".into(), None, false, Some(5)),
                ("anthropic".into(), None, false, Some(7)),
                ("bare".into(), None, false, Some(8)),
            ]
        );
        assert!(deps.iter().all(|d| d.ecosystem == "PyPI"));
        assert_eq!(deps[3].spec, "anthropic~=0.25");
        assert_eq!(deps[3].text.as_deref(), Some("anthropic~=0.25  # trailing"));
    }

    #[test]
    fn package_json_sections_lines_and_local_references() {
        let text = "{\n  \"dependencies\": {\n    \"react\": \"^19.3.1\",\n    \"@acme/ui\": \"workspace:*\",\n    \
                    \"left-pad\": \"1.3.0\",\n    \"zod\": \"catalog:\"\n  },\n  \"devDependencies\": {\n    \
                    \"vite\": \"latest\"\n  }\n}\n";
        let deps = package_json_lines(text);
        assert_eq!(
            summary(&deps),
            vec![
                ("react".into(), Some("19.3.1".into()), false, Some(3)),
                ("left-pad".into(), Some("1.3.0".into()), true, Some(5)),
                ("vite".into(), None, false, Some(9)),
            ]
        );
        assert_eq!(deps[2].section.as_deref(), Some("devDependencies"));
        assert!(package_json_lines("not json").is_empty());
    }

    #[test]
    fn package_json_non_string_versions_read_like_python_str() {
        let deps = package_json_lines(r#"{"dependencies": {"a": 1, "b": null, "c": true}}"#);
        let specs: Vec<&str> = deps.iter().map(|d| d.spec.as_str()).collect();
        assert_eq!(specs, vec!["1", "None", "True"]);
    }

    #[test]
    fn a_huge_package_name_does_not_panic() {
        // too big for a regex: the dependency is kept, without a line number
        let name = "a".repeat(2_000_000);
        let deps = package_json_lines(&format!(r#"{{"dependencies": {{"{name}": "1.0.0"}}}}"#));
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].line, None);
    }

    #[test]
    fn pyproject_project_groups_and_poetry() {
        let text = "[project]\nname = \"svc\"\ndependencies = [\n  \"fastapi>=0.110\",\n  \"openai==1.30.0\",  # pinned\n]\n\
                    [project.optional-dependencies]\ndev = [\"pytest==8.2.0\"]\n[dependency-groups]\nlint = [\"ruff>=0.4\"]\n\
                    [tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\nboto3 = \"^1.34\"\n";
        assert_eq!(
            parse_pyproject_text(text),
            vec![
                ("fastapi".into(), None),
                ("openai".into(), Some("1.30.0".into())),
                ("pytest".into(), Some("8.2.0".into())),
                ("ruff".into(), None),
                ("requests".into(), Some("2.31.0".into())),
                ("boto3".into(), None),
            ]
        );
        let deps = pyproject_lines(text);
        assert_eq!(deps[1].line, Some(5));
        assert_eq!(deps[1].spec, "\"openai==1.30.0\",  # pinned");
        // Poetry: `name = "version"` lines are found too, so they can be edited
        let sections: Vec<&str> = deps.iter().map(|d| d.section.as_deref().unwrap_or("")).collect();
        assert_eq!(sections, vec!["dependencies", "dependencies", "optional:dev", "group:lint", "dependencies", "dependencies"]);
        let poetry = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(
            (poetry.line, poetry.text.as_deref()),
            (Some(13), Some("requests = \"2.31.0\""))
        );
    }

    #[test]
    fn pyproject_name_and_other_keys_in_project_are_not_dependencies() {
        let text = "[project]\nkeywords = [\"not-a-dep\"]\ndependencies = [\"real\"]\n";
        assert_eq!(parse_pyproject_text(text), vec![("real".into(), None)]);
    }

    #[test]
    fn lockfiles_give_installed_versions_first_file_wins() {
        let t = TempDir::new();
        let uv = t.write("uv.lock", "[[package]]\nname = \"FastAPI\"\nversion = \"0.111.0\"\n");
        let bun = t.write(
            "bun.lock",
            "{\n  \"packages\": {\n    \"react\": [\"react@19.0.0\", {}],\n    \"alias\": [\"other@1.0.0\"]\n  }\n}\n",
        );
        let npm = t.write(
            "package-lock.json",
            r#"{"packages": {"": {}, "node_modules/react": {"version": "18.0.0"},
                "node_modules/a/node_modules/vite": {"version": "1.0.0"}, "node_modules/vite": {"version": "8.3.5"}}}"#,
        );
        let other = t.write("yarn.lock", "react@1:\n  version 1\n");
        let v = lock_versions(&[uv, bun, npm, other]);
        let get = |e: &str, n: &str| v.get(&(e.to_string(), n.to_string())).cloned();
        assert_eq!(get("PyPI", "fastapi").as_deref(), Some("0.111.0"));
        assert_eq!(get("npm", "react").as_deref(), Some("19.0.0")); // bun.lock came first
        assert_eq!(get("npm", "alias"), None); // the names differ
        assert_eq!(get("npm", "vite").as_deref(), Some("8.3.5")); // nested copies are not direct deps
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn gatekeeper_names_deduplicate_in_order() {
        let t = TempDir::new();
        t.write("requirements.txt", "Openai==1\nstripe>=2\nopenai==1\n");
        t.write(
            "package.json",
            r#"{"dependencies": {"@sentry/node": "^8", "x": "file:../x"}}"#,
        );
        let names = gatekeeper_names(
            t.path(),
            &["requirements.txt".into(), "package.json".into(), "missing.txt".into()],
        );
        assert_eq!(names, vec!["openai", "stripe", "@sentry/node"]);
    }

    #[test]
    fn lock_entries_read_every_registry_package() {
        let t = TempDir::new();
        let w = |name: &str, text: &str| {
            let p = t.path().join(name);
            std::fs::write(&p, text).unwrap();
            p
        };
        let files = vec![
            w("package-lock.json", r#"{"packages": {"": {"name": "app"}, "node_modules/a": {"version": "1.0.0"},
                "node_modules/a/node_modules/b": {"version": "2.0.0"}, "node_modules/local": {"link": true},
                "node_modules/@s/c": {"version": "3.0.0"}}}"#),
            w("bun.lock", "{\"packages\": {\n    \"d\": [\"d@4.0.0\", \"\", {}],\n    \"web\": [\"web@workspace:web\"],\n  }}"),
            w("uv.lock", "version = 1\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"e\"\nversion = \"5.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"),
            w("requirements.lock", "f==6.0 \\\n    --hash=sha256:00\n# g==7\n"),
        ];
        let got: Vec<(String, String, String)> =
            lock_entries(&files).into_iter().map(|(e, n, v, _)| (e, n, v)).collect();
        let want = [
            ("npm", "a", "1.0.0"),
            ("npm", "b", "2.0.0"),
            ("npm", "@s/c", "3.0.0"),
            ("npm", "d", "4.0.0"),
            ("PyPI", "e", "5.0"),
            ("PyPI", "f", "6.0"),
        ];
        assert_eq!(
            got,
            want.iter()
                .map(|(a, b, c)| ((*a).into(), (*b).into(), (*c).into()))
                .collect::<Vec<_>>()
        );
    }
}
