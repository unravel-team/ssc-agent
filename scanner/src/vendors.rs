//! Which third parties a project relies on: the vendor detection of .claude/skills/ssc-scan/scripts/scope_gen.py,
//! with its tables from the shared rules (`intel_api/config/scanner_rules.json`). Reads files only; runs nothing
//! from the project.

use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::manifests::{gatekeeper_names, is_manifest};
use crate::util::{basename, read_text, relpath};
use crate::walk;

const TYPES: [&str; 7] = [
    "platform",
    "ci",
    "developer_tool",
    "ai_provider",
    "saas",
    "package_registry",
    "other",
];

pub struct Rules {
    pub skip_dirs: HashSet<String>,
    pub project_skip_dirs: HashSet<String>,
    file_signs: Vec<(String, String, String)>,
    tf: BTreeMap<String, String>,
    pkg: Vec<(Regex, String, String)>,
    env: Vec<(Regex, String, String)>,
    secretish: Regex,
    not_secret: Regex,
    registry: Vec<(Regex, String)>,
    pub secrets: crate::secrets::SecretRules,
    /// Python import name -> PyPI name (usage.rs), lower case
    pub import_aliases: std::collections::BTreeMap<String, String>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

impl Rules {
    pub fn from_json(v: &Value) -> Result<Rules, String> {
        let set = |k: &str| -> HashSet<String> {
            v.get(k)
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        let list = |k: &str| v.get(k).and_then(|a| a.as_array()).cloned().unwrap_or_default();
        // Python's re.match(rx, name) is anchored at the start; (?i) where the Python code passes re.I
        let anchored = |p: &str, ci: bool| {
            RegexBuilder::new(&format!("^(?:{p})"))
                .case_insensitive(ci)
                .build()
                .map_err(|e| e.to_string())
        };
        let mut pkg = Vec::new();
        for r in list("package_vendors") {
            pkg.push((anchored(&s(&r, "pattern"), true)?, s(&r, "vendor"), s(&r, "type")));
        }
        let mut env = Vec::new();
        for r in list("env_prefixes") {
            env.push((anchored(&s(&r, "pattern"), false)?, s(&r, "vendor"), s(&r, "type")));
        }
        let mut registry = Vec::new();
        for r in list("registry_hosts") {
            registry.push((
                Regex::new(&s(&r, "pattern")).map_err(|e| e.to_string())?,
                s(&r, "vendor"),
            ));
        }
        let tf = v
            .get("terraform_providers")
            .and_then(|t| t.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, x)| (k.clone(), x.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Rules {
            skip_dirs: set("skip_dirs"),
            project_skip_dirs: set("project_skip_dirs"),
            file_signs: list("file_signs")
                .iter()
                .map(|r| (s(r, "glob"), s(r, "vendor"), s(r, "type")))
                .collect(),
            tf,
            pkg,
            env,
            secretish: RegexBuilder::new(&s(v, "secretish"))
                .case_insensitive(true)
                .build()
                .map_err(|e| e.to_string())?,
            not_secret: Regex::new(&s(v, "not_secret")).map_err(|e| e.to_string())?,
            registry,
            secrets: crate::secrets::SecretRules::from_json(v)?,
            import_aliases: v
                .get("import_aliases")
                .and_then(|a| a.as_object())
                .map(|o| {
                    o.iter()
                        .filter(|(k, _)| !k.starts_with('$'))
                        .filter_map(|(k, x)| x.as_str().map(|s| (k.to_lowercase(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Third parties found, keyed by lowercased name; the first detection sets the name and type.
struct Found {
    order: Vec<String>,
    by: HashMap<String, (String, String, Vec<String>)>, // name, type, secrets
}

impl Found {
    fn add(&mut self, name: &str, typ: &str) -> &mut Vec<String> {
        let key = name.to_lowercase();
        let order = &mut self.order;
        let entry = self.by.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            (name.to_string(), typ.to_string(), Vec::new())
        });
        &mut entry.2
    }
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

/// (name, type) of each third party, sorted like `scope_gen`'s `third_party` list. None if detection failed the way
/// the Python generator raises (then the scanner records no vendors for the project, as the Python one does).
pub fn detect(repo: &Path, rules: &Rules) -> Option<Vec<(String, String)>> {
    let skip = &rules.skip_dirs;
    let files: Vec<String> = walk::files(repo, &|d| !skip.contains(d))
        .iter()
        .map(|p| relpath(p, repo))
        .collect();
    let fset: HashSet<&str> = files.iter().map(String::as_str).collect();
    let mut found = Found {
        order: vec![],
        by: HashMap::new(),
    };
    let mut secrets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let read = |rel: &str, limit: Option<usize>| read_text(&repo.join(rel), limit);
    let base = |rel: &str| basename(Path::new(rel));

    let mut manifests: Vec<String> = files.iter().filter(|f| is_manifest(&base(f))).cloned().collect();
    manifests.sort();
    let names = gatekeeper_names(repo, &manifests);

    // file signatures
    for (pattern, vendor, typ) in &rules.file_signs {
        for hit in walk::glob_any(repo, pattern) {
            let rel = relpath(&hit, repo);
            if base(&rel) == "app.json" && !read(&rel, Some(3000)).to_lowercase().contains("heroku") {
                continue;
            }
            found.add(vendor, typ);
            break;
        }
    }

    // terraform providers, kubernetes, ECS, compose
    let tf_rx = re(r#"provider\s+"([a-z0-9_]+)""#);
    let k8s = re(r"(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|CronJob)\b");
    let compose_sect = re(r"(?m)^\s*(services|environment):");
    let compose_var = re(r"(?m)^\s*-?\s*([A-Z][A-Z0-9_]{2,})\s*[:=]");
    for f in &files {
        if f.ends_with(".tf") {
            let txt = read(f, Some(400_000));
            for m in tf_rx.captures_iter(&txt) {
                if let Some(v) = rules.tf.get(&m[1]) {
                    found.add(v, "platform");
                }
            }
        } else if (f.ends_with(".yaml") || f.ends_with(".yml")) && !f.starts_with(".github/") {
            let txt = read(f, Some(60_000));
            if k8s.is_match(&txt) && txt.contains("apiVersion:") {
                found.add("Kubernetes", "platform");
            }
            let b = base(f);
            if compose_sect.is_match(&txt) && (b.starts_with("docker-compose") || b.starts_with("compose")) {
                for m in compose_var.captures_iter(&txt) {
                    secrets.entry(m[1].to_string()).or_default().push(f.clone());
                }
            }
        } else if f.ends_with(".json") && read(f, Some(60_000)).contains("containerDefinitions") {
            found.add("AWS ECS", "platform");
        }
    }

    // Dockerfile base images -> container registries
    let from_rx = re(r"(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)");
    for f in &files {
        if !base(f).starts_with("Dockerfile") {
            continue;
        }
        for m in from_rx.captures_iter(&read(f, Some(400_000))) {
            let img = &m[1];
            if img.to_lowercase() == "scratch" || img.starts_with('$') {
                continue;
            }
            let mut reg = rules
                .registry
                .iter()
                .find(|(r, _)| r.is_match(img))
                .map(|(_, n)| n.clone());
            let first = img.split('/').next().unwrap_or("");
            if reg.is_none() && first.contains('.') && img.contains('/') {
                reg = Some(first.to_string());
            }
            found.add(reg.as_deref().unwrap_or("Docker Hub"), "package_registry");
        }
    }

    // CI secrets + third-party actions
    let gh_secret = re(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)");
    let ci_var = re(r"\$\{?([A-Z][A-Z0-9_]{3,})\}?");
    let other_ci = [
        (".gitlab-ci.yml", "GitLab CI"),
        (".circleci/config.yml", "CircleCI"),
        ("bitbucket-pipelines.yml", "Bitbucket Pipelines"),
        ("azure-pipelines.yml", "Azure Pipelines"),
    ];
    for f in &files {
        if f.starts_with(".github/workflows/") && (f.ends_with(".yml") || f.ends_with(".yaml")) {
            let txt = read(f, Some(400_000));
            let e = found.add("GitHub Actions", "ci");
            for m in gh_secret.captures_iter(&txt) {
                if &m[1] != "GITHUB_TOKEN" && !e.contains(&m[1].to_string()) {
                    e.push(m[1].to_string());
                }
            }
        } else if let Some((_, ci)) = other_ci.iter().find(|(p, _)| p == f) {
            for m in ci_var.captures_iter(&read(f, Some(400_000))) {
                if rules.secretish.is_match(&m[1]) {
                    let e = found.add(ci, "ci");
                    if !e.contains(&m[1].to_string()) {
                        e.push(m[1].to_string());
                    }
                }
            }
        }
    }

    // env var names: .env*, code
    let env_rx = re(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=");
    let code_rx = re(
        r#"(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\(\s*|process\.env\.|process\.env\[\s*|import\.meta\.env\.|Deno\.env\.get\(\s*)["']?([A-Z][A-Z0-9_]{2,})"#,
    );
    let code_ext = [".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rb"];
    for f in &files {
        if base(f).starts_with(".env") {
            for m in env_rx.captures_iter(&read(f, Some(400_000))) {
                secrets.entry(m[1].to_string()).or_default().push(f.clone());
            }
        } else if code_ext.iter().any(|e| f.ends_with(e)) {
            for m in code_rx.captures_iter(&read(f, Some(400_000))) {
                secrets.entry(m[1].to_string()).or_default().push(f.clone());
            }
        }
    }
    secrets.retain(|k, _| rules.secretish.is_match(k) && !rules.not_secret.is_match(k));

    // an old-format inventory file (infra/deployments.json) is imported, like scope.py's _from_inventory
    if fset.contains("infra/deployments.json") {
        let inv: Value = serde_json::from_str(&read("infra/deployments.json", Some(400_000)))
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
        let obj = inv.as_object()?; // Python: inv.get(...) on a non-object raises -> no vendors
        let mut entries: Vec<(String, &str)> = Vec::new();
        let mut seen = HashSet::new();
        let mut entry = |name: String, typ: &'static str, entries: &mut Vec<(String, &str)>| {
            if seen.insert(name.to_lowercase()) {
                entries.push((name, typ));
            }
        };
        for (key, typ, field) in [
            ("services", "platform", "platform"),
            ("developer_tools", "developer_tool", "name"),
            ("ci", "ci", "name"),
        ] {
            for item in obj.get(key).and_then(|x| x.as_array()).cloned().unwrap_or_default() {
                let name = item.get(field).and_then(|x| x.as_str())?.to_string(); // a missing field raises in Python
                entry(name, typ, &mut entries);
            }
        }
        for (name, typ) in entries {
            found.add(&name, typ);
        }
    }

    // vendors from dependencies
    for name in &names {
        if let Some((_, vendor, typ)) = rules.pkg.iter().find(|(r, _, _)| r.is_match(name)) {
            found.add(vendor, typ);
        }
    }

    // secrets -> vendors by prefix
    for s_ in secrets.keys() {
        if let Some((_, v, t)) = rules.env.iter().find(|(r, _, _)| r.is_match(s_)) {
            let e = found.add(v, t);
            if !e.contains(s_) {
                e.push(s_.clone());
            }
        }
    }
    // CI secrets that belong to a vendor (e.g. FASTAPI_CLOUD_TOKEN)
    let ci_entries: Vec<(String, Vec<String>)> = found
        .order
        .iter()
        .map(|k| &found.by[k])
        .filter(|(_, t, _)| t == "ci")
        .map(|(n, _, s)| (n.clone(), s.clone()))
        .collect();
    for (ci_name, ci_secrets) in ci_entries {
        for s_ in ci_secrets {
            if let Some((_, v, t)) = rules.env.iter().find(|(r, _, _)| r.is_match(&s_)) {
                if v != &ci_name {
                    found.add(v, t);
                }
            }
        }
    }

    let mut tp: Vec<(String, String)> = found
        .order
        .iter()
        .map(|k| (found.by[k].0.clone(), found.by[k].1.clone()))
        .collect();
    tp.sort_by(|a, b| {
        let ia = TYPES.iter().position(|t| *t == a.1).unwrap_or(TYPES.len());
        let ib = TYPES.iter().position(|t| *t == b.1).unwrap_or(TYPES.len());
        (ia, &a.0).cmp(&(ib, &b.0))
    });
    Some(tp)
}
