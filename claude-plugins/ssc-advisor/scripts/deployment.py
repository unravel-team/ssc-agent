"""Deployment context for the relevance check: what a project's own deployment files say about who can reach it.
Read only, and only the configuration: nothing is deployed, called or looked up.

Each fact names the file and line it comes from and what it means:
  - public:    something routes traffic from outside to it (a Fly.io http_service, a Procfile `web` process, a
               compose service publishing a port on every interface, a Kubernetes LoadBalancer or Ingress, a
               Terraform load balancer that isn't internal, a rule open to 0.0.0.0/0, an nginx front with proxy_pass)
  - internal:  only other services or this machine reach it (a compose service with no published port or one bound
               to 127.0.0.1, a Fly.io app with no public service, a Procfile worker, an internal load balancer)
  - declared:  a port the image declares (EXPOSE), which publishes nothing by itself

Facts from a file inside the project apply to it; compose services apply to the project their build context names;
Kubernetes, Terraform and nginx files elsewhere in the scanned folder can't be tied to one project, so they are
reported as applying to the whole folder.
"""

import re
from pathlib import Path

import ssc_scope

LIMIT = 400_000
PLATFORMS = {
    "vercel.json": "Vercel serves it on a public URL",
    "netlify.toml": "Netlify serves it on a public URL",
    "app.yaml": "App Engine serves it on a public URL",
    "railway.json": "Railway (public if a domain is generated)",
    "railway.toml": "Railway (public if a domain is generated)",
}
TERRAFORM = [
    (re.compile(r"^\s*internal\s*=\s*false\b"), "public", "load balancer that is not internal"),
    (re.compile(r"^\s*internal\s*=\s*true\b"), "internal", "internal load balancer"),
    (re.compile(r"cidr_blocks\s*=\s*\[[^\]]*\"0\.0\.0\.0/0\""), "public", "rule open to the internet (0.0.0.0/0)"),
    (re.compile(r"authorization_type\s*=\s*\"NONE\""), "public", "endpoint with no authorization"),
    (re.compile(r"\"allUsers\""), "public", "open to allUsers"),
    (re.compile(r"\bmap_public_ip_on_launch\s*=\s*true\b"), "public", "public IP addresses on launch"),
]  # fmt: skip


def _rel(path, base):
    try:
        return Path(path).relative_to(base).as_posix()
    except ValueError:
        return str(path)


def _fact(where, exposure, says, applies_to):
    return {"where": where, "exposure": exposure, "says": says, "applies_to": applies_to}


def _fly(f, base):
    text = ssc_scope.read_text(f, LIMIT)
    out = []
    for n, line in enumerate(ssc_scope.lines(text), 1):
        if re.match(r"\s*\[http_service\]", line):
            port = re.search(r"(?m)^\s*internal_port\s*=\s*(\d+)", text)
            out.append(_fact(f"{_rel(f, base)}:{n}", "public",
                             f"Fly.io public HTTPS to port {port[1] if port else '?'}", "project"))  # fmt: skip
        elif re.match(r"\s*\[\[services\]\]", line):
            out.append(_fact(f"{_rel(f, base)}:{n}", "public", "Fly.io service with public ports", "project"))
    if not out:
        out.append(_fact(_rel(f, base), "internal", "Fly.io app with no public service (private network)", "project"))
    return out


def _procfile(f, base):
    out = []
    for n, line in enumerate(ssc_scope.lines(ssc_scope.read_text(f, LIMIT)), 1):
        m = re.match(r"\s*([\w-]+)\s*:", line)
        if m:
            web = m[1] == "web"
            out.append(_fact(f"{_rel(f, base)}:{n}", "public" if web else "internal",
                             f"Procfile `{m[1]}` process" + (": the platform routes web traffic to it" if web else ""),
                             "project"))  # fmt: skip
    return out


def _dockerfile(f, base):
    out = []
    for n, line in enumerate(ssc_scope.lines(ssc_scope.read_text(f, LIMIT)), 1):
        m = re.match(r"(?i)\s*EXPOSE\s+(.+)", line)
        if m:
            says = f"the image declares port {m[1].strip()} (publishes nothing by itself)"
            out.append(_fact(f"{_rel(f, base)}:{n}", "declared", says, "project"))
    return out


# ---------------------------------------------------------------- compose: a small reader for the keys that matter
def _compose_services(text):
    """{service: {"line": n, "build": path or None, "ports": [(line, spec)], "expose": [..], "network_mode": ..}}"""
    services, current, key, indent = {}, None, None, None
    in_services = False
    for n, raw in enumerate(ssc_scope.lines(text), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        depth = len(raw) - len(raw.lstrip())
        line = re.sub(r"\s+#.*$", "", raw.strip())  # a trailing comment (YAML needs a space before the #)
        if depth == 0:
            in_services = line.startswith("services:")
            current = None
            continue
        if not in_services:
            continue
        if indent is None:
            indent = depth
        if depth == indent and line.endswith(":"):
            current = line[:-1].strip("\"'")
            services[current] = {"line": n, "build": None, "ports": [], "expose": [], "network_mode": None}
            key = None
            continue
        if current is None:
            continue
        svc = services[current]
        m = re.match(r"([\w-]+)\s*:\s*(.*)$", line)
        if m and depth == indent * 2:
            key, value = m[1], m[2].strip().strip("\"'")
            if key == "build" and value:
                svc["build"] = value
            elif key == "network_mode":
                svc["network_mode"] = value
            elif key in ("ports", "expose") and value.startswith("["):
                svc[key] += [(n, v.strip().strip("\"'")) for v in value.strip("[]").split(",") if v.strip()]
            continue
        if key == "build" and m and m[1] == "context":
            svc["build"] = m[2].strip().strip("\"'")
        elif key in ("ports", "expose") and line.startswith("-"):
            svc[key].append((n, line[1:].strip().strip("\"'")))
        elif key == "ports" and m and m[1] in ("published", "host_ip"):
            svc["ports"].append((n, f"{m[1]}: {m[2].strip()}"))
    return services


def _published(spec):
    """'public', 'internal' (bound to this machine only) for one compose port entry."""
    host = spec.split(":")[0] if spec.count(":") >= 2 else ""
    if spec.startswith("host_ip:"):
        host = spec.split(":", 1)[1].strip()
    return "internal" if host.strip("\"'[] ") in ("127.0.0.1", "localhost", "::1") else "public"


def _compose(f, base, project):
    out = []
    services = _compose_services(ssc_scope.read_text(f, LIMIT))
    for name, svc in services.items():
        if not svc["build"]:
            continue
        try:
            context = (f.parent / svc["build"]).resolve()
        except OSError:
            continue
        if context != project.resolve():
            continue
        where = f"{_rel(f, base)}:{svc['line']}"
        if svc["network_mode"] == "host":
            out.append(_fact(where, "public", f"compose service `{name}` uses the host's network", "project"))
        if svc["ports"]:
            for line, spec in svc["ports"]:
                kind = _published(spec)
                says = "published on every interface" if kind == "public" else "published on this machine only"
                out.append(_fact(f"{_rel(f, base)}:{line}", kind, f"compose service `{name}` port {spec}: {says}",
                                 "project"))  # fmt: skip
        elif svc["network_mode"] != "host":
            out.append(_fact(where, "internal", f"compose service `{name}` publishes no port (compose network only)",
                             "project"))  # fmt: skip
    return out


# ---------------------------------------------------------------- folder-wide files
def _kubernetes(f, base):
    text = ssc_scope.read_text(f, LIMIT)
    if not re.search(r"(?m)^\s*kind\s*:", text):
        return []
    out = []
    for n, line in enumerate(ssc_scope.lines(text), 1):
        if re.match(r"\s*kind\s*:\s*Ingress\b", line):
            out.append(_fact(f"{_rel(f, base)}:{n}", "public", "Kubernetes Ingress", "folder"))
        m = re.match(r"\s*type\s*:\s*(LoadBalancer|NodePort|ClusterIP)\b", line)
        if m:
            kind = "internal" if m[1] == "ClusterIP" else "public"
            out.append(_fact(f"{_rel(f, base)}:{n}", kind, f"Kubernetes Service of type {m[1]}", "folder"))
    return out


def _terraform(f, base):
    out = []
    for n, line in enumerate(ssc_scope.lines(ssc_scope.read_text(f, LIMIT)), 1):
        for rx, kind, says in TERRAFORM:
            if rx.search(line):
                out.append(_fact(f"{_rel(f, base)}:{n}", kind, f"Terraform: {says}", "folder"))
    return out


def _nginx(f, base):
    text = ssc_scope.read_text(f, LIMIT)
    if "proxy_pass" not in text:
        return []
    out = []
    for n, line in enumerate(ssc_scope.lines(text), 1):
        m = re.match(r"\s*listen\s+([^;]+);", line)
        if m and not re.search(r"127\.0\.0\.1|localhost", m[1]):
            out.append(_fact(f"{_rel(f, base)}:{n}", "public", f"nginx listens on {m[1].strip()} and proxies on",
                             "folder"))  # fmt: skip
    return out


def exposure(folder, project, project_files, folder_files):
    """What the deployment files say about who can reach a project, and a one-line summary."""
    folder, project = Path(folder), Path(project)
    facts = []
    for f in project_files:
        if f.name == "fly.toml":
            facts += _fly(f, folder)
        elif f.name == "Procfile":
            facts += _procfile(f, folder)
        elif f.name.startswith("Dockerfile"):
            facts += _dockerfile(f, folder)
        elif f.name in PLATFORMS:
            facts.append(_fact(_rel(f, folder), "public", PLATFORMS[f.name], "project"))
    for f in folder_files:
        name = f.name
        if name.startswith(("docker-compose", "compose")) and name.endswith((".yml", ".yaml")):
            facts += _compose(f, folder, project)
        elif name.endswith(".tf"):
            facts += _terraform(f, folder)
        elif name.endswith((".yml", ".yaml")) and not _rel(f, folder).startswith(".github/"):
            facts += _kubernetes(f, folder)
        elif name.endswith(".conf") or name == "nginx.conf":
            facts += _nginx(f, folder)
    own = {x["exposure"] for x in facts if x["applies_to"] == "project"}
    wide = {x["exposure"] for x in facts if x["applies_to"] == "folder"}
    if "public" in own:
        summary = "public: its own deployment config routes outside traffic to it"
    elif "internal" in own:
        summary = "internal: its own deployment config publishes it to no one outside" + (
            ", though config elsewhere in the folder opens something to the internet" if "public" in wide else ""
        )
    elif "public" in wide:
        summary = "unclear: config elsewhere in the folder opens something to the internet, not tied to this project"
    elif facts:
        summary = "unclear: a port is declared, but nothing says who can reach it"
    else:
        summary = "unknown: no deployment config found"
    return {"summary": summary, "facts": facts[:12]}
