#!/usr/bin/env python3
"""Build step: download one pinned Claude Code release and check it against its pinned SHA-256 (the values
Anthropic publishes in https://downloads.claude.ai/claude-code-releases/<version>/manifest.json).

    fetch_claude.py <version> <arch: amd64|arm64> <sha256 for x64> <sha256 for arm64> <output path>
"""

import hashlib
import os
import sys
import urllib.request

version, arch, sha_x64, sha_arm64, out = sys.argv[1:6]
platform, want = {"amd64": ("linux-x64", sha_x64), "arm64": ("linux-arm64", sha_arm64)}[arch]
url = f"https://downloads.claude.ai/claude-code-releases/{version}/{platform}/claude"
h, tmp = hashlib.sha256(), out + ".part"
with urllib.request.urlopen(url, timeout=300) as r, open(tmp, "wb") as f:
    while chunk := r.read(1 << 20):
        h.update(chunk)
        f.write(chunk)
if h.hexdigest() != want:
    os.remove(tmp)
    sys.exit(f"checksum mismatch for {url}: got {h.hexdigest()}, expected {want}")
os.chmod(tmp, 0o755)
os.replace(tmp, out)
print(f"Claude Code {version} ({platform}) verified: sha256 {want}")
