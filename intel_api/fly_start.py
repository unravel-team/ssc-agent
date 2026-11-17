"""Start the API and the agents on one Fly.io machine (Dockerfile.fly), each as its own user with only its own secrets.

Fly gives every process on the machine the same secrets as environment variables, so they are split here:
  - the API (user intel) gets everything except the AI credentials and the agents' key;
  - the agents (user agent) get only their key, the AI credentials and a few settings, never the database address,
    and reach the API on 127.0.0.1.
Each runs as a different user, so neither can read the other's environment. If either exits, this script stops the
other and exits too, and Fly restarts the machine.
"""

import os
import signal
import subprocess
import sys
import time

AGENT_ONLY = {
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "SSC_AGENT_KEY",
    "SSC_AGENT_MODEL",
    "SSC_AGENT_BUDGET_USD",
    "SSC_VERIFY_MODEL",  # the support check (agents/runner.py)
    "SSC_VERIFY_BUDGET_USD",
}
AGENT_PASS = AGENT_ONLY | {"PATH", "LANG", "TZ"}
AGENT_FIXED = {
    "HOME": "/home/agent",
    "SSC_INTEL_API": "http://127.0.0.1:8787",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}


def main():
    env = dict(os.environ)
    api_env = {k: v for k, v in env.items() if k not in AGENT_ONLY}
    agent_env = {**{k: v for k, v in env.items() if k in AGENT_PASS}, **AGENT_FIXED}

    api = subprocess.Popen(
        [sys.executable, "-m", "intel_api", "serve", "--host", "::", "--port", "8787"],
        cwd="/app",
        env=api_env,
        user="intel",
        group="intel",
    )
    time.sleep(5)  # let the API start before the agents ask it for jobs
    agents = subprocess.Popen(
        [sys.executable, "/agents/runner.py"], cwd="/work", env=agent_env, user="agent", group="agent"
    )
    procs = {"api": api, "agents": agents}

    def stop(*_):
        for p in procs.values():
            if p.poll() is None:
                p.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while all(p.poll() is None for p in procs.values()):
        time.sleep(1)
    name, ended = next((n, p) for n, p in procs.items() if p.poll() is not None)
    print(f"[fly_start] {name} exited with {ended.returncode}; stopping the other", flush=True)
    stop()
    for p in procs.values():
        try:
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
    sys.exit(ended.returncode or 1)


if __name__ == "__main__":
    main()
