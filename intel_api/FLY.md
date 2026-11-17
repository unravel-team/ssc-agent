# Deploying the sources API on Fly.io

Live: **https://unravel-ssc-api.fly.dev** (org Unravel.tech, region Singapore `sin`).

One Fly app runs the API **and** the agents on a single machine (the org has a machine limit), with Fly Managed
Postgres as the database. Fly's edge replaces nginx: it terminates HTTPS and manages the certificate.

| Docker Compose (DEPLOY.md) | Fly.io |
|---|---|
| `nginx` (TLS, ports 80/443) | not needed: Fly's edge does HTTPS |
| `api` and `agents` containers | app **unravel-ssc-api**: one machine, image `Dockerfile.fly`, started by `fly_start.py` |
| `postgres` | Managed Postgres **unravel-ssc-db** (Basic plan), attached as `DATABASE_URL` |
| `.env` | Fly secrets, copied by `fly-secrets.sh` |

> **Machine limit.** The Unravel.tech org is at Fly's limit of 20 machines, and at the limit Fly refuses even to update
> an existing machine. Raise it at https://fly.io/dashboard/unravel-tech/settings?request=machine-limit before
> deploying.

## How the two run on one machine
`fly_start.py` starts the API as user `intel` and the agents as user `agent`, and splits the secrets:
- the API gets everything except the AI credentials and the agents' key;
- the agents get only their key, the AI credentials and a few settings (never the database address), and reach
  the API on `127.0.0.1`.

Neither user can read the other process's environment. If either process exits, the machine exits and Fly restarts it.

## Deploying changes
```sh
cd intel_api && fly deploy --ha=false
```
`--ha=false` matters on a first deploy: Fly otherwise starts two machines, and this app must run exactly one (the
collection jobs and the scan worker run inside it, and claiming scans assumes one process). Never `fly scale count`
it above 1. `fly.toml` also keeps it always on (`auto_stop_machines = "off"`, `min_machines_running = 1`).

Configuration (`config/scope.json`, `config/sources.json`) is baked into the image: after editing it, deploy again.

## Setting it up from scratch (what was done)
```sh
brew install flyctl && fly auth login
fly apps create unravel-ssc-api --org unravel-tech
fly mpg create --name unravel-ssc-db --org unravel-tech --region sin --plan basic --pg-major-version 17
fly mpg attach <cluster id> -a unravel-ssc-api     # adds the DATABASE_URL secret
./fly-secrets.sh                                   # the rest, from intel_api/.env (nothing is printed)
fly deploy --ha=false
```

## Checking it
```sh
curl https://unravel-ssc-api.fly.dev/v1/health
fly logs -a unravel-ssc-api        # [intel-api] collection jobs, [agents] advisories
fly secrets list -a unravel-ssc-api
```

## Your own domain
```sh
fly certs add intel.yourcompany.com -a unravel-ssc-api     # then add the DNS records it prints
```

## Moving the existing data (optional)
Without this, the Fly database fills itself from the sources within a day. Scan history starts fresh too; ticks are
unaffected, since they live on the laptops.
```sh
docker compose exec -T postgres pg_dump -U intel -d intel -Fc > intel.dump      # from the local stack
fly mpg proxy <cluster id>          # in another terminal; it prints the local address to connect to
pg_restore --no-owner -d 'postgres://USER:PASSWORD@localhost:PORT/DBNAME' intel.dump
```
Keep `intel.dump` private (it holds scan history) and delete it afterwards.

## Laptops
Build the app with the new address and hand it out: each laptop gets its own scan key from the server on its first
scan (`POST /v1/register`; see "Laptop keys" in the top README to list or revoke them, or turn this off):
```sh
cd ../scanner && SSC_BUILD_API_URL=https://unravel-ssc-api.fly.dev cargo build --release --locked
```
Laptops that already have the app can set `SSC_API_URL=https://unravel-ssc-api.fly.dev` in their `.env` instead.

## What nginx did that Fly doesn't
nginx limited request rates and could restrict client IPs. On Fly the API still requires a key on every request
except `/v1/health`. For rate limits at the edge, put Cloudflare (or similar) in front of a custom domain.
