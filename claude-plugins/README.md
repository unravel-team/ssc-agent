# Claude Code plugins

A local marketplace (`ssc-local`) with one plugin.

## ssc-advisor

`/ssc-advisor:advise [folder]` works on a folder's **action items**: the same single list, with the same states, that
the scanner app shows. Each item is **pending**, **done** or **skipped** (not relevant to you, or you won't do it).

1. Scans the folder (reads files only; nothing is installed or run) and sends it to the advisory API.
2. Shows the summary and one table of pending action items (packages, secrets, certificates, breached vendors).
3. Checks each item against the project's own files (read only; nothing is sent). For Python it parses the code
   (`code_index.py`, the standard library's `ast`): what starts the program (run commands, routes, tasks,
   `__main__`) and whether a call path leads from there to the functions an advisory names, shown hop by hop; a path
   the assistant claims on its own is checked against the parsed code first (`confirm`). For a reachable call it
   adds who can reach it: the kind of entry point (web route, background job, command line), login and permission
   checks on the path, and what the deployment config says (`deployment.py`: Fly.io services, compose ports,
   Procfile, Kubernetes, Terraform, nginx), each with its file and line. Also: whether a file is
   test or shipped code, whether a secret ships inside a Docker image,
   whether Docker Hub is only pulled from or also pushed to. It labels each item relevant, likely not relevant or
   unclear, with the file and line, and offers to skip only the items you pick (your reason goes with the skip).
4. Asks which automatic fixes to apply; changes nothing until you answer.
5. Applies only those (files are backed up first, with a restore command) and marks them done.
6. Marks items done or skipped when you say so (for example "I rotated the database password", or "we don't push
   images to Docker Hub").

States live in `~/.ssc/results/<folder>/done.json`. A rescan marks done what it no longer finds, and reopens an
applied fix it still finds. Done and skipped items go to the server with each scan, so the advisory stops raising
them; skip reasons show which kinds of item aren't relevant. It changes manifest lines only and never installs
packages.

It needs nothing else: `scripts/ssc_scope.py` reads the folder's files the same way the `ssc` app does (a test checks
that both build the same scan) and the script talks to the advisory API itself. Results and ticks live in `~/.ssc`, so
if the app is installed too, both show the same list and ticks.

### No setup
The first scan gets this computer's scan key from the server (`POST /v1/register`) and saves it in `~/.ssc/key`
(readable only by you), or uses the `ssc` app's key if the app is set up here. The server is
https://unravel-ssc-api.fly.dev; `SSC_API_URL` / `SSC_API_KEY` environment variables override it.

If a server hands out no keys, get one from its admin and run this **in a terminal** (not in Claude), so the key never
enters a chat: `python3 /path/to/ssc_agent/claude-plugins/ssc-advisor/scripts/ssc_advise.py setup` (it asks for the
key without showing it).

### Install
```
claude plugin marketplace add /path/to/ssc_agent/claude-plugins
claude plugin install ssc-advisor@ssc-local
```
Or in a session: `/plugin marketplace add /path/to/ssc_agent/claude-plugins`, then `/plugin install ssc-advisor@ssc-local`.
After editing the plugin, run `/reload-plugins`.

### Script
`ssc-advisor/scripts/ssc_advise.py` (Python standard library only) can also be run by hand:
`setup`, `status`, `scan FOLDER`, `list FOLDER`, `context FOLDER`,
`confirm FOLDER --project P --hops A B ...`, `apply FOLDER --ids 1,3`, `done FOLDER --ids 2`,
`skip FOLDER --ids 3 --why "..."`, `pending FOLDER --ids 3`, `restore BACKUP_DIR FOLDER`.
