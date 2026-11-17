# What each finding turns into

Generated from the tables in `tests/test_state_matrix.py`, which check every combination against the code.
Edit the tables there, then: `python3 tests/test_state_matrix.py --doc > intel_api/ACTION_RULES.md`.

## Secrets
Only facts leave the laptop: the kind of secret, its file and line, git's view of the file. Never the value.

| Where | Git | Value | Action item | Priority | Criticality | The action says |
|---|---|---|---|---|---|---|
| env file | committed | real | yes | block | Critical | Rotate … history |
| env file | committed | example | none | | | |
| env file | not committed, ignored | real | none | | | |
| env file | not committed, ignored | example | none | | | |
| env file | not committed, not ignored | real | yes | hold | Medium | .gitignore |
| env file | not committed, not ignored | example | none | | | |
| env file | no git | real | none | | | |
| env file | no git | example | none | | | |
| source code | committed | real | yes | block | Critical | Rotate … history |
| source code | committed | example | none | | | |
| source code | not committed, ignored | real | yes | block | High | out of the code into an environment variable |
| source code | not committed, ignored | example | none | | | |
| source code | not committed, not ignored | real | yes | block | High | out of the code into an environment variable |
| source code | not committed, not ignored | example | none | | | |
| source code | no git | real | yes | block | High | out of the code into an environment variable |
| source code | no git | example | none | | | |

## Packages
A dependency only a lockfile lists (pulled in by another package) gets an item only for hard evidence:
malware, an advisory, or a block. A problem in a dependency used only in development (npm `devDependencies`,
Python `requirements-dev.txt` and the like, and `pyproject.toml` groups or extras named dev, test, lint, docs,
ci or typing, including Poetry's), or one no code imports and no run command starts, is one level
less critical (once, never twice). The laptop works out "used" and sends only yes or no; a framework may
still load a package by name, so this lowers, never hides. What may be malicious code (malware, or anything
blocked) keeps its level, since even an unused or dev-only package runs code when it is installed.

| Declared in | What the rules found | Action item | Priority | Criticality | The action says | Automatic |
|---|---|---|---|---|---|---|
| dependencies | nothing found | none | | | | |
| dependencies | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| dependencies | exploited advisory (KEV), fix verified | yes | hold | Critical | Change to 1.2.4 | yes |
| dependencies | high advisory, fix verified | yes | hold | High | Change to 1.2.4 | yes |
| dependencies | high advisory, fix unverified | yes | hold | High | Choose a safe version and pin it exactly | no |
| dependencies | high advisory, no fix | yes | hold | High | No fixed version exists | no |
| dependencies | deprecated | yes | hold | Low | Plan a replacement | no |
| dependencies | news only | yes | hold | Medium | Check the reports | no |
| dependencies | internal name | yes | hold | Medium | private registry | no |
| dependencies | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| dependencies | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| dependencies, not used | nothing found | none | | | | |
| dependencies, not used | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| dependencies, not used | exploited advisory (KEV), fix verified | yes | hold | High | Change to 1.2.4 | yes |
| dependencies, not used | high advisory, fix verified | yes | hold | Medium | Change to 1.2.4 | yes |
| dependencies, not used | high advisory, fix unverified | yes | hold | Medium | Choose a safe version and pin it exactly | no |
| dependencies, not used | high advisory, no fix | yes | hold | Medium | No fixed version exists | no |
| dependencies, not used | deprecated | yes | hold | Low | Plan a replacement | no |
| dependencies, not used | news only | yes | hold | Low | Check the reports | no |
| dependencies, not used | internal name | yes | hold | Low | private registry | no |
| dependencies, not used | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| dependencies, not used | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| devDependencies | nothing found | none | | | | |
| devDependencies | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| devDependencies | exploited advisory (KEV), fix verified | yes | hold | High | Change to 1.2.4 | yes |
| devDependencies | high advisory, fix verified | yes | hold | Medium | Change to 1.2.4 | yes |
| devDependencies | high advisory, fix unverified | yes | hold | Medium | Choose a safe version and pin it exactly | no |
| devDependencies | high advisory, no fix | yes | hold | Medium | No fixed version exists | no |
| devDependencies | deprecated | yes | hold | Low | Plan a replacement | no |
| devDependencies | news only | yes | hold | Low | Check the reports | no |
| devDependencies | internal name | yes | hold | Low | private registry | no |
| devDependencies | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| devDependencies | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| devDependencies, not used | nothing found | none | | | | |
| devDependencies, not used | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| devDependencies, not used | exploited advisory (KEV), fix verified | yes | hold | High | Change to 1.2.4 | yes |
| devDependencies, not used | high advisory, fix verified | yes | hold | Medium | Change to 1.2.4 | yes |
| devDependencies, not used | high advisory, fix unverified | yes | hold | Medium | Choose a safe version and pin it exactly | no |
| devDependencies, not used | high advisory, no fix | yes | hold | Medium | No fixed version exists | no |
| devDependencies, not used | deprecated | yes | hold | Low | Plan a replacement | no |
| devDependencies, not used | news only | yes | hold | Low | Check the reports | no |
| devDependencies, not used | internal name | yes | hold | Low | private registry | no |
| devDependencies, not used | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| devDependencies, not used | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| requirements-dev.txt | nothing found | none | | | | |
| requirements-dev.txt | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| requirements-dev.txt | exploited advisory (KEV), fix verified | yes | hold | High | Change to 1.2.4 | yes |
| requirements-dev.txt | high advisory, fix verified | yes | hold | Medium | Change to 1.2.4 | yes |
| requirements-dev.txt | high advisory, fix unverified | yes | hold | Medium | Choose a safe version and pin it exactly | no |
| requirements-dev.txt | high advisory, no fix | yes | hold | Medium | No fixed version exists | no |
| requirements-dev.txt | deprecated | yes | hold | Low | Plan a replacement | no |
| requirements-dev.txt | news only | yes | hold | Low | Check the reports | no |
| requirements-dev.txt | internal name | yes | hold | Low | private registry | no |
| requirements-dev.txt | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| requirements-dev.txt | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| Poetry dev group | nothing found | none | | | | |
| Poetry dev group | malicious, fix verified | yes | block | Critical | Change to 1.2.4 … Check machines and CI | yes |
| Poetry dev group | exploited advisory (KEV), fix verified | yes | hold | High | Change to 1.2.4 | yes |
| Poetry dev group | high advisory, fix verified | yes | hold | Medium | Change to 1.2.4 | yes |
| Poetry dev group | high advisory, fix unverified | yes | hold | Medium | Choose a safe version and pin it exactly | no |
| Poetry dev group | high advisory, no fix | yes | hold | Medium | No fixed version exists | no |
| Poetry dev group | deprecated | yes | hold | Low | Plan a replacement | no |
| Poetry dev group | news only | yes | hold | Low | Check the reports | no |
| Poetry dev group | internal name | yes | hold | Low | private registry | no |
| Poetry dev group | internal name on the public registry | yes | block | High | published this internal name on the public registry | no |
| Poetry dev group | lookalike of a popular name | yes | block | High | Replace it with requests | no |
| lockfile only | nothing found | none | | | | |
| lockfile only | malicious, fix verified | yes | block | Critical | Find which package pulls in  …  malicious | no |
| lockfile only | exploited advisory (KEV), fix verified | yes | hold | Critical | pulls it in | no |
| lockfile only | high advisory, fix verified | yes | hold | High | pulls it in | no |
| lockfile only | high advisory, fix unverified | yes | hold | High | pulls it in | no |
| lockfile only | high advisory, no fix | yes | hold | High | pulls it in | no |
| lockfile only | deprecated | none | | | | |
| lockfile only | news only | none | | | | |
| lockfile only | internal name | none | | | | |
| lockfile only | internal name on the public registry | yes | block | High | pulls it in | no |
| lockfile only | lookalike of a popular name | yes | block | High | pulls it in | no |

## Lockfiles
One Low item per ecosystem a project uses without its own kind of lockfile.

| Dependencies | Lockfiles | Items |
|---|---|---|
| npm | none | No npm lockfile |
| npm | package-lock.json | none |
| npm | uv.lock | No npm lockfile |
| npm | both | none |
| Python | none | No Python lockfile |
| Python | package-lock.json | No Python lockfile |
| Python | uv.lock | none |
| Python | both | none |
| npm and Python | none | No Python lockfile, No npm lockfile |
| npm and Python | package-lock.json | No Python lockfile |
| npm and Python | uv.lock | No npm lockfile |
| npm and Python | both | none |

## Consistency rules (every finished scan)
`intel_api/engine/checks.py` checks each result; problems are logged, returned with the scan as `checks`, and
counted by `python3 -m intel_api checks`.

- **fields**: every action item has a known priority, criticality and kind, an action, and (for packages, secrets and lockfiles) a place in the project; no two items share a key
- **summary_row**: every point of the Summary refers to at least one open action item, and only to items that exist
- **summary_done**: no point of the Summary refers to an item the developer already ticked off
- **fix_verified**: every automatic edit is verified and moves to the version the rules checked
- **other_project**: every row the agents add names exactly one project of the scan
- **other_source**: every row the agents add cites evidence the server gave them (by its id in evidence.json)
- **structured**: the advisory refers to items and evidence by id (one written as free text can't be checked)
- **supported**: what each summary point and agent row says is backed by the items and evidence it refers to (judged by a separate AI check in the agents container)
