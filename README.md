# arthunt

**Passive secret scanner for JFrog Artifactory** — the "TruffleHog for Artifactory"
you can drop on a locked‑down box. A single static `.exe` / binary, **no Python,
no runtime, no dependencies**. It discovers every repository from a base URL,
lists the files, fetches text/config artifacts within a byte budget and runs
~115 embedded detectors (TruffleHog/Gitleaks‑style) **entirely offline** — no
secret is ever sent to a third party for validation.

Built for **authorised** audits where you own the platform: low‑and‑slow by
default (global rate limiting, jitter, randomised order), a live dashboard,
resume/retry, and targeted Docker‑image modes.

```console
$ arthunt --url https://repo.corp.tld --user jdoe --mint-token
```

> ⚠️ **Authorised use only.** arthunt is for security auditing of infrastructure
> you own or are explicitly authorised to test. Generated reports can contain
> live credentials — handle them accordingly. See [Legal](#legal).

---

## Table of contents
- [Why](#why)
- [Features](#features)
- [Live dashboard](#live-dashboard)
- [Install](#install)
- [Build from source](#build-from-source)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Usage & recipes](#usage--recipes)
- [Targeted scan modes](#targeted-scan-modes)
- [Errors, retry & merge](#errors-retry--merge)
- [Output](#output)
- [OPSEC notes](#opsec-notes)
- [Detectors](#detectors)
- [Flag reference](#flag-reference)
- [Exit codes](#exit-codes)
- [How it works](#how-it-works)
- [Legal](#legal)
- [License](#license)

---

## Why

Hunting secrets in Artifactory by hand (AQL queries, downloading and grepping
artifacts) is slow and incomplete. arthunt automates the whole loop —
**discover → list → fetch → detect → report** — while staying quiet in the
access logs, and it cracks open the artifacts where secrets actually hide
(`.jar`/`.war` configs, `.npmrc` inside `.tgz`, Docker image `ENV`, …).

## Features

- **Single static binary** — cross‑compiled Go, stdlib only, zero third‑party
  dependencies and zero supply chain. Nothing to install on the target.
- **Fully passive** — regex + Shannon entropy + context. Contacts **only** the
  Artifactory host you provide. No telemetry, no update check, no callback to
  AWS/GitHub/etc. to "verify" a secret. Off‑host HTTP redirects (e.g. Direct
  Cloud Storage Download to S3/Azure) are **refused** to preserve passivity.
- **Low‑and‑slow OPSEC** — `stealth`/`balanced`/`aggressive` profiles, global
  rate limiter with jitter, randomised order, optional `--max-duration` to spread
  a scan over a window (e.g. 24h).
- **Auto‑discovery** — enumerates repos from the base URL via AQL, with a
  Storage‑API fallback when AQL is not permitted (non‑admin friendly).
- **Deep coverage (optional)** — crack archives (`--crack`), scan Docker image
  config/`ENV` (`--docker-config`) and image layer filesystems (`--docker-layers`).
- **Targeted modes** — `--no-files` (only targeted modes), `--repos` / `--exclude`
  / `--package-type`, `--since 7d` (incremental).
- **Live dashboard** — sticky header (repos/files progress, secrets by severity,
  ETA) with findings streaming below; auto‑falls back to plain lines when output
  is redirected.
- **Resume / retry / merge** — checkpoint to resume after interruption, an auto
  `*.errors.jsonl` of failures, targeted `--retry` and report `--merge`.
- **Reports** — self‑contained offline **HTML**, **JSON** and **CSV**; secrets
  redacted by default, files written `0600`.
- **~115 detectors** — cloud, VCS/CI, SaaS, AI providers, package registries,
  databases, private keys, JWTs; extensible via `--rules`.

## Live dashboard

On an interactive terminal you get a sticky header that refreshes in place, with
secrets streaming below as they're found:

```text
arthunt · repos 12/87 done · files 1490/44930 (3%)
secrets: crit 1 · high 6 · med 3 · low 0   (errors 2)
elapsed 16m04s · eta 8h02m
────────────────────────────────────────────────────────────
[+] CRITICAL private-key            libs-release-local/app/id_rsa:1   ----…[redacted 35]
[+] HIGH     aws-access-key-id      libs-release-local/conf.yml:2     AKIA…[redacted 20]
[+] HIGH     npm-token              npm-local/pkg/.npmrc:1            npm_…[redacted 40]
```

When stderr is not a TTY (piped/redirected) or with `--plain`, output degrades to
clean scrolling lines.

## Install

### Pre-built binaries
Download the binary for your target from the
[Releases](https://github.com/0x3EB/arthunt/releases) page:

| Target | File |
|---|---|
| Windows x64 | `arthunt.exe` |
| Windows ARM64 | `arthunt-arm64.exe` |
| Linux x64 | `arthunt-linux` |

Verify the checksum, then run it — there is nothing else to install:

```console
$ sha256sum -c SHA256SUMS
$ ./arthunt-linux --version
```

### `go install`
This requires the module path to match your repository. Rename it once after
forking/cloning (the module is `arthunt` by default):

```console
$ sed -i 's#^module arthunt#module github.com/0x3EB/arthunt#' go.mod
$ grep -rl '"arthunt/internal' . | xargs sed -i 's#"arthunt/internal#"github.com/0x3EB/arthunt/internal#g'
$ go mod tidy
# then, for users:
$ go install github.com/0x3EB/arthunt@latest
```

## Build from source

Requires **Go 1.22+** (developed/tested with Go 1.26). No external modules.

```console
$ git clone https://github.com/0x3EB/arthunt
$ cd arthunt
$ go build -o arthunt .
```

### Cross-compile a standalone Windows .exe (from Linux/macOS)
```console
$ CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/arthunt.exe .
```

### Build everything + checksums
`build.sh` runs the tests and emits Windows (amd64/arm64) and Linux binaries plus
`SHA256SUMS`:

```console
$ ./build.sh
```

> The result is a ~7 MB static PE32+/ELF executable. Copy it to the target —
> nothing else is required.

## Quick start

```console
# Stealth scan of all local repos, all report formats:
$ arthunt --url https://repo.corp.tld --token "$ARTHUNT_TOKEN"

# Normal (non-admin) account, mint a short-lived token, then scan under it:
$ ARTHUNT_PASSWORD=… arthunt --url https://repo.corp.tld --user jdoe --mint-token

# See what WOULD be scanned, without downloading anything:
$ arthunt --url https://repo.corp.tld --token "$ARTHUNT_TOKEN" --dry-run
```

## Authentication

Pick whichever your instance uses (first non‑empty wins). Prefer the environment
variables so credentials stay out of the process list.

| Method | Flag | Env |
|---|---|---|
| Bearer access token | `--token` | `ARTHUNT_TOKEN` |
| API key (`X-JFrog-Art-Api-Key`) | `--api-key` | `ARTHUNT_API_KEY` |
| Basic auth | `--user` / `--password` | `ARTHUNT_USER` / `ARTHUNT_PASSWORD` |
| Basic auth (raw base64) | `--basic` | `ARTHUNT_BASIC` |

`--user`/`--password` build the exact `Authorization: Basic <base64(user:password)>`
header you'd set by hand — no curl config file needed. If you already have that
base64 blob, paste it with `--basic <hash>` (the value after `Authorization: Basic `).

### Basic‑Auth → short‑lived token (recommended OPSEC)
With `--mint-token`, arthunt uses Basic‑Auth only for the initial handshake and
the token‑mint call, then runs the entire (noisy) scan under the resulting
**Bearer token** — the password is never re‑sent during the bulk scan. The token
is scoped to your own permissions and revocable.

```console
$ ARTHUNT_PASSWORD=… arthunt --url https://repo.corp.tld --user jdoe --mint-token --token-ttl 6h
```

It tries the Artifactory endpoint (`POST /api/security/token`, usable by a
non‑admin to create a self token) and falls back to the JFrog Platform Access API
(`POST /access/api/v1/tokens`).

## Usage & recipes

```console
# Faster (noisier) sweep, with resume across runs:
$ arthunt --url … --token "$T" --profile balanced --resume scan.ckpt

# Deep coverage: crack archives + scan Docker image configs:
$ arthunt --url … --token "$T" --crack --docker-config

# Target specific repos / package types, reveal full secret values:
$ arthunt --url … --token "$T" --repos libs-release-local,docker-local --show-secrets

# Only high/critical, JSON report only:
$ arthunt --url … --token "$T" --min-severity high --format json

# Spread the whole scan over ~24h for maximum stealth:
$ arthunt --url … --token "$T" --max-duration 24h
```

Scope filters: `--repos a,b` (allowlist, overrides type filters), `--exclude a,b`,
`--package-type maven,npm,docker`, `--include-remote`, `--include-virtual`,
`--max-size 5MB`.

## Targeted scan modes

By default arthunt scans loose text/config files. The biggest gains come from
opening the artifacts — these flags are composable:

| Flag | What it adds |
|---|---|
| `--crack` | open `jar/war/ear/zip/tgz/nupkg/whl/…` one level deep, scan inner text |
| `--docker-config` | for Docker repos, scan image **manifests + config blobs** (`ENV`/build‑args) — never pulls layers |
| `--docker-layers` | also crack Docker image **layer filesystems** (heavy; dedup'd by digest) |
| `--no-files` | skip the regular file scan; only the targeted modes run |
| `--since 7d` | only artifacts modified within the window (incremental; needs AQL) |

```console
# Docker images only (config/ENV), nothing else:
$ arthunt --url … --token "$T" --no-files --docker-config

# Docker images only, full (config + layers):
$ arthunt --url … --token "$T" --no-files --docker-layers

# Only recently-pushed Docker images, full:
$ arthunt --url … --token "$T" --no-files --docker-layers --since 30d
```

## Errors, retry & merge

Every run writes failures (unreachable artifacts, listing denials, …) to
**`<out>.errors.jsonl`** — one JSON object per failure, both human‑readable and
replayable. Re‑scan **only** those, without re‑listing the whole instance, and
fold the recovered findings back into the report:

```console
# 1) initial scan
$ arthunt --url … --token "$T" --out audit

# 2) replay just the failures and merge into the existing report
#    (repeat until the errors file is empty)
$ arthunt --url … --token "$T" --retry audit.errors.jsonl --merge audit.json --out audit
```

- `--retry` reconstructs the failed items directly (no AQL discovery); repo‑level
  listing failures re‑list only that repo; Docker layer blobs are re‑cracked.
- `--merge` loads the previous `*.json` report and de‑duplicates by fingerprint,
  then rewrites fresh `html/json/csv` (it never appends in place).
- A clean run clears the stale errors file, so the loop converges.
- `--resume` is the separate, general interruption‑recovery mechanism (skips
  already‑scanned items on a re‑run).

## Output

Three artifacts (`--out` prefix, default `arthunt-report`):

- **`.html`** — self‑contained, offline report: summary cards, breakdown by repo
  and category, sortable/filterable table with clickable artifact links.
- **`.json`** — full structured findings + scan stats (for pipelines / `--merge`).
- **`.csv`** — spreadsheet‑friendly (formula‑injection‑safe).

Each finding carries: rule, severity, repo, path (`archive!inner/file` when
cracked, `image!config:…` / layer paths for Docker), line/column, redacted match,
entropy, and `via_decoder` when found in a base64 blob. Secrets are **redacted by
default**; `--show-secrets` includes full values (the report then contains live
credentials — still written `0600`).

## OPSEC notes

- **Passive**: detection only; no third‑party validation, no telemetry.
- **Off‑host redirects refused**: an artifact `GET` that 302‑redirects to a cloud
  bucket is not followed (no DNS/IP leak to S3/Azure/GCS).
- **Pacing**: all requests (listing, downloads, retries) go through one global
  rate limiter with jitter; default `stealth` ≈ 1.5 req/s over 2 connections.
- **Credentials**: pass via env to keep them off the process list; `--mint-token`
  keeps the password off the bulk‑scan requests.
- **Routing**: `--proxy http://127.0.0.1:8080` (or `HTTP(S)_PROXY`) to tunnel
  through Burp/SOCKS; `--insecure` for internal CAs (an active proxy is reported).
- **Footprint**: byte‑capped streaming downloads, binaries skipped, nothing
  written to disk except the report and (optional) `--resume`/errors files.

## Detectors

~115 built‑in detectors covering cloud (AWS/GCP/Azure), VCS/CI (GitHub/GitLab),
SaaS (Slack/Stripe/SendGrid/…), AI providers, package registries
(npm/PyPI/NuGet/Docker/Artifactory/Maven), databases (connection‑string
passwords), private keys, JWTs and entropy‑gated generic assignments. False
positives are trimmed by an allowlist (documentation/example values, templates,
Maven `{encrypted}` blocks, checksum‑shaped hashes, low‑diversity strings).

Add your own with `--rules file.json` (same schema as
`internal/scan/rules.json`); they're merged with the built‑ins. Regexes must be
**RE2‑compatible** (Go `regexp`): no look‑around or back‑references.

## Flag reference

```text
  --url string            Artifactory base URL (https://host or .../artifactory) [required]

  Auth
  --token string          Bearer access token (env ARTHUNT_TOKEN)
  --api-key string        X-JFrog-Art-Api-Key (env ARTHUNT_API_KEY)
  --user / --password     Basic auth (env ARTHUNT_USER / ARTHUNT_PASSWORD)
  --basic string          base64 'user:password' (env ARTHUNT_BASIC)
  --mint-token            exchange Basic-Auth for a short-lived access token
  --token-ttl duration    minted token lifetime (0 = server default; e.g. 6h)

  Scope
  --repos string          comma-separated repo allowlist (overrides type filters)
  --exclude string        comma-separated repo keys to skip
  --package-type string   filter by packageType (maven,npm,docker,generic,…)
  --include-remote        also scan remote (cache) repositories
  --include-virtual       also scan virtual repositories
  --since string          only artifacts modified within e.g. 7d / 24h / 2w (AQL)
  --max-size string       max bytes fetched per file (default 5MB)
  --extensions string     extra file extensions to scan
  --extensionless         also scan files with no extension

  Coverage / targeted modes
  --crack                 open archives one level deep
  --docker-config         scan Docker image manifests + config blobs (ENV/build-args)
  --docker-layers         also scan Docker image layers (heavy)
  --max-layer-size string max bytes per Docker layer (default 100MB)
  --no-files              skip the regular file scan; only targeted modes
  --decode-base64         scan base64-decoded blobs (default true)
  --rules string          external JSON rules file to merge with built-ins

  Pace / OPSEC
  --profile string        stealth | balanced | aggressive (default stealth)
  --rate float            requests/sec (overrides profile)
  --concurrency int       concurrent connections (overrides profile)
  --jitter float          rate jitter fraction 0..1 (overrides profile)
  --max-duration duration spread the scan over ~this window (only slows down)
  --proxy string          proxy URL (else HTTP(S)_PROXY)
  --insecure              skip TLS verification
  --user-agent string     HTTP User-Agent

  Output / run control
  --out string            output file prefix (default arthunt-report)
  --format string         all | json | csv | html (default all)
  --show-secrets          include full secret values (default redacted)
  --min-severity string   low | medium | high | critical
  --max-findings int      stop after N findings (0 = unlimited)
  --resume string         checkpoint file to resume after interruption
  --retry string          re-scan only items from a previous <out>.errors.jsonl
  --merge string          merge findings from a previous <out>.json
  --dry-run               list selectable files without downloading
  --plain                 plain output instead of the sticky dashboard
  --no-live               do not stream findings to stderr
  --fail-on-findings      exit code 3 if any secrets are found (CI)
  --verbose               verbose progress
  --version               print version and exit
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | completed (clean, or findings without `--fail-on-findings`) |
| `1` | runtime error |
| `2` | usage error (bad/missing flags) |
| `3` | secrets found (only with `--fail-on-findings`) |

## How it works

1. `GET /api/system/ping` — connectivity (auto‑detects whether to append
   `/artifactory`).
2. `GET /api/repositories` — enumerate repos. Defaults to `LOCAL` + `FEDERATED`;
   add `--include-virtual` / `--include-remote` or pin with `--repos`.
3. Per repo: AQL (`POST /api/search/aql`, paginated). If AQL is forbidden it
   falls back to the Storage API (`GET /api/storage/{repo}?list&deep=1`, read‑only).
4. Per file: byte‑capped `GET {repo}/{path}` (HTTP `Range`), scan, report. Docker
   manifests additionally drive config/layer scanning.

All HTTP goes through one paced, jittered client; downloads stream and are
size‑capped; archives/layers are bomb‑guarded (entry count + total budget).

## Legal

arthunt is intended for **authorised security testing only** — assessments of
systems you own or have explicit, written permission to test. You are responsible
for complying with all applicable laws and agreements. The authors accept no
liability for misuse. Reports may contain **live secrets**: store them encrypted,
never on shared locations, and delete them when no longer needed.

## License

[MIT](LICENSE) © 0x3EB

---

*Inspired by [TruffleHog](https://github.com/trufflesecurity/trufflehog) and
[Gitleaks](https://github.com/gitleaks/gitleaks), focused on the JFrog
Artifactory attack surface.*
