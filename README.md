<p align="center">
  <pre>
██╗  ██╗ █████╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
███████║███████║██████╔╝██║  ██║██║     ██║   ██║██████╔╝██║  ██║█████╗
██╔══██║██╔══██║██╔══██╗██║  ██║██║     ██║   ██║██╔══██╗██║  ██║██╔══╝
██║  ██║██║  ██║██║  ██║██████╔╝╚██████╗╚██████╔╝██║  ██║██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
  </pre>
</p>


<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/rules-64-orange?style=flat-square" alt="Rules">
  <img src="https://img.shields.io/badge/dependencies-0-green?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
</p>

---
 <p align="center">Fast, intelligent credential hunting and discovery for penetration testers. Finds hardcoded passwords, API keys, tokens, and secrets across filesystems. Zero dependencies.</p>

## What it Does?
Recursively scans a target path and extracts hardcoded credentials with high confidence. Not a grep wrapper — it uses entropy analysis, context awareness, known-key detection, and confidence scoring to separate real secrets from placeholders and documentation.

Built for internal pentests, red team engagements, and CTF/lab environments.

## Quick Start

```bash
# Scan a directory
python3 -m hardcorde /var/www

# Scan with confidence filter (recommended)
python3 -m hardcorde /home --min-confidence 50

# Compact output, no surrounding context
python3 -m hardcorde /etc --no-context

# Export to JSON
python3 -m hardcorde /opt -f json -o findings.json

# Export to HTML report
python3 -m hardcorde /srv -f html -o report.html

# Only high-value files (configs, scripts, keys)
python3 -m hardcorde / --high-value-only --severity high
```

## Output

Each finding shows exactly what you need — the secret, where it is, and how confident the tool is:

```
  [1]  CRITICAL  Database Connection URI
      /opt/app/docker-compose.yml:7
      Secret:     postgres://admin:Sup3rS3cretDBP@ss!@db:5432/myapp
      Confidence: [████████████████████] 100%

  [2]  CRITICAL  Stripe API Key
      /opt/app/.env:13
      Secret:     sk_live_4eC39HqLyjWDarjtT1zdp7dc
      Confidence: [███████████████████░] 99%

  [3]  HIGH  Hardcoded password assignment
      /opt/app/config.py:12
      Secret:     Pr0d_Db_P@ssw0rd!2024
      Confidence: [██████████████████░░] 92%
```

Output formats: **terminal** (colored), **JSON**, **CSV**, **HTML** (standalone report).

## What it catches

| Category | Examples |
|----------|----------|
| Passwords | Variable assignments, XML configs, INI files, PHP `define()`, `.netrc`, CLI `-p` flags, `net user /add` |
| API Keys | AWS, Google, Stripe, SendGrid, Twilio, Mailgun, OpenAI, Anthropic |
| Tokens | GitHub, GitLab, Slack, npm, PyPI, HuggingFace, Vault, Discord, Grafana |
| Connection Strings | Database URIs, JDBC, ODBC, inline `Password=` parameters |
| Private Keys | RSA, DSA, EC, OpenSSH, PGP (PEM headers) |
| Cloud Keys | AWS Access/Secret keys, Azure secrets, DigitalOcean |
| Hashes | Unix shadow (`$6$`, `$2b$`, `$y$`), NTLM |
| App Secrets | Django `SECRET_KEY`, Flask, Laravel `APP_KEY`, WordPress salts |
| Infra | Docker env secrets, Kubernetes secrets, Terraform defaults |
| Windows | AutoLogon registry, PowerShell `ConvertTo-SecureString`, unattend.xml |

64 detection rules total. Run `hardcorde --list-rules` to see all of them.

## How it's smart

- **Entropy analysis** — Measures randomness to distinguish `Kj8$mNpQ2vXw!rT9` from `changeme`
- **Placeholder detection** — Recognizes `${VAR}`, `{{template}}`, `<your-key-here>`, `TODO`, etc.
- **Known public keys** — AWS example keys (`AKIAIOSFODNN7EXAMPLE`) score low, not high
- **Context scoring** — Boosts confidence when surrounding lines mention `password`, `database`, `auth`
- **Path awareness** — Files in `/prod/`, `.env`, `.aws/credentials` score higher than `/test/`, `/docs/`
- **Comment penalty** — Commented-out lines score lower
- **Keyword pre-filter** — Skips regex on lines that can't match, keeping it fast on large codebases

## Installation

```bash
# Clone and run (no install needed)
git clone https://github.com/yourusername/hardcorde.git
cd hardcorde
python3 -m hardcorde /path/to/scan

# Or install as a CLI tool
pip install -e .
hardcorde /path/to/scan
```

**Requirements:** Python 3.9+. No external dependencies.

## Build Standalone Binary

```bash
# Linux / macOS
pip install pyinstaller
./build.sh

# Windows
pip install pyinstaller
build.bat
```

Produces a single portable binary in `dist/` — drop it on a target and run.

## CLI Reference

```
hardcorde [OPTIONS] PATH [PATH ...]

Output:
  -f, --format          terminal | json | csv | html (default: terminal)
  -o, --output FILE     Write to file instead of stdout
  --no-context          Hide surrounding code lines
  --no-color            Disable colors
  --verbose             Show scoring breakdown per finding
  -q, --quiet           Suppress progress bar

Filtering:
  --min-confidence N    Minimum confidence 0-100 (default: 25)
  --severity LEVEL      Minimum severity: critical|high|medium|low|info
  --category CAT ...    Filter by category (password, api_key, token, etc.)
  --tags TAG ...        Filter by tag (aws, cloud, docker, etc.)
  --rules ID ...        Only run specific rule IDs
  --exclude-rules ID    Skip specific rule IDs

Scanner:
  --max-size MB         Max file size in MB (default: 10)
  --max-depth N         Max directory depth (default: 50)
  --high-value-only     Only scan config/secret/script files
  --follow-symlinks     Follow symbolic links
  --include-dirs DIR    Override skip list for specific dirs

Common locations:
  --win-common          Add common Windows credential locations
  --linux-common        Add common Linux credential locations

Performance:
  -t, --threads N       Scanner threads (default: 4)
```

## Common Credential Location Scanning

During internal pentests and privilege escalation, credentials are often left in predictable locations. The `--win-common` and `--linux-common` flags automatically scan these locations without requiring you to type every path manually.

```bash
hardcorde --linux-common                        # Scan all common Linux locations
hardcorde --win-common                          # Scan all common Windows locations
hardcorde /opt/webapp --linux-common            # User path + Linux common locations
hardcorde C:\Projects --win-common -f json      # User path + Windows common + JSON
hardcorde --linux-common --severity high -q     # Quick triage, high findings only
```

These flags are **additive** — they extend the scan scope alongside any user-supplied paths. Paths that don't exist or can't be accessed are silently skipped. No crashes on permission errors.

### Windows locations (`--win-common`)

PowerShell history, unattend/sysprep XML, IIS/web.config, .NET config, cloud credentials (AWS/Azure/GCP/Kube), SSH keys, PuTTY config, FileZilla/WinSCP/mRemoteNG saved sessions, OpenVPN configs, DPAPI credential locations, AppData config files, user desktops/documents/downloads.

### Linux locations (`--linux-common`)

Shell history (bash/zsh/fish/ash), SSH keys, /etc/shadow and backups, environment/profile files, cloud credentials (AWS/Azure/GCP/Kube/Docker), database client history (.mysql_history/.psql_history/.my.cnf), web roots (/var/www, nginx, apache configs), /etc configs, /opt and /srv apps, systemd units, cron jobs, /var/log, /tmp and /dev/shm.

## Disclaimer

This tool is intended for **authorized security assessments only**. Use it during legitimate penetration tests, red team engagements, CTF competitions, and lab environments where you have explicit permission. Unauthorized use against systems you do not own or have permission to test is illegal.
