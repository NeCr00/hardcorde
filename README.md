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
  <img src="https://img.shields.io/badge/rules-125-orange?style=flat-square" alt="Rules">
  <img src="https://img.shields.io/badge/dependencies-0-green?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
</p>

---
<p align="center">A cross-platform CLI that hunts hardcoded credentials, password-manager databases, and credential-suggestive files. Auto-detects the host OS and runs every check by default.</p>

## What it does

`credfinder` (the `hardcorde` package) runs four credential-discovery checks back-to-back:

1. **OS-default credential locations** — well-known dotfiles, system configs, registry exports, etc., scoped to the detected OS.
2. **Recursive content scan of `TARGET_PATH`** — when supplied, walks the path and applies all 64 detection rules to text-like files.
3. **Credential-store file discovery** — surfaces password-manager and vault files by extension (`.kdbx`, `.psafe3`, `.agilekeychain`, `.keychain`, `.opvault`, …). Flagged by name only — never opened.
4. **Suspicious filename patterns** — flags files whose name matches credential-suggestive keywords (`password`, `secret`, `id_rsa`, `htpasswd`, `wallet`, `keystore`, …).

Every check is on by default. Each can be turned off with a `--no-*` flag.

Built for authorized internal pentests, red-team engagements, and CTF/lab environments. Zero external dependencies.

## Quick start

```bash
# Auto-detect OS and run all default checks
python3 -m hardcorde

# Add a recursive content scan of /home
python3 -m hardcorde /home

# Force the Windows check set (regardless of host OS)
python3 -m hardcorde C:\Users --os windows

# Skip the OS-default-location sweep, just scan /etc
python3 -m hardcorde /etc --no-linux-common --no-cred-stores

# SARIF output for CI / GitHub Code Scanning ingestion
python3 -m hardcorde /opt -f sarif -o findings.sarif

# HTML report for client delivery
python3 -m hardcorde /srv -f html -o report.html

# High-signal triage on a noisy host
python3 -m hardcorde / --severity high --min-confidence 60
```

## CLI

```
credfinder [TARGET_PATH] [options]
```

### Scope

| Flag | Default | Effect |
|------|---------|--------|
| `TARGET_PATH` | — | Optional root directory. Triggers Check 2. |
| `--os {windows,linux,auto}` | `auto` | Override OS detection. |

### Default checks (all on)

Each check is enabled out of the box. Disable with the matching `--no-*` flag.

| Flag | Default | Description |
|------|---------|-------------|
| `--win-common` / `--no-win-common` | on (Windows) | Well-known Windows credential locations: registry exports, unattend/sysprep, IIS, .aws, PSReadLine history, PuTTY, FileZilla, WinSCP, mRemoteNG, OpenVPN, DPAPI material, AppData configs, user desktop/documents/downloads. |
| `--linux-common` / `--no-linux-common` | on (Linux) | Well-known Linux credential locations: shell history (bash/zsh/fish/ash/ksh), `.ssh/`, `/etc/shadow` and friends, `/etc/sudoers*`, environment/profile files, cloud creds (.aws, .azure, .config/gcloud, .kube, .docker), DB client history, `/var/www`, nginx/apache/httpd configs, `/etc`, `/opt`, `/srv`, systemd units, cron, `/var/log`, `/tmp`, `/var/tmp`, `/dev/shm`. |
| `--scan-target` / `--no-scan-target` | on if `TARGET_PATH` given | Recursive content scan of `TARGET_PATH` with the rule engine. |
| `--cred-stores` / `--no-cred-stores` | on | Discover password-manager / credential-vault files by extension. |
| `--filename-patterns` / `--no-filename-patterns` | on | Flag files whose name matches credential-suggestive keywords. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format {text,json,csv,sarif,html}` | `text` | Output format. `terminal` is accepted as an alias for `text`. |
| `-o, --output FILE` | stdout | Write findings to file. |
| `--no-color` | — | Disable ANSI colors. |
| `--no-context` | — | Hide the surrounding code lines per finding. |
| `-q, --quiet` | — | Suppress progress output. |
| `-v, --verbose` | — | Show the confidence-score breakdown for each finding. |

### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--min-confidence N` | `25` | Minimum confidence score (0–100) to report. |
| `--severity {critical,high,medium,low,info}` | `info` | Minimum severity to report. |
| `--category CAT...` | — | Limit to specific categories. |
| `--tags TAG...` | — | Limit to rules carrying any of these tags. |
| `--rules ID...` / `--exclude-rules ID...` | — | Run / skip specific rule IDs. |

### Tuning

| Flag | Default | Description |
|------|---------|-------------|
| `--max-size BYTES` | `10485760` (10 MB) | Skip files larger than this. |
| `--include-binary` | off | Include binary files in the content scan. |
| `--ext LIST` | — | **Override** the default content-scan extension allowlist (e.g. `--ext .env,.yml,.json`). |
| `--add-ext LIST` | — | **Extend** the default extension allowlist. |
| `--max-depth N` | `50` | Maximum recursion depth. |
| `--follow-symlinks` | off | Follow symbolic links. |
| `--high-value-only` | off | Only scan high-value file types (configs, scripts, secrets). |
| `--skip-dirs DIR...` | — | Additional directory names to skip. |
| `--skip-ext EXT...` | — | Additional extensions to skip. |
| `--include-dirs DIR...` | — | Override the built-in skip list for these dirs. |
| `-t, --threads N` | `4` | Concurrent workers. |

## Default extension allowlist

Used by the recursive content scan. Override with `--ext`, extend with `--add-ext`.

* **Plain-text / config / data** — `.txt .log .csv .tsv .md .ini .conf .config .cfg .cnf .env .envrc .properties .props .targets .xml .json .json5 .jsonc .yaml .yml .toml .plist .sql`
* **IaC / templating** — `.hcl .tf .tfvars .tfvars.json .tfstate .tfstate.backup .tftpl .tfplan .j2 .jinja .jinja2 .tpl .tmpl .liquid .mustache`
* **Scripting / source** — `.ps1 .psm1 .psd1 .bat .cmd .vbs .vbe .vbscript .wsf .hta .py .pyw .pl .pm .rb .php .php3 .phtml .phar .js .jsx .mjs .cjs .ts .tsx .go .java .kts .cs .vb .fs .fsx .cpp .cc .c .h .hpp .rs .swift .kt .m .mm .groovy .gradle .scala .sbt .lua .r .R .dart .ex .exs .erl .clj .tcl .awk .ksh .csh .tcsh .sh .bash .zsh .fish`
* **Web** — `.html .htm .xhtml .asp .aspx .ascx .cshtml .razor .master .jsp .jspx .cfm .ejs .twig .erb .hbs .handlebars .vue .svelte .astro .htaccess .htdigest`
* **Windows-specific** — `.reg .rdp .ica .pubxml .publishsettings .udl .dsn .ftpconfig .unattend .inf .gpp .sln .csproj .vcxproj .vbproj .fsproj .user .vcxproj.user .cscfg`
* **Auth-shaped files** — `.pwd .pass .passwd .password .cred .creds .credential .credentials .secret .secrets .htpasswd .htdigest`
* **Data / reports** — `.dump .dmp .har .eml .mbox .graphql .gql .proto`
* **Backup / leftover artifacts** — `.bak .bkp .old .orig .save .swp .swo .tmp .temp .cache .backup .bk .copy .prev`
* **Certs / keys** — `.pem .key .crt .cer .csr .p12 .pfx .jks .keystore .pub .asc .gpg .ppk .ovpn .kbx`

## Credential-store file extensions

Detected by Check 3 (`--cred-stores`). Files are flagged by extension only — the tool never tries to open or crack them.

`.kdbx` `.kdb` (KeePass) · `.psafe3` (Password Safe) · `.agilekeychain` `.opvault` `.1pif` `.1pux` (1Password) · `.keychain` `.keychain-db` (Apple Keychain) · `.ppk` (PuTTY private key) · `.age` (age-encrypted file) · `.bkp` `.fsk` `.rfx` `.spdb` (misc password managers) · `.walletx` (Bitwarden export variants) · `.mlb` (mSecure) · `.dashlane` (Dashlane)

Each hit reports full path, file size, last-modified time, and the matched store type.

## Suspicious filename keywords

Detected by Check 4 (`--filename-patterns`). Case-insensitive, matched as a token (`/`, `\`, `.`, `_`, `-`, or string boundary on each side).

**Primary** (any of these alone trigger a finding):
`password` / `passwords` · `passwd` · `pwd` · `passphrase` · `secret` / `secrets` · `credential` / `credentials` / `creds` / `cred` · `apikey` / `api_key` / `api-key` · `token` / `accesstoken` / `refreshtoken` · `bearer` · `auth` / `authkey` · `private_key` / `privatekey` · `id_rsa` · `id_dsa` · `id_ecdsa` · `id_ed25519` · `htpasswd` · `htdigest` · `shadow` · `smbpasswd` · `vncpasswd` · `vault` · `keystore` · `keyring` · `wallet` · `keychain` · `client_secret` / `clientsecret` · `service_account` · `kubeconfig` · `userlist` / `pwdlist` · `mnemonic` / `seedphrase` / `recovery_phrase`

**Qualified** (only fire when at least one primary keyword also hits the same name):
`backup` / `bkp` · `dump` / `dmp` · `export` · `archive` · `snapshot` / `snap` · `leak` / `leaked` · `old` / `orig` / `save`

So `db_dump.sql` alone is silent, but `passwords_backup.txt` flags both `passwords` and `backup`.

## Output

```
  [1]  CRITICAL  Database Connection URI
      /opt/app/docker-compose.yml:7
      Secret:     postgres://admin:Sup3rS3cretDBP@ss!@db:5432/myapp
      Confidence: [████████████████████] 100%

  [2]  CRITICAL  Stripe API Key
      /opt/app/.env:13
      Secret:     sk_live_4eC39HqLyjWDarjtT1zdp7dc
      Confidence: [███████████████████░] 99%

  [3]  CRITICAL  Credential store: KeePass 2 database
      /home/alice/Documents/personal.kdbx
      Secret:     <KeePass 2 database file: personal.kdbx>
      Confidence: [████████████████████] 100%

  [4]  MEDIUM  Suspicious filename: backup, passwords
      /var/backups/old_passwords_backup.txt
      Confidence: [████████████████░░░░] 80%
```

Output formats: **text** (colored terminal, default) · **json** · **csv** · **sarif** (SARIF 2.1.0 for CI ingestion) · **html** (standalone client report).

## How content detection is smart

* **Entropy analysis** — distinguishes `Kj8$mNpQ2vXw!rT9` from `changeme`.
* **Placeholder detection** — recognizes `${VAR}`, `{{template}}`, `<your-key-here>`, `TODO`, etc.
* **Known public keys** — AWS example keys (`AKIAIOSFODNN7EXAMPLE`) score low.
* **Context scoring** — boosts confidence when surrounding lines mention `password`, `database`, `auth`.
* **Path awareness** — files in `/prod/`, `.env`, `.aws/credentials` score higher than `/test/`, `/docs/`.
* **Comment penalty** — commented-out lines score lower.
* **Keyword pre-filter** — skips regex on lines that can't possibly match, keeping the scan fast on large codebases.

## Categories detected

| Category | Examples |
|----------|----------|
| Passwords (generic) | Variable assignments, XML configs, INI files, PHP `define()`, `.netrc`, CLI `-p` flags, `net user /add` |
| Passwords (structured) | JSON `"password": "..."`, YAML keys (incl. list items + `#` mid-value), TOML, Java `.properties` (Spring, Hibernate, Quarkus), function/constructor `password=` kwargs, Ruby/Perl `:password => "..."` |
| Passwords (Linux shells) | `export PASSWORD=`, `mysql -p…`, `mysqldump`, `PGPASSWORD=`, `psql password=…`, `sshpass -p`, `curl -u user:pass`, `wget --password=`, `systemd Environment=`, expect `send "…\r"`, `useradd -p`, `chpasswd` |
| Passwords (Windows) | PowerShell `$password=`, `New-Object PSCredential`, `ConvertTo-SecureString`, batch `set PASSWORD=`, `cmdkey /pass:`, `psexec -p`, `wmic /password:`, `net use`, `runas /user:`, `.reg` files, GPP `cpassword`, Task Scheduler XML `<Password>`, WinSCP saved sessions |
| Passwords (SQL) | `CREATE USER … IDENTIFIED BY`, `ALTER USER`, `ALTER LOGIN WITH PASSWORD = N'…'`, `GRANT … IDENTIFIED BY`, `SET PASSWORD FOR …` (MySQL / PostgreSQL / MSSQL) |
| Passwords (config files) | `.pgpass` lines, Apache `.htpasswd` (apr1, bcrypt, SHA1, DES), Maven `settings.xml`, .NET `<add key="…Password" value="…"/>`, Gradle `signing.password`/`maven.password`, OpenVPN inline `<auth-user-pass>`, Redis/Mongo CLI `-a`, ftp/lftp `-u user,pass` |
| API Keys | AWS, Google, Stripe, SendGrid, Twilio, Mailgun, OpenAI, Anthropic |
| Tokens | GitHub, GitLab, Slack, npm, PyPI, HuggingFace, Vault, Discord, Grafana, Bearer, JWT |
| Connection Strings | Database URIs (mysql/postgres/mongo/redis/mssql/oracle), JDBC, ODBC, inline `Password=` parameters |
| Private Keys | RSA, DSA, EC, OpenSSH, PGP (PEM headers) |
| Cloud Keys | AWS Access/Secret keys, Azure secrets, DigitalOcean |
| Hashes | Unix shadow (`$1$`, `$5$`, `$6$`, `$2a/b/y$`, `$argon2$`, `$scrypt$`, `$y$`), NTLM, htpasswd `{SHA}` |
| App Secrets | Django `SECRET_KEY`, Flask, Laravel `APP_KEY`, WordPress salts |
| Infra | Docker env secrets, Kubernetes secrets, Terraform defaults |
| Credential files | KeePass / Password Safe / 1Password / Apple Keychain / Bitwarden / mSecure / Dashlane / RoboForm vaults |
| Filename patterns | Files named `password*`, `secret*`, `id_rsa*`, `htpasswd`, `*vault*`, `*keystore*`, … |

125 detection rules total — run `hardcorde --list-rules` to see all of them.

## Installation

```bash
# Clone and run (no install needed)
git clone https://github.com/yourusername/hardcorde.git
cd hardcorde
python3 -m hardcorde /path/to/scan

# Or install as a CLI tool
pip install -e .
hardcorde /path/to/scan
credfinder /path/to/scan        # alias used in the help text
```

**Requirements:** Python 3.9+. No external dependencies.

## Build a standalone binary

The build script (`build/build.py`) supports a native build plus two
Docker-based cross-compile targets so you can produce x64 binaries for
Linux and Windows from any host with Docker installed.

```bash
# ── Native (uses local PyInstaller) ───────────────────────────────
pip install pyinstaller
./build.sh                       # → dist/hardcorde-<host>-<arch>

# ── Cross-compile (Docker required) ───────────────────────────────
./build.sh --linux-x64           # → dist/hardcorde-linux-x64
./build.sh --windows-x64         # → dist/hardcorde-windows-x64.exe
./build.sh --all                 # native + linux-x64 + windows-x64

# Windows host
build.bat                        # native Windows build
build.bat --linux-x64            # Linux cross-build (Docker required)
```

### Output

| Target | Image used | Compatibility |
|--------|------------|---------------|
| `linux-x64` | `python:3.11-slim-bullseye` (glibc 2.31) | Debian 11+, Ubuntu 20.04+, RHEL 9+, Alpine via gcompat |
| `windows-x64` | `tobix/pywine:3.10` (Wine) | Windows 10/11 x64, Server 2016+ |
| `native` | local PyInstaller | host triple |

Resulting binaries are single-file, ~5–8 MB each, fully self-contained
(Python runtime + stdlib + hardcorde bundled together). Drop them on a
target and run — no Python install required.

```bash
# Verify
./dist/hardcorde-linux-x64 --version
./dist/hardcorde-linux-x64 --list-rules | tail -1   # → "Total: 125 rules"
```

## Exit codes

* `0` — no high+ findings (or only filtered-out findings remained).
* `1` — at least one CRITICAL or HIGH finding above `--min-confidence`.
* `2` — argument / configuration error (e.g. all checks disabled, missing path).

## Disclaimer

This tool is intended for **authorized security assessments only**. Use it during legitimate penetration tests, red team engagements, CTF competitions, and lab environments where you have explicit permission. Unauthorized use against systems you do not own or have permission to test is illegal.
