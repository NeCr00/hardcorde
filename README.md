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
  <img src="https://img.shields.io/badge/rules-160-orange?style=flat-square" alt="Rules">
  <img src="https://img.shields.io/badge/password_rules-103-red?style=flat-square" alt="Password rules">
  <img src="https://img.shields.io/badge/dependencies-0-green?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
</p>

---
<p align="center">A cross-platform CLI that hunts hardcoded credentials, password-manager databases, and credential-suggestive files. Auto-detects the host OS and runs every check by default. Built for authorized internal pentests, red-team engagements, and CTF/lab environments. Zero external runtime dependencies.</p>

## What it does

`credfinder` (the `hardcorde` package) runs four credential-discovery checks back-to-back:

1. **OS-default credential locations** — well-known dotfiles, system configs, registry exports, auth-server configs (LDAP / Kerberos / RADIUS / Samba), Vault token caches, etc., scoped to the detected OS.
2. **Recursive content scan of `TARGET_PATH`** — when supplied, walks the path and applies all 160 detection rules to text-like files.
3. **Credential-store file discovery** — surfaces password-manager and vault files by extension (`.kdbx`, `.psafe3`, `.agilekeychain`, `.keychain`, `.opvault`, …). Flagged by name only — never opened.
4. **Suspicious filename patterns** — flags files whose name matches credential-suggestive keywords (`password`, `secret`, `id_rsa`, `htpasswd`, `wallet`, `keystore`, …).

Every check is on by default. Each can be turned off with a `--no-*` flag.

**v1.1.0 highlights**

- **160 detection rules** (103 password-class), covering Windows command-line idioms (`schtasks /RP`, `sc create password=`, `winrs /password`, `cmdkey`, `psexec`, `wmic`, `bitsadmin /SetCredentials`, `vaultcmd`, `Set-ADAccountPassword`, `Add-VpnConnection`), Linux command idioms (`smbclient -U user%pass`, `htpasswd -b`, `sudo -S <<<`, `passwd --stdin`, `ldapsearch -w`, `kinit`, `iwconfig key`, `wpa_passphrase`, `nmcli`, `vncpasswd`, `imapsync`, `rclone obscure`, `sqlplus user/pass@db`, `mosquitto_pub -P`), cross-platform CI/CD (`docker login -p`, `kubectl --from-literal`, `vault kv put`, `aws/az/gcloud configure set`, `dotnet user-secrets set`, `helm --set`), config-file formats (slapd `rootpw`, FreeRADIUS `secret`, Cisco/Juniper `key 0` / `snmp-server community`, Oracle `tnsnames.ora`, K8s `stringData`, `mount … credentials=`).
- Cross-compile to **Linux x64** and **Windows x64** static binaries via Docker — drop on a target and run.

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
| `--win-common` / `--no-win-common` | on (Windows) | Well-known Windows credential locations: registry exports, unattend/sysprep, IIS, .aws, PSReadLine history, PuTTY/KiTTY/Bitvise/SuperPuTTY, FileZilla, WinSCP, mRemoteNG, RDCMan, OpenVPN, DPAPI material, AppData configs, PowerShell profile dirs, WSL config, Vault token cache, rclone, SYSVOL/Group Policy history, user desktop/documents/downloads. |
| `--linux-common` / `--no-linux-common` | on (Linux) | Well-known Linux credential locations: shell history (bash/zsh/fish/ash/ksh), `.ssh/`, `/etc/shadow` and friends, `/etc/sudoers*`, environment/profile files, cloud creds (.aws, .azure, .config/gcloud, .kube, .docker), DB client history, `/var/www`, nginx/apache/httpd configs, `/etc`, `/opt`, `/srv`, systemd units, cron, `/var/log`, `/tmp`, `/var/tmp`, `/dev/shm`, OpenLDAP / Kerberos / Samba / FreeRADIUS / PAM configs, `/etc/fstab`, `.vault-token`, rclone config, Oracle homes. |
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
* **Windows-specific** — `.reg .rdp .rdg .ica .pubxml .publishsettings .udl .dsn .ftpconfig .unattend .inf .gpp .sln .csproj .vcxproj .vbproj .fsproj .user .vcxproj.user .cscfg`
* **Auth-shaped files** — `.pwd .pass .passwd .password .cred .creds .credential .credentials .secret .secrets .htpasswd .htdigest`
* **Data / reports** — `.dump .dmp .har .eml .mbox .graphql .gql .proto .pcap .pcapng`
* **Backup / leftover artifacts** — `.bak .bkp .old .orig .save .swp .swo .tmp .temp .cache .backup .bk .copy .prev`
* **Certs / keys / vaults** — `.pem .key .crt .cer .csr .p12 .pfx .jks .keystore .pub .asc .gpg .ppk .ovpn .kbx .keytab .sdb`

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

  [3]  CRITICAL  net use with inline password
      /opt/scripts/map-share.bat:4
      Secret:     S3cret-Sh4re-P@ss
      Confidence: [██████████████████░░] 92%

  [4]  CRITICAL  schtasks /RP inline password
      /opt/scripts/install-task.cmd:2
      Secret:     ServiceAcc0untP@ss
      Confidence: [██████████████████░░] 90%

  [5]  CRITICAL  Credential store: KeePass 2 database
      /home/alice/Documents/personal.kdbx
      Secret:     <KeePass 2 database file: personal.kdbx>
      Confidence: [████████████████████] 100%

  [6]  MEDIUM  Suspicious filename: backup, passwords
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
* **Comment penalty** — commented-out lines score lower (except for explicit `password is X` CTF-clue patterns, which are detected).
* **Keyword pre-filter** — skips regex on lines that can't possibly match, keeping the scan fast on large codebases.
* **Multi-line detection** — patterns spanning multiple lines (XML blocks, OpenVPN `<auth-user-pass>`, Maven `<server>`, here-strings, K8s manifests) are matched against the joined file content; line numbers are recovered from match offsets.

## Categories detected

| Category | Examples |
|----------|----------|
| Passwords (generic) | Variable assignments, XML attrs/elements, INI files, PHP `define()`, `.netrc`, generic CLI `-p` flags, comment leaks (`# password is X`) |
| Passwords (structured) | JSON `"password": "..."`, YAML keys (incl. list items + `#` mid-value + `stringData:` plaintext), TOML, Java `.properties` (Spring, Hibernate, Quarkus), function/constructor `password=` kwargs, Ruby/Perl `:password => "..."`, JS/TS unquoted keys (`{ password: '...' }`), here-strings |
| Passwords (Linux shells) | `export PASSWORD=`, `mysql -p…`, `mysqldump`, `PGPASSWORD=`, `psql password=…`, `sshpass -p`, `curl -u user:pass`, `wget --password=`, systemd `Environment=`, `expect send "…\r"`, `useradd -p`, `chpasswd`, `passwd --stdin`, `sudo -S <<<`, `kinit` piped pwd |
| Passwords (Linux services) | `htpasswd -b`, `smbclient -U user%pass`, `rpcclient`, `smbmap`, `ldapsearch -w` / `ldapmodify -w`, `redis-cli -a`, `mongo --password`, `mosquitto_pub -P`, `imapsync --password1`, `vncpasswd`, `x11vnc -storepasswd`, `iwconfig key s:…`, `wpa_passphrase`, `nmcli wifi-sec.psk`, `secret-tool store`, `rclone obscure / config password`, `sqlplus user/pass@SID` |
| Passwords (Windows) | PowerShell `$password=`, `New-Object PSCredential`, `ConvertTo-SecureString`, here-strings, `Set-ADAccountPassword`, `Add/Set/Connect-VpnConnection`, batch `set PASSWORD=`, `cmdkey /pass:`, `psexec -p`, `wmic /password:`, `net use`, `net user`, `runas /user:`, `schtasks /RP`, `sc create … password=`, `winrs /password:`, `BITSAdmin /SetCredentials`, `vaultcmd /password:`, `.reg` files, GPP `cpassword`, Task Scheduler XML `<Password>`, WinSCP saved sessions |
| Passwords (cross-platform CLI) | `docker/podman/nerdctl login -u -p`, `az login -p`, `kubectl create secret … --from-literal=`, `vault kv put / vault auth password=`, `aws/az/gcloud configure set <secret-key>`, `dotnet user-secrets set`, `helm --set`/`--set-string`/`--set-file` |
| Passwords (SQL) | `CREATE USER … IDENTIFIED BY`, `ALTER USER`, `ALTER LOGIN WITH PASSWORD = N'…'`, `GRANT … IDENTIFIED BY`, `SET PASSWORD FOR …` (MySQL / PostgreSQL / MSSQL), `db.createUser({ pwd: '...' })` (MongoDB) |
| Passwords (config files) | `.pgpass` lines, Apache `.htpasswd` (apr1, bcrypt, SHA1, DES), Maven `settings.xml` + `settings-security.xml` master pw, .NET `<add key="…Password" value="…"/>`, Gradle `signing.password`/`maven.password`, OpenVPN inline `<auth-user-pass>`, Redis `requirepass`, slapd `rootpw`, FreeRADIUS `secret =`, Cisco `enable secret` / `key 0` / `snmp-server community`, Oracle `tnsnames.ora` `(PASSWORD = …)`, K8s `stringData:`, `/etc/fstab` `credentials=` references |
| API Keys | AWS, Google, Stripe, SendGrid, Twilio, Mailgun, OpenAI, Anthropic, Heroku, Square, Shopify, Databricks, Discord, HuggingFace, Grafana |
| Tokens | GitHub, GitLab, Slack, npm, PyPI, Vault (HashiCorp), Bearer, JWT |
| Connection Strings | Database URIs (mysql/postgres/mongo/redis/mssql/oracle), JDBC, ODBC, inline `Password=` parameters, FTP/SFTP/SCP/SMB/CIFS/SVN/Git auth URLs |
| Private Keys | RSA, DSA, EC, OpenSSH, PGP (PEM headers) |
| Cloud Keys | AWS Access/Secret keys, Azure secrets, DigitalOcean |
| Hashes | Unix shadow (`$1$`, `$5$`, `$6$`, `$2a/b/y$`, `$argon2$`, `$scrypt$`, `$y$`), NTLM, htpasswd `{SHA}`, LDIF `userPassword:` |
| App Secrets | Django `SECRET_KEY`, Flask, Laravel `APP_KEY`, WordPress salts, Ansible Vault blobs |
| Infra | Docker env secrets, Kubernetes `data:` (base64) + `stringData:` (plaintext), Terraform defaults, Hadoop `<property>` |
| Indirect references | `--password-file=` / `--passfile` / `credentials=` flags pointing at a credential file (file contents triaged separately) |
| Credential files | KeePass / Password Safe / 1Password / Apple Keychain / Bitwarden / mSecure / Dashlane / RoboForm vaults |
| Filename patterns | Files named `password*`, `secret*`, `id_rsa*`, `htpasswd`, `*vault*`, `*keystore*`, … |

160 detection rules total — run `hardcorde --list-rules` to see all of them.

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

**Requirements:** Python 3.9+. No external runtime dependencies.

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

| Target | Image used | Compatibility | Typical size |
|--------|------------|---------------|--------------|
| `linux-x64` | `python:3.11-slim-bullseye` (glibc 2.31) | Debian 11+, Ubuntu 20.04+, RHEL 9+, Alpine via gcompat | ~7.4 MB |
| `windows-x64` | `tobix/pywine:3.10` (Wine) | Windows 10/11 x64, Server 2016+ | ~5.2 MB |
| `native` | local PyInstaller | host triple | ~6–8 MB |

Resulting binaries are single-file, fully self-contained (Python runtime
+ stdlib + hardcorde bundled together). Drop them on a target and run —
no Python install required.

```bash
# Verify
./dist/hardcorde-linux-x64 --version
./dist/hardcorde-linux-x64 --list-rules | tail -1   # → "Total: 160 rules"
```

## Exit codes

* `0` — no high+ findings (or only filtered-out findings remained).
* `1` — at least one CRITICAL or HIGH finding above `--min-confidence`.
* `2` — argument / configuration error (e.g. all checks disabled, missing path).

## Disclaimer

This tool is intended for **authorized security assessments only**. Use it during legitimate penetration tests, red team engagements, CTF competitions, and lab environments where you have explicit permission. Unauthorized use against systems you do not own or have permission to test is illegal.
