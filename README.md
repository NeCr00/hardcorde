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
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/rules-113%20password--only-red?style=flat-square">
  <img src="https://img.shields.io/badge/dependencies-0-green?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square">
</p>

<p align="center"><b>Hardcoded password discovery for authorized penetration tests.</b><br>Finds passwords and password+username pairs in source, configs, and OS-default credential locations.<br>Does <b>not</b> scan for API keys, OAuth tokens, JWTs, PEM keys, or generic secrets — by design.</p>

---

## Quick start

```bash
hardcorde                       # auto-detect OS, scan defaults
hardcorde /home                 # + recurse a path
hardcorde C:\Users --os windows
hardcorde /etc --no-linux-common
hardcorde / -f sarif -o out.sarif
```

## Why passwords-only

Generic secret-scanners surface hundreds of API keys, JWTs, public assembly signing keys, and base64 blobs — most irrelevant during a Windows / AD engagement. This tool focuses on what pentesters actually use: **plaintext passwords, password hashes, and embedded user:password pairs**. Less noise, faster triage, lower false-positive rate.

## What it finds

**Direct password assignments** in every common syntax — variable assignments (PASSWORD=, $password = "...", $password: "..."), JSON / YAML / TOML / `.properties` / Spring / Hibernate / Java config, XML `<password>` and `<credentials>`, `passwordFormat`/`passwordPolicy` correctly excluded · PHP `define()` / `$var` · .NET `<add key>` and `<connectionString>` · Maven settings.xml + master · Gradle · Tomcat · Hadoop · OpenVPN inline `<auth-user-pass>` · WordPress salts · SQL `CREATE/ALTER USER … IDENTIFIED BY` (MySQL/PG/MSSQL) · `db.createUser({pwd})` · Redis `requirepass` · Cisco `enable secret` / `key 0` · slapd `rootpw` · FreeRADIUS shared secret · Oracle `tnsnames.ora`.

**Linux command-line** — `mysql/mysqldump -p` · `psql password=` · `PGPASSWORD=` · `sshpass -p` · `curl -u` / `wget --password=` · `htpasswd -b` · `smbclient/rpcclient -U user%pass` · `sudo -S <<<` · `passwd --stdin` · `ldapsearch -w` · `kinit` · `wpa_passphrase` · `nmcli wifi-sec.psk` · `iwconfig key s:` · `vncpasswd` · `imapsync` · `rclone obscure` · `sqlplus user/pass@sid` · `mosquitto_pub -P` · `chpasswd`/`useradd -p` · expect `send`.

**Windows command-line** — `net use` · `net user` · `cmdkey /pass:` · `psexec/wmic /password:` · `runas /user:` · `schtasks /RP` · `sc create … password=` · `winrs /password:` · `bitsadmin /SetCredentials` · `vaultcmd /password:` · `New-Object PSCredential` · `ConvertTo-SecureString` · `Set-ADAccountPassword` · `Add-VpnConnection -Password`.

**Cross-platform CLI** — `docker/podman/az login -p` · `kubectl create secret --from-literal=password=` · `vault kv put / vault auth password=` · `aws/az/gcloud configure set` · `dotnet user-secrets` · `helm --set password=`.

**Config / state files** — `.netrc` · `.pgpass` · `.htpasswd` (bcrypt/MD5/SHA1/DES) · `wp-config.php` · WinSCP saved sessions · GPP `cpassword` (decryptable) · Task Scheduler XML `<Password>` · `.reg` exports · `/etc/fstab credentials=` · K8s `stringData:` · LAPS extracted passwords.

**User:password pairs** — database URIs (mysql/postgres/mongo/redis/mssql/oracle) · JDBC · ODBC/ADO.NET · `ftp/sftp/scp/smb/cifs/svn/git+ssh://user:pass@host` · HTTP `Authorization: Basic <b64>` · SMTP `AUTH PLAIN <b64>` · Impacket-style `user:pass@host`.

**Password hashes** (passwords-at-rest) — Unix shadow (`$1$/$2[aby]$/$5$/$6$/$y$/$argon2$/$scrypt$`) · NTLM · htpasswd `{SHA}` · LDIF `userPassword`.

113 rules total — `hardcorde --list-rules` to enumerate.

## Smart scoring & FP suppression

Shannon entropy · placeholder detection (`${VAR}`, `<your-key>`, `TODO`, `$(Get-Random)`) · context keyword proximity · path-based weighting (`/prod/` boosts, `/test/` penalises) · comment-line penalty · multi-line patterns (XML blocks, OpenVPN inline, here-strings, K8s manifests) · natural-language sentence detector (skips translation strings / error messages) · self-reference detection (`Credential = "Credential"`) · keyname blacklist (`passwordFormat`, `passwordPolicy`, `publicKey`, …).

## CLI

```
hardcorde [TARGET_PATH] [options]
```

| Group | Flag | Default | Effect |
|---|---|---|---|
| scope | `TARGET_PATH` | — | optional root directory to recurse |
| | `--os {auto,windows,linux}` | `auto` | override OS detection |
| | `--no-win-common` / `--no-linux-common` | on | skip OS-default password sweep |
| | `--no-scan-target` | on if `TARGET_PATH` set | skip recursive content scan |
| output | `-f {text,json,csv,sarif,html}` | `text` | output format |
| | `-o FILE` | stdout | write to file |
| | `--no-color` `--no-context` `-q` `-v` | — | UI tweaks |
| filtering | `--severity {critical,high,medium,low,info}` | `info` | minimum severity |
| | `--min-confidence N` | `25` | minimum 0–100 confidence |
| tuning | `--max-size BYTES` | 10 MB | skip files larger than this |
| | `--max-depth N` | `50` | recursion limit |
| | `--include-binary` | off | scan binary files too |
| | `--ext` / `--add-ext LIST` | — | override / extend extension allowlist |
| | `--skip-dirs DIR…` | — | extra dirs to skip |
| | `-t N` | `4` | concurrent workers |
| misc | `--list-rules` | — | print all rules and exit |
| | `-V, --version` | — | print version |

## Install

```bash
git clone https://github.com/yourusername/hardcorde.git && cd hardcorde
python3 -m hardcorde /path/to/scan
# or
pip install -e . && hardcorde /path/to/scan
```

Python 3.9+. Zero runtime dependencies.

## Build standalone binaries

```bash
./build.sh                   # native (host platform)
./build.sh --linux-x64       # → dist/hardcorde-linux-x64       (Docker)
./build.sh --windows-x64     # → dist/hardcorde-windows-x64.exe (Docker + Wine)
./build.sh --all
```

| Target | Toolchain | Compatibility | Size |
|---|---|---|---|
| `linux-x64` | `python:3.11-slim-bullseye` (glibc 2.31) | Debian 11+ / Ubuntu 20.04+ / RHEL 9+ / Alpine via gcompat | ~7.4 MB |
| `windows-x64` | `tobix/pywine:3.10` + PyInstaller 5.13.2, no UPX | Windows 7 SP1 / Server 2008 R2 SP1 → 11 / Server 2025 | ~6.2 MB |

Single-file, self-contained, no compression. Drop on a target and run.

## Output formats

Text (colored) · JSON · CSV · SARIF 2.1.0 (CI / GitHub Code Scanning) · HTML (client deliverable).

## Exit codes

`0` — no high+ findings · `1` — at least one critical/high above `--min-confidence` · `2` — config error.

## Disclaimer

For **authorized** security assessments only — pentests, red-team engagements, CTFs, and lab environments. Unauthorized use against systems you don't own or have permission to test is illegal.
