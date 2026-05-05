"""
File discovery and scanning engine.

Recursively walks directories, filters to text-based files, handles encoding
detection, and feeds content to the detection engine. Works on both Windows
and Linux filesystems.
"""

import os
import stat
from pathlib import Path
from typing import Generator
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Binary / skip extensions — we never open these
# ---------------------------------------------------------------------------
BINARY_EXTENSIONS: frozenset[str] = frozenset({
    # Compiled / object
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".a", ".lib", ".pyd",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".elf", ".bin", ".com", ".sys", ".ko", ".msi",
    # Archives / compressed
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz",
    ".tbz2", ".lz", ".lzma", ".zst", ".cab", ".iso", ".dmg",
    ".deb", ".rpm", ".snap", ".flatpak", ".apk", ".ipa",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".ico", ".svg", ".webp", ".psd", ".ai", ".eps", ".raw",
    ".cr2", ".nef", ".heic", ".heif", ".avif",
    # Audio / Video
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv",
    ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma",
    ".webm", ".m4v", ".3gp",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Documents (binary)
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp",
    # Database files
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".ldf", ".mdf",
    # Virtual / disk images
    ".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2",
    # Misc binary
    ".swf", ".fla", ".blend", ".unity3d",
    # Lock / package caches (noisy, no creds)
    ".lock",
    # Source maps (large, no creds)
    ".map",
})

# Extensions that are *high-value* for credential hunting.
# This list is the default content-scan allowlist. It is biased towards
# real-world CTF/HTB/pentest experience: a file that *probably* has secrets
# in plaintext on the box you just landed on.
HIGH_VALUE_EXTENSIONS: frozenset[str] = frozenset({
    # ── Config ────────────────────────────────────────────────────────
    ".env", ".envrc",                                  # dotenv + direnv
    ".ini", ".cfg", ".conf", ".config", ".cnf",
    ".toml", ".yaml", ".yml", ".json", ".json5", ".jsonc",
    ".xml", ".plist",
    ".properties", ".props",                           # Java props / msbuild
    ".targets",                                        # msbuild
    # IaC / configuration management
    ".hcl", ".tf", ".tfvars", ".tfvars.json", ".tfstate", ".tfstate.backup",
    ".tftpl", ".tfplan",
    # Templating (often contain creds in Ansible / Helm / Salt)
    ".j2", ".jinja", ".jinja2", ".tpl", ".tmpl",
    ".liquid", ".mustache",
    # Cloud / CI definitions
    ".cscfg", ".publishsettings", ".pubxml",
    # ── Scripts / Source ───────────────────────────────────────────────
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".wsf", ".hta", ".vbscript",
    ".py", ".pyw", ".rb", ".pl", ".pm", ".php", ".php3", ".php4",
    ".php5", ".phtml", ".phar",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".go", ".java", ".kts",
    ".cs", ".vb", ".fs", ".fsx",
    ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx",
    ".rs", ".swift", ".kt", ".m", ".mm",
    ".groovy", ".gradle", ".scala", ".sbt",
    ".lua", ".r", ".R",
    ".dart", ".elixir", ".ex", ".exs", ".erl", ".clj",
    ".tcl", ".awk",
    # ── Web ────────────────────────────────────────────────────────────
    ".html", ".htm", ".xhtml",
    ".asp", ".aspx", ".ascx", ".cshtml", ".razor", ".master",
    ".jsp", ".jspx", ".cfm", ".cfc",
    ".ejs", ".twig", ".erb", ".hbs", ".handlebars",
    ".vue", ".svelte", ".astro",
    ".htaccess", ".htdigest",                          # Apache control files
    # ── Infra / CI ─────────────────────────────────────────────────────
    ".dockerfile", ".containerfile", ".vagrantfile",
    ".sln", ".csproj", ".vcxproj", ".vbproj", ".fsproj",
    ".user", ".vcxproj.user",
    # ── Certs / keys ───────────────────────────────────────────────────
    ".pem", ".key", ".crt", ".cer", ".csr", ".p12", ".pfx",
    ".jks", ".keystore", ".pub", ".asc", ".gpg",
    ".ppk",                                            # PuTTY private key
    ".ovpn",                                           # OpenVPN client config (often has inline auth)
    # ── Auth-shaped files ──────────────────────────────────────────────
    ".pwd", ".pass", ".passwd", ".password",
    ".cred", ".creds", ".credential", ".credentials",
    ".secret", ".secrets",
    ".kbx",                                            # GnuPG keybox
    # ── Data / reports ─────────────────────────────────────────────────
    ".txt", ".log", ".csv", ".tsv", ".md", ".rst", ".tex", ".org",
    ".sql", ".sqlite-journal",                         # SQL dumps + WAL
    ".graphql", ".gql", ".proto",
    ".dump", ".dmp",                                   # generic dumps (DB / memory)
    ".har",                                            # HTTP archive — captures auth headers
    ".eml", ".mbox",                                   # email exports
    # ── Backup / temp / leftover ───────────────────────────────────────
    ".bak", ".bkp", ".old", ".orig", ".save", ".swp", ".swo",
    ".tmp", ".temp", ".cache",
    ".backup", ".bk", ".copy", ".prev",
    # ── Data formats ───────────────────────────────────────────────────
    ".reg",                                            # Windows registry export
    ".rdp", ".ica", ".pubxml.user",                    # remote-desktop / Citrix / VS user
    ".udl", ".dsn",                                    # ODBC / OLE-DB
    ".ftpconfig", ".unattend", ".inf", ".gpp",         # Windows deploy
    ".publishsettings",
    ".tnsnames", ".ora",                               # Oracle
})

# Filenames (basename only, no path components) that are high-value
HIGH_VALUE_FILENAMES: frozenset[str] = frozenset({
    # ── dotenv variants ────────────────────────────────────────────────
    ".env", ".env.local", ".env.dev", ".env.development",
    ".env.staging", ".env.production", ".env.prod", ".env.test",
    ".env.example", ".env.sample", ".env.backup", ".env.bak",
    ".env.dist", ".env.shared", ".env.defaults", ".env.override",
    ".env.docker", ".env.ci",
    # ── Git / package manager / generic credentials ────────────────────
    ".gitconfig", ".git-credentials", ".netrc", ".npmrc", ".yarnrc",
    ".yarnrc.yml", ".pypirc", ".dockercfg", ".dockerignore",
    ".composer-auth", ".composer.json", "auth.json",     # Composer auth
    ".bundle/config", "bundle/config",                    # Ruby bundler
    ".cargo/credentials", ".cargo/config",                # Rust
    ".gem/credentials",                                   # RubyGems
    ".terraformrc", "terraform.rc",                       # Terraform
    "id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
    # ── Dotfiles with potential secrets ────────────────────────────────
    ".pgpass", ".my.cnf", ".mylogin.cnf",
    ".mysql_history", ".psql_history", ".sqlite_history",
    ".bash_history", ".zsh_history", ".sh_history",
    ".ash_history", ".ksh_history", ".fish_history",
    ".python_history", ".node_repl_history", ".rediscli_history",
    ".lesshst", ".viminfo",                                # leak file paths/text
    ".gnupg", ".pinentry",
    ".rhosts", ".shosts",                                  # legacy r-services
    ".hgrc", ".hg/hgrc",
    # ── SSH key files ──────────────────────────────────────────────────
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss",
    "id_rsa-cert", "id_ed25519-cert",
    "known_hosts", "authorized_keys", "authorized_keys2",
    "ssh_host_rsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key",
    "ssh_host_dsa_key",                                   # legacy
    # ── Web / app configs (CMS, frameworks) ────────────────────────────
    "wp-config.php", "wp-config-sample.php", "wp-config.bak",
    "web.config", "machine.config", "appsettings.json",
    "appsettings.development.json", "appsettings.production.json",
    "database.yml", "database.yaml", "database.json",
    "secrets.yml", "secrets.yaml", "credentials.yml", "credentials.yaml",
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.override.yml", "docker-compose.prod.yml",
    "compose.yml", "compose.yaml",
    "Dockerfile", "Containerfile",
    "Vagrantfile", "Jenkinsfile", "Procfile",
    "Makefile", "Rakefile", "Gemfile", "Gemfile.lock",
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    # CMS configs
    "configuration.php",                                   # Joomla
    "settings.php",                                        # Drupal
    "config.inc.php",                                      # phpMyAdmin
    "local.xml",                                           # Magento 1
    "env.php",                                             # Magento 2
    "LocalSettings.php",                                   # MediaWiki
    "Configuration.yaml",                                  # NodeJS / generic
    # ── Auth / password files (Linux + Apache) ─────────────────────────
    "shadow", "shadow-", "passwd", "passwd-",
    "gshadow", "gshadow-",
    "master.passwd",                                       # FreeBSD
    "htpasswd", ".htpasswd", "htdigest", ".htdigest",
    "smbpasswd", "afppasswd",
    "users.ldif",                                          # LDAP export
    # ── Application settings & secrets ─────────────────────────────────
    "settings.py", "local_settings.py", "production.py",
    "config.py", "secrets.py", "private.py",
    "application.properties", "application.yml", "application.yaml",
    "application-prod.properties", "application-dev.properties",
    "bootstrap.properties",                                # Spring
    "context.xml", "server.xml",                           # Tomcat
    "standalone.xml", "domain.xml",                        # WildFly / JBoss
    "core-site.xml", "hdfs-site.xml", "yarn-site.xml",     # Hadoop
    "hive-site.xml",
    "connections.xml", "recentservers.xml",
    "filezilla.xml", "sitemanager.xml", "queue.xml",
    "dbeaver-data-sources.json",                           # DBeaver
    # ── Windows deployment ─────────────────────────────────────────────
    "unattend.xml", "sysprep.xml", "autounattend.xml",
    "Setupcomplete.cmd", "PostInstall.cmd",
    "Groups.xml", "Services.xml", "Drives.xml",            # GPP
    "ScheduledTasks.xml", "Printers.xml", "DataSources.xml",
    "LAPS.xml",
    # ── PowerShell / cmd history ───────────────────────────────────────
    "ConsoleHost_history.txt", "ConsoleHost_history-1.txt",
    # ── Framework configs (generic) ────────────────────────────────────
    "config.php", "configuration.php", "parameters.yml",
    "parameters.yaml", "params.yml",
    "secrets.json", "secret.json",
    "serviceAccountKey.json", "service-account.json",
    "service-account-key.json", "gcp-key.json",
    "client_secret.json", "credentials.json",
    "config.json", "config.local.json",
    "tokens.json", "auth.json",
    # ── Cloud / SDK creds ──────────────────────────────────────────────
    "credentials",                                         # AWS .aws/credentials
    "config",                                              # SSH/AWS/GCP
    "gcloud-credentials.json",
    "azure-credentials.json", "azureProfile.json",
    "kubeconfig", ".kubeconfig",
    "rclone.conf",                                         # rclone — cloud creds
    # ── Backup / artifact filenames seen on real boxes ─────────────────
    "backup.sql", "dump.sql", "users.sql",
    "users.csv", "passwords.csv", "userlist.txt",
    "passwords.txt", "secrets.txt", "creds.txt",
    "notes.txt", "todo.txt", "TODO",                       # CTF/HTB common
    "README", "README.md", "README.txt",                   # creds in dev READMEs
    # ── Ansible / Salt / Chef ──────────────────────────────────────────
    "hosts", "hosts.ini", "inventory", "inventory.ini",
    "ansible.cfg", "vault_pass.txt", ".vault_pass",
    "group_vars", "host_vars",
    "Pillar.sls", "top.sls",
    "knife.rb", "client.rb",                               # Chef
    # ── Other reflexively-secret files ─────────────────────────────────
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "phpinfo.php",                                         # leaks env vars
    "info.php",
    "phpunit.xml",                                         # often has DB creds
})

# Parent directory names that make a file high-value regardless of filename
# (handles cases like .aws/credentials, .ssh/config, .docker/config.json,
# gcloud/credentials.db, etc.).
HIGH_VALUE_PARENT_DIRS: frozenset[str] = frozenset({
    ".aws", ".ssh", ".gnupg", ".docker", ".kube",
    ".azure", ".gcloud", "gcloud",
    ".cargo", ".gem", ".npm", ".yarn", ".composer",
    ".terraform", ".ansible", ".vagrant",
    ".pgadmin", ".dbeaver", ".dbeaver4",
    "secrets", "secret", "credentials", "creds",
    "PSReadLine",                                          # PowerShell history
    "Sysprep", "Panther", "unattend",                      # Windows deploy
    "PuTTY", "WinSCP",
})

# Directories to always skip (basename only — no path separators)
SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", ".hg", ".bzr",
    "node_modules", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".cache", ".venv", "venv", "env",
    ".vagrant", ".terraform",
    "vendor", "bower_components",
    "dist", "build", "out", "target",
    ".idea", ".vscode", ".vs",
    # Windows system dirs
    "$Recycle.Bin", "System Volume Information",
    "WinSxS", "assembly",
    # macOS
    ".Spotlight-V100", ".fseventsd",
})


def _resolve_ext(fname: str) -> str:
    """
    Lowercase extension, with dotfile handling: a bare dotfile like
    ".env" or ".bashrc" is treated as having extension ".env" / ".bashrc"
    so users can target it with --ext .env.
    """
    if fname.startswith(".") and "." not in fname[1:]:
        return fname.lower()
    return Path(fname).suffix.lower()


@dataclass
class FileInfo:
    """Metadata about a discovered file."""
    path: str
    size: int
    extension: str
    filename: str
    is_high_value: bool
    is_symlink: bool = False


@dataclass
class ScanConfig:
    """Configuration for the file scanner."""
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    max_depth: int = 50
    follow_symlinks: bool = False
    include_hidden: bool = True
    extra_skip_dirs: list[str] = field(default_factory=list)
    extra_skip_extensions: list[str] = field(default_factory=list)
    include_dirs: list[str] = field(default_factory=list)  # override skip for these
    only_high_value: bool = False
    # Tuning flags from the CLI:
    include_binary: bool = False
    # If set, ONLY these extensions are scanned (overrides default allowlist).
    # Lower-case, dot-prefixed (e.g. {".env", ".yml"}). Empty = no override.
    ext_override: frozenset[str] = field(default_factory=frozenset)
    # If set, these are added to the high-value extension list.
    ext_extra: frozenset[str] = field(default_factory=frozenset)


# Magic bytes for binary file detection
_MAGIC_SIGS: list[bytes] = [
    b"\x7fELF",          # ELF
    b"MZ",               # PE / DOS
    b"\xfe\xed\xfa",     # Mach-O
    b"\xca\xfe\xba\xbe", # Mach-O fat
    b"\xcf\xfa\xed\xfe", # Mach-O 64
    b"PK\x03\x04",       # ZIP
    b"\x1f\x8b",         # gzip
    b"BZh",              # bzip2
    b"\xfd7zXZ",         # xz
    b"7z\xbc\xaf",       # 7z
    b"\x89PNG",          # PNG
    b"\xff\xd8\xff",     # JPEG
    b"GIF8",             # GIF
    b"RIFF",             # WAV/AVI
    b"\x00\x00\x01\x00", # ICO
    b"ID3",              # MP3 with ID3
]


def _is_likely_text(filepath: str, sample_size: int = 8192) -> bool:
    """
    Heuristic check: read the first N bytes and look for binary indicators.
    A file is considered binary if it contains null bytes or has a high ratio
    of non-printable characters.
    """
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(sample_size)
    except (OSError, PermissionError):
        return False

    if not chunk:
        return False  # empty file — skip

    # Magic byte check
    for sig in _MAGIC_SIGS:
        if chunk[:len(sig)] == sig:
            return False

    # Null byte check — strong binary indicator
    if b"\x00" in chunk:
        return False

    # Ratio of non-text bytes
    non_text = sum(
        1 for b in chunk
        if b < 0x09 or (0x0e <= b <= 0x1f and b != 0x1b)  # allow ESC for ANSI
    )
    if non_text / len(chunk) > 0.10:
        return False

    return True


def _is_high_value_by_path(filepath: str, fname: str, ext: str) -> bool:
    """Check if a file is high-value based on name, extension, or parent dir."""
    if ext in HIGH_VALUE_EXTENSIONS:
        return True
    fname_lower = fname.lower()
    if fname in HIGH_VALUE_FILENAMES or fname_lower in HIGH_VALUE_FILENAMES:
        return True
    # Check parent directory (handles .aws/credentials, .ssh/config, etc.)
    parent = os.path.basename(os.path.dirname(filepath))
    if parent in HIGH_VALUE_PARENT_DIRS:
        return True
    # Match .env.* variants not in the static set
    if fname_lower.startswith(".env"):
        return True
    return False


def discover_files(
    root: str,
    config: ScanConfig,
) -> Generator[FileInfo, None, None]:
    """
    Recursively discover text-based files suitable for credential scanning.

    Yields FileInfo objects for each candidate file, applying all filters:
    - Extension-based skip (binaries, media, archives)
    - Directory skip (VCS, caches, vendor dirs)
    - Size limit
    - Depth limit
    - Binary content detection
    """
    root = os.path.abspath(root)
    root_len = len(root)
    all_skip_dirs = set(SKIP_DIRS) | set(config.extra_skip_dirs)
    include_dirs = set(config.include_dirs)
    # Remove any included dirs from the skip set
    all_skip_dirs -= include_dirs
    # Skip extensions: binaries by default + user extras. When --include-binary
    # is on, drop the binary list entirely so even compiled artifacts are read.
    if config.include_binary:
        all_skip_ext = frozenset(config.extra_skip_extensions)
    else:
        all_skip_ext = BINARY_EXTENSIONS | frozenset(config.extra_skip_extensions)

    # Decide which extensions are "scannable" (= candidate for content scan).
    # ext_override fully replaces the default allowlist when present.
    if config.ext_override:
        allowlist = frozenset(config.ext_override)
    else:
        allowlist = HIGH_VALUE_EXTENSIONS | frozenset(config.ext_extra)

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=config.follow_symlinks
    ):
        # Depth check
        rel = dirpath[root_len:]
        depth = rel.count(os.sep) if rel else 0
        if depth >= config.max_depth:
            dirnames.clear()
            continue

        # Prune directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in all_skip_dirs
            and (config.include_hidden or not d.startswith("."))
        ]

        for fname in filenames:
            if not config.include_hidden and fname.startswith("."):
                # Still scan .env and similar
                if fname not in HIGH_VALUE_FILENAMES and not fname.startswith(".env"):
                    continue

            filepath = os.path.join(dirpath, fname)

            # Symlink check
            is_symlink = os.path.islink(filepath)
            if is_symlink and not config.follow_symlinks:
                continue

            # Stat the file
            try:
                st = os.stat(filepath)
            except (OSError, PermissionError):
                continue

            # Skip non-regular files
            if not stat.S_ISREG(st.st_mode):
                continue

            size = st.st_size
            if size == 0 or size > config.max_file_size:
                continue

            # Extension check (dotfile-aware: ".env" → ext ".env")
            ext = _resolve_ext(fname)
            if ext in all_skip_ext:
                continue

            # If the user passed --ext, ONLY those extensions are scanned —
            # the high-value-filename / parent-dir promotions are also
            # disabled, since the user's override is authoritative.
            if config.ext_override and ext not in allowlist:
                continue

            # Determine if high-value (relative to the active allowlist)
            is_high_value = (
                ext in allowlist
                or _is_high_value_by_path(filepath, fname, ext)
            )

            if config.only_high_value and not is_high_value:
                continue

            # Binary content check. With --include-binary the heuristic
            # is bypassed so even .so / .exe surface (caller still has to
            # cope with the bytes).
            if not config.include_binary:
                if ext not in allowlist and not is_high_value:
                    if not _is_likely_text(filepath):
                        continue

            yield FileInfo(
                path=filepath,
                size=size,
                extension=ext,
                filename=fname,
                is_high_value=is_high_value,
                is_symlink=is_symlink,
            )


def read_file_lines(filepath: str, max_lines: int = 50000) -> list[str]:
    """
    Read a file and return its lines. Handles encoding gracefully.
    Uses UTF-8 with replacement characters for invalid bytes.

    Long lines (>4 KB — almost always minified JS/CSS or binary-ish blobs)
    are truncated to 4096 chars rather than dropped, so that the indices in
    the returned list line up 1:1 with the file's real line numbers.
    Dropping would silently shift every subsequent finding's line_number.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                # Truncate (don't drop) to preserve 1:1 line-number alignment.
                if len(line) > 4096:
                    # Keep the trailing newline if present, drop the middle.
                    nl = "\n" if line.endswith("\n") else ""
                    line = line[:4096] + nl
                lines.append(line)
            return lines
    except (OSError, PermissionError):
        return []
