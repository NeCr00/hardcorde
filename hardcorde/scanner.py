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

# Extensions that are *high-value* for credential hunting
HIGH_VALUE_EXTENSIONS: frozenset[str] = frozenset({
    # Config
    ".env", ".ini", ".cfg", ".conf", ".config", ".cnf",
    ".toml", ".yaml", ".yml", ".json", ".xml", ".properties",
    ".hcl", ".tf", ".tfvars", ".tfstate",
    # Scripts
    ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".psm1",
    ".py", ".rb", ".pl", ".php", ".js", ".ts", ".go", ".java",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift", ".kt",
    ".groovy", ".gradle", ".scala", ".lua", ".r", ".R",
    # Web
    ".html", ".htm", ".asp", ".aspx", ".jsp", ".ejs", ".twig",
    ".erb", ".hbs", ".vue", ".svelte",
    # Infra / CI
    ".dockerfile", ".vagrantfile",
    # Certs / keys
    ".pem", ".key", ".crt", ".cer", ".csr", ".p12", ".pfx",
    ".jks", ".keystore", ".pub",
    # Misc text
    ".txt", ".log", ".csv", ".tsv", ".md", ".rst", ".tex",
    ".sql", ".graphql", ".proto",
    # Backup / temp
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".backup", ".copy",
    # Data formats
    ".plist", ".reg",
})

# Filenames (basename only, no path components) that are high-value
HIGH_VALUE_FILENAMES: frozenset[str] = frozenset({
    # dotenv variants
    ".env", ".env.local", ".env.dev", ".env.development",
    ".env.staging", ".env.production", ".env.prod", ".env.test",
    ".env.example", ".env.sample", ".env.backup",
    # Git / credentials
    ".gitconfig", ".git-credentials", ".netrc", ".npmrc",
    ".pypirc", ".dockercfg",
    # Dotfiles with secrets
    ".pgpass", ".my.cnf", ".mysql_history",
    ".bash_history", ".zsh_history", ".python_history",
    # SSH key files
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "known_hosts", "authorized_keys",
    # Web / app configs
    "wp-config.php", "web.config", "appsettings.json",
    "database.yml", "secrets.yml", "credentials.yml",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", "Vagrantfile", "Jenkinsfile",
    "Makefile", "Rakefile", "Gemfile",
    # Auth / password files
    "shadow", "passwd", "htpasswd", ".htpasswd",
    # App settings
    "settings.py", "local_settings.py", "config.py",
    "application.properties", "application.yml",
    "connections.xml", "recentservers.xml",
    "filezilla.xml", "sitemanager.xml",
    # Windows deployment
    "unattend.xml", "sysprep.xml",
    # PowerShell history
    "ConsoleHost_history.txt",
    # Framework configs
    "config.php", "configuration.php", "parameters.yml",
    "secrets.json", "serviceAccountKey.json",
    # Docker
    "config.json",
    # AWS
    "credentials",
    # SSH
    "config",
})

# Parent directory names that make a file high-value regardless of filename
# (handles cases like .aws/credentials, .ssh/config, .docker/config.json)
HIGH_VALUE_PARENT_DIRS: frozenset[str] = frozenset({
    ".aws", ".ssh", ".gnupg", ".docker", ".kube",
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
    all_skip_ext = BINARY_EXTENSIONS | frozenset(config.extra_skip_extensions)

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

            # Extension check
            ext = Path(fname).suffix.lower()
            if ext in all_skip_ext:
                continue

            # Determine if high-value
            is_high_value = _is_high_value_by_path(filepath, fname, ext)

            if config.only_high_value and not is_high_value:
                continue

            # Binary content check (skip for known text extensions)
            if ext not in HIGH_VALUE_EXTENSIONS and not is_high_value:
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
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                # Skip minified lines (>4KB single lines are almost certainly
                # minified JS/CSS or binary-ish data, not hand-written config)
                if len(line) > 4096:
                    continue
                lines.append(line)
            return lines
    except (OSError, PermissionError):
        return []
