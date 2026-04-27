"""
Common credential locations for Windows and Linux.

Provides path lists for --win-common and --linux-common flags.
Paths are expanded (env vars, globs, ~) and deduplicated at runtime.
Non-existent or inaccessible paths are silently skipped.
"""

import glob
import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTarget:
    """A common credential location to scan."""
    path: str               # Raw path (may contain env vars, globs)
    category: str           # e.g. "shell_history", "ssh_keys", "cloud_creds"
    description: str        # Human-readable description
    priority: int           # 1=high, 2=medium, 3=low
    max_depth: int = 5      # Limit recursion for broad dirs
    high_value_only: bool = False  # Only scan config/secret file types


# ── Windows common locations ────────────────────────────────────────────

_WIN_TARGETS: list[ScanTarget] = [
    # 1. PowerShell / command history
    ScanTarget("%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine", "powershell_history",
               "PowerShell command history", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine", "powershell_history",
               "PowerShell command history (all users)", 1, max_depth=1),

    # 2. Unattended install / sysprep
    ScanTarget("C:\\Windows\\Panther", "unattend", "Windows unattended install files", 1, max_depth=3),
    ScanTarget("C:\\Windows\\System32\\Sysprep", "unattend", "Sysprep configuration files", 1, max_depth=3),
    ScanTarget("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Panther",
               "unattend", "System profile Panther directory", 1, max_depth=2),

    # 3. IIS / .NET config
    ScanTarget("C:\\inetpub", "iis_config", "IIS web root", 1, max_depth=8, high_value_only=True),
    ScanTarget("C:\\Windows\\Microsoft.NET\\Framework\\*\\Config", "dotnet_config",
               ".NET Framework config", 2, max_depth=1),
    ScanTarget("C:\\Windows\\Microsoft.NET\\Framework64\\*\\Config", "dotnet_config",
               ".NET Framework64 config", 2, max_depth=1),

    # 4. Cloud / DevOps credentials
    ScanTarget("C:\\Users\\*\\.aws", "cloud_creds", "AWS credentials and config", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\.azure", "cloud_creds", "Azure CLI credentials", 1, max_depth=3),
    ScanTarget("C:\\Users\\*\\.config\\gcloud", "cloud_creds", "Google Cloud credentials", 1, max_depth=3),
    ScanTarget("C:\\Users\\*\\.kube", "cloud_creds", "Kubernetes config", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\.docker", "cloud_creds", "Docker config and auth", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\.npmrc", "cloud_creds", "npm registry credentials", 1, max_depth=0),
    ScanTarget("C:\\Users\\*\\.pypirc", "cloud_creds", "PyPI credentials", 1, max_depth=0),
    ScanTarget("C:\\Users\\*\\.git-credentials", "cloud_creds", "Git stored credentials", 1, max_depth=0),
    ScanTarget("C:\\Users\\*\\.gitconfig", "cloud_creds", "Git configuration", 2, max_depth=0),
    ScanTarget("C:\\Users\\*\\.netrc", "cloud_creds", "Netrc credentials", 1, max_depth=0),

    # 5. SSH / PuTTY
    ScanTarget("C:\\Users\\*\\.ssh", "ssh_keys", "SSH keys and config", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\PuTTY", "ssh_keys", "PuTTY configuration", 1, max_depth=2),

    # 6. Remote access tools
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\FileZilla", "remote_access",
               "FileZilla saved connections", 1, max_depth=1),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\WinSCP.ini", "remote_access",
               "WinSCP saved sessions", 1, max_depth=0),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\mRemoteNG", "remote_access",
               "mRemoteNG connection manager", 1, max_depth=2),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\OpenVPN", "remote_access",
               "OpenVPN client config", 2, max_depth=2),
    ScanTarget("C:\\Program Files\\OpenVPN\\config", "remote_access",
               "OpenVPN system config", 2, max_depth=2),
    ScanTarget("C:\\ProgramData\\OpenVPN", "remote_access", "OpenVPN data", 2, max_depth=2),

    # 7. DPAPI / Windows credential material (metadata only)
    ScanTarget("C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials", "dpapi_material",
               "DPAPI credential blobs (metadata only)", 2, max_depth=1),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials", "dpapi_material",
               "DPAPI credential blobs (metadata only)", 2, max_depth=1),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Protect", "dpapi_material",
               "DPAPI master key material", 2, max_depth=3),

    # 8. Application config dirs (broad, use high_value_only)
    ScanTarget("C:\\ProgramData", "app_config", "ProgramData configs", 3,
               max_depth=4, high_value_only=True),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming", "app_config",
               "User AppData Roaming configs", 3, max_depth=4, high_value_only=True),
    ScanTarget("C:\\Users\\*\\AppData\\Local", "app_config",
               "User AppData Local configs", 3, max_depth=4, high_value_only=True),

    # 9. User documents (scripts/configs in common spots)
    ScanTarget("C:\\Users\\*\\Desktop", "user_files", "User desktops", 3,
               max_depth=2, high_value_only=True),
    ScanTarget("C:\\Users\\*\\Documents", "user_files", "User documents", 3,
               max_depth=3, high_value_only=True),
    ScanTarget("C:\\Users\\*\\Downloads", "user_files", "User downloads", 3,
               max_depth=2, high_value_only=True),
]


# ── Linux common locations ──────────────────────────────────────────────

_LINUX_TARGETS: list[ScanTarget] = [
    # 1. Shell history
    ScanTarget("/home/*/.bash_history", "shell_history", "Bash command history", 1, max_depth=0),
    ScanTarget("/home/*/.zsh_history", "shell_history", "Zsh command history", 1, max_depth=0),
    ScanTarget("/home/*/.sh_history", "shell_history", "Sh command history", 1, max_depth=0),
    ScanTarget("/home/*/.ash_history", "shell_history", "Ash command history", 1, max_depth=0),
    ScanTarget("/home/*/.ksh_history", "shell_history", "Ksh command history", 1, max_depth=0),
    ScanTarget("/home/*/.fish_history", "shell_history", "Fish command history", 1, max_depth=0),
    ScanTarget("/root/.bash_history", "shell_history", "Root bash history", 1, max_depth=0),
    ScanTarget("/root/.zsh_history", "shell_history", "Root zsh history", 1, max_depth=0),
    ScanTarget("~/.bash_history", "shell_history", "Current user bash history", 1, max_depth=0),
    ScanTarget("~/.zsh_history", "shell_history", "Current user zsh history", 1, max_depth=0),

    # 2. SSH keys
    ScanTarget("/home/*/.ssh", "ssh_keys", "SSH keys and config", 1, max_depth=1),
    ScanTarget("/root/.ssh", "ssh_keys", "Root SSH keys", 1, max_depth=1),
    ScanTarget("~/.ssh", "ssh_keys", "Current user SSH keys", 1, max_depth=1),

    # 3. System credential files
    ScanTarget("/etc/shadow", "system_creds", "Shadow password file", 1, max_depth=0),
    ScanTarget("/etc/security/opasswd", "system_creds", "Old password hashes", 1, max_depth=0),
    ScanTarget("/etc/gshadow", "system_creds", "Group shadow file", 1, max_depth=0),
    ScanTarget("/etc/passwd", "system_creds", "System user list", 2, max_depth=0),
    ScanTarget("/etc/sudoers", "system_creds", "Sudoers configuration", 2, max_depth=0),
    ScanTarget("/etc/sudoers.d", "system_creds", "Sudoers includes", 2, max_depth=1),
    ScanTarget("/var/backups", "system_creds", "System backup directory", 2, max_depth=2),

    # 4. Environment / profile files
    ScanTarget("/etc/environment", "env_files", "System environment variables", 1, max_depth=0),
    ScanTarget("/etc/profile", "env_files", "System profile", 2, max_depth=0),
    ScanTarget("/etc/profile.d", "env_files", "Profile scripts", 2, max_depth=1),
    ScanTarget("/etc/bash.bashrc", "env_files", "System bashrc", 2, max_depth=0),
    ScanTarget("/home/*/.profile", "env_files", "User profiles", 2, max_depth=0),
    ScanTarget("/home/*/.bashrc", "env_files", "User bashrc files", 2, max_depth=0),
    ScanTarget("/home/*/.zshrc", "env_files", "User zshrc files", 2, max_depth=0),
    ScanTarget("/root/.profile", "env_files", "Root profile", 2, max_depth=0),
    ScanTarget("/root/.bashrc", "env_files", "Root bashrc", 2, max_depth=0),

    # 5. Cloud / DevOps creds
    ScanTarget("/home/*/.aws", "cloud_creds", "AWS credentials", 1, max_depth=1),
    ScanTarget("/home/*/.azure", "cloud_creds", "Azure CLI credentials", 1, max_depth=3),
    ScanTarget("/home/*/.config/gcloud", "cloud_creds", "Google Cloud credentials", 1, max_depth=3),
    ScanTarget("/home/*/.kube", "cloud_creds", "Kubernetes config", 1, max_depth=1),
    ScanTarget("/home/*/.docker", "cloud_creds", "Docker config", 1, max_depth=1),
    ScanTarget("/home/*/.npmrc", "cloud_creds", "npm credentials", 1, max_depth=0),
    ScanTarget("/home/*/.pypirc", "cloud_creds", "PyPI credentials", 1, max_depth=0),
    ScanTarget("/home/*/.netrc", "cloud_creds", "Netrc credentials", 1, max_depth=0),
    ScanTarget("/home/*/.git-credentials", "cloud_creds", "Git credentials", 1, max_depth=0),
    ScanTarget("/home/*/.gitconfig", "cloud_creds", "Git configuration", 2, max_depth=0),
    ScanTarget("/root/.aws", "cloud_creds", "Root AWS credentials", 1, max_depth=1),
    ScanTarget("/root/.azure", "cloud_creds", "Root Azure credentials", 1, max_depth=3),
    ScanTarget("/root/.config/gcloud", "cloud_creds", "Root GCloud credentials", 1, max_depth=3),
    ScanTarget("/root/.kube", "cloud_creds", "Root Kubernetes config", 1, max_depth=1),
    ScanTarget("/root/.docker", "cloud_creds", "Root Docker config", 1, max_depth=1),
    ScanTarget("~/.aws", "cloud_creds", "Current user AWS credentials", 1, max_depth=1),
    ScanTarget("~/.kube", "cloud_creds", "Current user kubeconfig", 1, max_depth=1),

    # 6. Database client history / config
    ScanTarget("/home/*/.mysql_history", "db_history", "MySQL command history", 1, max_depth=0),
    ScanTarget("/home/*/.psql_history", "db_history", "PostgreSQL command history", 1, max_depth=0),
    ScanTarget("/home/*/.my.cnf", "db_history", "MySQL client config", 1, max_depth=0),
    ScanTarget("/root/.mysql_history", "db_history", "Root MySQL history", 1, max_depth=0),
    ScanTarget("/root/.psql_history", "db_history", "Root PostgreSQL history", 1, max_depth=0),
    ScanTarget("/root/.my.cnf", "db_history", "Root MySQL config", 1, max_depth=0),

    # 7. Web application directories
    ScanTarget("/var/www", "web_apps", "Web application root", 1, max_depth=6, high_value_only=True),
    ScanTarget("/srv/www", "web_apps", "Alternative web root", 1, max_depth=6, high_value_only=True),
    ScanTarget("/usr/share/nginx", "web_apps", "Nginx default root", 2, max_depth=4, high_value_only=True),
    ScanTarget("/etc/nginx", "web_config", "Nginx configuration", 1, max_depth=3),
    ScanTarget("/etc/apache2", "web_config", "Apache configuration", 1, max_depth=3),
    ScanTarget("/etc/httpd", "web_config", "HTTPD configuration", 1, max_depth=3),

    # 8. Application / service configs
    ScanTarget("/etc", "system_config", "System configuration", 2, max_depth=3, high_value_only=True),
    ScanTarget("/opt", "app_config", "Optional application installs", 2, max_depth=4, high_value_only=True),
    ScanTarget("/srv", "app_config", "Service data", 2, max_depth=4, high_value_only=True),

    # 9. Systemd / cron
    ScanTarget("/etc/systemd/system", "systemd", "Custom systemd units", 2, max_depth=2),
    ScanTarget("/etc/cron.d", "cron", "Cron job definitions", 2, max_depth=1),
    ScanTarget("/etc/crontab", "cron", "System crontab", 2, max_depth=0),
    ScanTarget("/var/spool/cron", "cron", "User crontabs", 2, max_depth=2),
    ScanTarget("/var/spool/cron/crontabs", "cron", "User crontabs (Debian)", 2, max_depth=1),
    ScanTarget("/etc/init.d", "init_scripts", "Init scripts", 3, max_depth=1),

    # 10. Logs (low priority, limited depth)
    ScanTarget("/var/log", "logs", "System logs", 3, max_depth=2, high_value_only=True),

    # 11. Temp / shared memory
    ScanTarget("/tmp", "temp", "Temp directory", 3, max_depth=2, high_value_only=True),
    ScanTarget("/var/tmp", "temp", "Persistent temp", 3, max_depth=2, high_value_only=True),
    ScanTarget("/dev/shm", "temp", "Shared memory", 3, max_depth=2, high_value_only=True),
]


def _expand_path(raw: str) -> list[str]:
    """
    Expand a raw path string:
    - ~ → user home
    - %VAR% and $VAR → environment variable
    - * → glob expansion
    Returns list of existing, absolute paths (may be empty).
    """
    # Home expansion
    p = os.path.expanduser(raw)

    # Env var expansion (handles both $VAR and %VAR%)
    p = os.path.expandvars(p)

    # On Unix, also expand %VAR% style (Windows paths on Linux stay as-is and won't exist)
    if "%" in p and sys.platform != "win32":
        return []

    # Glob expansion
    if "*" in p or "?" in p:
        results = glob.glob(p)
    else:
        results = [p]

    # Filter to existing paths, make absolute
    out = []
    for r in results:
        try:
            r = os.path.abspath(r)
            if os.path.exists(r):
                out.append(r)
        except (OSError, ValueError):
            continue
    return out


def resolve_common_paths(targets: list[ScanTarget]) -> list[tuple[str, ScanTarget]]:
    """
    Expand and resolve a list of ScanTargets into (path, target) pairs.
    Deduplicates by resolved path. Sorted by priority (high first).
    """
    seen: set[str] = set()
    results: list[tuple[str, ScanTarget]] = []

    for target in sorted(targets, key=lambda t: t.priority):
        for path in _expand_path(target.path):
            if path not in seen:
                seen.add(path)
                results.append((path, target))

    return results


def get_windows_common_paths() -> list[ScanTarget]:
    """Return Windows common credential location targets."""
    return list(_WIN_TARGETS)


def get_linux_common_paths() -> list[ScanTarget]:
    """Return Linux common credential location targets."""
    return list(_LINUX_TARGETS)
