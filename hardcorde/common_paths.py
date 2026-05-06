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

    # 10. PowerShell profile + cached credentials (Export-Clixml dumps)
    ScanTarget("C:\\Users\\*\\Documents\\WindowsPowerShell", "powershell_profile",
               "PowerShell profile + saved cred xml", 1, max_depth=3),
    ScanTarget("C:\\Users\\*\\Documents\\PowerShell", "powershell_profile",
               "PS Core profile", 1, max_depth=3),

    # 11. WSL config & credentials
    ScanTarget("C:\\Users\\*\\.wslconfig", "user_files", "WSL config", 2, max_depth=0),
    ScanTarget("C:\\Users\\*\\AppData\\Local\\Packages\\CanonicalGroupLimited*",
               "user_files", "WSL distro file roots", 3, max_depth=4, high_value_only=True),

    # 12. HashiCorp / IaC token caches
    ScanTarget("C:\\Users\\*\\.vault-token", "cloud_creds",
               "HashiCorp Vault cached token", 1, max_depth=0),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\rclone", "cloud_creds",
               "rclone config", 1, max_depth=2),

    # 13. Common third-party SSH / RDP / VPN client storage
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\SuperPuTTY", "remote_access",
               "SuperPuTTY saved sessions", 2, max_depth=2),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\Bitvise", "remote_access",
               "Bitvise SSH client profiles", 2, max_depth=2),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\KiTTY", "remote_access",
               "KiTTY (PuTTY fork) sessions", 2, max_depth=2),
    ScanTarget("C:\\Users\\*\\AppData\\Roaming\\TeraTerm", "remote_access",
               "TeraTerm config", 2, max_depth=2),
    ScanTarget("C:\\Users\\*\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager",
               "remote_access", "RDCMan saved connections", 1, max_depth=2),

    # 14. SCCM / Group Policy on the local machine (if it's a DC / member)
    ScanTarget("C:\\Windows\\SYSVOL\\sysvol", "domain", "SYSVOL (GPP / scripts)",
               1, max_depth=8, high_value_only=True),
    ScanTarget("C:\\ProgramData\\Microsoft\\Group Policy\\History",
               "domain", "Cached GPO history", 2, max_depth=4),
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

    # 12. Auth / directory-service configs
    ScanTarget("/etc/openldap", "auth_server", "OpenLDAP server config", 1, max_depth=2),
    ScanTarget("/etc/ldap", "auth_server", "OpenLDAP client config", 1, max_depth=2),
    ScanTarget("/etc/krb5.conf", "auth_server", "Kerberos client config", 1, max_depth=0),
    ScanTarget("/etc/krb5.keytab", "auth_server", "System Kerberos keytab", 1, max_depth=0),
    ScanTarget("/etc/samba", "auth_server", "Samba config + secrets.tdb", 1, max_depth=2),
    ScanTarget("/etc/freeradius", "auth_server", "FreeRADIUS config", 1, max_depth=3),
    ScanTarget("/etc/raddb", "auth_server", "FreeRADIUS alt config", 1, max_depth=3),
    ScanTarget("/etc/pam.d", "auth_server", "PAM modules config", 2, max_depth=1),

    # 13. Mount / fstab credentials references
    ScanTarget("/etc/fstab", "system_creds", "Mount table (cifs creds= references)", 1, max_depth=0),
    ScanTarget("/etc/.smbcredentials", "system_creds", "SMB credentials file", 1, max_depth=0),
    ScanTarget("/etc/samba/.smbcredentials", "system_creds", "SMB credentials file", 1, max_depth=0),
    ScanTarget("/root/.smbcredentials", "system_creds", "Root SMB credentials file", 1, max_depth=0),
    ScanTarget("/home/*/.smbcredentials", "system_creds", "User SMB credentials file", 1, max_depth=0),

    # 14. HashiCorp / IaC tool caches
    ScanTarget("/home/*/.vault-token", "cloud_creds", "HashiCorp Vault cached token", 1, max_depth=0),
    ScanTarget("/root/.vault-token", "cloud_creds", "Root Vault cached token", 1, max_depth=0),
    ScanTarget("~/.vault-token", "cloud_creds", "Current user Vault token", 1, max_depth=0),
    ScanTarget("/home/*/.config/rclone", "cloud_creds", "rclone config (encrypted creds)", 1, max_depth=2),
    ScanTarget("/root/.config/rclone", "cloud_creds", "Root rclone config", 1, max_depth=2),
    ScanTarget("~/.config/rclone", "cloud_creds", "Current user rclone config", 1, max_depth=2),

    # 15. Oracle homes (commonly under /opt/oracle or $ORACLE_HOME)
    ScanTarget("/opt/oracle", "app_config", "Oracle install (tnsnames/wallet)", 2, max_depth=5, high_value_only=True),
    ScanTarget("/u01/app/oracle", "app_config", "Oracle install (alt path)", 2, max_depth=5, high_value_only=True),
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
