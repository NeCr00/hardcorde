"""
Credential-store and suspicious-filename discovery.

Two checks live here:

1. Credential-store file discovery (`--cred-stores`):
   Surface any file whose extension matches a known password-manager,
   keychain, or credential-vault format. Flagged by name only — the tool
   does not attempt to crack or open them.

2. Suspicious filename pattern matching (`--filename-patterns`):
   Flag any file whose basename or path contains credential-suggestive
   keywords (password, secret, id_rsa, htpasswd, etc.), regardless of
   extension. Case-insensitive, word-boundary aware.

Both checks emit `Finding` objects so they flow through the same
report/output pipeline as content-based detections.
"""

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Iterable, Optional

try:
    from .analyzer import Finding
    from .scanner import (
        BINARY_EXTENSIONS, ScanConfig, SKIP_DIRS, _is_likely_text,
    )
except ImportError:
    from hardcorde.analyzer import Finding
    from hardcorde.scanner import (
        BINARY_EXTENSIONS, ScanConfig, SKIP_DIRS, _is_likely_text,
    )


# ── Known password-manager / credential-vault extensions ──────────────
# Mapped to a human-readable store type and base severity.
#
# Only include extensions that are *specific* to a vault / credential
# format. Generic extensions like .dat, .key, .enc are NOT included here —
# they have too many other uses (game saves, TLS keys, miscellaneous
# encrypted blobs) and would generate noise. Such files surface via the
# filename-pattern check or content scan instead.
CRED_STORE_EXTENSIONS: dict[str, tuple[str, str]] = {
    # KeePass family
    ".kdbx": ("KeePass 2 database", "critical"),
    ".kdb":  ("KeePass 1 database", "critical"),
    # Password Safe (Schneier)
    ".psafe3": ("Password Safe v3 database", "critical"),
    # 1Password vaults / exports
    ".agilekeychain": ("1Password Agile Keychain", "critical"),
    ".opvault":       ("1Password OPVault", "critical"),
    ".1pif":          ("1Password Interchange Format export", "critical"),
    ".1pux":          ("1Password Unencrypted Export", "critical"),
    # Apple Keychain
    ".keychain":     ("Apple Keychain", "critical"),
    ".keychain-db":  ("Apple Keychain database", "critical"),
    # PuTTY private key (often the only key on Windows boxes)
    ".ppk":      ("PuTTY private key (may be passphrase-protected)", "critical"),
    # age-encrypted files (modern, format-specific)
    ".age":      ("age-encrypted file", "high"),
    # Misc password manager / wallet formats
    ".bkp":      ("Generic password-manager backup", "high"),
    ".fsk":      ("F-Secure Key vault", "high"),
    ".rfx":      ("RoboForm vault", "high"),
    ".spdb":     ("SplashID vault", "high"),
    ".walletx":  ("Bitwarden / wallet export variant", "high"),
    ".mlb":      ("mSecure database", "high"),
    ".dashlane": ("Dashlane export / vault", "high"),
}


# ── Suspicious filename keywords (case-insensitive, word-boundary aware) ─
# Each keyword is matched as a separate token: `[._\-/\\\b]keyword[._\-/\\\b]`
# Multi-word keys (`api_key`, `private_key`) match the literal token; the
# regex builder handles word boundaries.
#
# Keep this list TIGHT — every keyword fires on every basename in the tree.
# Adding `key`, `pass`, `user` alone would generate enormous noise.
_SECRET_KEYWORDS: list[str] = [
    # Password family
    "password", "passwords", "passwd", "pwd", "passphrase",
    # Secret family
    "secret", "secrets",
    # Credentials
    "credential", "credentials", "creds", "cred",
    # API keys
    "apikey", "apikeys", "api_key", "api_keys", "api-key", "api-keys",
    # Tokens
    "token", "tokens", "accesstoken", "access_token", "access-token",
    "refreshtoken", "refresh_token", "refresh-token",
    "bearer",
    # Auth
    "auth", "authkey", "auth_key", "auth-key",
    # Keys (private / SSH / GPG)
    "private_key", "privatekey", "private-key",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
    "ssh_host", "ssh-host",
    # System auth files
    "htpasswd", "htdigest", "shadow", "passwd",
    "smbpasswd", "vncpasswd", "afppasswd", "master.passwd",
    # Vault / wallet / keystore
    "vault", "vaults", "keystore", "keystores",
    "keyring", "keyrings", "wallet", "wallets",
    "keychain", "keychains",
    # OAuth client info
    "clientsecret", "client_secret", "client-secret",
    "clientid", "client_id", "client-id",
    # Cloud-specific
    "serviceaccount", "service_account", "service-account",
    "kubeconfig", "kubectl",
    # CTF / pentest evergreens
    "userlist", "user_list", "user-list",
    "pwdlist", "passlist", "pass_list", "pass-list",
    # Mnemonic / wallet recovery
    "mnemonic", "seedphrase", "seed_phrase", "seed-phrase",
    "recoveryphrase", "recovery_phrase", "recovery-phrase",
]

# These keywords only flag when combined with a primary one.
# `backup`, `dump`, `export`, `archive`, `snapshot` are common enough that
# without a primary co-occurrence they would fire on every random dump.
_QUALIFIED_KEYWORDS: list[str] = [
    "backup", "bkp",
    "dump", "dmp",
    "export", "exports",
    "archive", "archived",
    "snapshot", "snap",
    "leak", "leaked",
    "old", "orig", "save",
]


def _build_keyword_regex(keywords: Iterable[str]) -> re.Pattern:
    """
    Build a single case-insensitive regex that matches any of the
    keywords as a token (delimited by start, end, dot, underscore,
    dash, slash, or backslash). Anchored on basenames in practice.
    """
    # Keep punctuation so id_rsa / api-key / private_key all match literally.
    parts = sorted({re.escape(k) for k in keywords}, key=len, reverse=True)
    body = "|".join(parts)
    # (?:^|[._\-/\\])  — preceded by start or a separator
    # (?:$|[._\-/\\])  — followed by end or a separator
    return re.compile(
        rf"(?:^|[._\-/\\])(?P<kw>{body})(?:$|[._\-/\\])",
        re.IGNORECASE,
    )


_PRIMARY_KW_RE = _build_keyword_regex(_SECRET_KEYWORDS)
_QUALIFIED_KW_RE = _build_keyword_regex(_QUALIFIED_KEYWORDS)


def match_suspicious_filename(name: str) -> list[str]:
    """
    Return the list of credential-suggestive keywords that hit on the
    given basename (case-insensitive). Empty list if no hits.

    `backup` / `dump` only hit when at least one primary keyword also
    hits in the same name, since `db_backup.sql` alone is too noisy.
    """
    primary_hits = {m.group("kw").lower()
                    for m in _PRIMARY_KW_RE.finditer(name)}
    if not primary_hits:
        return []

    hits = list(primary_hits)
    # Add qualified keywords that co-occur with a primary hit
    for m in _QUALIFIED_KW_RE.finditer(name):
        hits.append(m.group("kw").lower())
    return sorted(set(hits))


# ─────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────

@dataclass
class StoreHit:
    """A credential-store or suspicious-name file discovery."""
    path: str
    size: int
    mtime: float
    extension: str
    kind: str            # "cred_store" or "filename_pattern"
    store_type: str = ""             # for cred_store: human-readable store
    keywords: list[str] = field(default_factory=list)  # filename keywords
    severity: str = "high"


def _walk_for_metadata(
    root: str,
    *,
    max_depth: int,
    follow_symlinks: bool,
    extra_skip_dirs: Iterable[str] = (),
) -> Generator[tuple[str, os.stat_result], None, None]:
    """
    Walk `root` yielding (filepath, stat_result) for every regular file,
    pruning the standard SKIP_DIRS plus extras. Unlike `discover_files`
    in scanner.py, this does NOT filter by extension or size — both
    cred-store and filename-pattern checks need to see everything by
    name first.
    """
    root = os.path.abspath(root)
    root_len = len(root)
    skip = set(SKIP_DIRS) | set(extra_skip_dirs)

    if os.path.isfile(root):
        try:
            st = os.stat(root)
            if stat.S_ISREG(st.st_mode):
                yield root, st
        except (OSError, PermissionError):
            pass
        return

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=follow_symlinks
    ):
        rel = dirpath[root_len:]
        depth = rel.count(os.sep) if rel else 0
        if depth >= max_depth:
            dirnames.clear()
            continue
        dirnames[:] = [d for d in dirnames if d not in skip]

        for fname in filenames:
            fp = os.path.join(dirpath, fname)
            try:
                if os.path.islink(fp) and not follow_symlinks:
                    continue
                st = os.stat(fp)
            except (OSError, PermissionError):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            yield fp, st


def discover_cred_stores(
    roots: Iterable[str],
    *,
    max_depth: int = 50,
    follow_symlinks: bool = False,
    extra_skip_dirs: Iterable[str] = (),
) -> list[StoreHit]:
    """
    Walk each root and return files whose extension matches a known
    credential-store / vault format. Deduplicated by absolute path.
    """
    seen: set[str] = set()
    hits: list[StoreHit] = []

    for root in roots:
        if not os.path.exists(root):
            continue
        for fp, st in _walk_for_metadata(
            root, max_depth=max_depth, follow_symlinks=follow_symlinks,
            extra_skip_dirs=extra_skip_dirs,
        ):
            if fp in seen:
                continue
            ext = Path(fp).suffix.lower()
            if ext not in CRED_STORE_EXTENSIONS:
                continue
            store_type, sev = CRED_STORE_EXTENSIONS[ext]
            seen.add(fp)
            hits.append(StoreHit(
                path=fp, size=st.st_size, mtime=st.st_mtime,
                extension=ext, kind="cred_store",
                store_type=store_type, severity=sev,
            ))
    return hits


def discover_filename_patterns(
    roots: Iterable[str],
    *,
    max_depth: int = 50,
    follow_symlinks: bool = False,
    max_size: int = 10 * 1024 * 1024,
    include_binary: bool = False,
    extra_skip_dirs: Iterable[str] = (),
) -> list[StoreHit]:
    """
    Walk each root and return files whose basename contains a
    credential-suggestive keyword (password, secret, id_rsa, …).
    Skips binary files unless `include_binary` is True, but still
    flags by name even when content is binary.

    Note: filename-pattern hits are reported on *name* alone. Content
    scanning is a separate step driven by the rules engine.
    """
    seen: set[str] = set()
    hits: list[StoreHit] = []

    for root in roots:
        if not os.path.exists(root):
            continue
        for fp, st in _walk_for_metadata(
            root, max_depth=max_depth, follow_symlinks=follow_symlinks,
            extra_skip_dirs=extra_skip_dirs,
        ):
            if fp in seen:
                continue
            base = os.path.basename(fp)
            kws = match_suspicious_filename(base)
            if not kws:
                continue
            ext = Path(fp).suffix.lower()
            seen.add(fp)
            hits.append(StoreHit(
                path=fp, size=st.st_size, mtime=st.st_mtime,
                extension=ext, kind="filename_pattern",
                keywords=kws, severity="medium",
            ))
    return hits


# ─────────────────────────────────────────────────────────────────────
# Bridge to the unified Finding model used by reporters
# ─────────────────────────────────────────────────────────────────────

def hit_to_finding(hit: StoreHit) -> Finding:
    """
    Render a `StoreHit` as a `Finding` so it flows through the same
    report pipeline as content matches. line_number is 0 for
    name-only hits.
    """
    if hit.kind == "cred_store":
        rule_id = "CRED_STORE_FILE"
        rule_name = f"Credential store: {hit.store_type}"
        category = "credential_file"
        try:
            mtime_str = datetime.fromtimestamp(hit.mtime, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        except (OverflowError, OSError, ValueError):
            mtime_str = "?"
        description = (
            f"{hit.store_type} discovered ({hit.size} bytes, modified {mtime_str}). "
            "Flagged by extension; contents not opened."
        )
        secret = f"<{hit.store_type} file: {os.path.basename(hit.path)}>"
        tags = ["cred_store", hit.extension.lstrip(".")]
        breakdown = {
            "extension_match": 100,
        }
    else:  # filename_pattern
        rule_id = "FILENAME_PATTERN"
        kws = hit.keywords or []
        rule_name = f"Suspicious filename: {', '.join(kws)}"
        category = "credential_file"
        description = (
            f"Filename matches credential-suggestive keyword(s): "
            f"{', '.join(kws)}"
        )
        secret = f"<filename match: {os.path.basename(hit.path)}>"
        tags = ["filename_pattern"] + kws
        breakdown = {"keyword_match": 80}

    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        severity=hit.severity,
        description=description,
        file_path=hit.path,
        line_number=0,
        line_content="",
        secret_value=secret,
        secret_masked=secret,
        confidence=100 if hit.kind == "cred_store" else 80,
        entropy=0.0,
        context_before=[],
        context_after=[],
        tags=tags,
        score_breakdown=breakdown,
    )
