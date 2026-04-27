"""
Confidence scoring, entropy analysis, and false-positive reduction.

The analyzer takes raw regex matches from the rules engine and applies
multiple layers of validation to produce a confidence score (0-100).

Scoring factors:
- Shannon entropy of the secret value
- Presence of contextual keywords nearby
- File type and path relevance
- Secret length and character class diversity
- Known false-positive pattern matching
- Known public/example key detection
- Allowlist/denylist filtering
"""

import math
import re
from dataclasses import dataclass, field
from typing import Optional
try:
    from .rules import Rule, Severity
except ImportError:
    from hardcorde.rules import Rule, Severity


@dataclass
class Finding:
    """A single credential finding with full context."""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    secret_value: str
    secret_masked: str
    confidence: int  # 0-100
    entropy: float
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    score_breakdown: dict[str, int] = field(default_factory=dict)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _char_class_diversity(s: str) -> int:
    """Count how many character classes are present (upper, lower, digit, special)."""
    classes = 0
    if re.search(r'[a-z]', s):
        classes += 1
    if re.search(r'[A-Z]', s):
        classes += 1
    if re.search(r'[0-9]', s):
        classes += 1
    if re.search(r'[^a-zA-Z0-9]', s):
        classes += 1
    return classes


def _mask_secret(secret: str, **_kwargs) -> str:
    """Return the secret as-is — no masking. Pentesters need to see
    the full value to validate findings quickly."""
    return secret


# Maximum characters to keep around the matched secret in line_content.
# Keeps output clean on long one-liners (minified scripts, connection strings).
_LINE_CONTEXT_CHARS = 20
_MAX_LINE_DISPLAY = 160
_MAX_CONTEXT_DISPLAY = 160


def _trim_line_around_secret(line: str, secret: str) -> str:
    """
    Trim a long line to show only a window around the matched secret.
    Returns the original line if it's short enough, otherwise returns
    a snippet with '...' ellipsis on each side.
    """
    if len(line) <= _MAX_LINE_DISPLAY:
        return line

    idx = line.find(secret[:20])  # match on first 20 chars of secret
    if idx == -1:
        # secret not found literally (regex may have transformed it),
        # just truncate the line
        return line[:_MAX_LINE_DISPLAY] + "..."

    # Build a window: some chars before the match, the match, some chars after
    start = max(0, idx - _LINE_CONTEXT_CHARS)
    end = min(len(line), idx + len(secret) + _LINE_CONTEXT_CHARS)

    snippet = line[start:end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(line) else ""
    return prefix + snippet + suffix


def _trim_context_line(line: str) -> str:
    """Truncate a context line if it's too long."""
    if len(line) <= _MAX_CONTEXT_DISPLAY:
        return line
    return line[:_MAX_CONTEXT_DISPLAY] + "..."


# -----------------------------------------------------------------------
# Known public / example keys that appear in documentation.
# These are NOT real credentials and should always score low.
# -----------------------------------------------------------------------
KNOWN_PUBLIC_KEYS: set[str] = {
    # AWS documentation example keys
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    # Stripe documentation
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_TYooMQauvdEDq54NiTphI7jx",
    # GitHub documentation
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    # Common test JWTs
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
}

# Substrings that strongly indicate a value is a documentation example
KNOWN_EXAMPLE_MARKERS: list[str] = [
    "EXAMPLE",     # AWS uses this
    "example",
    "SAMPLE",
    "sample",
    "xxxxxxxxxxxx",
    "XXXXXXXXXXXX",
    "your-api-key",
    "your_api_key",
    "INSERT_YOUR",
    "REPLACE_ME",
    "CHANGE_ME",
    "PUT_YOUR",
]


# Common placeholder / example values that are not real secrets
PLACEHOLDER_PATTERNS: list[re.Pattern] = [
    re.compile(r'^x{4,}$', re.IGNORECASE),
    re.compile(r'^0{6,}$'),
    re.compile(r'^1{6,}$'),
    re.compile(r'^(abc|123|test_?|example_?|sample_?|dummy_?|fake_?|temp_?)', re.IGNORECASE),
    re.compile(r'^(password|changeme|admin|root|guest|default)$', re.IGNORECASE),
    re.compile(r'^\$\{.*\}$'),       # ${VARIABLE}
    re.compile(r'^\$\(.*\)$'),       # $(command)
    re.compile(r'^%.*%$'),           # %VARIABLE%
    re.compile(r'^\{\{.*\}\}$'),     # {{template}}
    re.compile(r'^<[^>]+>$'),        # <placeholder>
    re.compile(r'^\[.*\]$'),         # [placeholder]
    re.compile(r'^ENV\[', re.IGNORECASE),
    re.compile(r'^process\.env\.', re.IGNORECASE),
    re.compile(r'^os\.environ', re.IGNORECASE),
    re.compile(r'^None$', re.IGNORECASE),
    re.compile(r'^null$', re.IGNORECASE),
    re.compile(r'^undefined$', re.IGNORECASE),
    re.compile(r'^true$', re.IGNORECASE),
    re.compile(r'^false$', re.IGNORECASE),
    re.compile(r'^TODO', re.IGNORECASE),
    re.compile(r'^FIXME', re.IGNORECASE),
    re.compile(r'^YOUR[_-]', re.IGNORECASE),
    re.compile(r'^PUT[_-]YOUR', re.IGNORECASE),
    re.compile(r'^CHANGE[_-]?ME', re.IGNORECASE),
    re.compile(r'^REPLACE[_-]', re.IGNORECASE),
    re.compile(r'^INSERT[_-]', re.IGNORECASE),
    # Variable interpolation patterns
    re.compile(r'^[a-zA-Z_]\w*\('),   # function call: func(...)
    re.compile(r'^vault:', re.IGNORECASE),  # vault:secret/path
]

# File path patterns that reduce confidence (test/example/doc files)
LOW_CONFIDENCE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r'[\\/](?:test|spec|mock|fixture|example|sample|demo|doc|readme)s?[\\/]', re.IGNORECASE),
    re.compile(r'(?:__test__|\.test\.|\.spec\.|_test\.)', re.IGNORECASE),
    re.compile(r'[\\/](?:node_modules|vendor|third.?party)[\\/]', re.IGNORECASE),
]

# File path patterns that boost confidence
HIGH_CONFIDENCE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?:\.env|config|setting|secret|credential|auth)', re.IGNORECASE),
    re.compile(r'(?:deploy|prod|staging|release)', re.IGNORECASE),
    re.compile(r'(?:docker-compose|ansible|terraform|puppet|chef)', re.IGNORECASE),
    re.compile(r'[\\/]\.(?:aws|ssh|gnupg|docker|kube)[\\/]', re.IGNORECASE),
    re.compile(r'(?:unattend|sysprep|autologon)', re.IGNORECASE),
    re.compile(r'(?:shadow|passwd|htpasswd|\.netrc|\.pgpass)', re.IGNORECASE),
]

# Line patterns that indicate a comment or documentation (lower confidence)
COMMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r'^\s*#(?!!)'),          # Shell/Python/YAML comments (but not shebangs)
    re.compile(r'^\s*//'),              # C-style line comments
    re.compile(r'^\s*/?\*'),            # C-style block comments
    re.compile(r'^\s*;'),              # INI comments
    re.compile(r'^\s*<!--'),           # HTML/XML comments
    re.compile(r'^\s*rem\s', re.IGNORECASE),  # Windows batch comments
]

# Allowlist: values that are always safe to ignore
VALUE_ALLOWLIST: frozenset[str] = frozenset({
    "password", "changeme", "admin", "root", "test", "guest",
    "default", "example", "sample", "placeholder", "none",
    "null", "undefined", "true", "false", "yes", "no",
    "password123", "abc123", "p@ssw0rd", "qwerty",
    "localhost", "127.0.0.1", "0.0.0.0",
    "my_password", "my_secret", "your_password", "your_secret",
    "password1", "pass", "secret", "test123",
    # XML attribute values that match "pass=" but aren't credentials
    "oobesystem", "specialize", "windowspe", "offlineservicing",
    "generalize", "audituser", "auditsystem",
    # Django/framework constant names that contain "password"
    "auth_password_validators", "password_hashers",
    "password_reset_timeout", "password_validators",
})

# Patterns for shadow file metadata fields that aren't passwords
_SHADOW_METADATA_RE = re.compile(r'^\d+:\d+:\d+:\d+:{0,3}$')


def _is_placeholder(value: str) -> bool:
    """Check if a value looks like a placeholder rather than a real secret."""
    v = value.strip().strip("'\"")
    if v.lower() in VALUE_ALLOWLIST:
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if pat.search(v):
            return True
    # All same character or only 2 unique chars (e.g., "aababab")
    if len(set(v)) <= 2 and len(v) > 4:
        return True
    # Shadow file metadata fields (e.g., "19000:0:99999:7:::")
    if _SHADOW_METADATA_RE.match(v):
        return True
    return False


def _is_known_public_key(value: str) -> bool:
    """Check if a value is a known public/example key from documentation."""
    v = value.strip().strip("'\"")
    if v in KNOWN_PUBLIC_KEYS:
        return True
    for marker in KNOWN_EXAMPLE_MARKERS:
        if marker in v:
            return True
    return False


def _is_comment_line(line: str) -> bool:
    """Check if a line is a code comment."""
    for pat in COMMENT_PATTERNS:
        if pat.match(line):
            return True
    return False


def compute_confidence(
    rule: Rule,
    secret_value: str,
    line: str,
    file_path: str,
    context_lines: list[str],
) -> tuple[int, float, dict[str, int]]:
    """
    Compute a confidence score (0-100) for a match.

    Returns (confidence, entropy, score_breakdown).
    """
    breakdown: dict[str, int] = {}
    score = 50  # Base score

    secret_clean = secret_value.strip().strip("'\"")

    # ------ 1. Entropy scoring ------
    entropy = shannon_entropy(secret_clean)
    if rule.check_entropy:
        if entropy >= 4.5:
            breakdown["entropy_high"] = 20
            score += 20
        elif entropy >= 3.5:
            breakdown["entropy_good"] = 12
            score += 12
        elif entropy >= rule.min_entropy:
            breakdown["entropy_ok"] = 5
            score += 5
        elif entropy < rule.min_entropy:
            breakdown["entropy_low"] = -25
            score -= 25

    # ------ 2. Length scoring ------
    slen = len(secret_clean)
    if slen < rule.min_length:
        breakdown["too_short"] = -40
        score -= 40
    elif slen > rule.max_length:
        breakdown["too_long"] = -20
        score -= 20
    elif slen >= 20:
        breakdown["good_length"] = 8
        score += 8
    elif slen >= 10:
        breakdown["decent_length"] = 4
        score += 4

    # ------ 3. Character diversity ------
    diversity = _char_class_diversity(secret_clean)
    if diversity >= 3:
        breakdown["char_diversity"] = 8
        score += 8
    elif diversity <= 1:
        breakdown["low_diversity"] = -10
        score -= 10

    # ------ 4. Placeholder detection ------
    if _is_placeholder(secret_clean):
        breakdown["placeholder"] = -40
        score -= 40

    # ------ 5. Known public key detection ------
    if _is_known_public_key(secret_clean):
        breakdown["known_public_key"] = -35
        score -= 35

    # ------ 6. False-positive indicator check ------
    lower_val = secret_clean.lower()
    for fp in rule.false_positive_indicators:
        if fp.lower() in lower_val:
            breakdown["fp_indicator"] = -30
            score -= 30
            break

    # ------ 7. Context keyword proximity ------
    full_context = " ".join(context_lines + [line]).lower()
    keyword_hits = sum(1 for kw in rule.context_keywords if kw.lower() in full_context)
    if keyword_hits >= 2:
        breakdown["strong_context"] = 15
        score += 15
    elif keyword_hits >= 1:
        breakdown["some_context"] = 8
        score += 8

    # ------ 8. File path relevance ------
    for pat in HIGH_CONFIDENCE_PATH_PATTERNS:
        if pat.search(file_path):
            breakdown["high_value_path"] = 10
            score += 10
            break

    for pat in LOW_CONFIDENCE_PATH_PATTERNS:
        if pat.search(file_path):
            breakdown["low_value_path"] = -10
            score -= 10
            break

    # ------ 9. Comment line penalty ------
    if _is_comment_line(line):
        breakdown["comment_line"] = -15
        score -= 15

    # ------ 10. Severity baseline ------
    severity_bonus = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 3,
        Severity.MEDIUM: 0,
        Severity.LOW: -3,
        Severity.INFO: -5,
    }
    bonus = severity_bonus.get(rule.severity, 0)
    if bonus:
        breakdown["severity_baseline"] = bonus
        score += bonus

    # ------ 11. Line-match rules (PEM headers etc.) always high ------
    if rule.line_match:
        breakdown["structural_match"] = 25
        score += 25

    # ------ 12. DB URI with credentials bonus ------
    # If the secret looks like a URI with user:pass@host, boost confidence
    if "://" in secret_clean and "@" in secret_clean:
        parts = secret_clean.split("://", 1)
        if len(parts) == 2 and ":" in parts[1].split("@")[0]:
            breakdown["uri_with_creds"] = 10
            score += 10

    # Clamp to [0, 100]
    score = max(0, min(100, score))

    return score, entropy, breakdown


def analyze_line(
    rule: Rule,
    line: str,
    line_number: int,
    file_path: str,
    lines: list[str],
    context_window: int = 3,
) -> Optional[Finding]:
    """
    Apply a rule to a single line and return a Finding if it matches
    with sufficient confidence.
    """
    match = rule.pattern.search(line)
    if not match:
        return None

    # Extract the secret value from named groups
    secret_value = None
    for group_name in ("secret", "secret_unquoted", "secret2"):
        try:
            val = match.group(group_name)
            if val:
                secret_value = val
                break
        except IndexError:
            continue

    if not secret_value:
        # Fallback: use the entire match
        secret_value = match.group(0)

    # Gather context lines
    start = max(0, line_number - 1 - context_window)
    end = min(len(lines), line_number + context_window)
    context_before_raw = [l.rstrip("\n\r") for l in lines[start:line_number - 1]]
    context_after_raw = [l.rstrip("\n\r") for l in lines[line_number:end]]

    confidence, entropy, breakdown = compute_confidence(
        rule=rule,
        secret_value=secret_value,
        line=line,
        file_path=file_path,
        context_lines=context_before_raw + context_after_raw,
    )

    # Trim long lines for clean output — keeps the secret visible,
    # cuts noise from one-liners and minified code
    trimmed_line = _trim_line_around_secret(line.rstrip("\n\r"), secret_value)
    context_before = [_trim_context_line(l) for l in context_before_raw]
    context_after = [_trim_context_line(l) for l in context_after_raw]

    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category.value,
        severity=rule.severity.value,
        description=rule.description,
        file_path=file_path,
        line_number=line_number,
        line_content=trimmed_line,
        secret_value=secret_value,
        secret_masked=_mask_secret(secret_value),
        confidence=confidence,
        entropy=entropy,
        context_before=context_before,
        context_after=context_after,
        tags=list(rule.tags),
        score_breakdown=breakdown,
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings (same file, line, secret prefix).
    When multiple rules match the same secret on the same line, keep the
    highest-confidence match. Also keep findings from different rules that
    match different secrets on the same line.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        # Key by file + line + first 20 chars of secret to group overlapping matches
        key = f"{f.file_path}:{f.line_number}:{f.secret_value[:20]}"
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return sorted(seen.values(), key=lambda x: (-x.confidence, x.file_path, x.line_number))
