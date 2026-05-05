"""
Credential detection rules and pattern library.

Each rule is a dataclass that encapsulates:
- A regex pattern to match
- Metadata (category, severity, description)
- Optional validators (entropy threshold, length bounds, keyword context)
- False-positive indicators to suppress noisy matches
- Fast keywords for pre-filtering (skip regex if no keyword on line)

Rules are grouped by category for clarity and maintainability.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    CLOUD_KEY = "cloud_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    ENV_SECRET = "env_secret"
    GENERIC_SECRET = "generic_secret"
    CREDENTIAL_FILE = "credential_file"
    HASH = "hash"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Default false-positive indicators shared across most rules
_DEFAULT_FP_INDICATORS: list[str] = [
    "example", "sample", "placeholder", "your_", "xxx", "changeme",
    "insert", "replace", "todo", "fixme", "dummy", "fake",
    "<your", "{your", "CHANGE_ME", "PUT_YOUR",
    "xxxxxxxx", "00000000", "11111111",
]


@dataclass
class Rule:
    """A single detection rule."""
    id: str
    name: str
    category: Category
    severity: Severity
    description: str
    pattern: re.Pattern
    # Minimum Shannon entropy for the secret portion to be considered real
    min_entropy: float = 0.0
    # Length bounds for the captured secret group
    min_length: int = 1
    max_length: int = 2048
    # Keywords that, if present on the same line or nearby, boost confidence
    context_keywords: list[str] = field(default_factory=list)
    # Strings that indicate a false positive (placeholder, example, etc.)
    false_positive_indicators: list[str] = field(default_factory=lambda: list(_DEFAULT_FP_INDICATORS))
    # If True, the entire matched line is the finding (e.g., private key headers)
    line_match: bool = False
    # Named group in the regex that contains the actual secret value
    secret_group: str = "secret"
    # Whether to apply entropy check
    check_entropy: bool = True
    # Additional tags for filtering
    tags: list[str] = field(default_factory=list)
    # Fast pre-filter: if set, at least one keyword must appear on the line
    # (case-insensitive) before the regex is even attempted. Empty = always try.
    fast_keywords: list[str] = field(default_factory=list)
    # If True, the rule is matched against the whole file content (multi-line)
    # in a separate pass instead of line-by-line. Use for patterns that span
    # multiple lines (XML blocks, OpenVPN <auth-user-pass>, etc.).
    multiline: bool = False


def _build_rules() -> list[Rule]:
    """Build and return all detection rules."""
    rules: list[Rule] = []

    # -----------------------------------------------------------------------
    # 1. PASSWORDS — assignment patterns
    # -----------------------------------------------------------------------
    rules.append(Rule(
        id="PASSWORD_ASSIGNMENT",
        name="Hardcoded password assignment",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Variable assignment containing password/secret keyword with a literal string value",
        pattern=re.compile(
            r'(?i)'
            # Variable name must contain a password-like keyword as a distinct segment
            # (word boundary or underscore/dot/dash separated), not as a substring
            # of an unrelated word like "compass" or "bypass"
            r'[\w.-]*(?:_|^|\.|-|"|\')(?:pass(?:word|wd|phrase)?|pwd|secret|credential|auth_?token)'
            r'[\w.-]*'
            r'\s*(?:=|:=?|=>|<-)\s*'
            r'(?:'
            r"""["\'](?P<secret>[^"\'\\]{4,})["\']"""  # quoted value
            r'|'
            r'(?P<secret_unquoted>[^\s#;,\])}\\\x27"]{4,})'  # unquoted value
            r')',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["password", "secret", "credential", "auth"],
        check_entropy=True,
        tags=["password", "hardcoded"],
        fast_keywords=["password", "passwd", "passphrase", "pwd", "secret", "credential", "auth_token", "authtoken"],
    ))

    # XML/HTML attribute passwords
    rules.append(Rule(
        id="PASSWORD_XML_ATTR",
        name="Password in XML/HTML attribute",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Password or secret value in an XML/HTML attribute",
        pattern=re.compile(
            r'(?i)(?:password|passwd|pwd|secret|credential)\s*=\s*"(?P<secret>[^"]{4,})"',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "xml"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential"],
    ))

    # XML element content: <Password>value</Password> or <Value>value</Value>
    # inside password context
    rules.append(Rule(
        id="PASSWORD_XML_ELEMENT",
        name="Password in XML element",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Password value inside XML element tags",
        pattern=re.compile(
            r'(?i)<(?:password|secret|credential|passphrase)>'
            r'\s*(?P<secret>[^<]{4,})\s*'
            r'</(?:password|secret|credential|passphrase)>',
        ),
        min_entropy=1.5,
        min_length=4,
        check_entropy=True,
        tags=["password", "xml"],
        fast_keywords=["<password", "<secret", "<credential", "<passphrase"],
    ))

    # XML <Value> inside password context (unattend.xml pattern)
    rules.append(Rule(
        id="PASSWORD_XML_VALUE",
        name="Password value in XML config",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="<Value> element likely containing a password (e.g., unattend.xml)",
        pattern=re.compile(
            r'(?i)<Value>(?P<secret>[^<]{4,})</Value>',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["password", "autologon", "useraccount", "localaccount", "credential"],
        check_entropy=True,
        tags=["password", "xml", "windows"],
        fast_keywords=["<value>"],
    ))

    # Connection string inline password (;Password=value; or ;Pwd=value;)
    rules.append(Rule(
        id="CONNSTR_INLINE_PASSWORD",
        name="Password in connection string",
        category=Category.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="Password embedded in a database connection string parameter",
        pattern=re.compile(
            r'(?i)[;"\s](?:Password|Pwd)\s*=\s*(?P<secret>[^;"\s<>]{3,})',
        ),
        min_entropy=1.5,
        min_length=3,
        context_keywords=["connection", "server", "database", "data source", "provider"],
        check_entropy=True,
        false_positive_indicators=[],  # passwords in connstrings are always findings
        tags=["connection_string", "password", "database"],
        fast_keywords=["password", "pwd"],
    ))

    # Command-line password arguments: -p "password", --password=value, etc.
    rules.append(Rule(
        id="CLI_PASSWORD_ARG",
        name="Password in command-line argument",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Password passed as command-line argument (visible in process list)",
        pattern=re.compile(
            r'(?i)(?:-p\s+|--password[=\s]+|--passwd[=\s]+|--secret[=\s]+)'
            r'["\']?(?P<secret>[^\s"\']{3,})["\']?',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=True,
        tags=["password", "cli"],
        fast_keywords=["-p ", "--password", "--passwd", "--secret"],
    ))

    # net user command with inline password
    rules.append(Rule(
        id="NET_USER_PASSWORD",
        name="net user command with password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Windows net user command with inline password",
        pattern=re.compile(
            r'(?i)net\s+user\s+\S+\s+(?P<secret>[^\s/]{3,})\s+/add',
        ),
        min_entropy=1.0,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "windows", "command"],
        fast_keywords=["net user", "net  user"],
    ))

    # .netrc file format: machine <host> login <user> password <pass>
    rules.append(Rule(
        id="NETRC_PASSWORD",
        name=".netrc credential",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Credentials in .netrc format",
        pattern=re.compile(
            r'(?i)(?:machine|default)\s+\S*\s*login\s+\S+\s+password\s+(?P<secret>\S+)',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "netrc"],
        fast_keywords=["machine", "default"],
    ))

    # INI-style password entries
    rules.append(Rule(
        id="INI_PASSWORD",
        name="Password in INI/config file",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Password value in INI-style configuration",
        pattern=re.compile(
            r'(?im)^[\s]*(?:password|passwd|pwd|pass|secret|auth_token|api_key)\s*='
            r'\s*(?P<secret>[^\s#;]{4,})',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "ini", "config"],
        fast_keywords=["password", "passwd", "pwd", "pass=", "secret", "auth_token", "api_key"],
    ))

    # PHP define() password
    rules.append(Rule(
        id="PHP_DEFINE_PASSWORD",
        name="PHP define() with credential",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="PHP define() call setting a password or secret constant",
        pattern=re.compile(
            r"""(?i)define\(\s*['"](?:DB_PASSWORD|DB_PASS|PASSWORD|SECRET|AUTH_KEY|"""
            r"""API_KEY|SALT|NONCE_KEY|LOGGED_IN_KEY|SECURE_AUTH_KEY|"""
            r"""AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['"]"""
            r"""\s*,\s*['"](?P<secret>[^'"]{4,})['"]""",
        ),
        min_entropy=2.0,
        min_length=4,
        false_positive_indicators=["put your unique phrase here"],
        tags=["password", "php"],
        fast_keywords=["define("],
    ))

    # -----------------------------------------------------------------------
    # 2. API KEYS — provider-specific patterns
    # -----------------------------------------------------------------------

    # AWS Access Key ID
    rules.append(Rule(
        id="AWS_ACCESS_KEY",
        name="AWS Access Key ID",
        category=Category.CLOUD_KEY,
        severity=Severity.CRITICAL,
        description="AWS Access Key ID (starts with AKIA, ABIA, ACCA, ASIA)",
        pattern=re.compile(
            r'(?P<secret>(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})',
        ),
        min_entropy=3.0,
        min_length=20,
        max_length=20,
        context_keywords=["aws", "amazon", "access_key", "key_id"],
        tags=["aws", "cloud"],
        fast_keywords=["AKIA", "ABIA", "ACCA", "ASIA"],
    ))

    # AWS Secret Access Key
    rules.append(Rule(
        id="AWS_SECRET_KEY",
        name="AWS Secret Access Key",
        category=Category.CLOUD_KEY,
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key (40-char base64)",
        pattern=re.compile(
            r'(?i)(?:aws)?_?secret_?(?:access)?_?key[\s]*[=:]\s*["\']?(?P<secret>[A-Za-z0-9/+=]{40})["\']?',
        ),
        min_entropy=4.0,
        min_length=40,
        max_length=40,
        context_keywords=["aws", "secret", "access"],
        tags=["aws", "cloud"],
        fast_keywords=["secret"],
    ))

    # Google API Key
    rules.append(Rule(
        id="GOOGLE_API_KEY",
        name="Google API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Google API key (AIza prefix, 39 chars)",
        pattern=re.compile(
            r'(?P<secret>AIza[0-9A-Za-z_-]{35})',
        ),
        min_entropy=3.5,
        min_length=39,
        max_length=39,
        context_keywords=["google", "api", "gcp"],
        tags=["google", "cloud"],
        fast_keywords=["AIza"],
    ))

    # Google OAuth Client Secret
    rules.append(Rule(
        id="GOOGLE_OAUTH_SECRET",
        name="Google OAuth Client Secret",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Google OAuth client secret",
        pattern=re.compile(
            r'(?P<secret>GOCSPX-[A-Za-z0-9_-]{28})',
        ),
        min_entropy=3.0,
        tags=["google", "oauth"],
        fast_keywords=["GOCSPX-"],
    ))

    # GitHub Token (classic PAT, fine-grained, OAuth, etc.)
    rules.append(Rule(
        id="GITHUB_TOKEN",
        name="GitHub Token",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub personal access token or app token",
        pattern=re.compile(
            r'(?P<secret>(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255})',
        ),
        min_entropy=3.0,
        context_keywords=["github", "token", "pat"],
        tags=["github", "token"],
        fast_keywords=["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
    ))

    # GitLab Token
    rules.append(Rule(
        id="GITLAB_TOKEN",
        name="GitLab Token",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="GitLab personal/project/group access token",
        pattern=re.compile(
            r'(?P<secret>glpat-[A-Za-z0-9_-]{20,})',
        ),
        min_entropy=3.0,
        context_keywords=["gitlab", "token"],
        tags=["gitlab", "token"],
        fast_keywords=["glpat-"],
    ))

    # Slack Token
    rules.append(Rule(
        id="SLACK_TOKEN",
        name="Slack Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Slack bot, user, or workspace token",
        pattern=re.compile(
            r'(?P<secret>xox[bporas]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)',
        ),
        min_entropy=3.0,
        context_keywords=["slack"],
        tags=["slack", "token"],
        fast_keywords=["xoxb-", "xoxp-", "xoxo-", "xoxa-", "xoxr-", "xoxs-"],
    ))

    # Slack Webhook
    rules.append(Rule(
        id="SLACK_WEBHOOK",
        name="Slack Webhook URL",
        category=Category.TOKEN,
        severity=Severity.MEDIUM,
        description="Slack incoming webhook URL",
        pattern=re.compile(
            r'(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)',
        ),
        min_entropy=2.5,
        context_keywords=["slack", "webhook"],
        tags=["slack", "webhook"],
        fast_keywords=["hooks.slack.com"],
    ))

    # Stripe API Key
    rules.append(Rule(
        id="STRIPE_KEY",
        name="Stripe API Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        description="Stripe secret or publishable API key",
        pattern=re.compile(
            r'(?P<secret>[sr]k_(?:live|test)_[A-Za-z0-9]{20,})',
        ),
        min_entropy=3.0,
        context_keywords=["stripe"],
        tags=["stripe", "payment"],
        fast_keywords=["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
    ))

    # Twilio API Key
    rules.append(Rule(
        id="TWILIO_KEY",
        name="Twilio API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Twilio Account SID or Auth Token",
        pattern=re.compile(
            r'(?P<secret>SK[a-f0-9]{32})',
        ),
        min_entropy=3.5,
        context_keywords=["twilio"],
        tags=["twilio"],
        fast_keywords=["SK"],
    ))

    # SendGrid API Key
    rules.append(Rule(
        id="SENDGRID_KEY",
        name="SendGrid API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="SendGrid API key",
        pattern=re.compile(
            r'(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})',
        ),
        min_entropy=4.0,
        context_keywords=["sendgrid"],
        tags=["sendgrid", "email"],
        fast_keywords=["SG."],
    ))

    # Heroku API Key
    rules.append(Rule(
        id="HEROKU_KEY",
        name="Heroku API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Heroku API key (UUID format)",
        pattern=re.compile(
            r'(?i)heroku[\w_-]*(?:api)?[\w_-]*(?:key|token)\s*[=:]\s*["\']?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?',
        ),
        min_entropy=3.0,
        context_keywords=["heroku"],
        tags=["heroku"],
        fast_keywords=["heroku"],
    ))

    # Azure
    rules.append(Rule(
        id="AZURE_SECRET",
        name="Azure Client Secret / Storage Key",
        category=Category.CLOUD_KEY,
        severity=Severity.CRITICAL,
        description="Azure service principal secret or storage account key",
        pattern=re.compile(
            r'(?i)(?:azure|az)[\w_-]*(?:secret|key|password|connection[\s_-]*string)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9+/=]{32,88})["\']?',
        ),
        min_entropy=4.0,
        min_length=32,
        context_keywords=["azure", "microsoft", "storage", "tenant"],
        tags=["azure", "cloud"],
        fast_keywords=["azure", "az_"],
    ))

    # DigitalOcean Token
    rules.append(Rule(
        id="DIGITALOCEAN_TOKEN",
        name="DigitalOcean Access Token",
        category=Category.CLOUD_KEY,
        severity=Severity.HIGH,
        description="DigitalOcean personal access token",
        pattern=re.compile(
            r'(?P<secret>dop_v1_[a-f0-9]{64})',
        ),
        min_entropy=3.5,
        tags=["digitalocean", "cloud"],
        fast_keywords=["dop_v1_"],
    ))

    # npm Token
    rules.append(Rule(
        id="NPM_TOKEN",
        name="npm Access Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="npm registry authentication token",
        pattern=re.compile(
            r'(?P<secret>npm_[A-Za-z0-9]{36})',
        ),
        min_entropy=3.0,
        tags=["npm", "registry"],
        fast_keywords=["npm_"],
    ))

    # PyPI Token
    rules.append(Rule(
        id="PYPI_TOKEN",
        name="PyPI API Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="PyPI API token",
        pattern=re.compile(
            r'(?P<secret>pypi-[A-Za-z0-9_-]{50,})',
        ),
        min_entropy=3.0,
        tags=["pypi", "python"],
        fast_keywords=["pypi-"],
    ))

    # Mailgun API Key
    rules.append(Rule(
        id="MAILGUN_KEY",
        name="Mailgun API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Mailgun API key",
        pattern=re.compile(
            r'(?P<secret>key-[a-f0-9]{32})',
        ),
        min_entropy=3.5,
        context_keywords=["mailgun"],
        tags=["mailgun", "email"],
        fast_keywords=["key-"],
    ))

    # Square Access Token
    rules.append(Rule(
        id="SQUARE_TOKEN",
        name="Square Access Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Square OAuth or personal access token",
        pattern=re.compile(
            r'(?P<secret>sq0[a-z]{3}-[A-Za-z0-9_-]{22,})',
        ),
        min_entropy=3.0,
        tags=["square", "payment"],
        fast_keywords=["sq0"],
    ))

    # Shopify Access Token
    rules.append(Rule(
        id="SHOPIFY_TOKEN",
        name="Shopify Access Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Shopify admin API or private app token",
        pattern=re.compile(
            r'(?P<secret>shpat_[a-f0-9]{32})',
        ),
        min_entropy=3.0,
        tags=["shopify"],
        fast_keywords=["shpat_"],
    ))

    # Databricks Token
    rules.append(Rule(
        id="DATABRICKS_TOKEN",
        name="Databricks Access Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Databricks personal access token",
        pattern=re.compile(
            r'(?P<secret>dapi[a-f0-9]{32})',
        ),
        min_entropy=3.5,
        tags=["databricks"],
        fast_keywords=["dapi"],
    ))

    # Discord Token
    rules.append(Rule(
        id="DISCORD_TOKEN",
        name="Discord Bot / User Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Discord bot or user authentication token",
        pattern=re.compile(
            r'(?P<secret>[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27,})',
        ),
        min_entropy=4.0,
        context_keywords=["discord", "bot", "token"],
        tags=["discord"],
    ))

    # OpenAI API Key
    rules.append(Rule(
        id="OPENAI_KEY",
        name="OpenAI API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="OpenAI API key",
        pattern=re.compile(
            r'(?P<secret>sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})',
        ),
        min_entropy=4.0,
        context_keywords=["openai", "gpt", "api"],
        tags=["openai", "ai"],
        fast_keywords=["sk-"],
    ))

    # OpenAI project key (newer format)
    rules.append(Rule(
        id="OPENAI_PROJECT_KEY",
        name="OpenAI Project API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="OpenAI project-scoped API key",
        pattern=re.compile(
            r'(?P<secret>sk-proj-[A-Za-z0-9_-]{40,})',
        ),
        min_entropy=4.0,
        context_keywords=["openai", "gpt", "api"],
        tags=["openai", "ai"],
        fast_keywords=["sk-proj-"],
    ))

    # Anthropic API Key
    rules.append(Rule(
        id="ANTHROPIC_KEY",
        name="Anthropic API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        description="Anthropic Claude API key",
        pattern=re.compile(
            r'(?P<secret>sk-ant-[A-Za-z0-9_-]{80,})',
        ),
        min_entropy=4.0,
        context_keywords=["anthropic", "claude", "api"],
        tags=["anthropic", "ai"],
        fast_keywords=["sk-ant-"],
    ))

    # HuggingFace Token
    rules.append(Rule(
        id="HUGGINGFACE_TOKEN",
        name="HuggingFace Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="HuggingFace access token",
        pattern=re.compile(
            r'(?P<secret>hf_[A-Za-z0-9]{34,})',
        ),
        min_entropy=3.5,
        context_keywords=["huggingface", "hf", "transformers"],
        tags=["huggingface", "ai"],
        fast_keywords=["hf_"],
    ))

    # HashiCorp Vault Token
    rules.append(Rule(
        id="VAULT_TOKEN",
        name="HashiCorp Vault Token",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="HashiCorp Vault service or root token",
        pattern=re.compile(
            r'(?P<secret>hvs\.[A-Za-z0-9_-]{24,})',
        ),
        min_entropy=3.0,
        context_keywords=["vault", "hashicorp"],
        tags=["vault", "hashicorp"],
        fast_keywords=["hvs."],
    ))

    # Grafana API Key / Service Account Token
    rules.append(Rule(
        id="GRAFANA_TOKEN",
        name="Grafana API Key / Service Account Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Grafana API key or service account token",
        pattern=re.compile(
            r'(?P<secret>glsa_[A-Za-z0-9_]{32,})',
        ),
        min_entropy=3.0,
        context_keywords=["grafana"],
        tags=["grafana"],
        fast_keywords=["glsa_"],
    ))

    # -----------------------------------------------------------------------
    # 3. PRIVATE KEYS
    # -----------------------------------------------------------------------
    for key_type in [
        "RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ]:
        rules.append(Rule(
            id=f"PRIVATE_KEY_{key_type.replace(' ', '_')}",
            name=f"{key_type} detected",
            category=Category.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            description=f"PEM-encoded {key_type} found in file",
            pattern=re.compile(
                rf'(?P<secret>-----BEGIN {re.escape(key_type)}-----)',
            ),
            check_entropy=False,
            line_match=True,
            min_length=10,
            false_positive_indicators=[],  # PEM headers are never false positives
            tags=["private_key", "pem"],
            fast_keywords=["-----BEGIN"],
        ))

    # -----------------------------------------------------------------------
    # 4. CONNECTION STRINGS
    # -----------------------------------------------------------------------

    # Generic database URI with embedded credentials (user:pass@host)
    rules.append(Rule(
        id="DATABASE_URI",
        name="Database Connection URI",
        category=Category.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="Database connection string with embedded credentials",
        pattern=re.compile(
            r'(?P<secret>(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql|oracle|mariadb)'
            r'://[^\s"\'<>]*[:@][^\s"\'<>]{6,})',
            re.IGNORECASE,
        ),
        min_entropy=1.5,
        context_keywords=["database", "db", "connection", "dsn", "uri", "url"],
        tags=["database", "connection_string"],
        fast_keywords=["://"],
    ))

    # JDBC connection strings
    rules.append(Rule(
        id="JDBC_STRING",
        name="JDBC Connection String",
        category=Category.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="JDBC connection string (may contain credentials)",
        pattern=re.compile(
            r'(?P<secret>jdbc:[a-z]+://[^\s"\'<>]{10,})',
            re.IGNORECASE,
        ),
        min_entropy=2.0,
        context_keywords=["jdbc", "database", "connection"],
        tags=["database", "jdbc"],
        fast_keywords=["jdbc:"],
    ))

    # ODBC / ADO.NET connection strings
    rules.append(Rule(
        id="CONNECTION_STRING_GENERIC",
        name="Connection String with Password",
        category=Category.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="Connection string containing password parameter",
        pattern=re.compile(
            r'(?i)(?:connection[\s_-]*string|dsn|data[\s_-]*source)\s*[=:]\s*["\']?'
            r'(?P<secret>[^"\';\n]*(?:password|pwd)\s*=[^"\';\n]+)',
        ),
        min_entropy=1.5,
        tags=["connection_string"],
        fast_keywords=["connection", "dsn", "data source"],
    ))

    # -----------------------------------------------------------------------
    # 5. GENERIC / ENV PATTERNS
    # -----------------------------------------------------------------------

    # Generic KEY= or TOKEN= or SECRET= in env files / shell
    rules.append(Rule(
        id="ENV_SECRET_ASSIGNMENT",
        name="Secret in environment variable",
        category=Category.ENV_SECRET,
        severity=Severity.HIGH,
        description="Environment variable assignment with secret-like name",
        pattern=re.compile(
            r'(?i)^(?:export\s+)?'
            r'(?P<varname>[A-Z_]*(?:SECRET|TOKEN|API[_-]?KEY|AUTH|CREDENTIAL|PASSWORD|PASSWD|PWD)[A-Z_]*)'
            r'\s*=\s*["\']?(?P<secret>[^\s"\'#]{4,})["\']?',
            re.MULTILINE,
        ),
        min_entropy=2.5,
        min_length=4,
        tags=["env", "secret"],
        fast_keywords=["SECRET", "TOKEN", "API_KEY", "APIKEY", "AUTH", "CREDENTIAL", "PASSWORD", "PASSWD", "PWD"],
    ))

    # Bearer tokens in code
    rules.append(Rule(
        id="BEARER_TOKEN",
        name="Bearer Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Hardcoded Bearer token in authorization header",
        pattern=re.compile(
            r'(?i)(?:authorization|bearer)\s*[=:]\s*["\']?Bearer\s+(?P<secret>[A-Za-z0-9_.+/=-]{20,})["\']?',
        ),
        min_entropy=3.0,
        min_length=20,
        tags=["token", "bearer"],
        fast_keywords=["bearer"],
    ))

    # Basic auth in URLs
    rules.append(Rule(
        id="BASIC_AUTH_URL",
        name="Credentials in URL",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Username and password embedded in URL",
        pattern=re.compile(
            r'(?P<secret>https?://[^:@\s]+:[^:@\s]+@[^\s"\'<>]+)',
        ),
        min_entropy=1.5,
        context_keywords=["url", "endpoint", "api", "http"],
        tags=["url", "basic_auth"],
        fast_keywords=["://"],
    ))

    # Base64-encoded secrets (long base64 in assignment context)
    rules.append(Rule(
        id="BASE64_SECRET",
        name="Base64-encoded secret value",
        category=Category.GENERIC_SECRET,
        severity=Severity.MEDIUM,
        description="Likely base64-encoded secret in variable assignment",
        pattern=re.compile(
            r'(?i)(?:secret|key|token|password|credential|cert)\s*[=:]\s*["\']?'
            r'(?P<secret>[A-Za-z0-9+/]{40,}={0,2})["\']?',
        ),
        min_entropy=4.0,
        min_length=40,
        tags=["base64", "encoded"],
        fast_keywords=["secret", "key", "token", "password", "credential", "cert"],
    ))

    # -----------------------------------------------------------------------
    # 6. JWT Tokens
    # -----------------------------------------------------------------------
    rules.append(Rule(
        id="JWT_TOKEN",
        name="JWT Token",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="JSON Web Token (may contain sensitive claims)",
        # JWT = base64url(header) + '.' + base64url(payload) + '.' + base64url(sig)
        # base64url is [A-Za-z0-9_-] (NO `.`, `+`, `/`, `=`). The previous
        # signature class allowed `.+/=` which over-greedily swallowed text
        # spanning multiple tokens.
        pattern=re.compile(
            r'(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})',
        ),
        min_entropy=3.0,
        min_length=50,
        check_entropy=False,  # JWTs are structured, entropy check not meaningful
        tags=["jwt", "token"],
        fast_keywords=["eyJ"],
    ))

    # -----------------------------------------------------------------------
    # 7. HASH PATTERNS (found in config files, shadow files, etc.)
    # -----------------------------------------------------------------------

    # Unix shadow hashes
    rules.append(Rule(
        id="UNIX_SHADOW_HASH",
        name="Unix Password Hash",
        category=Category.HASH,
        severity=Severity.CRITICAL,
        description="Unix crypt password hash ($1$, $5$, $6$, $y$, $2a$, $2b$)",
        pattern=re.compile(
            r'(?P<secret>\$(?:1|2[aby]?|5|6|y|argon2[id]?|scrypt)\$[^\s:]{8,})',
        ),
        check_entropy=False,
        min_length=20,
        false_positive_indicators=[],
        tags=["hash", "unix", "shadow"],
        fast_keywords=["$1$", "$2a$", "$2b$", "$2y$", "$5$", "$6$", "$y$", "$argon2", "$scrypt"],
    ))

    # NTLM Hash
    rules.append(Rule(
        id="NTLM_HASH",
        name="NTLM Hash",
        category=Category.HASH,
        severity=Severity.HIGH,
        description="Windows NTLM password hash",
        pattern=re.compile(
            r'(?i)(?:ntlm|hash)\s*[=:]\s*["\']?(?P<secret>[a-f0-9]{32})["\']?',
        ),
        check_entropy=False,
        min_length=32,
        max_length=32,
        tags=["hash", "ntlm", "windows"],
        fast_keywords=["ntlm", "hash"],
    ))

    # -----------------------------------------------------------------------
    # 8. WINDOWS-SPECIFIC PATTERNS
    # -----------------------------------------------------------------------

    # Windows Registry credential
    rules.append(Rule(
        id="WINDOWS_AUTOLOGON",
        name="Windows AutoLogon Credentials",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Windows auto-logon password in registry or config",
        pattern=re.compile(
            r'(?i)(?:DefaultPassword|AutoAdminLogon|DefaultDomainName)\s*[=:]\s*'
            r'["\']?(?P<secret>[^\s"\']{2,})["\']?',
        ),
        check_entropy=False,
        min_length=2,
        tags=["windows", "registry"],
        fast_keywords=["defaultpassword", "autoadminlogon", "defaultdomainname"],
    ))

    # PowerShell SecureString (often not actually secure)
    rules.append(Rule(
        id="POWERSHELL_CREDENTIAL",
        name="PowerShell Credential",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="PowerShell credential or password in script",
        pattern=re.compile(
            r'(?i)ConvertTo-SecureString\s+["\'](?P<secret>[^"\']+)["\']',
        ),
        check_entropy=False,
        tags=["powershell", "windows"],
        fast_keywords=["convertto-securestring"],
    ))

    # -----------------------------------------------------------------------
    # 9. CLOUD / INFRA SPECIFIC
    # -----------------------------------------------------------------------

    # Terraform variables with default secrets
    rules.append(Rule(
        id="TERRAFORM_SECRET",
        name="Terraform Secret Variable",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="Terraform variable with sensitive default value",
        pattern=re.compile(
            r'(?i)(?:default|value)\s*=\s*"(?P<secret>[^"]{8,})"',
        ),
        min_entropy=3.5,
        min_length=8,
        context_keywords=["password", "secret", "key", "token", "credential"],
        tags=["terraform", "iac"],
        fast_keywords=["default", "value"],
    ))

    # Kubernetes Secret (base64 in YAML)
    rules.append(Rule(
        id="K8S_SECRET",
        name="Kubernetes Secret Data",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="Base64-encoded value in Kubernetes Secret manifest",
        pattern=re.compile(
            r'(?i)^\s+(?:password|token|secret|key|cert):\s*(?P<secret>[A-Za-z0-9+/]{16,}={0,2})\s*$',
            re.MULTILINE,
        ),
        min_entropy=3.5,
        context_keywords=["kind: Secret", "kubernetes", "apiVersion"],
        tags=["kubernetes", "k8s"],
        fast_keywords=["password:", "token:", "secret:", "key:", "cert:"],
    ))

    # Docker / docker-compose environment secrets
    rules.append(Rule(
        id="DOCKER_ENV_SECRET",
        name="Docker Environment Secret",
        category=Category.ENV_SECRET,
        severity=Severity.HIGH,
        description="Secret passed as environment variable in Docker config",
        pattern=re.compile(
            r'(?im)^\s*-?\s*(?P<varname>[A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Z_]*)'
            r'\s*=\s*(?P<secret>[^\s"\'#]{4,})',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["docker", "environment", "compose"],
        tags=["docker", "container"],
        fast_keywords=["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL"],
    ))

    # -----------------------------------------------------------------------
    # 10. GENERIC HIGH-ENTROPY SECRETS
    # -----------------------------------------------------------------------
    rules.append(Rule(
        id="GENERIC_HIGH_ENTROPY_SECRET",
        name="High-entropy string in secret context",
        category=Category.GENERIC_SECRET,
        severity=Severity.MEDIUM,
        description="High-entropy string assigned to a secret-like variable name",
        pattern=re.compile(
            r'(?i)(?:secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key|encryption[_-]?key|signing[_-]?key)'
            r'\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9+/_.=-]{16,})["\']?',
        ),
        min_entropy=3.8,
        min_length=16,
        tags=["generic", "high_entropy"],
        fast_keywords=["secret", "api_key", "apikey", "auth_token", "authtoken",
                        "private_key", "privatekey", "access_key", "accesskey",
                        "encryption_key", "signing_key"],
    ))

    # -----------------------------------------------------------------------
    # 11. APPLICATION CONFIG PATTERNS
    # -----------------------------------------------------------------------

    # Django SECRET_KEY
    rules.append(Rule(
        id="DJANGO_SECRET_KEY",
        name="Django SECRET_KEY",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="Django SECRET_KEY setting",
        pattern=re.compile(
            r'(?i)SECRET_KEY\s*=\s*["\'](?P<secret>[^"\']{20,})["\']',
        ),
        min_entropy=3.0,
        min_length=20,
        tags=["django", "python"],
        fast_keywords=["SECRET_KEY"],
    ))

    # Flask secret key
    rules.append(Rule(
        id="FLASK_SECRET_KEY",
        name="Flask Secret Key",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="Flask app secret key",
        pattern=re.compile(
            r'(?i)app\.(?:secret_key|config\[.SECRET_KEY.\])\s*=\s*["\'](?P<secret>[^"\']{8,})["\']',
        ),
        min_entropy=2.5,
        tags=["flask", "python"],
        fast_keywords=["secret_key", "SECRET_KEY"],
    ))

    # Laravel APP_KEY
    rules.append(Rule(
        id="LARAVEL_APP_KEY",
        name="Laravel APP_KEY",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="Laravel application key",
        pattern=re.compile(
            r'(?i)APP_KEY\s*=\s*(?:base64:)?(?P<secret>[A-Za-z0-9+/=]{32,})',
        ),
        min_entropy=3.0,
        tags=["laravel", "php"],
        fast_keywords=["APP_KEY"],
    ))

    # WordPress auth keys/salts (generalized — handles wp-config.php)
    rules.append(Rule(
        id="WORDPRESS_KEY",
        name="WordPress Auth Key/Salt",
        category=Category.GENERIC_SECRET,
        severity=Severity.HIGH,
        description="WordPress authentication key or salt",
        pattern=re.compile(
            r"(?i)define\(\s*['\"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|"
            r"AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]\s*,\s*"
            r"['\"](?P<secret>[^'\"]{10,})['\"]",
        ),
        min_entropy=3.0,
        false_positive_indicators=["put your unique phrase here"],
        tags=["wordpress", "php"],
        fast_keywords=["define("],
    ))

    # =======================================================================
    # 12. EXTENDED PASSWORD PATTERNS — OS / file-format coverage
    # =======================================================================
    #
    # The patterns below extend the generic PASSWORD_ASSIGNMENT with more
    # surface area for specific languages, OSes, and file formats. They are
    # additive: when several rules match the same line and value, the
    # deduper keeps the highest-confidence finding.

    # ── 12.1 Generic structured-format keys ────────────────────────────
    # JSON object key: "password": "value"  /  "passwd": "value"  /  ...
    rules.append(Rule(
        id="PASSWORD_JSON_KEY",
        name="Password in JSON object",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description='JSON property whose key contains a password/secret/credential keyword',
        pattern=re.compile(
            r'(?i)"(?:[\w.-]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|auth[_-]?token|access[_-]?key))'
            r'[\w.-]*"\s*:\s*"(?P<secret>[^"\\]{4,})"',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["password", "secret", "credential", "auth"],
        tags=["password", "json", "config"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "api_key", "apikey", "auth_token", "authtoken", "access_key"],
    ))

    # YAML key with password-ish name (handles `password: value`, list items
    # `- password: value`, indented children, and quoted/unquoted values).
    # `#` is permitted mid-value: YAML treats `#` as a comment only when
    # preceded by whitespace, so `foo#bar` is literal "foo#bar".
    rules.append(Rule(
        id="PASSWORD_YAML_KEY",
        name="Password in YAML key",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="YAML key whose name contains a password/secret keyword",
        pattern=re.compile(
            r'(?im)^\s*-?\s*'
            r'(?P<keyname>[\w.-]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key|signing[_-]?key|encryption[_-]?key)'
            r'[\w.-]*)'
            r'\s*:\s*'
            r'(?:["\'](?P<secret>[^"\'\n]{4,})["\']'
            r'|(?P<secret_unquoted>[^\s"\'\n][^\s\n]{2,}[^\s\n]))'  # no leading ws, ≥4 chars
            r'\s*(?:\s+#[^\n]*)?\s*$',  # optional trailing YAML comment
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["password", "secret", "credential", "auth", "key"],
        tags=["password", "yaml"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "api_key", "apikey", "auth_token", "authtoken",
                       "access_key", "signing_key", "encryption_key"],
    ))

    # TOML password = "value"  (TOML uses # for comments; values are usually
    # quoted, but unquoted basic values are also possible)
    rules.append(Rule(
        id="PASSWORD_TOML_KEY",
        name="Password in TOML key",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="TOML key whose name contains a password/secret keyword",
        pattern=re.compile(
            r'(?im)^\s*'
            r'(?P<keyname>[\w.-]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key)[\w.-]*)'
            r'\s*=\s*'
            r'(?:["\'](?P<secret>[^"\'\n]{4,})["\']'
            r'|(?P<secret_unquoted>[^\s"\'\n][^\s\n]{2,}[^\s\n]))'
            r'\s*(?:\s+#[^\n]*)?\s*$',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "toml"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "api_key", "apikey", "auth_token", "authtoken", "access_key"],
    ))

    # Java .properties / Spring / Hibernate / Quarkus / Micronaut nested keys.
    # Catches db.password=, spring.datasource.password=, jdbc.password=,
    # quarkus.datasource.password=, hibernate.connection.password=, etc.
    rules.append(Rule(
        id="PASSWORD_JAVA_PROPERTIES",
        name="Password in Java .properties / Spring config",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Dotted Java/Spring property key with password value",
        pattern=re.compile(
            r'(?im)^\s*'
            r'(?P<keyname>(?:[\w-]+\.)+'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token))'
            r'\s*=\s*(?P<secret>[^\s#]{4,})',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["spring", "datasource", "hibernate", "quarkus",
                          "micronaut", "jdbc", "db"],
        tags=["password", "java", "properties", "spring"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "api_key", "apikey", "auth_token", "authtoken"],
    ))

    # Function/constructor call with password keyword arg
    # connect(host, port, "user", "password")  /  Login(user="...", password="...")
    rules.append(Rule(
        id="PASSWORD_KWARG",
        name="Password as keyword argument",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Function-call keyword argument whose name contains a password keyword",
        pattern=re.compile(
            r'(?i)(?:[\w.]+\.)*\w*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential)'
            r'\w*\s*=\s*["\'](?P<secret>[^"\'\\]{4,})["\']',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "kwarg", "function_call"],
        fast_keywords=["password", "passwd", "passphrase", "pwd",
                       "secret", "credential"],
    ))

    # Ruby/Perl-style hash literal: :password => "value" / "api_key" => "value"
    rules.append(Rule(
        id="PASSWORD_RUBY_HASH",
        name="Password in Ruby hash / Perl hash literal",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description='Symbol or string hash key like :password => "..." or "api_key" => "..."',
        pattern=re.compile(
            r'(?i)[:\'"](?P<keyname>[\w-]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key|signing[_-]?key)[\w-]*)\'?"?'
            r'\s*=>\s*'
            r'["\'](?P<secret>[^"\'\\]{4,})["\']',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "ruby", "perl"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "api_key", "apikey", "auth_token", "authtoken",
                       "access_key", "signing_key", "=>"],
    ))

    # ── 12.2 Linux / Unix shell idioms ─────────────────────────────────
    # `export PASSWORD=value` / `export PASSWORD="value"`
    rules.append(Rule(
        id="SHELL_EXPORT_PASSWORD",
        name="Shell export with password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="POSIX shell export of a password/credential variable",
        pattern=re.compile(
            r'(?im)^\s*(?:export|declare\s+-x|readonly)\s+'
            r'(?P<varname>[A-Z_]*'
            r'(?:PASS(?:WORD|WD|PHRASE)?|PWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY|'
            r'AUTH|ACCESS[_-]?KEY)[A-Z_]*)'
            r'=\s*'
            r'(?:["\'](?P<secret>[^"\'\n]{3,})["\']'
            r'|(?P<secret_unquoted>[^\s#"\'\n]{3,}))',
        ),
        min_entropy=2.0,
        min_length=3,
        tags=["password", "shell", "linux"],
        fast_keywords=["export ", "declare -x", "readonly "],
    ))

    # `mysql -ppassword` / `mysql --password=value` / `mysqldump -p"..."`
    # Uses lazy `[^\n]*?` to skip over flag-args between the binary name and
    # the password flag (e.g. `mysql -u root -pPASS`).
    rules.append(Rule(
        id="MYSQL_CLI_PASSWORD",
        name="MySQL CLI with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="mysql / mysqldump / mysqladmin invocation with -p<password>",
        pattern=re.compile(
            r'(?i)\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mariadb)\b'
            r'[^\n]*?'                                         # lazy skip over other args
            r'(?:\s-p\s*|\s--password\s*=\s*)'
            r'(?:["\'](?P<secret>[^"\'\s]{2,})["\']'
            r'|(?P<secret_unquoted>[^\s"\']{2,}))',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "mysql", "linux", "command"],
        fast_keywords=["mysql", "mariadb", "mysqldump", "mysqladmin",
                       "mysqlimport", "mysqlshow"],
    ))

    # `psql password=...` connection string and `PGPASSWORD=` env
    rules.append(Rule(
        id="PSQL_CLI_PASSWORD",
        name="PostgreSQL CLI / PGPASSWORD with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="PGPASSWORD=, psql conninfo, or pg_dump with password",
        pattern=re.compile(
            r'(?i)(?:'
            r'\bPGPASSWORD\s*=\s*'
            r'|\b(?:psql|pg_dump|pg_dumpall|pg_restore)\b[^\n]*?\bpassword\s*=\s*'
            r')'
            r'(?:["\'](?P<secret>[^"\'\s]{2,})["\']'
            r'|(?P<secret_unquoted>[^\s"\';]{2,}))',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "postgresql", "linux", "command"],
        fast_keywords=["pgpassword", "psql", "pg_dump", "pg_restore"],
    ))

    # `sshpass -p "password" ssh ...` / `sshpass -p<pass>`
    rules.append(Rule(
        id="SSHPASS_PASSWORD",
        name="sshpass with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="sshpass invoked with -p / -e and an inline password",
        pattern=re.compile(
            r'(?i)\bsshpass\s+-p\s*'
            r'(?:["\'](?P<secret>[^"\'\s]{2,})["\']'
            r'|(?P<secret_unquoted>[^\s"\']{2,}))',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "ssh", "linux", "command"],
        fast_keywords=["sshpass"],
    ))

    # `curl -u user:password` / `curl --user user:pass` / wget --password=
    rules.append(Rule(
        id="CURL_BASIC_AUTH",
        name="curl/wget basic-auth credential",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="curl or wget invocation with inline basic-auth credentials",
        pattern=re.compile(
            r'(?i)\b(?:curl|wget)\b[^\n]*?'
            r'(?:'
            r'(?:-u\s+|--user\s+|--user=)'
            r'(?:["\'](?P<secret>[^"\':\s]+:[^"\'\s]+)["\']'
            r'|(?P<secret_unquoted>[^\s"\':]+:[^\s"\']+))'
            r'|--password[=\s]+'
            r'(?:["\'](?P<secret2>[^"\'\s]{2,})["\']'
            r'|(?P<secret2_unquoted>[^\s"\']{2,}))'
            r')',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        tags=["password", "curl", "wget", "linux", "command"],
        fast_keywords=["curl ", "wget "],
    ))

    # systemd unit Environment= / EnvironmentFile=
    rules.append(Rule(
        id="SYSTEMD_PASSWORD",
        name="Password in systemd unit Environment=",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="systemd unit file Environment= with password/secret value",
        pattern=re.compile(
            r'(?im)^\s*Environment\s*=\s*"?'
            r'(?P<varname>[A-Z_]*'
            r'(?:PASS(?:WORD|WD|PHRASE)?|PWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)'
            r'[A-Z_]*)'
            r'=(?P<secret>[^\s"]{3,})"?',
        ),
        min_entropy=2.0,
        min_length=3,
        tags=["password", "systemd", "linux"],
        fast_keywords=["environment="],
    ))

    # `expect` script: send "password\r" right after a Password: prompt
    rules.append(Rule(
        id="EXPECT_PASSWORD",
        name="Expect script send password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Expect/TCL script issuing a password via send",
        pattern=re.compile(
            r'(?i)\bsend\s+"(?P<secret>[^"\\]{3,}?)\\[rn]+"',
        ),
        min_entropy=2.0,
        min_length=3,
        context_keywords=["expect", "spawn", "password"],
        tags=["password", "expect", "linux"],
        fast_keywords=["send "],
    ))

    # /etc/passwd-style chpasswd / useradd inline password
    rules.append(Rule(
        id="CHPASSWD_PASSWORD",
        name="chpasswd / useradd inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="chpasswd batch entry or useradd -p with inline password",
        pattern=re.compile(
            r'(?i)(?:'
            r'\buseradd\s+(?:[^\s\-]+\s+)*-p\s+["\']?(?P<secret>[^"\'\s]{2,})["\']?'
            r'|\bchpasswd\b[^\n]*?<<<\s*["\']?[^:]+:(?P<secret2>[^\s"\']{2,})["\']?'
            r'|\becho\s+["\']?[^:]+:(?P<secret3>[^\s"\']{2,})["\']?\s*\|\s*chpasswd'
            r')',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "linux", "command"],
        fast_keywords=["useradd", "chpasswd"],
    ))

    # OpenVPN auth-user-pass file format (when the inline file form is used)
    # auth-user-pass <<EOF\nusername\npassword\nEOF
    rules.append(Rule(
        id="OPENVPN_INLINE_PASSWORD",
        name="OpenVPN inline auth-user-pass",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="OpenVPN config with inline <auth-user-pass> credentials",
        pattern=re.compile(
            r'(?is)<auth-user-pass>\s*\n[^\n]*\n(?P<secret>[^\n<]{3,})\s*\n</auth-user-pass>',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        tags=["password", "openvpn", "vpn"],
        fast_keywords=["<auth-user-pass>"],
        multiline=True,
    ))

    # /etc/shadow-like row in arbitrary file: user:$6$...:::
    # (already covered by UNIX_SHADOW_HASH for the hash itself; this catches
    # the colon-delimited format specifically.)
    # → no new rule, UNIX_SHADOW_HASH is sufficient.

    # ── 12.3 Windows-specific idioms ───────────────────────────────────
    # PowerShell variable: $password = "..."  /  $script:DBPass = '...'
    rules.append(Rule(
        id="POWERSHELL_VAR_PASSWORD",
        name="PowerShell password variable assignment",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="PowerShell `$variable = '...'` whose name contains a password keyword",
        pattern=re.compile(
            r'(?i)\$(?:script:|global:|local:|private:|env:)?'
            r'(?P<varname>[\w]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key)[\w]*)'
            r'\s*=\s*'
            r'(?:["\'](?P<secret>[^"\'\n]{4,})["\']'
            r'|(?P<secret_unquoted>[^\s#;|`)\n]{4,}))',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "powershell", "windows"],
        fast_keywords=["$"],
    ))

    # PowerShell New-Object PSCredential with both args inline
    rules.append(Rule(
        id="POWERSHELL_PSCREDENTIAL_INLINE",
        name="PowerShell PSCredential with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="New-Object PSCredential with literal username and ConvertTo-SecureString password",
        pattern=re.compile(
            r'(?i)New-Object\s+(?:System\.Management\.Automation\.)?PSCredential'
            r'\s*\(\s*["\'][^"\']+["\']\s*,\s*'
            r'\(\s*ConvertTo-SecureString\s+["\'](?P<secret>[^"\'\n]+)["\']',
        ),
        min_entropy=1.5,
        min_length=2,
        check_entropy=False,
        tags=["password", "powershell", "windows"],
        fast_keywords=["pscredential", "convertto-securestring"],
    ))

    # Batch: SET PASSWORD=foo  (with or without quotes, including `set "PWD=foo"`)
    rules.append(Rule(
        id="BATCH_SET_PASSWORD",
        name="Batch SET with password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Windows batch SET assigning a password-like environment variable",
        pattern=re.compile(
            r'(?im)^\s*set\s+"?(?P<varname>[A-Z_]*'
            r'(?:PASS(?:WORD|WD|PHRASE)?|PWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY|'
            r'AUTH|ACCESS[_-]?KEY)[A-Z_]*)'
            r'=(?P<secret>[^"\n]{3,})"?\s*$',
        ),
        min_entropy=1.5,
        min_length=3,
        tags=["password", "batch", "windows"],
        fast_keywords=["set ", "set\t"],
    ))

    # cmdkey: cmdkey /add:<target> /user:<user> /pass:<password>
    rules.append(Rule(
        id="CMDKEY_PASSWORD",
        name="cmdkey with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Windows cmdkey command storing plaintext credentials",
        pattern=re.compile(
            r'(?i)\bcmdkey\b[^\n]*?'
            r'/(?:pass|smartcard|password)\s*:\s*'
            r'["\']?(?P<secret>[^"\'\s/]{2,})["\']?',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "windows", "command"],
        fast_keywords=["cmdkey"],
    ))

    # PsExec / paexec inline -p
    rules.append(Rule(
        id="PSEXEC_PASSWORD",
        name="PsExec/paexec with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="PsExec, paexec, or psexec.py invocation with -p password",
        pattern=re.compile(
            r'(?i)\b(?:psexec(?:\.exe|\.py)?|paexec)\b[^\n]*?'
            r'\s-p\s+["\']?(?P<secret>[^"\'\s]{2,})["\']?',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "windows", "command", "lateral_movement"],
        fast_keywords=["psexec", "paexec"],
    ))

    # WMIC /password: argument
    rules.append(Rule(
        id="WMIC_PASSWORD",
        name="WMIC /password: argument",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="WMIC remote invocation with inline /password:",
        pattern=re.compile(
            r'(?i)\bwmic\b[^\n]*?/password\s*:\s*'
            r'["\']?(?P<secret>[^"\'\s/]{2,})["\']?',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "windows", "command", "lateral_movement"],
        fast_keywords=["wmic"],
    ))

    # net use — handle every common positional/flagged form:
    #   1.  net use \\srv\share PASSWORD /user:DOM\user
    #   2.  net use X:  \\srv\share PASSWORD /user:DOM\user
    #   3.  net use \\srv\share /user:DOM\user PASSWORD
    #   4.  net use X:  \\srv\share /user:DOM\user PASSWORD
    #   5.  net use X:  \\srv\share PASSWORD                     (no /user:)
    #   6.  net use X:  \\srv\share USER PASSWORD                (positional)
    #   7.  net use X:  V\fs01\backups USER PASSWORD             (typo'd path)
    rules.append(Rule(
        id="NET_USE_PASSWORD",
        name="net use with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Windows `net use` command with inline password (any positional form)",
        pattern=re.compile(
            r'(?i)\bnet\s+use\b'
            r'(?:'
            # Form A: password is the token immediately before /user:
            # The captured secret must not look like a UNC path or a drive letter,
            # so we won't false-flag the share name when /user: follows it.
            r'[^\n]*?\s(?P<secret>(?!\\)(?![A-Za-z]:\s)[^\s/]{3,})\s+/user:'
            r'|'
            # Form B: /user:DOM\user followed (eventually) by the password
            r'[^\n]*?/user:\S+\s+'
            r'(?:\S+\s+)*?'
            r'(?P<secret_after>(?!\\)[^\s/:][^\s/:]{2,})\s*$'
            r'|'
            # Form C: pure-positional. After "net use" we eat the drive/path
            # (and optionally a username) and capture the trailing password.
            # Excludes UNC paths (start with \\), flags (start with /), and
            # the "*" prompt placeholder. Requires ≥2 prior tokens so a bare
            # "net use \\share" doesn't trigger.
            r'\s+\S+(?:\s+\S+)+\s+'
            r'(?P<secret_pos>(?!\\)(?!/)[^\s][^\s]{3,})\s*$'
            r')',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=True,
        false_positive_indicators=[],
        context_keywords=["net use", "user", "password"],
        tags=["password", "windows", "command"],
        fast_keywords=["net use"],
    ))

    # runas /user:... with credential or savecred (less directly extractable
    # but flag the form)
    rules.append(Rule(
        id="RUNAS_USER",
        name="runas /user invocation",
        category=Category.PASSWORD,
        severity=Severity.MEDIUM,
        description="Windows runas /user — flag for review (saved credential reuse)",
        pattern=re.compile(
            r'(?i)\brunas\s+(?:/savecred\s+)?/user:(?P<secret>[^\s]+)',
        ),
        min_entropy=0.0,
        min_length=2,
        check_entropy=False,
        tags=["windows", "command", "lateral_movement"],
        fast_keywords=["runas"],
    ))

    # Group Policy Preferences cpassword (reversibly encrypted MS04 known key)
    rules.append(Rule(
        id="GPP_CPASSWORD",
        name="Group Policy Preferences cpassword",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="GPP cpassword attribute — reversibly decryptable with the published Microsoft key",
        pattern=re.compile(
            r'(?i)\bcpassword\s*=\s*"(?P<secret>[A-Za-z0-9+/=]{16,})"',
        ),
        min_entropy=3.0,
        min_length=16,
        check_entropy=True,
        false_positive_indicators=[],
        tags=["password", "windows", "gpp", "domain"],
        fast_keywords=["cpassword"],
    ))

    # Task Scheduler XML export: <Password>...</Password> nested under <UserId>
    rules.append(Rule(
        id="TASK_SCHEDULER_PASSWORD",
        name="Task Scheduler XML password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Scheduled-task XML export with embedded <Password> element (service account)",
        pattern=re.compile(
            # <UserId> followed (within the same Principal block) by <Password>
            r'(?is)<UserId>[^<]+</UserId>'
            r'(?:(?!</?Principal\b).){0,2000}?'  # any chars up to the closing Principal
            r'<Password>\s*(?P<secret>[^<]{2,})\s*</Password>',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=True,
        false_positive_indicators=[],
        tags=["password", "windows", "scheduledtask"],
        fast_keywords=["<password>"],
        multiline=True,
    ))

    # .reg file: "DefaultPassword"="..." or "Password"="..."  (covered by
    # WINDOWS_AUTOLOGON for AutoLogon, but flag generic "Password" entries).
    rules.append(Rule(
        id="REG_FILE_PASSWORD",
        name="Password in .reg export",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Windows .reg export with a Password value",
        pattern=re.compile(
            r'(?i)"(?:[^"]*'
            r'(?:password|passwd|pwd|secret|credential|auth_?token)'
            r'[^"]*)"\s*=\s*"(?P<secret>[^"]{3,})"',
        ),
        min_entropy=2.0,
        min_length=3,
        tags=["password", "windows", "registry"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential", "auth"],
    ))

    # WinSCP.ini SessionPassword (encrypted) — flag for triage
    rules.append(Rule(
        id="WINSCP_SESSION_PASSWORD",
        name="WinSCP saved session password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="WinSCP.ini saved session password (proprietary obfuscation, decryptable)",
        pattern=re.compile(
            r'(?im)^\s*Password\s*=\s*(?P<secret>[A-Fa-f0-9]{8,})\s*$',
        ),
        min_entropy=2.5,
        min_length=8,
        check_entropy=False,
        context_keywords=["winscp", "session", "hostname"],
        tags=["password", "windows", "winscp"],
        fast_keywords=["password="],
    ))

    # ── 12.4 SQL: CREATE/ALTER USER, GRANT, COPY WITH PASSWORD ─────────
    # CREATE USER 'name'@'host' IDENTIFIED BY 'pass'  (MySQL/MariaDB)
    # CREATE USER name WITH PASSWORD 'pass'           (PostgreSQL)
    # CREATE LOGIN name WITH PASSWORD = N'pass'       (MSSQL)
    rules.append(Rule(
        id="SQL_CREATE_USER_PASSWORD",
        name="SQL CREATE USER with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="CREATE USER / CREATE LOGIN / CREATE ROLE statement with literal password",
        pattern=re.compile(
            r'(?is)\bCREATE\s+(?:USER|LOGIN|ROLE)\s+[^\s;]+'
            r'[^\n;]*?'
            r'(?:IDENTIFIED\s+(?:BY|WITH\s+\w+\s+AS)\s+|WITH\s+PASSWORD\s*=?\s*N?|PASSWORD\s+)'
            r"['\"](?P<secret>[^'\";\n]{3,})['\"]",
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "sql", "database"],
        fast_keywords=["create user", "create login", "create role"],
    ))

    # ALTER USER ... IDENTIFIED BY '...'  /  ALTER USER ... PASSWORD '...'
    # ALTER LOGIN ... WITH PASSWORD = ...
    # ALTER ROLE ... WITH PASSWORD '...'
    rules.append(Rule(
        id="SQL_ALTER_USER_PASSWORD",
        name="SQL ALTER USER/LOGIN with inline password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="ALTER USER / ALTER LOGIN / ALTER ROLE statement with literal password",
        pattern=re.compile(
            r'(?is)\bALTER\s+(?:USER|LOGIN|ROLE)\s+[^\s;]+'
            r'[^\n;]*?'
            r'(?:IDENTIFIED\s+(?:BY|WITH\s+\w+\s+AS)\s+|WITH\s+PASSWORD\s*=?\s*N?|PASSWORD\s+)'
            r"['\"](?P<secret>[^'\";\n]{3,})['\"]",
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "sql", "database"],
        fast_keywords=["alter user", "alter login", "alter role"],
    ))

    # GRANT ... IDENTIFIED BY '...'  (legacy MySQL)
    rules.append(Rule(
        id="SQL_GRANT_PASSWORD",
        name="SQL GRANT with IDENTIFIED BY password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="MySQL GRANT statement with inline IDENTIFIED BY password",
        pattern=re.compile(
            r"(?is)\bGRANT\b[^;]+?\bIDENTIFIED\s+BY\s+['\"](?P<secret>[^'\";\n]{3,})['\"]",
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "sql", "mysql"],
        fast_keywords=["grant ", "identified by"],
    ))

    # SET PASSWORD FOR 'user'@'host' = ...
    rules.append(Rule(
        id="SQL_SET_PASSWORD",
        name="SQL SET PASSWORD",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="SET PASSWORD statement",
        pattern=re.compile(
            r"(?is)\bSET\s+PASSWORD\s+(?:FOR\s+[^\s=]+\s*)?=\s*"
            r"(?:PASSWORD\(\s*['\"](?P<secret>[^'\"]{3,})['\"]\s*\)"
            r"|['\"](?P<secret2>[^'\";]{3,})['\"])",
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "sql"],
        fast_keywords=["set password"],
    ))

    # ── 12.5 Other config-file formats ────────────────────────────────
    # .pgpass: hostname:port:database:username:password
    # Each field follows libpq grammar — no whitespace, no slashes, no `@`,
    # and the port is numeric or `*`. This rules out URL-shaped lines like
    # `postgres://admin:secret@host:5432/db`, log timestamps, etc.
    rules.append(Rule(
        id="PGPASS_LINE",
        name=".pgpass entry",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="PostgreSQL .pgpass-format line: host:port:db:user:password",
        pattern=re.compile(
            r'(?m)^'
            r'(?P<host>[^\s#:/@\n]+):'                # hostname (or *)
            r'(?P<port>\*|\d{1,5}):'                   # numeric port or *
            r'(?P<db>[^\s:/@\n]+):'                    # database (or *)
            r'(?P<user>[^\s:/@\n]+):'                  # username
            r'(?P<secret>[^\s:\n]{2,})'                # password (no whitespace/colon)
            r'\s*$',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        context_keywords=["pgpass", "postgres", "postgresql", "psql"],
        tags=["password", "postgresql", "linux"],
        # Pre-filter on a literal substring that nearly all real .pgpass lines have:
        # at least one ':' AND something postgres-related nearby. We can't easily
        # require "postgres" in the line itself (real .pgpass files don't), so we
        # require the line have at least 4 colons in addition to ':' fast-key.
        fast_keywords=[":"],
    ))

    # .htpasswd: user:hash (only flags the hash; real catch is the file
    # itself via filename-pattern, but we still want to score the line).
    rules.append(Rule(
        id="HTPASSWD_LINE",
        name="Apache htpasswd entry",
        category=Category.HASH,
        severity=Severity.CRITICAL,
        description="Apache htpasswd entry: user:hash",
        pattern=re.compile(
            r'(?m)^(?P<user>[^:\s#][^:\s]*)\s*:\s*'
            r'(?P<secret>(?:'
            r'\$(?:apr1|2a|2b|2y|5|6|y)\$[^\s:]{8,}'  # bcrypt/MD5/SHA-512 crypt
            r'|\{SHA\}[A-Za-z0-9+/=]{20,}'             # ldap-style SHA1
            r'|[A-Za-z0-9./]{13}'                      # legacy DES (13 chars)
            r'))',
        ),
        min_entropy=2.0,
        min_length=13,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["hash", "apache", "htpasswd"],
        fast_keywords=["$apr1$", "$2a$", "$2b$", "$2y$", "$5$", "$6$",
                       "{SHA}"],
    ))

    # Maven settings.xml: <password>plaintext</password>
    # (Already partly covered by PASSWORD_XML_ELEMENT — kept distinct for
    # the higher confidence boost when the surrounding <server> block is
    # nearby.)
    rules.append(Rule(
        id="MAVEN_PASSWORD",
        name="Maven settings.xml server password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Maven <server><password>...</password></server> credential",
        pattern=re.compile(
            r'(?is)<server>\s*(?:<[^>]+>\s*[^<]*\s*</[^>]+>\s*)*'
            r'<password>\s*(?P<secret>[^<]{4,})\s*</password>',
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["maven", "server", "repository"],
        tags=["password", "maven", "java"],
        fast_keywords=["<server>"],
        multiline=True,
    ))

    # .NET <add key="...Password..." value="..." /> in app.config / web.config
    rules.append(Rule(
        id="DOTNET_APPSETTING_PASSWORD",
        name=".NET appSettings password key",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description='<add key="...Password..." value="..." /> in app.config / web.config',
        pattern=re.compile(
            r'(?is)<add\s+key\s*=\s*"[^"]*'
            r'(?:password|passwd|pwd|secret|credential|api[_-]?key|auth[_-]?token)'
            r'[^"]*"\s+value\s*=\s*"(?P<secret>[^"]{3,})"',
        ),
        min_entropy=2.0,
        min_length=3,
        tags=["password", "dotnet", "windows", "xml"],
        fast_keywords=["<add ", "<add\t"],
    ))

    # .NET <connectionString name="..." connectionString="...Password=...;" />
    rules.append(Rule(
        id="DOTNET_CONNECTIONSTRING_ELEMENT",
        name=".NET connectionStrings element with password",
        category=Category.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="<add ... connectionString=\"...Password=...\" /> in .NET config",
        pattern=re.compile(
            r'(?is)<add\s+name\s*=\s*"[^"]+"\s+connectionString\s*=\s*"'
            r'(?P<secret>[^"]*(?:password|pwd)\s*=[^"]+)"',
        ),
        min_entropy=2.0,
        min_length=8,
        tags=["password", "dotnet", "windows", "connection_string"],
        fast_keywords=["connectionstring"],
    ))

    # Gradle: signing.password=, mavenPassword= , RELEASE_STORE_PASSWORD=
    rules.append(Rule(
        id="GRADLE_PASSWORD",
        name="Gradle signing/repo password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Gradle property/file for signing or maven-repository password",
        pattern=re.compile(
            r'(?im)^\s*'
            r'(?P<keyname>(?:signing|maven|repo|release|store|keystore|nexus|artifactory|sonatype)'
            r'[\w.]*'
            r'(?:[Pp]assword|[Pp]asswd|[Pp]wd|[Ss]ecret|[Tt]oken|[Cc]redential))'
            r'\s*=\s*(?P<secret>[^\s#]{4,})',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "gradle", "java"],
        fast_keywords=["signing", "maven", "repo", "release", "store",
                       "keystore", "nexus", "artifactory", "sonatype"],
    ))

    # ── 12.6 Generic catch-alls (lower severity, looser patterns) ─────
    # CLI -P (capital P) used by some tools (mongo, redis-cli)
    rules.append(Rule(
        id="REDIS_MONGO_PASSWORD",
        name="Redis/Mongo CLI password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="redis-cli / mongo / mongosh inline password",
        pattern=re.compile(
            r'(?i)\b(?:redis-cli|mongo(?:sh)?|mongoexport|mongodump|mongorestore)\b'
            r'[^\n]*?'
            r'(?:-a\s+|--password\s*=?\s*|-p\s+)'
            r'(?:["\'](?P<secret>[^"\'\s]{2,})["\']'
            r'|(?P<secret_unquoted>[^\s"\']{2,}))',
        ),
        min_entropy=1.0,
        min_length=2,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "redis", "mongo", "linux", "command"],
        fast_keywords=["redis-cli", "mongo", "mongosh",
                       "mongoexport", "mongodump", "mongorestore"],
    ))

    # ftp -u user:pass@host  /  ftp user pass via stdin
    rules.append(Rule(
        id="FTP_INLINE_PASSWORD",
        name="FTP inline credential",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="FTP/lftp/sftp invocation with inline -u user:password",
        pattern=re.compile(
            r'(?i)\b(?:lftp|ftp)\b[^\n]*?'
            r'-u\s+(?P<secret>[^\s,]+,[^\s]+)',
        ),
        min_entropy=1.5,
        min_length=4,
        check_entropy=False,
        tags=["password", "ftp", "linux", "command"],
        fast_keywords=["lftp", "ftp "],
    ))

    # =======================================================================
    # 13. EXTRA REAL-WORLD PATTERNS (CTF / HTB / pentest gold mines)
    # =======================================================================

    # JS/TS object literal with UNQUOTED key (very common in JS/TS source).
    # The PASSWORD_JSON_KEY rule requires `"password"` (quoted). Real JS uses
    # unquoted keys: `{ password: 'foo' }`, `{ apiKey: "bar" }`. Quoted-key
    # values don't double-trigger because the leading char class excludes `"`.
    rules.append(Rule(
        id="PASSWORD_JS_UNQUOTED_KEY",
        name="Password in JS/TS object literal (unquoted key)",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="JavaScript/TypeScript object literal with unquoted password-style key",
        pattern=re.compile(
            r'(?i)(?:^|[\s,{(\[])'                              # start, ws, or block opener
            r'(?P<keyname>[a-z_$][\w$]*'
            r'(?:[Pp]ass(?:word|wd|phrase)?|[Pp]wd|[Ss]ecret|[Cc]redential|'
            r'[Aa]pi[_-]?[Kk]ey|[Aa]uth[_-]?[Tt]oken|[Aa]ccess[_-]?[Kk]ey|'
            r'[Cc]lient[_-]?[Ss]ecret)[\w$]*)'
            r'\s*:\s*'
            r'["\'`](?P<secret>[^"\'`\\\n]{4,})["\'`]',         # backticks too (template literals)
        ),
        min_entropy=2.0,
        min_length=4,
        context_keywords=["password", "secret", "credential", "auth", "key", "config"],
        tags=["password", "javascript", "typescript", "object_literal"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "apikey", "api_key", "auth_token", "authtoken",
                       "access_key", "client_secret", "clientsecret"],
    ))

    # HTTP `Authorization: Basic <base64>` headers.
    # Decoded base64 contains `user:pass`, but we only flag the encoded form
    # so the user can decode and validate manually.
    rules.append(Rule(
        id="HTTP_BASIC_AUTH_HEADER",
        name="HTTP Basic Auth header (base64)",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Authorization: Basic <base64> header (decode for credentials)",
        pattern=re.compile(
            r'(?i)Authorization\s*:\s*Basic\s+(?P<secret>[A-Za-z0-9+/=]{8,})',
        ),
        min_entropy=2.5,
        min_length=8,
        context_keywords=["authorization", "basic", "header", "request"],
        tags=["password", "http", "basic_auth", "header"],
        fast_keywords=["authorization", "basic"],
    ))

    # FTP/SFTP/SCP URL with embedded credentials. BASIC_AUTH_URL only matched
    # http(s); these schemes are extremely common in pentests, especially on
    # legacy Windows boxes and HTB pwn boxes.
    rules.append(Rule(
        id="NON_HTTP_AUTH_URL",
        name="FTP / SFTP / SCP URL with credentials",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Non-HTTP URL with user:password embedded in the authority",
        pattern=re.compile(
            r'(?P<secret>(?:ftp|ftps|sftp|scp|smb|cifs|svn(?:\+ssh)?|git(?:\+ssh|\+https)?)'
            r'://[^:@\s]+:[^:@\s]+@[^\s"\'<>]+)',
            re.IGNORECASE,
        ),
        min_entropy=1.5,
        context_keywords=["url", "remote", "endpoint"],
        tags=["url", "basic_auth", "ftp", "smb"],
        fast_keywords=["://"],
    ))

    # Ansible Vault encrypted blob — distinctive header line.
    rules.append(Rule(
        id="ANSIBLE_VAULT_BLOB",
        name="Ansible Vault encrypted blob",
        category=Category.GENERIC_SECRET,
        severity=Severity.CRITICAL,
        description="$ANSIBLE_VAULT;1.x;AES256 — encrypted secret blob (review for vault password reuse)",
        pattern=re.compile(
            r'(?P<secret>\$ANSIBLE_VAULT;\d+\.\d+;AES256(?:;[\w-]+)?)',
        ),
        check_entropy=False,
        line_match=True,
        false_positive_indicators=[],
        tags=["ansible", "vault", "encrypted"],
        fast_keywords=["$ANSIBLE_VAULT"],
    ))

    # SSH passphrase prompt in scripts: `ssh-keygen ... -N "passphrase"`,
    # `ssh-keygen -p -P old -N new ...`
    rules.append(Rule(
        id="SSH_KEYGEN_PASSPHRASE",
        name="ssh-keygen with inline passphrase",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="ssh-keygen invocation with -N (new passphrase) or -P (old passphrase)",
        pattern=re.compile(
            r'(?i)\bssh-keygen\b[^\n]*?'
            r'\s-(?P<flag>[NP])\s+'
            r'(?:["\'](?P<secret>[^"\'\n]*)["\']'
            r'|(?P<secret_unquoted>[^\s"\']+))',
        ),
        min_entropy=1.0,
        min_length=0,                                 # empty -N "" still notable
        check_entropy=False,
        tags=["password", "ssh", "linux", "command"],
        fast_keywords=["ssh-keygen"],
    ))

    # Windows runas with password (`runas /user:DOM\u /noprofile passwordvalue`)
    # Plus the rarer `psexec.py user:pass@host` Impacket form.
    rules.append(Rule(
        id="IMPACKET_USER_PASS",
        name="Impacket-style user:pass@host",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Impacket / Python-style user:password@host argument",
        pattern=re.compile(
            r'(?i)\b(?:psexec|wmiexec|smbexec|atexec|dcomexec|smbclient|'
            r'crackmapexec|cme|nxc|netexec|impacket-\w+)(?:\.py)?\b[^\n]*?\s'
            r'(?P<secret>[A-Za-z0-9._\\-]+/[A-Za-z0-9._\\-]+:'
            r'[^\s@/\\:]{2,}@[^\s/]+)',
        ),
        min_entropy=1.5,
        min_length=6,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "windows", "command", "lateral_movement", "impacket"],
        fast_keywords=["psexec", "wmiexec", "smbexec", "atexec",
                       "smbclient", "crackmapexec", "netexec",
                       "impacket"],
    ))

    # Maven master password (settings-security.xml: `<master>{...}</master>`)
    rules.append(Rule(
        id="MAVEN_MASTER_PASSWORD",
        name="Maven master password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Maven settings-security.xml master password block",
        pattern=re.compile(
            r'(?is)<master>\s*\{(?P<secret>[A-Za-z0-9+/=]{12,})\}\s*</master>',
        ),
        min_entropy=2.5,
        min_length=12,
        false_positive_indicators=[],
        tags=["password", "maven", "java"],
        fast_keywords=["<master>"],
        multiline=True,
    ))

    # Hadoop core-site.xml / hbase-site.xml `<value>password</value>`
    # nested under property name=*password*
    rules.append(Rule(
        id="HADOOP_PROPERTY_PASSWORD",
        name="Hadoop XML property password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Hadoop-style XML <property> with password-like name and inline value",
        pattern=re.compile(
            r'(?is)<property>\s*'
            r'<name>\s*(?P<keyname>[\w.-]*'
            r'(?:password|passwd|pwd|secret|credential)[\w.-]*)\s*</name>\s*'
            r'<value>\s*(?P<secret>[^<]{3,})\s*</value>',
        ),
        min_entropy=1.5,
        min_length=3,
        false_positive_indicators=[],
        tags=["password", "hadoop", "xml"],
        fast_keywords=["<property>", "<name>"],
        multiline=True,
    ))

    # PHP variable assignment: `$var = "..."` where var contains password keyword.
    # Catches `$db_password = "..."`, `$DBPassword = "..."`, etc. Distinct from
    # PASSWORD_KWARG because PHP heredocs and complex expressions may mismatch.
    rules.append(Rule(
        id="PHP_VAR_PASSWORD",
        name="PHP password variable assignment",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="PHP `$variable = '...';` whose name contains a password keyword",
        pattern=re.compile(
            r'(?i)\$(?P<varname>[\w]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key|client[_-]?secret)[\w]*)'
            r'\s*=\s*'
            r'(?:["\'](?P<secret>[^"\'\\\n]{4,})["\'])'
            r'\s*;?',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "php"],
        fast_keywords=["$", "password", "passwd", "pwd", "secret",
                       "credential", "client_secret"],
    ))

    # C / C++ / C# / Java / Go / Rust string literal with password keyword.
    # `string password = "secret"` — covers most typed languages.
    rules.append(Rule(
        id="TYPED_LANG_PASSWORD",
        name="Typed-language password variable",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Typed-language declaration assigning a password literal "
                    "(C / C++ / C# / Java / Go / Rust / Kotlin / Swift)",
        pattern=re.compile(
            r'(?i)\b(?:'
            r'(?:public|private|protected|internal|static|final|const|let|var|val|'
            r'readonly|String|string|char|wchar_t|TCHAR|CHAR\*?)\s+)+'
            r'(?P<varname>[\w]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'auth[_-]?token|access[_-]?key|client[_-]?secret)[\w]*)'
            r'\s*(?:=|:)\s*'
            r'(?:[Ll]"|@"|"|\'|`)(?P<secret>[^"\'\n`]{4,})(?:"|\'|`)',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "typed_language"],
        fast_keywords=["password", "passwd", "pwd", "secret", "credential",
                       "client_secret"],
    ))

    # Redis AUTH / requirepass directive in redis.conf
    rules.append(Rule(
        id="REDIS_REQUIREPASS",
        name="Redis requirepass / AUTH",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Redis configuration `requirepass` or in-script AUTH command",
        pattern=re.compile(
            r'(?im)^\s*(?:requirepass|masterauth)\s+'
            r'["\']?(?P<secret>[^\s"\'#]{3,})["\']?',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "redis"],
        fast_keywords=["requirepass", "masterauth"],
    ))

    # MongoDB role / SCRAM credential in shell scripts:
    # `db.createUser({ user: "...", pwd: "secret", roles: [...] })`
    rules.append(Rule(
        id="MONGO_CREATEUSER_PWD",
        name="MongoDB createUser with pwd",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="MongoDB createUser / updateUser invocation with inline pwd",
        pattern=re.compile(
            r'(?is)\bdb(?:\.\w+)?\.(?:createUser|updateUser)\s*\([^)]*?'
            r'\bpwd\s*:\s*["\'](?P<secret>[^"\']{3,})["\']',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "mongodb"],
        fast_keywords=["createuser", "updateuser"],
    ))

    # Splunk `bind_password = ...` (LDAP auth in authorize.conf)
    rules.append(Rule(
        id="LDAP_BIND_PASSWORD",
        name="LDAP bind password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="LDAP / AD bind password in app config (Splunk, Jenkins, etc.)",
        pattern=re.compile(
            r'(?im)^\s*(?:bind[_-]?(?:password|pw)|ldap[_.-]?(?:password|pw))'
            r'\s*=\s*["\']?(?P<secret>[^"\'\s#]{3,})["\']?',
        ),
        min_entropy=1.5,
        min_length=3,
        tags=["password", "ldap", "ad"],
        fast_keywords=["bind_password", "bind-password", "bindpassword",
                       "ldap_password", "ldap-password", "ldap.password",
                       "bind_pw"],
    ))

    # SMB / CIFS mount in /etc/fstab or scripts:
    #   `mount -t cifs //srv/share -o username=u,password=p,dom=...`
    #   `//srv/share /mnt cifs username=u,password=p ...`
    rules.append(Rule(
        id="CIFS_MOUNT_PASSWORD",
        name="CIFS / SMB mount password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="CIFS / SMB mount line with inline password=",
        pattern=re.compile(
            r'(?i)(?:^|[\s,])password\s*=\s*'
            r'(?P<secret>[^\s,#"\']{3,})'
            r'(?=[\s,#].*?(?:cifs|smb|//\S+/\S+|guest|domain\s*=|workgroup))'
            r'|(?:cifs|smb)[^\n]*?[\s,]password\s*=\s*'
            r'(?P<secret2>[^\s,#"\']{3,})',
        ),
        min_entropy=1.5,
        min_length=3,
        check_entropy=False,
        tags=["password", "cifs", "smb", "linux"],
        fast_keywords=["cifs", "smb", "password=", "//"],
    ))

    # OpenLDAP / LDIF userPassword line: `userPassword: <hash>` or
    # `userPassword:: <base64>` (binary attribute).
    rules.append(Rule(
        id="LDIF_USERPASSWORD",
        name="LDIF userPassword attribute",
        category=Category.HASH,
        severity=Severity.CRITICAL,
        description="LDIF userPassword: hash or base64-encoded password",
        pattern=re.compile(
            r'(?im)^\s*userPassword\s*::\s*(?P<secret>[A-Za-z0-9+/=]{8,})\s*$'
            r'|^\s*userPassword\s*:\s*(?P<secret2>\S{4,})\s*$',
        ),
        min_entropy=2.0,
        min_length=4,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["hash", "ldap", "ldif"],
        fast_keywords=["userpassword"],
    ))

    # Stored Outlook IMAP/SMTP / Thunderbird inbox config (rare but seen):
    #   `imap.password = ...`
    rules.append(Rule(
        id="MAIL_CLIENT_PASSWORD",
        name="Mail client (IMAP/POP/SMTP) password",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Mail client config with imap/pop/smtp password",
        pattern=re.compile(
            r'(?i)\b(?:imap|pop3?|smtp|mail)[._-]?(?:password|passwd|pw|pwd|secret)'
            r'\s*[=:]\s*["\']?(?P<secret>[^\s"\'#]{3,})["\']?',
        ),
        min_entropy=1.5,
        min_length=3,
        tags=["password", "mail"],
        fast_keywords=["imap", "pop3", "smtp", "mail.password", "mail_password"],
    ))

    # Inline PSK (Pre-Shared Key) for VPN / WPA / IPSec
    rules.append(Rule(
        id="PSK_PRESHARED_KEY",
        name="Pre-Shared Key (VPN / WPA / IPSec)",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="Pre-shared key in network config (IPSec, WPA, OpenVPN tls-auth)",
        pattern=re.compile(
            r'(?i)\b(?:psk|pre[_-]?shared[_-]?key|wpa[_-]?(?:passphrase|psk)|'
            r'shared[_-]?secret|secret)\s*[=:]\s*'
            r'["\']?(?P<secret>[^\s"\'#]{8,})["\']?',
        ),
        min_entropy=2.5,
        min_length=8,
        context_keywords=["vpn", "ipsec", "wpa", "wireless", "openvpn",
                          "strongswan", "racoon"],
        tags=["password", "vpn", "wireless", "psk"],
        fast_keywords=["psk", "pre_shared", "preshared", "pre-shared",
                       "wpa_passphrase", "wpa_psk", "shared_secret"],
    ))

    # Cisco / Juniper enable-password / enable-secret in router/switch configs
    rules.append(Rule(
        id="CISCO_ENABLE_SECRET",
        name="Cisco enable secret / password",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Cisco / Juniper enable secret, enable password, or username password",
        pattern=re.compile(
            r'(?im)^\s*(?:enable\s+(?:secret|password)|'
            r'username\s+\S+\s+(?:secret|password|privilege\s+\d+\s+(?:secret|password)))'
            r'(?:\s+\d)?\s+(?P<secret>\S{3,})',
        ),
        min_entropy=1.0,
        min_length=3,
        check_entropy=False,
        false_positive_indicators=[],
        tags=["password", "cisco", "juniper", "network"],
        fast_keywords=["enable secret", "enable password",
                       "username "],
    ))

    # Ruby/Rails `ENV['PASSWORD']` fallback patterns —  `|| 'fallback'`
    # The fallback is often a real password used in dev that leaks to prod.
    rules.append(Rule(
        id="ENV_FALLBACK_PASSWORD",
        name="Environment-variable fallback secret",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="`ENV['X'] || 'fallback'` style: fallback often a real dev password",
        pattern=re.compile(
            r'(?i)(?:ENV|process\.env)'
            r'(?:\[\s*["\'](?P<varname>[\w]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'token)[\w]*)["\']\s*\]|'
            r'\.(?P<varname2>[\w]*'
            r'(?:pass(?:word|wd|phrase)?|pwd|secret|credential|api[_-]?key|'
            r'token)[\w]*))'
            r'\s*\|\|\s*'
            r'["\'](?P<secret>[^"\']{4,})["\']',
        ),
        min_entropy=2.0,
        min_length=4,
        tags=["password", "env_fallback", "ruby", "javascript"],
        fast_keywords=["env[", "process.env", "||"],
    ))

    # Windows `LAPS` ms-Mcs-AdmPwd in PowerShell extracts:
    #   `Get-LAPSADPassword … : Password = "..."`
    rules.append(Rule(
        id="LAPS_PASSWORD",
        name="LAPS local-admin password (extracted)",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        description="Microsoft LAPS local-admin password retrieved from AD",
        pattern=re.compile(
            r'(?i)\bms-?Mcs-?AdmPwd\b\s*[:=]\s*'
            r'["\']?(?P<secret>[^\s"\']{6,})["\']?'
            r'|\bGet-LAPS(?:AD)?Password\b[^\n]*?'
            r'\bPassword\s*[:=]\s*["\']?(?P<secret2>[^\s"\']{6,})["\']?',
        ),
        min_entropy=2.0,
        min_length=6,
        false_positive_indicators=[],
        tags=["password", "windows", "laps", "active_directory"],
        fast_keywords=["ms-mcs-admpwd", "msmcsadmpwd", "get-laps"],
    ))

    # Smtp / sendmail-style auth: `AUTH PLAIN <base64>` (fired on captured traffic)
    rules.append(Rule(
        id="SMTP_AUTH_PLAIN",
        name="SMTP AUTH PLAIN credential blob",
        category=Category.PASSWORD,
        severity=Severity.HIGH,
        description="SMTP AUTH PLAIN <base64> — base64 of \\0user\\0pass",
        pattern=re.compile(
            r'(?i)\bAUTH\s+(?:PLAIN|LOGIN)\s+(?P<secret>[A-Za-z0-9+/=]{12,})',
        ),
        min_entropy=2.5,
        min_length=12,
        context_keywords=["smtp", "auth", "ehlo", "helo", "mail from"],
        tags=["password", "smtp"],
        fast_keywords=["auth plain", "auth login"],
    ))

    # Generic "the password is X" / "password = X" comment pattern (CTF clue)
    rules.append(Rule(
        id="COMMENT_PASSWORD_LEAK",
        name="Password leaked in comment / docstring",
        category=Category.PASSWORD,
        severity=Severity.MEDIUM,
        description="Password mentioned in a comment, docstring, or README: 'password is X' / 'pass: X'",
        pattern=re.compile(
            r'(?i)(?:#|//|/\*|;|<!--|\*)\s*'
            r'(?:(?:the\s+)?(?:default\s+|admin\s+|root\s+)?'
            r'(?:password|passwd|pwd|secret|credential|login)'
            r'\s*(?:is|:|=)\s*)'
            r'["\']?(?P<secret>[^\s"\'#<*]{3,})["\']?',
        ),
        min_entropy=1.5,
        min_length=3,
        tags=["password", "comment", "ctf"],
        fast_keywords=["password is", "passwd is", "pwd is",
                       "secret is", "credential is", "login is",
                       "password:", "passwd:", "secret:",
                       "password=", "secret="],
    ))

    return rules


# Singleton rule set
ALL_RULES: list[Rule] = _build_rules()

def get_rules_by_category(category: Category) -> list[Rule]:
    return [r for r in ALL_RULES if r.category == category]

def get_rules_by_severity(severity: Severity) -> list[Rule]:
    return [r for r in ALL_RULES if r.severity == severity]

def get_rules_by_tag(tag: str) -> list[Rule]:
    return [r for r in ALL_RULES if tag in r.tags]
