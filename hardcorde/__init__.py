"""
hardcorde — Hardcoded password discovery for authorized penetration tests.

Scope: passwords and password+username pairs only. Does NOT scan for API
keys, OAuth tokens, JWTs, PEM private keys, generic high-entropy secrets,
credential-store files, or filename heuristics — by design, to keep noise
low and signal high.

For authorized internal penetration tests, red-team engagements, CTF, and
lab environments only.
"""

__version__ = "2.0.0"
__author__ = "hardcorde"
