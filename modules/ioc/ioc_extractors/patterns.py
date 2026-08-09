"""Shared regex patterns for text-based IOC extraction.

Centralized here specifically so no two extractors maintain their own,
slightly different copy of the same pattern -- the project's own "no
duplicated extraction logic" requirement, applied to regexes.
"""

from __future__ import annotations

import re

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Deliberately conservative (full RFC 4291 coverage is not worth the
# false-positive risk here): matches standard 8-group and common
# zero-compressed ("::") forms only.
IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b"
)

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# Domain-only matches (no scheme): requires a dot and a plausible TLD,
# specifically excludes pure IPv4 (checked separately) and Windows
# path-like tokens by requiring letters immediately after the last dot.
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

UNC_PATH_RE = re.compile(r"\\\\[^\\\s]+\\[^\s\"']+")

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi",
}
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}


def is_ipv4(value: str) -> bool:
    return bool(IPV4_RE.fullmatch(value))