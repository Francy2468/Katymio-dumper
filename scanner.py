"""
Katymio Dumper – security scanner for uploaded Lua / Luau files.

Detects scripts that attempt to:
  • Discover the bot's filesystem path  (debug.getinfo, package.path/cpath, /proc/self/*)
  • Execute arbitrary shell commands     (os.execute, io.popen)
  • Read sensitive system files          (absolute io.open, /etc/passwd, etc.)
  • Exfiltrate path/user env variables   (os.getenv with PATH/HOME/PWD/etc.)
  • Hide malicious code via obfuscation  (heuristic checks)

Usage::

    result = scan_file(raw_bytes)
    if result.is_dangerous:
        # block the file and send a Discord alert

Two scan stages are supported (controlled by the ``stage`` parameter in
the helpers in bot.py):

  • "pre-dump"  – scans the raw uploaded bytes BEFORE the dumper runs.
  • "post-dump" – scans the deobfuscated dumper output AFTER it runs;
                  catches patterns that were hidden by obfuscation layers.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """A single detected threat or suspicious indicator."""
    name: str
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM"
    description: str


@dataclass
class ScanResult:
    """Result returned by :func:`scan_file`."""
    is_dangerous: bool          # True when any HIGH or CRITICAL finding exists
    findings: list[Finding] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        """Return the worst severity found, or ``"NONE"``."""
        for level in ("CRITICAL", "HIGH", "MEDIUM"):
            if any(f.severity == level for f in self.findings):
                return level
        return "NONE"


# --------------------------------------------------------------------------- #
# Regex pattern definitions
# --------------------------------------------------------------------------- #

@dataclass
class _Pattern:
    name: str
    regex: re.Pattern
    severity: str
    description: str


# Each pattern fires independently; all matches are collected.
_PATTERNS: list[_Pattern] = [

    # ── Path / directory discovery ──────────────────────────────────────────

    _Pattern(
        name="debug_path_leak",
        regex=re.compile(r"debug\s*\.\s*getinfo\b", re.IGNORECASE),
        severity="HIGH",
        description=(
            "debug.getinfo() can reveal the bot's script path "
            "(e.g. debug.getinfo(1,'S').source)"
        ),
    ),
    _Pattern(
        name="package_path_leak",
        regex=re.compile(
            r"\bpackage\s*\.\s*(?:path|cpath|config)\b", re.IGNORECASE
        ),
        severity="HIGH",
        description=(
            "package.path / package.cpath / package.config expose "
            "Lua installation directories and the bot's working tree"
        ),
    ),
    _Pattern(
        name="proc_self",
        regex=re.compile(
            r"""[\"'][/\\]proc[/\\](?:self|\d+)[/\\]""", re.IGNORECASE
        ),
        severity="CRITICAL",
        description=(
            "References /proc/self/* – reveals the bot's executable "
            "path and memory maps on Linux"
        ),
    ),

    # ── Shell command execution ─────────────────────────────────────────────

    _Pattern(
        name="shell_popen",
        regex=re.compile(r"\bio\s*\.\s*popen\s*\(", re.IGNORECASE),
        severity="HIGH",
        description=(
            "io.popen() can run arbitrary shell commands "
            "(e.g. pwd, ls, find, cat /etc/passwd)"
        ),
    ),
    _Pattern(
        name="shell_execute",
        regex=re.compile(r"\bos\s*\.\s*execute\s*\(", re.IGNORECASE),
        severity="HIGH",
        description="os.execute() can run arbitrary shell commands",
    ),

    # ── Environment variable exfiltration ──────────────────────────────────

    _Pattern(
        name="env_path_vars",
        regex=re.compile(
            r"os\s*\.\s*getenv\s*\(\s*[\"']"
            r"(?:PWD|HOME|PATH|TEMP|TMP|APPDATA|USERPROFILE|"
            r"USER|USERNAME|COMPUTERNAME|HOSTNAME|LOGNAME)"
            r"[\"']\s*\)",
            re.IGNORECASE,
        ),
        severity="HIGH",
        description=(
            "os.getenv() reading system path / user environment "
            "variables to discover the bot's location or identity"
        ),
    ),

    # ── Absolute-path file access ───────────────────────────────────────────

    _Pattern(
        name="absolute_path_open_unix",
        regex=re.compile(
            r"io\s*\.\s*open\s*\(\s*[\"'][/~]", re.IGNORECASE
        ),
        severity="HIGH",
        description="io.open() with an absolute Unix path",
    ),
    _Pattern(
        name="absolute_path_open_windows",
        regex=re.compile(
            r"io\s*\.\s*open\s*\(\s*[\"'][A-Za-z]:[/\\]", re.IGNORECASE
        ),
        severity="HIGH",
        description="io.open() with an absolute Windows path",
    ),
    _Pattern(
        name="sensitive_file_access",
        regex=re.compile(
            r"""[\"'][/\\]etc[/\\](?:passwd|shadow|hosts|sudoers|crontab)\b""",
            re.IGNORECASE,
        ),
        severity="CRITICAL",
        description=(
            "References sensitive system files "
            "(/etc/passwd, /etc/shadow, /etc/hosts, …)"
        ),
    ),

    # ── Path traversal ──────────────────────────────────────────────────────

    _Pattern(
        name="path_traversal",
        regex=re.compile(r"\.\.[/\\]"),
        severity="MEDIUM",
        description="Path-traversal sequence (../) detected",
    ),
]


# --------------------------------------------------------------------------- #
# Heuristic thresholds
# --------------------------------------------------------------------------- #

# string.char() calls per KB of source → above this level suggests obfuscation
_CHAR_CALLS_PER_KB = 15

# Lines longer than this suggest a packed/obfuscated payload
_MAX_LINE_LENGTH = 1_000

# Ratio of \xNN / \NNN / \uNNNN escapes to non-whitespace characters
_MAX_ESCAPE_RATIO = 0.30


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def scan_file(content: bytes) -> ScanResult:
    """
    Scan raw file *content* (bytes) for dangerous or suspicious Lua patterns.

    Returns a :class:`ScanResult`.  ``is_dangerous`` is ``True`` when at
    least one HIGH or CRITICAL finding is present.

    Call this both *before* running the Lua dumper (to block obvious threats)
    and *after* on the deobfuscated output (to catch obfuscated threats).
    """
    # Decode tolerantly – scripts may use latin-1 or mixed encodings
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="replace")

    findings: list[Finding] = []

    # ── 1. Regex pattern scan ────────────────────────────────────────────────
    for p in _PATTERNS:
        if p.regex.search(text):
            findings.append(
                Finding(
                    name=p.name,
                    severity=p.severity,
                    description=p.description,
                )
            )
            logger.debug("Security pattern '%s' matched during file scan", p.name)

    # ── 2. Heuristic: excessive string.char() density ────────────────────────
    char_calls = len(re.findall(r"\bstring\.char\s*\(", text, re.IGNORECASE))
    size_kb = max(len(content) / 1024, 1.0)
    if char_calls / size_kb > _CHAR_CALLS_PER_KB:
        findings.append(
            Finding(
                name="excessive_string_char",
                severity="MEDIUM",
                description=(
                    f"Excessive string.char() usage: {char_calls} calls in "
                    f"{size_kb:.1f} KB – likely obfuscated payload"
                ),
            )
        )

    # ── 3. Heuristic: very long single lines ─────────────────────────────────
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > _MAX_LINE_LENGTH:
            findings.append(
                Finding(
                    name="obfuscated_long_line",
                    severity="MEDIUM",
                    description=(
                        f"Line {lineno} is {len(line)} characters long – "
                        "possible obfuscated/packed payload"
                    ),
                )
            )
            break  # report once; additional long lines add no new information

    # ── 4. Heuristic: high escape-sequence density ───────────────────────────
    non_ws_len = len(re.sub(r"\s", "", text))
    escape_count = len(
        re.findall(
            r"\\(?:x[0-9a-fA-F]{2}|[0-9]{1,3}|u[0-9a-fA-F]{4})", text
        )
    )
    if non_ws_len > 0 and (escape_count / non_ws_len) > _MAX_ESCAPE_RATIO:
        findings.append(
            Finding(
                name="high_escape_density",
                severity="MEDIUM",
                description=(
                    f"High escape-sequence density "
                    f"({escape_count}/{non_ws_len} = "
                    f"{escape_count / non_ws_len:.0%}) – "
                    "possible obfuscated string payload"
                ),
            )
        )

    is_dangerous = any(f.severity in ("HIGH", "CRITICAL") for f in findings)
    return ScanResult(is_dangerous=is_dangerous, findings=findings)
