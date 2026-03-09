"""
Tests for scanner.py – security scanner for uploaded Lua / Luau files.

Run with:  python -m pytest tests/test_scanner.py -v
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("DISCORD_TOKEN", "fake-token-for-testing")

from scanner import scan_file, ScanResult, Finding


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _scan(code: str) -> ScanResult:
    return scan_file(code.encode())


# --------------------------------------------------------------------------- #
# Clean / benign files should NOT trigger alarms
# --------------------------------------------------------------------------- #

def test_clean_file_not_dangerous():
    result = _scan('print("hello world")\nlocal x = 1 + 2\n')
    assert not result.is_dangerous
    assert result.findings == []


def test_clean_file_highest_severity_none():
    result = _scan('print("hello")\n')
    assert result.highest_severity == "NONE"


# --------------------------------------------------------------------------- #
# Path-discovery patterns – HIGH severity
# --------------------------------------------------------------------------- #

def test_debug_getinfo_is_dangerous():
    result = _scan('local src = debug.getinfo(1, "S").source\nprint(src)\n')
    assert result.is_dangerous
    names = [f.name for f in result.findings]
    assert "debug_path_leak" in names


def test_debug_getinfo_obfuscated_spaces():
    """Spaces around the dot should still match."""
    result = _scan("local i = debug . getinfo(2)\n")
    assert result.is_dangerous
    assert any(f.name == "debug_path_leak" for f in result.findings)


def test_package_path_is_dangerous():
    result = _scan("print(package.path)\n")
    assert result.is_dangerous
    assert any(f.name == "package_path_leak" for f in result.findings)


def test_package_cpath_is_dangerous():
    result = _scan("print(package.cpath)\n")
    assert result.is_dangerous
    assert any(f.name == "package_path_leak" for f in result.findings)


def test_package_config_is_dangerous():
    result = _scan("print(package.config)\n")
    assert result.is_dangerous
    assert any(f.name == "package_path_leak" for f in result.findings)


def test_proc_self_exe_is_critical():
    result = _scan('local f = io.open("/proc/self/exe", "r")\n')
    assert result.is_dangerous
    assert any(f.severity == "CRITICAL" for f in result.findings)
    assert any(f.name == "proc_self" for f in result.findings)


# --------------------------------------------------------------------------- #
# Shell command execution – HIGH severity
# --------------------------------------------------------------------------- #

def test_io_popen_is_dangerous():
    result = _scan('local h = io.popen("pwd")\nprint(h:read("*a"))\n')
    assert result.is_dangerous
    assert any(f.name == "shell_popen" for f in result.findings)


def test_os_execute_is_dangerous():
    result = _scan('os.execute("ls /home/")\n')
    assert result.is_dangerous
    assert any(f.name == "shell_execute" for f in result.findings)


def test_io_popen_case_insensitive():
    """Case variants should still be caught."""
    result = _scan('io.pOpen("whoami")\n')
    assert result.is_dangerous
    assert any(f.name == "shell_popen" for f in result.findings)


# --------------------------------------------------------------------------- #
# Environment variable exfiltration – HIGH severity
# --------------------------------------------------------------------------- #

def test_getenv_pwd_is_dangerous():
    result = _scan('local p = os.getenv("PWD")\n')
    assert result.is_dangerous
    assert any(f.name == "env_path_vars" for f in result.findings)


def test_getenv_home_is_dangerous():
    result = _scan('local h = os.getenv("HOME")\n')
    assert result.is_dangerous
    assert any(f.name == "env_path_vars" for f in result.findings)


def test_getenv_path_is_dangerous():
    result = _scan("local p = os.getenv('PATH')\n")
    assert result.is_dangerous
    assert any(f.name == "env_path_vars" for f in result.findings)


def test_getenv_safe_key_not_flagged():
    """Reading an unrelated env var should not trigger the path alarm."""
    result = _scan('local k = os.getenv("MY_CUSTOM_KEY")\n')
    # Should NOT produce a path-var finding
    assert not any(f.name == "env_path_vars" for f in result.findings)


# --------------------------------------------------------------------------- #
# Absolute path file access – HIGH severity
# --------------------------------------------------------------------------- #

def test_io_open_absolute_unix_is_dangerous():
    result = _scan('local f = io.open("/home/user/secrets.txt", "r")\n')
    assert result.is_dangerous
    assert any(f.name == "absolute_path_open_unix" for f in result.findings)


def test_io_open_absolute_windows_is_dangerous():
    result = _scan('local f = io.open("C:\\\\Users\\\\bot\\\\config.txt", "r")\n')
    assert result.is_dangerous
    assert any(f.name == "absolute_path_open_windows" for f in result.findings)


def test_io_open_relative_path_not_flagged():
    """Relative paths should not trigger the absolute-path alarm."""
    result = _scan('local f = io.open("data/config.txt", "r")\n')
    assert not any(
        f.name in ("absolute_path_open_unix", "absolute_path_open_windows")
        for f in result.findings
    )


# --------------------------------------------------------------------------- #
# Sensitive file access – CRITICAL severity
# --------------------------------------------------------------------------- #

def test_etc_passwd_is_critical():
    result = _scan('local f = io.open("/etc/passwd", "r")\n')
    assert result.is_dangerous
    criticals = [f for f in result.findings if f.severity == "CRITICAL"]
    assert any(f.name == "sensitive_file_access" for f in criticals)


def test_etc_shadow_is_critical():
    result = _scan('io.open("/etc/shadow")\n')
    assert result.is_dangerous
    assert any(f.name == "sensitive_file_access" for f in result.findings)


# --------------------------------------------------------------------------- #
# Path traversal – MEDIUM severity
# --------------------------------------------------------------------------- #

def test_path_traversal_detected():
    result = _scan('local f = io.open("../../config.lua")\n')
    assert any(f.name == "path_traversal" for f in result.findings)
    # MEDIUM only → not is_dangerous
    assert not result.is_dangerous


# --------------------------------------------------------------------------- #
# Obfuscation heuristics – MEDIUM severity
# --------------------------------------------------------------------------- #

def test_excessive_string_char_detected():
    # 20 string.char() calls in ~0.3 KB → well above threshold
    calls = "string.char(104,101,108,108,111)\n" * 20
    result = _scan(calls)
    assert any(f.name == "excessive_string_char" for f in result.findings)
    assert not result.is_dangerous  # MEDIUM only


def test_very_long_line_detected():
    long_line = "local x = " + ("1+" * 600) + "0\n"
    result = _scan(long_line)
    assert any(f.name == "obfuscated_long_line" for f in result.findings)
    assert not result.is_dangerous


def test_high_escape_density_detected():
    # Build a string with many literal \NNN sequences (backslash + digits).
    # In the encoded Lua source these appear as \65\66\67... which the scanner
    # counts as escape sequences and flags when the ratio exceeds the threshold.
    escapes = "\\65\\66\\67" * 200  # literal backslash-digit triples in the source
    code = f'local s = "{escapes}"\n'
    result = _scan(code)
    assert any(f.name == "high_escape_density" for f in result.findings)
    assert not result.is_dangerous


# --------------------------------------------------------------------------- #
# ScanResult helpers
# --------------------------------------------------------------------------- #

def test_highest_severity_critical():
    r = ScanResult(
        is_dangerous=True,
        findings=[
            Finding("a", "HIGH", "desc"),
            Finding("b", "CRITICAL", "desc"),
        ],
    )
    assert r.highest_severity == "CRITICAL"


def test_highest_severity_high():
    r = ScanResult(
        is_dangerous=True,
        findings=[Finding("a", "HIGH", "desc"), Finding("b", "MEDIUM", "desc")],
    )
    assert r.highest_severity == "HIGH"


def test_highest_severity_medium_only():
    r = ScanResult(
        is_dangerous=False,
        findings=[Finding("a", "MEDIUM", "desc")],
    )
    assert r.highest_severity == "MEDIUM"


def test_highest_severity_none():
    r = ScanResult(is_dangerous=False, findings=[])
    assert r.highest_severity == "NONE"


# --------------------------------------------------------------------------- #
# Binary / non-UTF-8 content
# --------------------------------------------------------------------------- #

def test_binary_content_does_not_crash():
    """Scan should tolerate non-UTF-8 bytes without raising."""
    binary = bytes(range(256))
    result = scan_file(binary)
    assert isinstance(result, ScanResult)


def test_latin1_content_with_dangerous_pattern():
    code = 'io.popen("pwd")'.encode("latin-1")
    result = scan_file(code)
    assert result.is_dangerous
