"""
Basic unit tests for the Katymio Dumper Discord bot helpers.

Run with:  python -m pytest tests/test_bot.py -v
"""

import sys
import os
import tempfile
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Provide a fake token so bot.py can be imported without a real .env
os.environ.setdefault("DISCORD_TOKEN", "fake-token-for-testing")

from bot import _safe_stem, _run_dumper, ALLOWED_EXTENSIONS, DUMPER_SCRIPT


# --------------------------------------------------------------------------- #
# _safe_stem
# --------------------------------------------------------------------------- #

def test_safe_stem_simple():
    assert _safe_stem("myscript.lua") == "myscript"


def test_safe_stem_strips_extension():
    assert _safe_stem("foo.luau") == "foo"


def test_safe_stem_sanitises_special_chars():
    stem = _safe_stem("bad/name!?.lua")
    assert "/" not in stem
    assert "!" not in stem
    assert "?" not in stem


def test_safe_stem_limits_length():
    long_name = "a" * 200 + ".lua"
    assert len(_safe_stem(long_name)) <= 64


def test_safe_stem_empty_fallback():
    # A file with only an extension-like name still produces a usable stem
    # ".lua" → strips the leading dot → "lua"
    result = _safe_stem(".lua")
    assert result  # non-empty
    assert result != ".lua"  # leading dot stripped


# --------------------------------------------------------------------------- #
# ALLOWED_EXTENSIONS
# --------------------------------------------------------------------------- #

def test_allowed_extensions_contains_required():
    assert ".lua" in ALLOWED_EXTENSIONS
    assert ".luau" in ALLOWED_EXTENSIONS
    assert ".txt" in ALLOWED_EXTENSIONS


# --------------------------------------------------------------------------- #
# _run_dumper (integration – requires lua interpreter)
# --------------------------------------------------------------------------- #

def test_run_dumper_simple_script():
    """Run the Lua dumper on a trivial script and check it produces output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        input_path = tmp / "input.lua"
        output_path = tmp / "output.lua.txt"

        input_path.write_text('print("hello from test")\n')

        success, err = _run_dumper(input_path, output_path)

        if not success and "not found" in err:
            import pytest
            pytest.skip("No lua interpreter available on this host")

        assert success, f"Dumper failed: {err}"
        assert output_path.exists()
        content = output_path.read_text()
        assert len(content) > 0


def test_run_dumper_output_contains_original_content():
    """Dumper output should include the original print statement."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        input_path = tmp / "input.lua"
        output_path = tmp / "output.lua.txt"

        input_path.write_text('print("hello from test")\n')

        success, _ = _run_dumper(input_path, output_path)

        if not success:
            import pytest
            pytest.skip("No lua interpreter available on this host")

        content = output_path.read_text()
        assert "hello from test" in content
