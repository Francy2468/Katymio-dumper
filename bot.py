"""
Katymio Dumper – Discord bot that dumps Lua / Luau scripts.

Command:  .l [attachment | url]

Accepted input extensions: .lua  .luau  .txt
Output:   <original_name>.lua.txt
Response: "file successfully dumped in <ms> ms"
"""

import asyncio
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

import aiohttp
import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
PREFIX = "."
ALLOWED_EXTENSIONS = {".lua", ".luau", ".txt"}
DUMPER_SCRIPT = Path(__file__).parent / "dumper.lua"
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB – Discord upload limit

# --------------------------------------------------------------------------- #
# Bot setup
# --------------------------------------------------------------------------- #

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _safe_stem(name: str) -> str:
    """Return a sanitised file stem (no path separators, limit length)."""
    p = Path(name)
    # Path(".lua").stem == ".lua" (no suffix), Path("foo.lua").stem == "foo"
    stem = p.stem if p.suffix else p.name
    # If the stem is just the extension dot-prefix (e.g. ".lua"), strip it
    if stem.startswith("."):
        stem = stem[1:]
    stem = re.sub(r"[^\w\-.]", "_", stem)
    return stem[:64] or "script"


async def _download_url(session: aiohttp.ClientSession, url: str) -> bytes:
    """Download content from *url*, raising ValueError on problems."""
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status} when fetching URL")
        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_FILE_SIZE:
            raise ValueError("Remote file is too large (> 8 MB)")
        data = await resp.read()
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Remote file is too large (> 8 MB)")
    return data


def _find_lua() -> str | None:
    """Return the name of the first available Lua interpreter, or None."""
    for candidate in ("lua", "lua5.4", "lua5.3", "lua5.2", "lua5.1", "luajit"):
        if subprocess.run(
            ["which", candidate], capture_output=True
        ).returncode == 0:
            return candidate
    return None


_LUA_BIN: str | None = _find_lua()


def _run_dumper(input_path: Path, output_path: Path) -> tuple[bool, str]:
    """
    Run the Lua dumper on *input_path*, writing result to *output_path*.

    Returns (success, error_message).
    The dumper is invoked as:
        lua dumper.lua <input> <output>
    """
    if _LUA_BIN is None:
        return False, "`lua` interpreter not found on the server"
    try:
        result = subprocess.run(
            [_LUA_BIN, str(DUMPER_SCRIPT), str(input_path), str(output_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            return False, stderr or "Dumper exited with a non-zero code"
        return True, ""
    except FileNotFoundError:
        return False, "`lua` interpreter not found on the server"
    except subprocess.TimeoutExpired:
        return False, "Dumper timed out (> 30 s)"


# --------------------------------------------------------------------------- #
# Command
# --------------------------------------------------------------------------- #

@bot.command(name="l")
async def dump_command(ctx: commands.Context, url: str = ""):
    """
    `.l [url]`  or  `.l` with a file attachment.

    Dumps the provided Lua / Luau / txt script and returns a .lua.txt file.
    """
    attachment = None
    raw_name = None
    file_bytes = None

    # ── 1. Determine source ──────────────────────────────────────────────────
    if ctx.message.attachments:
        attachment = ctx.message.attachments[0]
        raw_name = attachment.filename
    elif url:
        # Accept a bare URL or a markdown-style link [text](url)
        match = re.search(r"https?://\S+", url)
        if not match:
            await ctx.send("❌ Please provide a valid URL or attach a file.")
            return
        url = match.group(0).rstrip(")")
        raw_name = url.split("/")[-1].split("?")[0] or "script.lua"
    else:
        await ctx.send(
            "❌ Usage: `.l [url]` or attach a `.lua` / `.luau` / `.txt` file."
        )
        return

    # ── 2. Validate extension ────────────────────────────────────────────────
    ext = Path(raw_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        await ctx.send(
            f"❌ Unsupported file type `{ext}`. "
            f"Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
        return

    # ── 3. Download content ──────────────────────────────────────────────────
    async with ctx.typing():
        try:
            if attachment:
                if attachment.size > MAX_FILE_SIZE:
                    await ctx.send("❌ File is too large (> 8 MB).")
                    return
                file_bytes = await attachment.read()
            else:
                async with aiohttp.ClientSession() as session:
                    file_bytes = await _download_url(session, url)
        except ValueError as exc:
            await ctx.send(f"❌ {exc}")
            return
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            await ctx.send(f"❌ Failed to download the file: {exc}")
            return

        # ── 4. Write to temp dir, run dumper, collect output ─────────────────
        stem = _safe_stem(raw_name)
        output_name = f"{stem}.lua.txt"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            input_path = tmp / f"input{ext}"
            output_path = tmp / output_name

            input_path.write_bytes(file_bytes)

            start = time.monotonic()
            success, error = _run_dumper(input_path, output_path)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if not success:
                await ctx.send(f"❌ Dumper error: {error}")
                return

            if not output_path.exists() or output_path.stat().st_size == 0:
                await ctx.send("❌ Dumper produced no output.")
                return

            await ctx.send(
                f"✅ file successfully dumped in {elapsed_ms} ms",
                file=discord.File(str(output_path), filename=output_name),
            )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (id: {bot.user.id})")
    print("Ready. Prefix:", PREFIX)


if __name__ == "__main__":
    if not TOKEN:
        raise RuntimeError(
            "DISCORD_TOKEN environment variable is not set. "
            "Copy .env.example to .env and fill in your token."
        )
    bot.run(TOKEN)
