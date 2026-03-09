/**
 * Katymio Dumper – Discord bot that dumps Lua / Luau scripts (Node.js).
 *
 * Command:  .l [attachment | url]
 *
 * Accepted input extensions: .lua  .luau  .txt
 * Output:   <original_name>.lua.txt
 * Response: "file successfully dumped in <ms> ms"
 *
 * Security: uploaded files are scanned for dangerous patterns (path-discovery,
 * shell execution, sensitive-file access, heavy obfuscation) both before and
 * after the Lua dumper runs.  Dangerous files are blocked and a Discord embed
 * alarm is sent in the channel.
 */

"use strict";

require("dotenv").config();

const fs          = require("fs");
const os          = require("os");
const path        = require("path");
const { execFileSync, spawnSync } = require("child_process");

const { Client, GatewayIntentBits, EmbedBuilder, AttachmentBuilder, Colors } = require("discord.js");
const axios = require("axios");

const { scanFile } = require("./scanner");

// --------------------------------------------------------------------------- //
// Configuration
// --------------------------------------------------------------------------- //

const TOKEN              = process.env.DISCORD_TOKEN;
const PREFIX             = ".";
const ALLOWED_EXTENSIONS = new Set([".lua", ".luau", ".txt"]);
const DUMPER_SCRIPT      = path.join(__dirname, "dumper.lua");
const MAX_FILE_SIZE      = 8 * 1024 * 1024; // 8 MB – Discord upload limit
const DUMPER_TIMEOUT_MS  = 30_000;           // 30 seconds
const HTTP_TIMEOUT_MS    = 15_000;           // 15 seconds

// --------------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------------- //

/**
 * Return a sanitised file stem (no path separators, limited to 64 chars).
 * @param {string} name
 * @returns {string}
 */
function safeStem(name) {
  const ext  = path.extname(name);
  let   stem = ext ? path.basename(name, ext) : path.basename(name);
  if (stem.startsWith(".")) stem = stem.slice(1);
  stem = stem.replace(/[^\w\-.]/g, "_");
  return (stem.slice(0, 64) || "script");
}

/**
 * Find the first available Lua interpreter on PATH, or null.
 * @returns {string|null}
 */
function findLua() {
  for (const candidate of ["lua", "lua5.4", "lua5.3", "lua5.2", "lua5.1", "luajit"]) {
    const result = spawnSync("which", [candidate], { encoding: "utf8" });
    if (result.status === 0) return candidate;
  }
  return null;
}

const LUA_BIN = findLua();

/**
 * Run the Lua dumper on inputPath, writing the result to outputPath.
 * Returns { success: boolean, error: string }.
 * @param {string} inputPath
 * @param {string} outputPath
 * @returns {{ success: boolean, error: string }}
 */
function runDumper(inputPath, outputPath) {
  if (!LUA_BIN) {
    return { success: false, error: "`lua` interpreter not found on the server" };
  }
  try {
    execFileSync(LUA_BIN, [DUMPER_SCRIPT, inputPath, outputPath], {
      timeout: DUMPER_TIMEOUT_MS,
      encoding: "utf8",
    });
    return { success: true, error: "" };
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      return { success: false, error: `Dumper timed out (> ${DUMPER_TIMEOUT_MS / 1000} s)` };
    }
    if (err.code === "ENOENT") {
      return { success: false, error: "`lua` interpreter not found on the server" };
    }
    const stderr = (err.stderr || err.stdout || "").toString().trim();
    return { success: false, error: stderr || "Dumper exited with a non-zero code" };
  }
}

// --------------------------------------------------------------------------- //
// Security alert helpers
// --------------------------------------------------------------------------- //

const SEVERITY_EMOJI = { CRITICAL: "🚨", HIGH: "⛔", MEDIUM: "⚠️" };
const SEVERITY_COLOR = {
  CRITICAL: Colors.DarkRed,
  HIGH:     Colors.Red,
  MEDIUM:   Colors.Orange,
};

/**
 * Send a Discord embed alarm when a dangerous file is detected.
 * @param {import('discord.js').Message} message
 * @param {string} filename
 * @param {{ isDangerous: boolean, findings: Array, highestSeverity: string }} result
 * @param {"pre-dump"|"post-dump"} stage
 */
async function alertDangerousFile(message, filename, result, stage = "pre-dump") {
  const top = result.highestSeverity;

  console.warn(
    `[SECURITY ALERT] Dangerous file blocked | stage=${stage} | ` +
    `user=${message.author.tag} (id=${message.author.id}) | ` +
    `channel=#${message.channel.name} (id=${message.channel.id}) | ` +
    `file=${filename} | severity=${top} | ` +
    `findings=${JSON.stringify(result.findings.map((f) => f.name))}`
  );

  const escapedName = filename.replace(/[\\\_*~`|]/g, "\\$&");
  const description =
    stage === "post-dump"
      ? `The file **${escapedName}** was deobfuscated and the resulting code ` +
        "contains dangerous patterns. The output has been withheld."
      : `The file **${escapedName}** was blocked before execution because it ` +
        "contains patterns associated with bot path discovery or remote code execution.";

  const embed = new EmbedBuilder()
    .setTitle(`${SEVERITY_EMOJI[top] ?? "⚠️"} Dangerous File Blocked`)
    .setDescription(description)
    .setColor(SEVERITY_COLOR[top] ?? Colors.Orange)
    .addFields(
      { name: "Submitted by", value: `<@${message.author.id}>`, inline: true },
      { name: "Channel",      value: `<#${message.channel.id}>`, inline: true },
      { name: "Severity",     value: top,                         inline: true },
      { name: "Stage",        value: stage,                       inline: true }
    );

  const findingsLines = result.findings.map(
    (f) => `• **${f.name}** \`[${f.severity}]\` – ${f.description}`
  );
  if (findingsLines.length > 0) {
    embed.addFields({
      name: "Findings",
      value: findingsLines.join("\n").slice(0, 1024),
      inline: false,
    });
  }

  embed.setFooter({ text: "This incident has been logged. Contact an admin if needed." });

  await message.channel.send({ embeds: [embed] });
}

// --------------------------------------------------------------------------- //
// Discord client
// --------------------------------------------------------------------------- //

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

client.once("ready", () => {
  console.log(`Logged in as ${client.user.tag} (id: ${client.user.id})`);
  console.log("Ready. Prefix:", PREFIX);
});

// --------------------------------------------------------------------------- //
// Command handler
// --------------------------------------------------------------------------- //

client.on("messageCreate", async (message) => {
  if (message.author.bot) return;
  if (!message.content.startsWith(`${PREFIX}l`)) return;

  // Allow ".l" or ".l <url>" – strip the command prefix
  const rest = message.content.slice(2).trim(); // everything after ".l"

  let rawName    = null;
  let fileBuffer = null;

  // ── 1. Determine source ──────────────────────────────────────────────────
  if (message.attachments.size > 0) {
    const attachment = message.attachments.first();
    rawName = attachment.name;

    if (attachment.size > MAX_FILE_SIZE) {
      await message.channel.send("❌ File is too large (> 8 MB).");
      return;
    }

    try {
      const resp = await axios.get(attachment.url, {
        responseType: "arraybuffer",
        timeout: HTTP_TIMEOUT_MS,
      });
      fileBuffer = Buffer.from(resp.data);
    } catch (err) {
      await message.channel.send(`❌ Failed to download the attachment: ${err.message}`);
      return;
    }
  } else if (rest) {
    const urlMatch = rest.match(/https?:\/\/\S+/);
    if (!urlMatch) {
      await message.channel.send("❌ Please provide a valid URL or attach a file.");
      return;
    }
    const url = urlMatch[0].replace(/\)$/, "");
    rawName = url.split("/").pop().split("?")[0] || "script.lua";

    try {
      const resp = await axios.get(url, {
        responseType: "arraybuffer",
        timeout: HTTP_TIMEOUT_MS,
        maxContentLength: MAX_FILE_SIZE,
      });
      const data = Buffer.from(resp.data);
      if (data.length > MAX_FILE_SIZE) {
        await message.channel.send("❌ Remote file is too large (> 8 MB).");
        return;
      }
      fileBuffer = data;
    } catch (err) {
      const httpStatus = err.response ? err.response.status : null;
      const msg = httpStatus
        ? `HTTP ${httpStatus} when fetching URL`
        : err.message;
      await message.channel.send(`❌ Failed to download the file: ${msg}`);
      return;
    }
  } else {
    await message.channel.send(
      "❌ Usage: `.l [url]` or attach a `.lua` / `.luau` / `.txt` file."
    );
    return;
  }

  // ── 2. Validate extension ────────────────────────────────────────────────
  const ext = path.extname(rawName).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    await message.channel.send(
      `❌ Unsupported file type \`${ext}\`. ` +
      `Accepted: ${[...ALLOWED_EXTENSIONS].sort().join(", ")}`
    );
    return;
  }

  // ── 3.5 Pre-dump security scan ───────────────────────────────────────────
  const preScan = scanFile(fileBuffer);
  if (preScan.isDangerous) {
    await alertDangerousFile(message, rawName, preScan, "pre-dump");
    return;
  }
  if (preScan.findings.length > 0) {
    console.warn(
      `[SECURITY WARNING] Suspicious file (MEDIUM heuristics only) | ` +
      `user=${message.author.tag} (id=${message.author.id}) | ` +
      `file=${rawName} | ` +
      `findings=${JSON.stringify(preScan.findings.map((f) => f.name))}`
    );
  }

  // ── 4. Write to temp dir, run dumper, collect output ─────────────────────
  const stem       = safeStem(rawName);
  const outputName = `${stem}.lua.txt`;

  const tmpDir     = fs.mkdtempSync(path.join(os.tmpdir(), "katymio-"));
  const inputPath  = path.join(tmpDir, `input${ext}`);
  const outputPath = path.join(tmpDir, outputName);

  try {
    fs.writeFileSync(inputPath, fileBuffer);

    const start   = Date.now();
    const { success, error } = runDumper(inputPath, outputPath);
    const elapsedMs = Date.now() - start;

    if (!success) {
      await message.channel.send(`❌ Dumper error: ${error}`);
      return;
    }

    if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size === 0) {
      await message.channel.send("❌ Dumper produced no output.");
      return;
    }

    // ── 4.5 Post-dump security scan (deobfuscated output) ──────────────────
    const postScan = scanFile(fs.readFileSync(outputPath));
    if (postScan.isDangerous) {
      await alertDangerousFile(message, rawName, postScan, "post-dump");
      return;
    }

    const attachment = new AttachmentBuilder(outputPath, { name: outputName });
    await message.channel.send({
      content: `✅ file successfully dumped in ${elapsedMs} ms`,
      files: [attachment],
    });
  } finally {
    // Clean up temp directory
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

// --------------------------------------------------------------------------- //
// Entry point
// --------------------------------------------------------------------------- //

if (!TOKEN) {
  console.error(
    "DISCORD_TOKEN environment variable is not set.\n" +
    "Copy .env.example to .env and fill in your token."
  );
  process.exit(1);
}

client.login(TOKEN);
