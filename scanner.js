/**
 * Katymio Dumper – security scanner for uploaded Lua / Luau files (Node.js).
 *
 * Detects scripts that attempt to:
 *   • Discover the bot's filesystem path  (debug.getinfo, package.path/cpath, /proc/self/*)
 *   • Execute arbitrary shell commands     (os.execute, io.popen)
 *   • Read sensitive system files          (absolute io.open, /etc/passwd, etc.)
 *   • Exfiltrate path/user env variables   (os.getenv with PATH/HOME/PWD/etc.)
 *   • Hide malicious code via obfuscation  (heuristic checks)
 *
 * Usage:
 *   const { scanFile } = require('./scanner');
 *   const result = scanFile(buffer);
 *   if (result.isDangerous) { ... }
 */

"use strict";

// --------------------------------------------------------------------------- //
// Pattern definitions
// --------------------------------------------------------------------------- //

const PATTERNS = [
  // ── Path / directory discovery ──────────────────────────────────────────
  {
    name: "debug_path_leak",
    regex: /debug\s*\.\s*getinfo\b/i,
    severity: "HIGH",
    description:
      "debug.getinfo() can reveal the bot's script path " +
      "(e.g. debug.getinfo(1,'S').source)",
  },
  {
    name: "package_path_leak",
    regex: /\bpackage\s*\.\s*(?:path|cpath|config)\b/i,
    severity: "HIGH",
    description:
      "package.path / package.cpath / package.config expose " +
      "Lua installation directories and the bot's working tree",
  },
  {
    name: "proc_self",
    regex: /["'][/\\]proc[/\\](?:self|\d+)[/\\]/i,
    severity: "CRITICAL",
    description:
      "References /proc/self/* – reveals the bot's executable " +
      "path and memory maps on Linux",
  },

  // ── Shell command execution ─────────────────────────────────────────────
  {
    name: "shell_popen",
    regex: /\bio\s*\.\s*popen\s*\(/i,
    severity: "HIGH",
    description:
      "io.popen() can run arbitrary shell commands " +
      "(e.g. pwd, ls, find, cat /etc/passwd)",
  },
  {
    name: "shell_execute",
    regex: /\bos\s*\.\s*execute\s*\(/i,
    severity: "HIGH",
    description: "os.execute() can run arbitrary shell commands",
  },

  // ── Environment variable exfiltration ──────────────────────────────────
  {
    name: "env_path_vars",
    regex: /os\s*\.\s*getenv\s*\(\s*["'](?:PWD|HOME|PATH|TEMP|TMP|APPDATA|USERPROFILE|USER|USERNAME|COMPUTERNAME|HOSTNAME|LOGNAME)["']\s*\)/i,
    severity: "HIGH",
    description:
      "os.getenv() reading system path / user environment " +
      "variables to discover the bot's location or identity",
  },

  // ── Absolute-path file access ───────────────────────────────────────────
  {
    name: "absolute_path_open_unix",
    regex: /io\s*\.\s*open\s*\(\s*["'][/~]/i,
    severity: "HIGH",
    description: "io.open() with an absolute Unix path",
  },
  {
    name: "absolute_path_open_windows",
    regex: /io\s*\.\s*open\s*\(\s*["'][A-Za-z]:[/\\]/i,
    severity: "HIGH",
    description: "io.open() with an absolute Windows path",
  },
  {
    name: "sensitive_file_access",
    regex: /["'][/\\]etc[/\\](?:passwd|shadow|hosts|sudoers|crontab)\b/i,
    severity: "CRITICAL",
    description:
      "References sensitive system files " +
      "(/etc/passwd, /etc/shadow, /etc/hosts, …)",
  },

  // ── Path traversal ──────────────────────────────────────────────────────
  {
    name: "path_traversal",
    regex: /\.\.[/\\]/,
    severity: "MEDIUM",
    description: "Path-traversal sequence (../) detected",
  },
];

// --------------------------------------------------------------------------- //
// Heuristic thresholds
// --------------------------------------------------------------------------- //

const CHAR_CALLS_PER_KB = 15;   // string.char() calls per KB → above = obfuscation
const MAX_LINE_LENGTH   = 1000; // lines longer than this suggest a packed payload
const MAX_ESCAPE_RATIO  = 0.30; // ratio of escape sequences to non-whitespace

// --------------------------------------------------------------------------- //
// Public API
// --------------------------------------------------------------------------- //

/**
 * Scan raw file content (Buffer) for dangerous or suspicious Lua patterns.
 *
 * @param {Buffer} content
 * @returns {{ isDangerous: boolean, findings: Array<{name:string, severity:string, description:string}>, highestSeverity: string }}
 */
function scanFile(content) {
  let text;
  try {
    text = content.toString("utf8");
  } catch {
    text = content.toString("latin1");
  }

  const findings = [];

  // ── 1. Regex pattern scan ────────────────────────────────────────────────
  for (const p of PATTERNS) {
    if (p.regex.test(text)) {
      findings.push({ name: p.name, severity: p.severity, description: p.description });
    }
  }

  // ── 2. Heuristic: excessive string.char() density ────────────────────────
  const charCalls = (text.match(/\bstring\.char\s*\(/gi) || []).length;
  const sizeKb    = Math.max(content.length / 1024, 1.0);
  if (charCalls / sizeKb > CHAR_CALLS_PER_KB) {
    findings.push({
      name: "excessive_string_char",
      severity: "MEDIUM",
      description:
        `Excessive string.char() usage: ${charCalls} calls in ` +
        `${sizeKb.toFixed(1)} KB – likely obfuscated payload`,
    });
  }

  // ── 3. Heuristic: very long single lines ─────────────────────────────────
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > MAX_LINE_LENGTH) {
      findings.push({
        name: "obfuscated_long_line",
        severity: "MEDIUM",
        description:
          `Line ${i + 1} is ${lines[i].length} characters long – ` +
          "possible obfuscated/packed payload",
      });
      break;
    }
  }

  // ── 4. Heuristic: high escape-sequence density ───────────────────────────
  const nonWsLen    = text.replace(/\s/g, "").length;
  const escapeCount = (text.match(/\\(?:x[0-9a-fA-F]{2}|[0-9]{1,3}|u[0-9a-fA-F]{4})/g) || []).length;
  if (nonWsLen > 0 && escapeCount / nonWsLen > MAX_ESCAPE_RATIO) {
    findings.push({
      name: "high_escape_density",
      severity: "MEDIUM",
      description:
        `High escape-sequence density ` +
        `(${escapeCount}/${nonWsLen} = ` +
        `${Math.round((escapeCount / nonWsLen) * 100)}%) – ` +
        "possible obfuscated string payload",
    });
  }

  const isDangerous = findings.some(
    (f) => f.severity === "HIGH" || f.severity === "CRITICAL"
  );

  const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"];
  const highestSeverity =
    SEVERITY_ORDER.find((lvl) => findings.some((f) => f.severity === lvl)) || "NONE";

  return { isDangerous, findings, highestSeverity };
}

module.exports = { scanFile };
