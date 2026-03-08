// REMOVED external import: import * as process from "process";
import * as fs from "fs";
import * as path from "path";
import type { InspectionResult, VerificationResult, VerificationFailure, KidMismatchError, ClockSkewError, AlgorithmMismatchError, FormattedDuration, JwtPayload, JwtHeader } from "./types.js";
import { inspect } from "./inspector.js";
import { verify } from "./verifier.js";

const ANSI = { reset: "\x1b[0m", bold: "\x1b[1m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m", blue: "\x1b[34m", cyan: "\x1b[36m", gray: "\x1b[90m" } as const;
const isTTY = process.stdout.isTTY ?? false;

/** Apply ANSI color code if enabled.
 * @param name - Color name from ANSI palette
 * @param text - Text to colorize
 * @param enabled - Whether colors are enabled
 * @returns Colorized or plain text */
function color(name: keyof typeof ANSI, text: string, enabled: boolean): string {
  return enabled ? `${ANSI[name]}${text}${ANSI.reset}` : text;
}

/** Parse command line arguments into structured options.
 * @param argv - process.argv array
 * @returns Parsed arguments configuration */
export function parseArgs(argv: string[]): { cmd: "inspect" | "verify" | null; token: string; json: boolean; color: boolean; secret?: string; pubKey?: string; jwks?: string; tolerance?: number } {
  const args = argv.slice(2);
  let cmd: "inspect" | "verify" | null = null;
  let token = "";
  let json = false;
  let useColor = isTTY;
  let secret: string | undefined;
  let pubKey: string | undefined;
  let jwks: string | undefined;
  let tolerance: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--help" || a === "-h") { console.log("Usage: jwt-inspect <inspect|verify> [token] [options]"); process.exit(0); }
    if (a === "--version" || a === "-v") { console.log("1.0.0"); process.exit(0); }
    if (a === "--json") json = true;
    else if (a === "--no-color") useColor = false;
    else if (a === "--color") useColor = true;
    else if (a === "--secret") secret = args[++i];
    else if (a === "--public-key") pubKey = args[++i];
    else if (a === "--jwks") jwks = args[++i];
    else if (a === "--clock-tolerance") tolerance = parseInt(args[++i], 10);
    else if (a === "inspect" || a === "verify") cmd = a;
    else if (!a.startsWith("-") && !token) token = a;
  }
  if (!token && args.length > 0 && !args[0].startsWith("-")) token = args[0];
  return { cmd, token, json, color: useColor, secret, pubKey, jwks, tolerance };
}

/** Format a duration object for display.
 * @param d - Formatted duration or undefined
 * @returns Human readable string */
export function fmtDuration(d?: FormattedDuration): string {
  if (!d) return "N/A";
  return d.isExpired ? `${d.text} ago` : `in ${d.text}`;
}

/** Format a claim value for terminal display.
 * @param v - Value to format
 * @returns Formatted string representation */
export function fmtValue(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string") return `"${v}"`;
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** Render JWT header section.
 * @param h - JWT header object
 * @param useColor - Enable ANSI colors
 * @returns Formatted header string */
export function renderHeader(h: JwtHeader, useColor: boolean): string {
  const lines: string[] = [`Algorithm: ${color("yellow", h.alg, useColor)}`];
  if (h.typ) lines.push(`Type: ${h.typ}`);
  if (h.kid) lines.push(`Key ID: ${h.kid}`);
  return lines.join("\n");
}

/** Render payload claims as aligned key-value pairs.
 * @param payload - JWT payload object
 * @param useColor - Enable ANSI colors
 * @returns Formatted claims string */
export function renderClaims(payload: JwtPayload, useColor: boolean): string {
  const entries = Object.entries(payload);
  if (entries.length === 0) return "  (no claims)";
  const maxKey = Math.max(...entries.map(([k]) => k.length));
  return entries.map(([k, v]) => `  ${color("cyan", k, useColor)}${" ".repeat(maxKey - k.length)}  ${fmtValue(v)}`).join("\n");
}

/** Render verification result with diagnostic details.
 * @param r - Verification result
 * @param useColor - Enable ANSI colors
 * @returns Formatted verification status */
export function renderVerification(r: VerificationResult, useColor: boolean): string {
  if (r.valid) return color("green", "✓ Valid signature", useColor);
  const f = r as VerificationFailure;
  let diag = "";
  if (f.code === "KID_MISMATCH") {
    const e = f as KidMismatchError;
    diag = `\n    Expected kid: ${e.expectedKid}\n    Available: ${e.availableKids.join(", ") || "none"}`;
  } else if (f.code === "CLOCK_SKEW") {
    const e = f as ClockSkewError;
    diag = `\n    Current: ${e.currentTime}\n    Valid from: ${e.validFrom}\n    Valid until: ${e.validUntil}`;
  } else if (f.code === "ALGORITHM_MISMATCH") {
    const e = f as AlgorithmMismatchError;
    diag = `\n    Allowed: ${e.expectedAlgorithms.join(", ")}\n    Actual: ${e.actualAlgorithm}`;
  }
  return color("red", `✗ ${f.reason} [${f.code}]${diag}`, useColor);
}

/** Render full inspection result as formatted terminal output.
 * @param res - Inspection result
 * @param useColor - Enable ANSI colors
 * @returns Complete formatted output */
export function renderPretty(res: InspectionResult, useColor: boolean): string {
  const out: string[] = [];
  out.push(color("bold", "HEADER", useColor));
  out.push(renderHeader(res.token.header, useColor));
  out.push("");
  out.push(color("bold", "PAYLOAD", useColor));
  out.push(renderClaims(res.token.payload, useColor));
  out.push("");
  out.push(color("bold", "TIMING", useColor));
  out.push(`  Issued:      ${res.timing.issuedAt ? res.timing.issuedAt.text + " ago" : "N/A"}`);
  out.push(`  Expires:     ${fmtDuration(res.timing.expiresIn)}`);
  if (res.timing.notBefore) out.push(`  Not Before:  ${fmtDuration(res.timing.notBefore)}`);
  if (res.verification) {
    out.push("");
    out.push(color("bold", "VERIFICATION", useColor));
    out.push(renderVerification(res.verification, useColor));
  }
  return out.join("\n");
}

/** Read JWT from stdin when not provided as argument.
 * @returns Promise resolving to trimmed token string */
export function readStdin(): Promise<string> {
  return new Promise((res, rej) => {
    if (process.stdin.isTTY) { res(""); return; }
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => data += chunk);
    process.stdin.on("end", () => res(data.trim()));
    process.stdin.on("error", rej);
  });
}

/** Main CLI entry point. Parses arguments, executes command, and renders output. */
async function main(): Promise<void> {
  const args = parseArgs(process.argv);
  const token = args.token || await readStdin();

  if (!token) {
    console.error(color("red", "Error: No JWT token provided. Provide as argument or via stdin.", true));
    process.exit(1);
  }

  try {
    let result: InspectionResult;
    if (args.cmd === "verify") {
      const opts: { secret?: string; publicKey?: string; jwks?: string; clockTolerance?: number } = {};
      if (args.secret) opts.secret = args.secret;
      if (args.pubKey) opts.publicKey = fs.readFileSync(path.join(process.cwd(), args.pubKey), "utf-8");
      if (args.jwks) opts.jwks = fs.readFileSync(path.join(process.cwd(), args.jwks), "utf-8");
      if (args.tolerance) opts.clockTolerance = args.tolerance;
      result = verify(token, opts);
    } else {
      result = inspect(token);
    }

    if (args.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(renderPretty(result, args.color));
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(color("red", `Error: ${msg}`, args.color));
    process.exit(1);
  }
}

main();