/**
 * Public API barrel file for jwt-inspect.
 * 
 * This module serves as the single import point for programmatic use of the library,
 * re-exporting all public functions and types from the core modules.
 * 
 * @example
 * ```typescript
 * import { inspectJwt, verifyJwt, parseCliArgs } from "jwt-inspect";
 * 
 * // Decode and inspect a token
 * const result = inspectJwt(token);
 * 
 * // Verify signature against a local key
 * const verification = verifyJwt(decoded, { publicKey: pem });
 * ```
 */

// Core decoding and inspection functionality
export { decodeJwt, inspectJwt, formatDuration } from "./decode.js";

// Signature verification and key management
export { verifyJwt, loadKey } from "./verify.js";

// CLI rendering and argument parsing utilities
export {
  renderInspectResult,
  renderVerifyResult,
  parseCliArgs,
  runCli,
} from "./cli.js";

// Type definitions for all public interfaces
export * from "./types.js";