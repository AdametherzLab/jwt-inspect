import type {
  JwtString,
  Base64UrlString,
  JwtHeader,
  JwtPayload,
  DecodedJwt,
  FormattedDuration,
  InspectionResult,
} from "./types.js";

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 * @param encoded - Base64url-encoded string
 * @returns Decoded UTF-8 string
 * @throws {Error} If the input is not valid base64url
 */
function base64UrlDecode(encoded: Base64UrlString): string {
  try {
    return Buffer.from(encoded, "base64url").toString("utf-8");
  } catch {
    throw new Error(
      `Invalid base64url encoding: ${encoded.slice(0, 20)}${
        encoded.length > 20 ? "..." : ""
      }`
    );
  }
}

/**
 * Parse a JWT string into its decoded components.
 * @param token - The JWT string to parse
 * @returns Decoded JWT structure with header, payload, and signature
 * @throws {Error} If the token format is invalid or JSON parsing fails
 * @example
 * const decoded = parseJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" as JwtString);
 */
export function parseJwt(token: JwtString): DecodedJwt {
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new Error(
      `Invalid JWT format: expected 3 segments separated by dots, found ${segments.length}`
    );
  }

  const [headerB64, payloadB64, signatureB64] = segments as [
    Base64UrlString,
    Base64UrlString,
    Base64UrlString
  ];

  let header: JwtHeader;
  let payload: JwtPayload;

  try {
    header = JSON.parse(base64UrlDecode(headerB64)) as JwtHeader;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : "Invalid JSON";
    throw new Error(`Failed to decode JWT header: ${message}`);
  }

  try {
    payload = JSON.parse(base64UrlDecode(payloadB64)) as JwtPayload;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : "Invalid JSON";
    throw new Error(`Failed to decode JWT payload: ${message}`);
  }

  return {
    header,
    payload,
    signature: signatureB64,
    raw: {
      header: headerB64,
      payload: payloadB64,
      signature: signatureB64,
    },
  } satisfies DecodedJwt;
}

/**
 * Format a duration between two timestamps into a human-readable string.
 * @param targetTimestamp - Unix timestamp (seconds) to calculate duration to/from
 * @param referenceTimestamp - Unix timestamp (seconds) to use as reference (defaults to now)
 * @returns Formatted duration with components and human-readable text
 * @example
 * const duration = formatDuration(1893456000); // Future date
 * console.log(duration.text); // "expires in 2d 4h 30m"
 *
 * const past = formatDuration(1609459200); // Past date
 * console.log(past.text); // "expired 1y 2d ago"
 */
export function formatDuration(
  targetTimestamp: number,
  referenceTimestamp: number = Math.floor(Date.now() / 1000)
): FormattedDuration {
  const totalSeconds = targetTimestamp - referenceTimestamp;
  const isExpired = totalSeconds < 0;
  const absoluteSeconds = Math.abs(totalSeconds);

  const days = Math.floor(absoluteSeconds / 86400);
  const hours = Math.floor((absoluteSeconds % 86400) / 3600);
  const minutes = Math.floor((absoluteSeconds % 3600) / 60);
  const seconds = absoluteSeconds % 60;

  const components: string[] = [];
  if (days > 0) components.push(`${days}d`);
  if (hours > 0) components.push(`${hours}h`);
  if (minutes > 0) components.push(`${minutes}m`);
  if (seconds > 0 && days === 0) components.push(`${seconds}s`);

  const text =
    components.length === 0
      ? isExpired
        ? "expired"
        : "expires now"
      : isExpired
      ? `expired ${components.join(" ")} ago`
      : `expires in ${components.join(" ")}`;

  return {
    isExpired,
    totalSeconds,
    days,
    hours,
    minutes,
    seconds,
    text,
  } satisfies FormattedDuration;
}

/**
 * Inspect a JWT token and extract comprehensive metadata including timing information.
 * @param token - The JWT string to inspect
 * @param currentTime - Unix timestamp (seconds) to use as reference time (defaults to now)
 * @returns Complete inspection result with decoded token, timing, and metadata
 * @throws {Error} If the token is malformed or cannot be decoded
 * @example
 * const result = inspectJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature" as JwtString);
 * console.log(result.metadata.algorithm); // "HS256"
 * console.log(result.timing.expiresIn?.text); // "expires in 2h 30m"
 */
export function inspectJwt(
  token: JwtString,
  currentTime: number = Math.floor(Date.now() / 1000)
): InspectionResult {
  const decoded = parseJwt(token);
  const { header, payload } = decoded;

  return {
    token: decoded,
    timing: {
      issuedAt:
        payload.iat !== undefined
          ? formatDuration(payload.iat, currentTime)
          : undefined,
      expiresIn:
        payload.exp !== undefined
          ? formatDuration(payload.exp, currentTime)
          : undefined,
      notBefore:
        payload.nbf !== undefined
          ? formatDuration(payload.nbf, currentTime)
          : undefined,
    },
    metadata: {
      algorithm: header.alg,
      keyId: header.kid,
      tokenId: payload.jti,
      issuer: payload.iss,
      subject: payload.sub,
      audience: payload.aud,
    },
  } satisfies InspectionResult;
}