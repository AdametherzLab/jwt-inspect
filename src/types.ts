/**
 * Branded type for JWT token strings to ensure type safety at compile time.
 */
export type JwtString = string & { readonly __brand: "JwtString" };

/**
 * Branded type for Base64Url encoded strings.
 */
export type Base64UrlString = string & { readonly __brand: "Base64UrlString" };

/**
 * Standard JWT header with registered parameters and extensible custom claims.
 */
export interface JwtHeader {
  readonly alg: string;
  readonly typ?: string;
  readonly kid?: string;
  readonly jku?: string;
  readonly x5u?: string;
  readonly x5t?: string;
  readonly x5c?: readonly string[];
  readonly [key: string]: unknown;
}

/**
 * Standard JWT payload claims per RFC 7519.
 */
export interface JwtPayload {
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  readonly exp?: number;
  readonly nbf?: number;
  readonly iat?: number;
  readonly jti?: string;
  readonly [key: string]: unknown;
}

/**
 * Complete decoded JWT with raw Base64Url segments preserved for verification.
 */
export interface DecodedJwt {
  readonly header: JwtHeader;
  readonly payload: JwtPayload;
  readonly signature: Base64UrlString;
  readonly raw: {
    readonly header: Base64UrlString;
    readonly payload: Base64UrlString;
    readonly signature: Base64UrlString;
  };
}

/**
 * JSON Web Key structure per RFC 7517.
 */
export interface JsonWebKey {
  readonly kty: string;
  readonly kid?: string;
  readonly use?: string;
  readonly key_ops?: readonly string[];
  readonly alg?: string;
  readonly x5c?: readonly string[];
  readonly x5t?: string;
  readonly "x5t#S256"?: string;
  readonly [key: string]: unknown;
}

/**
 * Configuration options for JWT signature verification.
 */
export interface VerificationOptions {
  readonly algorithms?: readonly string[];
  readonly publicKey?: string | Buffer;
  readonly secret?: string | Buffer;
  readonly jwks?: readonly JsonWebKey[];
  readonly clockTolerance?: number;
  readonly maxAge?: number;
  readonly complete?: boolean;
}

/**
 * Error codes for verification failure modes.
 */
export type VerificationErrorCode =
  | "KID_MISMATCH"
  | "CLOCK_SKEW"
  | "ALGORITHM_MISMATCH"
  | "INVALID_SIGNATURE"
  | "TOKEN_EXPIRED"
  | "TOKEN_NOT_YET_VALID"
  | "MISSING_KEY";

/**
 * Base interface for all verification failures.
 */
export interface VerificationFailure {
  readonly valid: false;
  readonly reason: string;
  readonly code: VerificationErrorCode;
}

/**
 * Key ID not found in provided JWK set.
 */
export interface KidMismatchError extends VerificationFailure {
  readonly code: "KID_MISMATCH";
  readonly expectedKid: string;
  readonly availableKids: readonly string[];
}

/**
 * Token timestamp outside valid window exceeding clock tolerance.
 */
export interface ClockSkewError extends VerificationFailure {
  readonly code: "CLOCK_SKEW";
  readonly currentTime: number;
  readonly validFrom?: number;
  readonly validUntil?: number;
  readonly skewTolerance: number;
}

/**
 * Algorithm mismatch between token and allowed algorithms.
 */
export interface AlgorithmMismatchError extends VerificationFailure {
  readonly code: "ALGORITHM_MISMATCH";
  readonly expectedAlgorithms: readonly string[];
  readonly actualAlgorithm: string;
}

/**
 * Cryptographic signature verification failed.
 */
export interface InvalidSignatureError extends VerificationFailure {
  readonly code: "INVALID_SIGNATURE";
  readonly algorithm: string;
}

/**
 * Current time exceeds expiration claim.
 */
export interface TokenExpiredError extends VerificationFailure {
  readonly code: "TOKEN_EXPIRED";
  readonly expiredAt: number;
  readonly currentTime: number;
}

/**
 * Current time precedes not-before claim.
 */
export interface TokenNotYetValidError extends VerificationFailure {
  readonly code: "TOKEN_NOT_YET_VALID";
  readonly notBefore: number;
  readonly currentTime: number;
}

/**
 * No key provided for signature verification.
 */
export interface MissingKeyError extends VerificationFailure {
  readonly code: "MISSING_KEY";
}

/**
 * Discriminated union of all verification error types.
 */
export type VerificationError =
  | KidMismatchError
  | ClockSkewError
  | AlgorithmMismatchError
  | InvalidSignatureError
  | TokenExpiredError
  | TokenNotYetValidError
  | MissingKeyError;

/**
 * Successful verification result.
 */
export interface VerificationSuccess {
  readonly valid: true;
  readonly decoded: DecodedJwt;
  readonly algorithm: string;
}

/**
 * Union type representing either verification success or specific failure.
 */
export type VerificationResult = VerificationSuccess | VerificationError;

/**
 * Human-readable duration breakdown for token timing claims.
 */
export interface FormattedDuration {
  readonly isExpired: boolean;
  readonly totalSeconds: number;
  readonly days: number;
  readonly hours: number;
  readonly minutes: number;
  readonly seconds: number;
  readonly text: string;
}

/**
 * Output format options for CLI rendering.
 */
export interface RenderOptions {
  readonly format: "pretty" | "json" | "compact";
  readonly colors: boolean;
  readonly showSignature: boolean;
  readonly timeFormat: "relative" | "iso" | "unix";
}

/**
 * Complete inspection result combining decoding, timing analysis, and verification.
 */
export interface InspectionResult {
  readonly token: DecodedJwt;
  readonly verification?: VerificationResult;
  readonly timing: {
    readonly issuedAt?: FormattedDuration;
    readonly expiresIn?: FormattedDuration;
    readonly notBefore?: FormattedDuration;
  };
  readonly metadata: {
    readonly algorithm: string;
    readonly keyId?: string;
    readonly tokenId?: string;
    readonly issuer?: string;
    readonly subject?: string;
    readonly audience?: string | readonly string[];
  };
}