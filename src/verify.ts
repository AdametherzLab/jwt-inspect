import * as crypto from "node:crypto";
import type {
  DecodedJwt,
  JwtHeader,
  VerificationOptions,
  VerificationResult,
  VerificationSuccess,
  KidMismatchError,
  AlgorithmMismatchError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  MissingKeyError,
  JsonWebKey,
  Base64UrlString,
} from "./types.js";

const ALG_CONFIG: Record<string, { hash: string; scheme: "hmac" | "rsa" | "pss" | "ecdsa" }> = {
  HS256: { hash: "sha256", scheme: "hmac" },
  HS384: { hash: "sha384", scheme: "hmac" },
  HS512: { hash: "sha512", scheme: "hmac" },
  RS256: { hash: "sha256", scheme: "rsa" },
  RS384: { hash: "sha384", scheme: "rsa" },
  RS512: { hash: "sha512", scheme: "rsa" },
  PS256: { hash: "sha256", scheme: "pss" },
  PS384: { hash: "sha384", scheme: "pss" },
  PS512: { hash: "sha512", scheme: "pss" },
  ES256: { hash: "sha256", scheme: "ecdsa" },
  ES384: { hash: "sha384", scheme: "ecdsa" },
  ES512: { hash: "sha512", scheme: "ecdsa" },
};

const KTY_MAP: Record<string, string> = {
  RS256: "RSA", RS384: "RSA", RS512: "RSA",
  PS256: "RSA", PS384: "RSA", PS512: "RSA",
  ES256: "EC", ES384: "EC", ES512: "EC",
  HS256: "oct", HS384: "oct", HS512: "oct",
};

/**
 * Verify a JWT signature and validate temporal claims.
 * @param decoded - The decoded JWT components from parseJwt()
 * @param options - Verification configuration including keys and tolerances
 * @returns Structured result indicating success or specific failure mode
 * @example
 * const result = verifyJwt(decoded, { publicKey: fs.readFileSync("key.pem") });
 * if (!result.valid) console.error(result.reason);
 */
export function verifyJwt(decoded: DecodedJwt, options: VerificationOptions): VerificationResult {
  const now = Math.floor(Date.now() / 1000);
  const tolerance = options.clockTolerance ?? 0;
  const { header } = decoded;
  const alg = header.alg;

  if (options.algorithms?.length && !options.algorithms.includes(alg)) {
    return {
      valid: false, code: "ALGORITHM_MISMATCH",
      reason: `Algorithm "${alg}" not in allowed list: ${options.algorithms.join(", ")}`,
      expectedAlgorithms: options.algorithms, actualAlgorithm: alg,
    } satisfies AlgorithmMismatchError;
  }

  if (header.exp !== undefined && now > header.exp + tolerance) {
    return {
      valid: false, code: "TOKEN_EXPIRED",
      reason: `Token expired ${now - header.exp}s ago (exp: ${header.exp})`,
      expiredAt: header.exp, currentTime: now,
    } satisfies TokenExpiredError;
  }

  if (header.nbf !== undefined && now < header.nbf - tolerance) {
    return {
      valid: false, code: "TOKEN_NOT_YET_VALID",
      reason: `Token not valid for another ${header.nbf - now}s (nbf: ${header.nbf})`,
      notBefore: header.nbf, currentTime: now,
    } satisfies TokenNotYetValidError;
  }

  if (options.maxAge && header.iat && now > header.iat + options.maxAge + tolerance) {
    return {
      valid: false, code: "TOKEN_EXPIRED",
      reason: `Token age exceeds ${options.maxAge}s maximum`,
      expiredAt: header.iat + options.maxAge, currentTime: now,
    } satisfies TokenExpiredError;
  }

  const signingInput = `${decoded.raw.header}.${decoded.raw.payload}`;
  const keyResult = resolveKey(header, options);
  if (!keyResult.found) return keyResult.error;

  const valid = verifySignature(signingInput, decoded.raw.signature, alg, keyResult.key);
  if (!valid) {
    return {
      valid: false, code: "INVALID_SIGNATURE",
      reason: "Signature verification failed - token may have been tampered with or wrong key",
      algorithm: alg,
    } satisfies InvalidSignatureError;
  }

  return { valid: true, decoded, algorithm: alg } satisfies VerificationSuccess;
}

type KeyResolution = 
  | { found: true; key: crypto.KeyObject | Buffer }
  | { found: false; error: MissingKeyError | KidMismatchError };

function resolveKey(header: JwtHeader, opts: VerificationOptions): KeyResolution {
  if (opts.secret) {
    return { found: true, key: Buffer.from(opts.secret) };
  }

  if (opts.publicKey) {
    try {
      // Attempt to create a public key from PEM or SPKI format
      return { found: true, key: crypto.createPublicKey(opts.publicKey) };
    } catch (e) {
      // If that fails, try parsing as JWK
      try {
        const jwk = JSON.parse(Buffer.from(opts.publicKey).toString()) as JsonWebKey;
        return { found: true, key: crypto.createPublicKey({ key: jwk, format: "jwk" }) };
      } catch (e2) {
        return {
          found: false, error: {
            valid: false, code: "MISSING_KEY",
            reason: `Invalid key format: ${e instanceof Error ? e.message : "parse error"} or ${e2 instanceof Error ? e2.message : "parse error"}`,
          } satisfies MissingKeyError,
        };
      }
    }
  }

  if (opts.jwks?.length) {
    const kid = header.kid;
    let candidate: JsonWebKey | undefined;
    
    if (kid) {
      candidate = opts.jwks.find(k => k.kid === kid);
      if (!candidate) {
        return {
          found: false, error: {
            valid: false, code: "KID_MISMATCH",
            reason: `Header specifies kid "${kid}" but no matching key found in JWKS`,
            expectedKid: kid,
            availableKids: opts.jwks.map(k => k.kid).filter((k): k is string => !!k),
          } satisfies KidMismatchError,
        };
      }
    } else {
      const expectedKty = KTY_MAP[header.alg];
      candidate = opts.jwks.find(k => !expectedKty || k.kty === expectedKty);
    }

    if (!candidate) {
      return {
        found: false, error: {
          valid: false, code: "MISSING_KEY",
          reason: `No suitable key found for algorithm ${header.alg}`,
        } satisfies MissingKeyError,
      };
    }

    try {
      return { found: true, key: crypto.createPublicKey({ key: candidate, format: "jwk" }) };
    } catch (e) {
      return {
        found: false, error: {
          valid: false, code: "MISSING_KEY",
          reason: `Failed to import JWK: ${e instanceof Error ? e.message : "unknown error"}`,
        } satisfies MissingKeyError,
      };
    }
  }

  return {
    found: false, error: {
      valid: false, code: "MISSING_KEY",
      reason: "No verification key provided (secret, publicKey, or jwks required)",
    } satisfies MissingKeyError,
  };
}

export function verifySignature(
  input: string, 
  signature: Base64UrlString, 
  alg: string, 
  key: crypto.KeyObject | Buffer
): boolean {
  const config = ALG_CONFIG[alg];
  if (!config) throw new RangeError(`Unsupported algorithm: ${alg}`);

  const sig = Buffer.from(signature.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const data = Buffer.from(input);

  try {
    switch (config.scheme) {
      case "hmac": {
        const hmac = crypto.createHmac(config.hash, key as Buffer);
        hmac.update(data);
        return crypto.timingSafeEqual(hmac.digest(), sig);
      }
      case "rsa": {
        return crypto.verify(`RSA-${config.hash.toUpperCase()}`, data, key as crypto.KeyObject, sig);
      }
      case "ecdsa": {
        // Node.js crypto.verify for ECDSA expects the signature to be in DER format.
        // JWT ES256 signatures are r||s (concatenation of r and s values).
        // We need to convert r||s to DER format for verification.
        // r and s are 32 bytes each for ES256 (P-256 curve).
        const r = sig.subarray(0, sig.length / 2);
        const s = sig.subarray(sig.length / 2);

        // Construct DER sequence: SEQUENCE (INTEGER r, INTEGER s)
        const derSig = Buffer.concat([
          Buffer.from([0x30]), // SEQUENCE
          Buffer.from([r.length + s.length + 4]), // Length of sequence content
          Buffer.from([0x02]), // INTEGER
          Buffer.from([r.length]), // Length of r
          r,
          Buffer.from([0x02]), // INTEGER
          Buffer.from([s.length]), // Length of s
          s,
        ]);

        return crypto.verify(config.hash.toUpperCase(), data, key as crypto.KeyObject, derSig);
      }
      case "pss": {
        return crypto.verify(
          config.hash.toUpperCase(),
          data,
          { key: key as crypto.KeyObject, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
          sig
        );
      }
      default:
        return false;
    }
  } catch (e) {
    console.error("Signature verification error:", e);
    return false;
  }
}
