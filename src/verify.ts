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

  const valid = verifySignature(signingInput, decoded.signature, alg, keyResult.key);
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
      return { found: true, key: crypto.createPublicKey(opts.publicKey) };
    } catch {
      try {
        const jwk = JSON.parse(Buffer.from(opts.publicKey).toString()) as JsonWebKey;
        return { found: true, key: crypto.createPublicKey({ key: jwk, format: "jwk" }) };
      } catch (e) {
        return {
          found: false, error: {
            valid: false, code: "MISSING_KEY",
            reason: `Invalid key format: ${e instanceof Error ? e.message : "parse error"}`,
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

function verifySignature(
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
      case "pss": {
        return crypto.verify(
          `RSA-PSS`, 
          data, 
          { key: key as crypto.KeyObject, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, 
          sig
        );
      }
      case "ecdsa": {
        // Node.js crypto expects DER-encoded signatures for ECDSA, but JWT uses raw R+S concatenation.
        // We need to convert the raw signature to DER format.
        const hashLength = sig.length / 2; // R and S are each half the signature length
        const r = sig.subarray(0, hashLength);
        const s = sig.subarray(hashLength);

        // Convert raw R and S to DER-encoded ASN.1 signature
        const derSignature = toDER(r, s);

        return crypto.verify(config.hash.toUpperCase(), data, key as crypto.KeyObject, derSignature);
      }
      default:
        return false;
    }
  } catch (e) {
    // Log or handle specific crypto errors if needed
    console.error(`Signature verification failed for algorithm ${alg}:`, e);
    return false;
  }
}

/**
 * Converts a raw ECDSA signature (R and S concatenated) into a DER-encoded ASN.1 signature.
 * This is required for Node.js's `crypto.verify` function for ECDSA.
 * @param r - The R component of the signature.
 * @param s - The S component of the signature.
 * @returns A Buffer containing the DER-encoded signature.
 */
function toDER(r: Buffer, s: Buffer): Buffer {
  // Ensure R and S are positive integers (leading zero if MSB is 1)
  const r_ = Buffer.concat([Buffer.from([0]), r]);
  const s_ = Buffer.concat([Buffer.from([0]), s]);

  // Remove leading zeros if not needed (e.g., if the first byte is 0x00 and the second byte's MSB is 0)
  const trimLeadingZero = (buf: Buffer) => {
    if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80) === 0x00) {
      return buf.subarray(1);
    }
    return buf;
  };

  const derR = trimLeadingZero(r_);
  const derS = trimLeadingZero(s_);

  // Construct the DER sequence: SEQUENCE (INTEGER R, INTEGER S)
  const encodeLength = (len: number) => {
    if (len < 0x80) {
      return Buffer.from([len]);
    } else if (len < 0x100) {
      return Buffer.from([0x81, len]);
    } else if (len < 0x10000) {
      return Buffer.from([0x82, (len >> 8) & 0xFF, len & 0xFF]);
    } else {
      throw new Error("Length too large for DER encoding");
    }
  };

  const rLen = encodeLength(derR.length);
  const sLen = encodeLength(derS.length);

  const rSeq = Buffer.concat([Buffer.from([0x02]), rLen, derR]); // 0x02 is INTEGER tag
  const sSeq = Buffer.concat([Buffer.from([0x02]), sLen, derS]); // 0x02 is INTEGER tag

  const sequence = Buffer.concat([rSeq, sSeq]);
  const sequenceLen = encodeLength(sequence.length);

  return Buffer.concat([Buffer.from([0x30]), sequenceLen, sequence]); // 0x30 is SEQUENCE tag
}
