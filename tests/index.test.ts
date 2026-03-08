import { describe, it, expect } from "bun:test";
import { decodeJwt, formatDuration, verifyJwt } from "../src/index";
import * as crypto from "node:crypto";

describe("jwt-inspect public API", () => {
  it("decodeJwt extracts exact header and payload values from well-formed JWT", () => {
    const header = { alg: "HS256", typ: "JWT", kid: "key-1" };
    const payload = { sub: "user-123", iss: "test-issuer", custom_claim: "value" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const token = `${headerB64}.${payloadB64}.dummySignature123`;

    const decoded = decodeJwt(token);

    expect(decoded.header.alg).toBe("HS256");
    expect(decoded.header.typ).toBe("JWT");
    expect(decoded.header.kid).toBe("key-1");
    expect(decoded.payload.sub).toBe("user-123");
    expect(decoded.payload.iss).toBe("test-issuer");
    expect(decoded.payload.custom_claim).toBe("value");
    expect(decoded.signature).toBe("dummySignature123");
    expect(decoded.raw.header).toBe(headerB64);
    expect(decoded.raw.payload).toBe(payloadB64);
  });

  it("formatDuration returns correct human-readable strings for future and past timestamps", () => {
    const referenceTime = 1609459200;

    const future = formatDuration(1609462865, referenceTime);
    expect(future.isExpired).toBe(false);
    expect(future.text).toBe("expires in 1h 1m 5s");
    expect(future.days).toBe(0);
    expect(future.hours).toBe(1);
    expect(future.minutes).toBe(1);
    expect(future.seconds).toBe(5);

    const past = formatDuration(1609286400, referenceTime);
    expect(past.isExpired).toBe(true);
    expect(past.text).toBe("expired 2d ago");
    expect(past.days).toBe(2);
    expect(past.totalSeconds).toBe(-172800);
  });

  it("decodeJwt throws descriptive error for malformed JWT with incorrect segment count", () => {
    const malformedTwoSegments = "header.payload";
    const malformedFourSegments = "a.b.c.d";

    expect(() => decodeJwt(malformedTwoSegments)).toThrow("expected 3 segments");
    expect(() => decodeJwt(malformedFourSegments)).toThrow("expected 3 segments");
  });

  it("verifyJwt returns valid true for correctly signed RS256 token", async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const header = { alg: "RS256", typ: "JWT" };
    const payload = { sub: "test-user", iat: 1609459200 };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;

    const signer = crypto.createSign("SHA256");
    signer.update(signingInput);
    const signature = signer.sign(privateKey, "base64url");
    const token = `${signingInput}.${signature}`;

    const result = await verifyJwt(decodeJwt(token), {
      publicKey,
      algorithms: ["RS256"],
    });

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe("RS256");
  });

  it("verifyJwt returns valid true for correctly signed ES256 token", async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const header = { alg: "ES256", typ: "JWT" };
    const payload = { sub: "test-user", iat: 1609459200 };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;

    const signer = crypto.createSign("SHA256");
    signer.update(signingInput);
    const signature = signer.sign(privateKey, "base64url");
    const token = `${signingInput}.${signature}`;

    const result = await verifyJwt(decodeJwt(token), {
      publicKey,
      algorithms: ["ES256"],
    });

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe("ES256");
  });

  it("verifyJwt returns KID_MISMATCH error when JWT kid does not match any JWK kid", async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "jwk" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const header = { alg: "RS256", typ: "JWT", kid: "expected-key-id" };
    const payload = { sub: "test" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;

    const signer = crypto.createSign("SHA256");
    signer.update(signingInput);
    const signature = signer.sign(privateKey, "base64url");
    const token = `${signingInput}.${signature}`;

    const jwkWithDifferentKid = { ...publicKey, kid: "wrong-key-id", alg: "RS256" };

    const result = await verifyJwt(decodeJwt(token), {
      jwks: [jwkWithDifferentKid],
      algorithms: ["RS256"],
    });

    expect(result.valid).toBe(false);
    expect(result.code).toBe("KID_MISMATCH");
    expect(result.expectedKid).toBe("expected-key-id");
    expect(result.availableKids).toEqual(["wrong-key-id"]);
  });
});
