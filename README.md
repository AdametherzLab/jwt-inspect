[![CI](https://github.com/AdametherzLab/jwt-inspect/actions/workflows/ci.yml/badge.svg)](https://github.com/AdametherzLab/jwt-inspect/actions) [![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)](https://www.typescriptlang.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# jwt-inspect 🔐

Decode, inspect, and verify JWTs from your terminal with zero network calls, zero telemetry, and maximum paranoia. Because your tokens shouldn't touch a browser.

## Features

- 🔒 **100% Offline** — No network requests, no jwt.io, no data leakage, no browser DevTools
- 🎨 **Colorized Output** — Pretty-printed headers and payloads with smart syntax highlighting
- ⏰ **Smart Timing** — Human-readable expiry countdowns ("expires in 4h 12m") and clock skew detection
- 🔑 **Flexible Keys** — Support for PEM (RSA/EC), JWKS JSON, and single JWK files
- 🚨 **Clear Diagnostics** — Specific error codes for kid mismatch, algorithm mismatch, clock skew, and expired tokens

## Installation

```bash
npm install -g @adametherzlab/jwt-inspect
# or locally
npm install @adametherzlab/jwt-inspect

# Bun users
bun add @adametherzlab/jwt-inspect
```

## Quick Start

```bash
# Via npx (no install required)
npx @adametherzlab/jwt-inspect inspect eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature

# Or programmatically
// REMOVED external import: import { inspectJwt } from "@adametherzlab/jwt-inspect";

const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature" as const;
const result = inspectJwt(token);
console.log(result.timing.expiresIn?.text); // "expires in 2h 30m"
```

## CLI Usage

The `inspect` command decodes and displays JWT metadata with colorized output:

```bash
jwt-inspect inspect eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature
```

Sample output:
```
┌─────────────────────────────────────────┐
│  HEADER                                 │
├─────────────────────────────────────────┤
│  alg: RS256                             │
│  typ: JWT                               │
│  kid: "2024-key-1"                      │
├─────────────────────────────────────────┤
│  PAYLOAD                                │
├─────────────────────────────────────────┤
│  sub: "12345"                           │
│  exp: 1735689600 (expires in 4h 12m)    │
│  iat: 1735675200 (issued 2h ago)        │
│  custom_claim: "admin"                  │
└─────────────────────────────────────────┘
```

The `verify` command validates signatures against local keys:

```bash
# With PEM public key
jwt-inspect verify token.jwt --key public.pem

# With JWKS file (automatic kid matching)
jwt-inspect verify token.jwt --jwks keys.json

# With clock tolerance for skewed systems
jwt-inspect verify token.jwt --key key.pem --clock-tolerance 60
```

## Supported Key Formats

- **PEM RSA**: Standard `-----BEGIN PUBLIC KEY-----` files supporting RS256, RS384, RS512
- **PEM EC**: Elliptic Curve keys in PEM format for ES256, ES384, ES512
- **JWKS JSON**: Standard `{"keys": [...]}` format with automatic Key ID lookup
- **Single JWK**: Individual `{"kty": "RSA", "n": "...", "e": "..."}` objects

## Error Codes & Diagnostics

When verification fails, you get structured error codes instead of cryptic stack traces:

| Code | Meaning | Resolution |
|------|---------|------------|
| `KID_MISMATCH` | Key ID in token header not found in provided JWKS | Verify your JWKS file includes the key with matching `kid` |
| `CLOCK_SKEW` | Token timestamp outside allowed tolerance window | Sync system clock or increase `clockTolerance` option |
| `ALGORITHM_MISMATCH` | Token algorithm incompatible with provided key | Ensure key type matches algorithm (e.g., RSA key for RS256) |
| `INVALID_SIGNATURE` | Cryptographic signature verification failed | Token was tampered with or wrong key provided |
| `TOKEN_EXPIRED` | Current time exceeds `exp` claim | Token is expired, obtain a fresh one |
| `TOKEN_NOT_YET_VALID` | Current time precedes `nbf` claim | Token not yet active, check issuance timing |
| `MISSING_KEY` | No key provided for verification | Provide `--key` or `--jwks` argument |

## Security Rationale

Why offline-only matters: JWTs often contain sensitive claims (user IDs, roles, internal service metadata, PII). Pasting them into online decoders sends your tokens to third-party servers, creating audit trail nightmares, potential data breaches, and compliance violations. `jwt-inspect` runs entirely on your local machine using only Node.js/Bun built-in crypto modules — your tokens never leave your shell, never touch a network interface, and never get logged to external services.

## API Reference

#### `decodeJwt(token: JwtString): DecodedJwt`

```typescript
// REMOVED external import: import { decodeJwt, type JwtString } from "@adametherzlab/jwt-inspect";

const decoded = decodeJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig" as JwtString);
console.log(decoded.header.alg); // "HS256"
```

#### `inspectJwt(token: JwtString, currentTime?: number): InspectionResult`

```typescript
// REMOVED external import: import { inspectJwt } from "@adametherzlab/jwt-inspect";

const result = inspectJwt(token);
console.log(result.metadata.algorithm); // "RS256"
console.log(result.timing.expiresIn?.text); // "expires in 4h 12m"
```

#### `formatDuration(targetTimestamp: number, referenceTimestamp?: number): FormattedDuration`

```typescript
// REMOVED external import: import { formatDuration } from "@adametherzlab/jwt-inspect";

const duration = formatDuration(1893456000);
console.log(duration.text); // "expires in 2d 4h 30m"
```

#### `verifyJwt(decoded: DecodedJwt, options: VerificationOptions): VerificationResult`

```typescript
// REMOVED external import: import { verifyJwt, loadKey, type DecodedJwt } from "@adametherzlab/jwt-inspect";
import * as fs from "fs";

const decoded: DecodedJwt = decodeJwt(token);
const key = loadKey(fs.readFileSync("public.pem"));
const result = verifyJwt(decoded, { 
  publicKey: key, 
  algorithms: ["RS256"],
  clockTolerance: 30 
});

if (!result.valid) {
  console.error(`Verification failed: ${result.code} - ${result.reason}`);
}
```

#### `loadKey(source: string | Buffer): JsonWebKey | Buffer`

#### `renderInspectResult(result: InspectionResult, useColor?: boolean): string`

#### `renderVerifyResult(result: VerificationResult, useColor?: boolean): string`

#### `parseCliArgs(argv: string[]): ParsedArgs`

#### `runCli(): Promise<void>`

## Advanced Usage

```typescript
import { 
  decodeJwt, 
  inspectJwt, 
  verifyJwt, 
  loadKey,
  type JwtString,
  type VerificationError 
} from "@adametherzlab/jwt-inspect";
import * as fs from "fs";
import * as path from "path";

function validateToken(token: JwtString, keyDir: string) {
  // Step 1: Decode and inspect timing
  const inspection = inspectJwt(token);
  console.log(`Algorithm: ${inspection.metadata.algorithm}`);
  console.log(`Expires: ${inspection.timing.expiresIn?.text || "never"}`);
  
  // Step 2: Load appropriate key
  const keyPath = path.join(keyDir, "public.pem");
  const key = loadKey(fs.readFileSync(keyPath));
  
  // Step 3: Verify signature with tolerance for clock skew
  const verification = verifyJwt(inspection.decoded, {
    publicKey: key,
    algorithms: ["RS256", "ES256"],
    clockTolerance: 30 // 30 seconds leeway for distributed systems
  });
  
  if (!verification.valid) {
    const error = verification as VerificationError;
    throw new Error(`Security validation failed: ${error.code} - ${error.reason}`);
  }
  
  return inspection.decoded.payload;
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT (c) [AdametherzLab](https://github.com/AdametherzLab)