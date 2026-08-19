# Server-Blind Document Upload

[![CI](https://github.com/GabrielMSaraiva/server-blind-document-upload/actions/workflows/ci.yml/badge.svg)](https://github.com/GabrielMSaraiva/server-blind-document-upload/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2B8765.svg)](LICENSE)

Browser-side envelope encryption paired with a constrained upload API. Plaintext documents never cross the browser/server boundary.

This is an independent educational implementation built from public cryptographic primitives and generic secure-upload patterns. It contains no proprietary source code, production endpoints, credentials, customer data, or company assets.

## What it demonstrates

- RSA-OAEP recipient keys generated in the browser.
- Per-document AES-256-GCM data keys.
- RSA-wrapped data keys and a versioned ciphertext envelope.
- File-signature validation before encryption.
- Short-lived, single-use upload tokens stored as SHA-256 hashes.
- Server-enforced organization, object key, content type, size, and recipient-key constraints.
- Ciphertext digest verification before metadata persistence.
- Local download and decryption with a private key held only in browser memory.
- Explicit frontend workflow states instead of scattered loading booleans.
- API tests for replay and tampering; browser tests for encryption and file validation.

## Boundary

```text
Browser                              API / storage

validate file signature
generate AES-GCM key
encrypt plaintext
wrap AES key with RSA public key
       |
       | ciphertext + wrapped key + digest
       v
                               validate one-time session
                               validate envelope and size
                               store ciphertext object
                               verify SHA-256
                               persist metadata
       |
       | download ciphertext
       v
unwrap AES key with local private key
decrypt in browser memory
```

Server can inspect ciphertext length, digest, envelope version, content-type claim, recipient-key ID, and audit constraints. Server cannot decrypt document because private RSA key never leaves browser memory.

## Run locally

Requires Node.js 22+.

```bash
npm install
copy apps\api\.env.example apps\api\.env
copy apps\web\.env.example apps\web\.env
npm run dev
```

Open `http://localhost:5173`, generate a local key, then upload a PDF, PNG, or JPEG. API listens on `http://localhost:4000` and stores ciphertext under `apps/api/.local-storage`.

macOS/Linux environment setup:

```bash
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env
```

## Verify

```bash
npm run ci
```

This runs strict TypeScript checks, Vitest suites, and production builds for shared contracts, Fastify API, and React client.

## API flow

1. `POST /recipient-keys` registers browser-generated public key.
2. `POST /upload-sessions` binds an expiring token to organization, size, content type, storage key, and recipient key.
3. `PUT /storage/:sessionId` accepts a versioned ciphertext envelope once.
4. `POST /artifacts` verifies stored bytes and atomically consumes session.
5. `GET /artifacts/:id/download` returns ciphertext location plus cryptographic metadata.
6. Browser unwraps data key and decrypts document locally.

## Security properties

- Upload tokens use 256 bits of randomness; repository stores only token hashes.
- Token comparison uses constant-time digest comparison.
- Storage keys use server-generated UUIDs and a strict allowlist pattern.
- Local object writes use create-only semantics.
- AES-GCM authenticates ciphertext and detects decryption-time tampering.
- SHA-256 binds persisted artifact metadata to stored ciphertext.
- Session constraints block object-key, content-type, size, organization, and recipient-key substitution.
- Session replay fails after first successful persistence.

See [SECURITY.md](SECURITY.md) for threat model and production gaps.

## Deliberate demo limits

- “Server-blind” describes product boundary. Project does not implement formal zero-knowledge proofs.
- Metadata repository is in memory and resets when API restarts.
- Ciphertext storage uses local disk, not S3.
- Demo has one explicit organization context and no authentication layer.
- Browser private key is ephemeral. Refresh requires generating a new demo key.
- Upload endpoint is local API route, not cloud presigned POST.

Production version needs authenticated tenant context, durable transactional database, S3-compatible object storage, rate limiting, key rotation/recovery, audit persistence, malware policy, lifecycle deletion, and externally reviewed cryptographic design.

## Structure

```text
apps/api       Fastify routes, session repository, local ciphertext adapter
apps/web       React workflow, Web Crypto envelope, file validation
packages/shared  Zod contracts and security constants
```

## License

MIT
