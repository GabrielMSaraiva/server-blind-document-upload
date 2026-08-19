import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { KEY_ENVELOPE_ALGORITHM } from "@zk/shared";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { ApiConfig } from "./config.js";
import { createServer } from "./server.js";

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
portfolio-demo-key
-----END PUBLIC KEY-----`;

describe("server-blind upload API", () => {
  let storageRoot: string;
  let config: ApiConfig;

  beforeEach(async () => {
    storageRoot = await mkdtemp(join(tmpdir(), "server-blind-upload-"));
    config = {
      port: 4000,
      baseUrl: "http://localhost:4000",
      webOrigin: "http://localhost:5173",
      localStorageRoot: storageRoot,
    };
  });

  afterEach(async () => {
    await rm(storageRoot, { recursive: true, force: true });
  });

  it("persists only ciphertext and rejects upload-session replay", async () => {
    const app = await createServer(config);
    const keyResponse = await app.inject({
      method: "POST",
      url: "/recipient-keys",
      payload: {
        organizationId: "demo-org",
        publicKeyPem: PUBLIC_KEY_PEM,
        algorithm: KEY_ENVELOPE_ALGORITHM,
      },
    });
    expect(keyResponse.statusCode).toBe(201);
    const recipientKeyId = keyResponse.json().recipientKeyId as string;

    const ciphertext = makeCiphertextEnvelope();
    const sessionResponse = await app.inject({
      method: "POST",
      url: "/upload-sessions",
      payload: {
        organizationId: "demo-org",
        contentType: "application/pdf",
        sizeBytes: ciphertext.byteLength,
      },
    });
    expect(sessionResponse.statusCode).toBe(201);
    const session = sessionResponse.json<{
      uploadSessionId: string;
      uploadSessionToken: string;
      storageKey: string;
    }>();

    const uploadResponse = await app.inject({
      method: "PUT",
      url: `/storage/${session.uploadSessionId}`,
      headers: {
        "content-type": "application/octet-stream",
        "x-upload-token": session.uploadSessionToken,
      },
      payload: ciphertext,
    });
    expect(uploadResponse.statusCode).toBe(204);

    const artifactRequest = {
      organizationId: "demo-org",
      uploadSessionToken: session.uploadSessionToken,
      artifact: {
        storageKey: session.storageKey,
        contentType: "application/pdf",
        sizeBytes: ciphertext.byteLength,
        sha256: createHash("sha256").update(ciphertext).digest("hex"),
        encryptionVersion: 2,
        wrappedDekBase64: randomBytes(32).toString("base64"),
        recipientKeyId,
        keyEnvelopeAlgorithm: KEY_ENVELOPE_ALGORITHM,
      },
    } as const;
    const artifactResponse = await app.inject({
      method: "POST",
      url: "/artifacts",
      payload: artifactRequest,
    });
    expect(artifactResponse.statusCode).toBe(201);
    const artifactId = artifactResponse.json().artifactId as string;

    const replayResponse = await app.inject({
      method: "POST",
      url: "/artifacts",
      payload: artifactRequest,
    });
    expect(replayResponse.statusCode).toBe(422);
    expect(replayResponse.json().error.code).toBe("SESSION_ALREADY_USED");

    const objectResponse = await app.inject({
      method: "GET",
      url: `/objects/${artifactId}`,
    });
    expect(objectResponse.statusCode).toBe(200);
    expect(objectResponse.rawPayload.equals(ciphertext)).toBe(true);
    await app.close();
  });

  it("rejects a digest that does not match stored ciphertext", async () => {
    const app = await createServer(config);
    const key = await bootstrap(app);
    const ciphertext = makeCiphertextEnvelope();
    const session = await createAndUpload(app, ciphertext);

    const response = await app.inject({
      method: "POST",
      url: "/artifacts",
      payload: {
        organizationId: "demo-org",
        uploadSessionToken: session.uploadSessionToken,
        artifact: {
          storageKey: session.storageKey,
          contentType: "application/pdf",
          sizeBytes: ciphertext.byteLength,
          sha256: "0".repeat(64),
          encryptionVersion: 2,
          wrappedDekBase64: randomBytes(32).toString("base64"),
          recipientKeyId: key,
          keyEnvelopeAlgorithm: KEY_ENVELOPE_ALGORITHM,
        },
      },
    });
    expect(response.statusCode).toBe(422);
    expect(response.json().error.code).toBe("HASH_MISMATCH");
    await app.close();
  });
});

function makeCiphertextEnvelope(): Buffer {
  return Buffer.concat([
    Buffer.from("SBDU", "ascii"),
    Buffer.from([1, 12]),
    randomBytes(12),
    randomBytes(64),
  ]);
}

async function bootstrap(app: Awaited<ReturnType<typeof createServer>>): Promise<string> {
  const response = await app.inject({
    method: "POST",
    url: "/recipient-keys",
    payload: {
      organizationId: "demo-org",
      publicKeyPem: PUBLIC_KEY_PEM,
      algorithm: KEY_ENVELOPE_ALGORITHM,
    },
  });
  return response.json().recipientKeyId as string;
}

async function createAndUpload(
  app: Awaited<ReturnType<typeof createServer>>,
  ciphertext: Buffer,
) {
  const sessionResponse = await app.inject({
    method: "POST",
    url: "/upload-sessions",
    payload: {
      organizationId: "demo-org",
      contentType: "application/pdf",
      sizeBytes: ciphertext.byteLength,
    },
  });
  const session = sessionResponse.json<{
    uploadSessionId: string;
    uploadSessionToken: string;
    storageKey: string;
  }>();
  const uploadResponse = await app.inject({
    method: "PUT",
    url: `/storage/${session.uploadSessionId}`,
    headers: {
      "content-type": "application/octet-stream",
      "x-upload-token": session.uploadSessionToken,
    },
    payload: ciphertext,
  });
  expect(uploadResponse.statusCode).toBe(204);
  return session;
}
