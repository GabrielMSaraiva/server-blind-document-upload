import cors from "@fastify/cors";
import { createHash } from "node:crypto";
import Fastify, { type FastifyReply } from "fastify";
import {
  MAX_UPLOAD_SIZE_BYTES,
  activeRecipientKeyResponseSchema,
  artifactSummarySchema,
  bootstrapRecipientKeyRequestSchema,
  createUploadSessionRequestSchema,
  downloadArtifactResponseSchema,
  persistArtifactRequestSchema,
} from "@zk/shared";

import type { ApiConfig } from "./config.js";
import { DemoRepository, RepositoryError, recipientKeyAlgorithm } from "./repository.js";
import { LocalCiphertextStorage } from "./storage.js";

type ServerDependencies = {
  repository?: DemoRepository;
  storage?: LocalCiphertextStorage;
};

export async function createServer(config: ApiConfig, dependencies: ServerDependencies = {}) {
  const repository = dependencies.repository ?? new DemoRepository();
  const storage = dependencies.storage ?? new LocalCiphertextStorage(config.localStorageRoot);
  const app = Fastify({
    logger: process.env.NODE_ENV !== "test",
    bodyLimit: MAX_UPLOAD_SIZE_BYTES + 128,
  });

  app.addContentTypeParser(
    "application/octet-stream",
    { parseAs: "buffer" },
    (_request, body, done) => done(null, body),
  );

  await app.register(cors, {
    origin: config.webOrigin,
    methods: ["GET", "POST", "PUT"],
    allowedHeaders: ["content-type", "x-upload-token"],
  });

  app.get("/health", async () => ({
    ok: true,
    service: "server-blind-document-upload-api",
  }));

  app.post("/recipient-keys", async (request, reply) => {
    const parsed = bootstrapRecipientKeyRequestSchema.safeParse(request.body);
    if (!parsed.success) return validationProblem(reply, parsed.error.flatten());
    const key = repository.bootstrapRecipientKey(parsed.data);
    return reply.code(201).send({
      recipientKeyId: key.id,
      organizationId: key.organizationId,
      algorithm: recipientKeyAlgorithm,
      status: key.status,
    });
  });

  app.get("/recipient-keys/active", async (request, reply) => {
    const organizationId = queryOrganizationId(request.query);
    if (!organizationId) return problem(reply, 400, "ORGANIZATION_REQUIRED", "organizationId is required.");
    const key = repository.getActiveRecipientKey(organizationId);
    if (!key) return problem(reply, 404, "RECIPIENT_KEY_NOT_FOUND", "No active recipient key exists.");
    return activeRecipientKeyResponseSchema.parse({
      recipientKeyId: key.id,
      organizationId: key.organizationId,
      publicKeyPem: key.publicKeyPem,
      algorithm: recipientKeyAlgorithm,
      status: key.status,
    });
  });

  app.post("/upload-sessions", async (request, reply) => {
    const parsed = createUploadSessionRequestSchema.safeParse(request.body);
    if (!parsed.success) return validationProblem(reply, parsed.error.flatten());
    try {
      const { session, token } = repository.createUploadSession(parsed.data);
      return reply.code(201).send({
        uploadSessionId: session.id,
        uploadSessionToken: token,
        storageKey: session.storageKey,
        expiresAt: session.expiresAt.toISOString(),
        uploadUrl: `${config.baseUrl}/storage/${session.id}`,
        uploadMethod: "PUT",
      });
    } catch (error) {
      return repositoryProblem(reply, error);
    }
  });

  app.put<{ Params: { sessionId: string }; Body: Buffer }>(
    "/storage/:sessionId",
    async (request, reply) => {
      const token = headerValue(request.headers["x-upload-token"]);
      if (!token) return problem(reply, 401, "UPLOAD_TOKEN_REQUIRED", "x-upload-token header is required.");
      if (!Buffer.isBuffer(request.body)) {
        return problem(reply, 415, "CIPHERTEXT_REQUIRED", "Use application/octet-stream.");
      }
      try {
        const session = repository.authorizeUpload(request.params.sessionId, token);
        if (request.body.byteLength !== session.sizeBytes) {
          return problem(reply, 422, "SIZE_MISMATCH", "Ciphertext size does not match upload session.");
        }
        if (!isCiphertextEnvelope(request.body)) {
          return problem(reply, 422, "INVALID_ENVELOPE", "Ciphertext envelope header is invalid.");
        }
        await storage.put(session.storageKey, request.body);
        repository.markUploaded(session.id);
        return reply.code(204).send();
      } catch (error) {
        return repositoryProblem(reply, error);
      }
    },
  );

  app.post("/artifacts", async (request, reply) => {
    const parsed = persistArtifactRequestSchema.safeParse(request.body);
    if (!parsed.success) return validationProblem(reply, parsed.error.flatten());
    try {
      const bytes = await storage.get(parsed.data.artifact.storageKey);
      const actualSha256 = createHash("sha256").update(bytes).digest("hex");
      if (actualSha256 !== parsed.data.artifact.sha256.toLowerCase()) {
        return problem(reply, 422, "HASH_MISMATCH", "Ciphertext digest does not match uploaded bytes.");
      }
      const artifact = repository.consumeSession({
        token: parsed.data.uploadSessionToken,
        organizationId: parsed.data.organizationId,
        artifact: parsed.data.artifact,
      });
      return reply.code(201).send({
        artifactId: artifact.id,
        storageKey: artifact.storageKey,
        createdAt: artifact.createdAt.toISOString(),
      });
    } catch (error) {
      return repositoryProblem(reply, error);
    }
  });

  app.get("/artifacts", async (request, reply) => {
    const organizationId = queryOrganizationId(request.query);
    if (!organizationId) return problem(reply, 400, "ORGANIZATION_REQUIRED", "organizationId is required.");
    return artifactSummarySchema.array().parse(repository.listArtifacts(organizationId));
  });

  app.get<{ Params: { artifactId: string } }>("/artifacts/:artifactId/download", async (request, reply) => {
    const artifact = repository.getArtifact(request.params.artifactId);
    if (!artifact) return problem(reply, 404, "ARTIFACT_NOT_FOUND", "Artifact does not exist.");
    return downloadArtifactResponseSchema.parse({
      downloadUrl: `${config.baseUrl}/objects/${artifact.id}`,
      urlExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      artifact: {
        artifactId: artifact.id,
        storageKey: artifact.storageKey,
        contentType: artifact.contentType,
        sizeBytes: artifact.sizeBytes,
        sha256: artifact.sha256,
        encryptionVersion: artifact.encryptionVersion,
        wrappedDekBase64: artifact.wrappedDekBase64,
        recipientKeyId: artifact.recipientKeyId,
        keyEnvelopeAlgorithm: artifact.keyEnvelopeAlgorithm,
      },
    });
  });

  app.get<{ Params: { artifactId: string } }>("/objects/:artifactId", async (request, reply) => {
    const artifact = repository.getArtifact(request.params.artifactId);
    if (!artifact) return problem(reply, 404, "ARTIFACT_NOT_FOUND", "Artifact does not exist.");
    try {
      const bytes = await storage.get(artifact.storageKey);
      return reply.type("application/octet-stream").send(bytes);
    } catch {
      return problem(reply, 404, "OBJECT_NOT_FOUND", "Ciphertext object does not exist.");
    }
  });

  return app;
}

function queryOrganizationId(query: unknown): string | undefined {
  if (!query || typeof query !== "object") return undefined;
  const value = (query as Record<string, unknown>).organizationId;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isCiphertextEnvelope(bytes: Buffer): boolean {
  const minimumLength = 4 + 1 + 1 + 12 + 16;
  return (
    bytes.byteLength >= minimumLength &&
    bytes.subarray(0, 4).toString("ascii") === "SBDU" &&
    bytes[4] === 1 &&
    bytes[5] === 12
  );
}

function validationProblem(reply: FastifyReply, details: unknown) {
  return reply.code(400).send({
    error: { code: "VALIDATION_ERROR", message: "Request validation failed.", details },
  });
}

function repositoryProblem(reply: FastifyReply, error: unknown) {
  if (error instanceof RepositoryError) {
    const status = error.code === "RECIPIENT_KEY_REQUIRED" ? 409 : 422;
    return problem(reply, status, error.code, error.message);
  }
  if (error instanceof Error && "code" in error && error.code === "ENOENT") {
    return problem(reply, 422, "OBJECT_NOT_FOUND", "Uploaded ciphertext object does not exist.");
  }
  if (error instanceof Error && "code" in error && error.code === "EEXIST") {
    return problem(reply, 409, "OBJECT_ALREADY_UPLOADED", "Upload target already contains ciphertext.");
  }
  throw error;
}

function problem(reply: FastifyReply, status: number, code: string, message: string) {
  return reply.code(status).send({ error: { code, message } });
}
