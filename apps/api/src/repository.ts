import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

import {
  KEY_ENVELOPE_ALGORITHM,
  UPLOAD_SESSION_TTL_SECONDS,
  type ArtifactMetadata,
  type ArtifactSummary,
  type UploadContentType,
} from "@zk/shared";

type RecipientKeyRecord = {
  id: string;
  organizationId: string;
  publicKeyPem: string;
  status: "ACTIVE";
  createdAt: Date;
};

export type UploadSessionRecord = {
  id: string;
  organizationId: string;
  recipientKeyId: string;
  storageKey: string;
  contentType: UploadContentType;
  sizeBytes: number;
  tokenHash: Buffer;
  expiresAt: Date;
  uploadedAt?: Date;
  usedAt?: Date;
};

export type ArtifactRecord = ArtifactMetadata & {
  id: string;
  organizationId: string;
  uploadSessionId: string;
  createdAt: Date;
};

export class DemoRepository {
  readonly #keysByOrganization = new Map<string, RecipientKeyRecord>();
  readonly #sessions = new Map<string, UploadSessionRecord>();
  readonly #artifacts = new Map<string, ArtifactRecord>();

  bootstrapRecipientKey(input: {
    organizationId: string;
    publicKeyPem: string;
  }): RecipientKeyRecord {
    const key: RecipientKeyRecord = {
      id: randomUUID(),
      organizationId: input.organizationId,
      publicKeyPem: input.publicKeyPem,
      status: "ACTIVE",
      createdAt: new Date(),
    };
    this.#keysByOrganization.set(input.organizationId, key);
    return key;
  }

  getActiveRecipientKey(organizationId: string): RecipientKeyRecord | undefined {
    return this.#keysByOrganization.get(organizationId);
  }

  createUploadSession(input: {
    organizationId: string;
    contentType: UploadContentType;
    sizeBytes: number;
  }): { session: UploadSessionRecord; token: string } {
    const recipientKey = this.getActiveRecipientKey(input.organizationId);
    if (!recipientKey) {
      throw new RepositoryError("RECIPIENT_KEY_REQUIRED", "Create a recipient key before uploading.");
    }

    const token = randomBytes(32).toString("hex");
    const session: UploadSessionRecord = {
      id: randomUUID(),
      organizationId: input.organizationId,
      recipientKeyId: recipientKey.id,
      storageKey: `${randomUUID()}.ciphertext`,
      contentType: input.contentType,
      sizeBytes: input.sizeBytes,
      tokenHash: hashToken(token),
      expiresAt: new Date(Date.now() + UPLOAD_SESSION_TTL_SECONDS * 1_000),
    };
    this.#sessions.set(session.id, session);
    return { session, token };
  }

  authorizeUpload(sessionId: string, token: string): UploadSessionRecord {
    const session = this.#sessions.get(sessionId);
    if (!session || !tokensMatch(session.tokenHash, token)) {
      throw new RepositoryError("INVALID_UPLOAD_TOKEN", "Upload session or token is invalid.");
    }
    assertSessionOpen(session);
    return session;
  }

  markUploaded(sessionId: string): void {
    const session = this.#sessions.get(sessionId);
    if (!session) throw new RepositoryError("SESSION_NOT_FOUND", "Upload session does not exist.");
    session.uploadedAt = new Date();
  }

  consumeSession(input: {
    token: string;
    organizationId: string;
    artifact: ArtifactMetadata;
  }): ArtifactRecord {
    const tokenHash = hashToken(input.token);
    const session = [...this.#sessions.values()].find((candidate) =>
      timingSafeEqual(candidate.tokenHash, tokenHash),
    );
    if (!session) throw new RepositoryError("INVALID_UPLOAD_TOKEN", "Upload session token is invalid.");
    assertSessionOpen(session);
    if (!session.uploadedAt) {
      throw new RepositoryError("UPLOAD_REQUIRED", "Ciphertext must be uploaded before metadata is persisted.");
    }
    if (session.organizationId !== input.organizationId) {
      throw new RepositoryError("SESSION_SCOPE_MISMATCH", "Organization does not match upload session.");
    }
    if (
      session.storageKey !== input.artifact.storageKey ||
      session.contentType !== input.artifact.contentType ||
      session.sizeBytes !== input.artifact.sizeBytes ||
      session.recipientKeyId !== input.artifact.recipientKeyId
    ) {
      throw new RepositoryError("SESSION_CONSTRAINT_MISMATCH", "Artifact metadata does not match upload session.");
    }

    // Synchronous check-and-set is atomic within one Node.js event-loop turn.
    session.usedAt = new Date();
    const artifact: ArtifactRecord = {
      ...input.artifact,
      id: randomUUID(),
      organizationId: input.organizationId,
      uploadSessionId: session.id,
      createdAt: new Date(),
    };
    this.#artifacts.set(artifact.id, artifact);
    return artifact;
  }

  getArtifact(id: string): ArtifactRecord | undefined {
    return this.#artifacts.get(id);
  }

  listArtifacts(organizationId: string): ArtifactSummary[] {
    return [...this.#artifacts.values()]
      .filter((artifact) => artifact.organizationId === organizationId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .map((artifact) => ({
        artifactId: artifact.id,
        organizationId: artifact.organizationId,
        storageKey: artifact.storageKey,
        contentType: artifact.contentType,
        sizeBytes: artifact.sizeBytes,
        sha256: artifact.sha256,
        encryptionVersion: artifact.encryptionVersion,
        recipientKeyId: artifact.recipientKeyId,
        createdAt: artifact.createdAt.toISOString(),
      }));
  }
}

export class RepositoryError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function tokensMatch(expected: Buffer, token: string): boolean {
  const actual = hashToken(token);
  return actual.length === expected.length && timingSafeEqual(expected, actual);
}

function assertSessionOpen(session: UploadSessionRecord): void {
  if (session.usedAt) throw new RepositoryError("SESSION_ALREADY_USED", "Upload session was already consumed.");
  if (session.expiresAt.getTime() <= Date.now()) {
    throw new RepositoryError("SESSION_EXPIRED", "Upload session expired.");
  }
}

export const recipientKeyAlgorithm = KEY_ENVELOPE_ALGORITHM;
