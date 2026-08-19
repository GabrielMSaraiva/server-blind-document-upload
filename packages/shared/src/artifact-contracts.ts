import { z } from "zod";
import {
  ENCRYPTION_VERSION,
  MAX_UPLOAD_SIZE_BYTES,
  uploadContentTypeSchema,
} from "./content-types.js";
import {
  base64Schema,
  keyEnvelopeAlgorithmSchema,
  sha256HexSchema,
} from "./crypto-contracts.js";

export const artifactMetadataSchema = z.object({
  storageKey: z.string().min(1),
  contentType: uploadContentTypeSchema,
  sizeBytes: z.number().int().positive().max(MAX_UPLOAD_SIZE_BYTES),
  sha256: sha256HexSchema,
  encryptionVersion: z.literal(ENCRYPTION_VERSION),
  wrappedDekBase64: base64Schema,
  recipientKeyId: z.string().min(1),
  keyEnvelopeAlgorithm: keyEnvelopeAlgorithmSchema,
});

export const persistArtifactRequestSchema = z.object({
  organizationId: z.string().min(1),
  uploadSessionToken: z.string().min(64),
  artifact: artifactMetadataSchema,
});

export const persistArtifactResponseSchema = z.object({
  artifactId: z.string().min(1),
  storageKey: z.string().min(1),
  createdAt: z.string().datetime(),
});

export const artifactSummarySchema = z.object({
  artifactId: z.string().min(1),
  organizationId: z.string().min(1),
  storageKey: z.string().min(1),
  contentType: uploadContentTypeSchema,
  sizeBytes: z.number().int().positive(),
  sha256: sha256HexSchema,
  encryptionVersion: z.literal(ENCRYPTION_VERSION),
  recipientKeyId: z.string().min(1),
  createdAt: z.string().datetime(),
});

export const downloadArtifactResponseSchema = z.object({
  downloadUrl: z.string().url(),
  urlExpiresAt: z.string().datetime(),
  artifact: artifactMetadataSchema.extend({
    artifactId: z.string().min(1),
  }),
});

export type ArtifactMetadata = z.infer<typeof artifactMetadataSchema>;

export type PersistArtifactRequest = z.infer<
  typeof persistArtifactRequestSchema
>;

export type PersistArtifactResponse = z.infer<
  typeof persistArtifactResponseSchema
>;

export type ArtifactSummary = z.infer<typeof artifactSummarySchema>;

export type DownloadArtifactResponse = z.infer<
  typeof downloadArtifactResponseSchema
>;
