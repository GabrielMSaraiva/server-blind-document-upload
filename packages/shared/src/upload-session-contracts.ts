import { z } from "zod";
import {
  MAX_UPLOAD_SIZE_BYTES,
  uploadContentTypeSchema,
} from "./content-types.js";

export const createUploadSessionRequestSchema = z.object({
  organizationId: z.string().min(1),
  contentType: uploadContentTypeSchema,
  sizeBytes: z.number().int().positive().max(MAX_UPLOAD_SIZE_BYTES),
});

export const createUploadSessionResponseSchema = z.object({
  uploadSessionId: z.string().min(1),
  uploadSessionToken: z.string().min(64),
  storageKey: z.string().min(1),
  expiresAt: z.string().datetime(),
  uploadUrl: z.string().url(),
  uploadMethod: z.literal("PUT"),
});

export type CreateUploadSessionRequest = z.infer<
  typeof createUploadSessionRequestSchema
>;

export type CreateUploadSessionResponse = z.infer<
  typeof createUploadSessionResponseSchema
>;
