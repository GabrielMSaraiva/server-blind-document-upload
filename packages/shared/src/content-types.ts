import { z } from "zod";

export const ACCEPTED_UPLOAD_CONTENT_TYPES = [
  "application/pdf",
  "image/png",
  "image/jpeg",
] as const;

export const MAX_UPLOAD_SIZE_BYTES = 20 * 1024 * 1024;
export const ENCRYPTION_VERSION = 2;
export const UPLOAD_SESSION_TTL_SECONDS = 10 * 60;

export const uploadContentTypeSchema = z.enum(ACCEPTED_UPLOAD_CONTENT_TYPES);

export type UploadContentType = z.infer<typeof uploadContentTypeSchema>;

export type UploadPurpose = "DOCUMENT_ARTIFACT";
