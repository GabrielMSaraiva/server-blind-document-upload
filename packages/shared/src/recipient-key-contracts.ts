import { z } from "zod";
import {
  keyEnvelopeAlgorithmSchema,
  publicKeyPemSchema,
} from "./crypto-contracts.js";

export const recipientKeyStatusSchema = z.enum([
  "ACTIVE",
  "ROTATED",
  "REVOKED",
]);

export const bootstrapRecipientKeyRequestSchema = z.object({
  organizationId: z.string().min(1),
  publicKeyPem: publicKeyPemSchema,
  algorithm: keyEnvelopeAlgorithmSchema,
  deviceLabel: z.string().trim().min(1).max(80).optional(),
});

export const bootstrapRecipientKeyResponseSchema = z.object({
  recipientKeyId: z.string().min(1),
  organizationId: z.string().min(1),
  algorithm: keyEnvelopeAlgorithmSchema,
  status: recipientKeyStatusSchema,
});

export const activeRecipientKeyResponseSchema = z.object({
  recipientKeyId: z.string().min(1),
  organizationId: z.string().min(1),
  publicKeyPem: publicKeyPemSchema,
  algorithm: keyEnvelopeAlgorithmSchema,
  status: z.literal("ACTIVE"),
});

export type RecipientKeyStatus = z.infer<typeof recipientKeyStatusSchema>;

export type BootstrapRecipientKeyRequest = z.infer<
  typeof bootstrapRecipientKeyRequestSchema
>;

export type BootstrapRecipientKeyResponse = z.infer<
  typeof bootstrapRecipientKeyResponseSchema
>;

export type ActiveRecipientKeyResponse = z.infer<
  typeof activeRecipientKeyResponseSchema
>;
