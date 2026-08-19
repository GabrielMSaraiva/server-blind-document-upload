import { z } from "zod";

export const KEY_ENVELOPE_ALGORITHM = "RSA-OAEP-SHA256";
export const PRIVATE_KEY_CIPHER_ALGORITHM = "AES-GCM-256";
export const PRIVATE_KEY_KDF_ALGORITHM = "PBKDF2-SHA256";
export const RECOVERY_BUNDLE_VERSION = 1;

export const base64Schema = z
  .string()
  .min(1)
  .regex(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    "Expected a Base64-encoded value",
  );

export const sha256HexSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/i, "Expected a SHA-256 hex digest");

export const publicKeyPemSchema = z
  .string()
  .min(1)
  .regex(
    /^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----$/,
    "Expected a PEM-encoded public key",
  );

export const keyEnvelopeAlgorithmSchema = z.literal(KEY_ENVELOPE_ALGORITHM);

export const encryptedPrivateKeyBundleSchema = z.object({
  privateKeyCiphertext: base64Schema,
  cipherAlgorithm: z.literal(PRIVATE_KEY_CIPHER_ALGORITHM),
  kdfAlgorithm: z.literal(PRIVATE_KEY_KDF_ALGORITHM),
  kdfSaltBase64: base64Schema,
  kdfIterations: z.number().int().min(100_000),
  nonceBase64: base64Schema,
  bundleVersion: z.literal(RECOVERY_BUNDLE_VERSION),
});

export type KeyEnvelopeAlgorithm = z.infer<typeof keyEnvelopeAlgorithmSchema>;

export type EncryptedPrivateKeyBundle = z.infer<
  typeof encryptedPrivateKeyBundleSchema
>;
