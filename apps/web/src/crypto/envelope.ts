import {
  ENCRYPTION_VERSION,
  KEY_ENVELOPE_ALGORITHM,
  type KeyEnvelopeAlgorithm,
} from "@zk/shared";

const MAGIC = new TextEncoder().encode("SBDU");
const FORMAT_VERSION = 1;
const IV_LENGTH = 12;

export type EncryptedDocument = {
  ciphertextEnvelope: Uint8Array;
  sha256: string;
  wrappedDekBase64: string;
  encryptionVersion: typeof ENCRYPTION_VERSION;
  keyEnvelopeAlgorithm: KeyEnvelopeAlgorithm;
};

export async function generateRecipientKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function exportPublicKeyPem(publicKey: CryptoKey): Promise<string> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  const body = bytesToBase64(spki).match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
}

export async function encryptDocument(
  plaintext: Uint8Array,
  publicKey: CryptoKey,
): Promise<EncryptedDocument> {
  const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: copyToArrayBuffer(iv) },
      dataKey,
      copyToArrayBuffer(plaintext),
    ),
  );
  const rawDataKey = await crypto.subtle.exportKey("raw", dataKey);
  const wrappedDataKey = new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawDataKey),
  );
  const ciphertextEnvelope = concatenate(
    MAGIC,
    new Uint8Array([FORMAT_VERSION, IV_LENGTH]),
    iv,
    ciphertext,
  );
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", copyToArrayBuffer(ciphertextEnvelope)),
  );

  return {
    ciphertextEnvelope,
    sha256: bytesToHex(digest),
    wrappedDekBase64: bytesToBase64(wrappedDataKey),
    encryptionVersion: ENCRYPTION_VERSION,
    keyEnvelopeAlgorithm: KEY_ENVELOPE_ALGORITHM,
  };
}

export async function decryptDocument(
  ciphertextEnvelope: Uint8Array,
  wrappedDekBase64: string,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const { iv, ciphertext } = parseEnvelope(ciphertextEnvelope);
  const rawDataKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    copyToArrayBuffer(base64ToBytes(wrappedDekBase64)),
  );
  const dataKey = await crypto.subtle.importKey(
    "raw",
    rawDataKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: copyToArrayBuffer(iv) },
      dataKey,
      copyToArrayBuffer(ciphertext),
    ),
  );
}

function parseEnvelope(envelope: Uint8Array) {
  const minimumLength = MAGIC.length + 2 + IV_LENGTH + 16;
  if (envelope.byteLength < minimumLength) throw new Error("Ciphertext envelope is truncated.");
  if (!MAGIC.every((byte, index) => envelope[index] === byte)) {
    throw new Error("Ciphertext envelope magic is invalid.");
  }
  if (envelope[4] !== FORMAT_VERSION || envelope[5] !== IV_LENGTH) {
    throw new Error("Ciphertext envelope version is unsupported.");
  }
  return {
    iv: envelope.slice(6, 6 + IV_LENGTH),
    ciphertext: envelope.slice(6 + IV_LENGTH),
  };
}

function concatenate(...arrays: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(arrays.reduce((size, value) => size + value.byteLength, 0));
  let offset = 0;
  for (const value of arrays) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
