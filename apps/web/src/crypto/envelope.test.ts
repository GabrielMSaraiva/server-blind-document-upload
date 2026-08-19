import { describe, expect, it } from "vitest";

import { decryptDocument, encryptDocument, generateRecipientKeyPair } from "./envelope";

describe("browser envelope encryption", () => {
  it("round-trips plaintext with a wrapped one-time data key", async () => {
    const keyPair = await generateRecipientKeyPair();
    const plaintext = new TextEncoder().encode("plaintext stays in browser memory");
    const encrypted = await encryptDocument(plaintext, keyPair.publicKey);
    const decrypted = await decryptDocument(
      encrypted.ciphertextEnvelope,
      encrypted.wrappedDekBase64,
      keyPair.privateKey,
    );

    expect(new TextDecoder().decode(decrypted)).toBe("plaintext stays in browser memory");
    expect(encrypted.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(new TextDecoder().decode(encrypted.ciphertextEnvelope.slice(0, 4))).toBe("SBDU");
  });

  it("fails decryption with an unrelated recipient key", async () => {
    const owner = await generateRecipientKeyPair();
    const attacker = await generateRecipientKeyPair();
    const encrypted = await encryptDocument(new Uint8Array([1, 2, 3]), owner.publicKey);

    await expect(
      decryptDocument(encrypted.ciphertextEnvelope, encrypted.wrappedDekBase64, attacker.privateKey),
    ).rejects.toThrow();
  });
});
