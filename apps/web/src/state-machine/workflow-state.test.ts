import { describe, expect, it } from "vitest";

import { transition } from "./workflow-state";

describe("upload workflow state machine", () => {
  it("accepts the encrypted upload happy path", () => {
    const states = [
      "key-ready",
      "validating",
      "encrypting",
      "requesting-session",
      "uploading",
      "persisting",
      "uploaded",
      "decrypting",
      "decrypted",
    ] as const;
    expect(states.reduce(transition, "idle")).toBe("decrypted");
  });

  it("rejects skipping browser-side encryption", () => {
    expect(() => transition("validating", "uploading")).toThrow("Invalid workflow transition");
  });
});
