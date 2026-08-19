import { describe, expect, it } from "vitest";

import { matchesSignature } from "./file-validation";

describe("document signature validation", () => {
  it("accepts a PDF header and EOF marker", () => {
    expect(matchesSignature(new TextEncoder().encode("%PDF-1.7\nbody\n%%EOF"), "application/pdf")).toBe(true);
  });

  it("rejects text masquerading as a PDF", () => {
    expect(matchesSignature(new TextEncoder().encode("invoice.pdf"), "application/pdf")).toBe(false);
  });

  it("accepts bounded JPEG markers", () => {
    expect(matchesSignature(new Uint8Array([0xff, 0xd8, 0xff, 1, 2, 0xff, 0xd9]), "image/jpeg")).toBe(true);
  });
});
