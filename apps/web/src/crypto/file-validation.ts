import {
  ACCEPTED_UPLOAD_CONTENT_TYPES,
  MAX_UPLOAD_SIZE_BYTES,
  type UploadContentType,
} from "@zk/shared";

export type ValidatedDocument = {
  bytes: Uint8Array;
  contentType: UploadContentType;
};

export async function validateDocument(file: File): Promise<ValidatedDocument> {
  if (!ACCEPTED_UPLOAD_CONTENT_TYPES.includes(file.type as UploadContentType)) {
    throw new Error("Choose a PDF, PNG, or JPEG document.");
  }
  if (file.size === 0 || file.size > MAX_UPLOAD_SIZE_BYTES) {
    throw new Error("Document must contain data and be no larger than 20 MB.");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const contentType = file.type as UploadContentType;
  if (!matchesSignature(bytes, contentType)) {
    throw new Error(`File bytes do not match declared type ${contentType}.`);
  }
  return { bytes, contentType };
}

export function matchesSignature(bytes: Uint8Array, contentType: UploadContentType): boolean {
  switch (contentType) {
    case "application/pdf": {
      const header = new TextDecoder().decode(bytes.slice(0, 5));
      const tail = new TextDecoder().decode(bytes.slice(Math.max(0, bytes.length - 1_024)));
      return header === "%PDF-" && tail.includes("%%EOF");
    }
    case "image/png":
      return startsWith(bytes, [137, 80, 78, 71, 13, 10, 26, 10]) && containsAscii(bytes, "IEND");
    case "image/jpeg":
      return (
        bytes.length >= 4 &&
        bytes[0] === 0xff &&
        bytes[1] === 0xd8 &&
        bytes[2] === 0xff &&
        bytes.at(-2) === 0xff &&
        bytes.at(-1) === 0xd9
      );
  }
}

function startsWith(bytes: Uint8Array, expected: number[]): boolean {
  return expected.every((byte, index) => bytes[index] === byte);
}

function containsAscii(bytes: Uint8Array, value: string): boolean {
  const needle = new TextEncoder().encode(value);
  return bytes.some((_, index) => needle.every((byte, offset) => bytes[index + offset] === byte));
}
