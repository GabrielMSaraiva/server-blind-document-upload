import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const STORAGE_KEY_PATTERN = /^[0-9a-f-]+\.ciphertext$/i;

export class LocalCiphertextStorage {
  readonly #root: string;

  constructor(root: string) {
    this.#root = resolve(root);
  }

  async put(storageKey: string, bytes: Buffer): Promise<void> {
    await mkdir(this.#root, { recursive: true });
    await writeFile(this.#pathFor(storageKey), bytes, { flag: "wx" });
  }

  async get(storageKey: string): Promise<Buffer> {
    return readFile(this.#pathFor(storageKey));
  }

  #pathFor(storageKey: string): string {
    if (!STORAGE_KEY_PATTERN.test(storageKey)) {
      throw new Error("Invalid storage key");
    }
    return resolve(this.#root, storageKey);
  }
}
