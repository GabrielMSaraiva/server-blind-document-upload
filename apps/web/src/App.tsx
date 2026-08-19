import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ArtifactMetadata, UploadContentType } from "@zk/shared";

import {
  bootstrapRecipientKey,
  createUploadSession,
  getArtifactDownload,
  persistArtifact,
  uploadCiphertext,
} from "./api/client";
import {
  decryptDocument,
  encryptDocument,
  exportPublicKeyPem,
  generateRecipientKeyPair,
} from "./crypto/envelope";
import { validateDocument } from "./crypto/file-validation";
import { transition, type WorkflowState } from "./state-machine/workflow-state";

const ORGANIZATION_ID = "portfolio-demo";

type UploadedArtifact = {
  id: string;
  fileName: string;
  contentType: UploadContentType;
  metadata: ArtifactMetadata;
};

export function App() {
  const keyPair = useRef<CryptoKeyPair | null>(null);
  const [recipientKeyId, setRecipientKeyId] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [workflow, setWorkflow] = useState<WorkflowState>("idle");
  const [artifact, setArtifact] = useState<UploadedArtifact | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  function move(next: WorkflowState) {
    setWorkflow((current) => transition(current, next));
  }

  async function setUpRecipientKey() {
    setError(null);
    try {
      const pair = await generateRecipientKeyPair();
      const publicKeyPem = await exportPublicKeyPem(pair.publicKey);
      const response = await bootstrapRecipientKey({
        organizationId: ORGANIZATION_ID,
        publicKeyPem,
      });
      keyPair.current = pair;
      setRecipientKeyId(response.recipientKeyId);
      move("key-ready");
    } catch (cause) {
      fail(cause);
    }
  }

  async function upload(event: FormEvent) {
    event.preventDefault();
    if (!selectedFile || !keyPair.current || !recipientKeyId) {
      setError("Create a local recipient key and choose a document first.");
      return;
    }
    setError(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }

    try {
      move("validating");
      const validated = await validateDocument(selectedFile);
      move("encrypting");
      const encrypted = await encryptDocument(validated.bytes, keyPair.current.publicKey);
      move("requesting-session");
      const session = await createUploadSession({
        organizationId: ORGANIZATION_ID,
        contentType: validated.contentType,
        sizeBytes: encrypted.ciphertextEnvelope.byteLength,
      });
      move("uploading");
      await uploadCiphertext(session, encrypted.ciphertextEnvelope);
      move("persisting");
      const metadata: ArtifactMetadata = {
        storageKey: session.storageKey,
        contentType: validated.contentType,
        sizeBytes: encrypted.ciphertextEnvelope.byteLength,
        sha256: encrypted.sha256,
        encryptionVersion: encrypted.encryptionVersion,
        wrappedDekBase64: encrypted.wrappedDekBase64,
        recipientKeyId,
        keyEnvelopeAlgorithm: encrypted.keyEnvelopeAlgorithm,
      };
      const persisted = await persistArtifact({
        organizationId: ORGANIZATION_ID,
        uploadSessionToken: session.uploadSessionToken,
        artifact: metadata,
      });
      setArtifact({
        id: persisted.artifactId,
        fileName: selectedFile.name,
        contentType: validated.contentType,
        metadata,
      });
      move("uploaded");
    } catch (cause) {
      fail(cause);
    }
  }

  async function decryptPreview() {
    if (!artifact || !keyPair.current) return;
    setError(null);
    try {
      move("decrypting");
      const download = await getArtifactDownload(artifact.id);
      const response = await fetch(download.downloadUrl);
      if (!response.ok) throw new Error(`Ciphertext download failed: ${response.status}`);
      const ciphertext = new Uint8Array(await response.arrayBuffer());
      const plaintext = await decryptDocument(
        ciphertext,
        download.artifact.wrappedDekBase64,
        keyPair.current.privateKey,
      );
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      const plaintextBuffer = plaintext.buffer.slice(
        plaintext.byteOffset,
        plaintext.byteOffset + plaintext.byteLength,
      ) as ArrayBuffer;
      setPreviewUrl(URL.createObjectURL(new Blob([plaintextBuffer], { type: artifact.contentType })));
      move("decrypted");
    } catch (cause) {
      fail(cause);
    }
  }

  function fail(cause: unknown) {
    setError(cause instanceof Error ? cause.message : "Unexpected workflow error.");
    setWorkflow("error");
  }

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Browser cryptography + constrained API</p>
          <h1>Server-blind document upload</h1>
          <p className="lede">
            Plaintext is validated and encrypted in this browser. API stores ciphertext, a wrapped one-time key,
            and auditable metadata—never readable document bytes.
          </p>
        </div>
        <div className="guarantee">
          <strong>Threat boundary</strong>
          <span>Server compromise exposes encrypted objects, not plaintext documents.</span>
        </div>
      </header>

      <section className="flow" aria-label="Encryption flow">
        <span>1 · validate bytes</span><i>→</i><span>2 · AES-GCM encrypt</span><i>→</i>
        <span>3 · RSA wrap key</span><i>→</i><span>4 · upload ciphertext</span>
      </section>

      <div className="workspace">
        <section className="panel control-panel">
          <div className="panel-heading">
            <div>
              <p className="step">Step 01</p>
              <h2>Recipient key</h2>
            </div>
            <StatusBadge state={recipientKeyId ? "ready" : "required"} />
          </div>
          <p>RSA-OAEP key pair stays in browser memory. API receives public key only.</p>
          <button className="button secondary" type="button" onClick={setUpRecipientKey}>
            {recipientKeyId ? "Rotate local demo key" : "Generate local key"}
          </button>

          <hr />

          <div className="panel-heading">
            <div>
              <p className="step">Step 02</p>
              <h2>Encrypt and upload</h2>
            </div>
            <StatusBadge state={artifact ? "complete" : "waiting"} />
          </div>
          <form onSubmit={upload}>
            <label className="file-field">
              <span>PDF, PNG, or JPEG · 20 MB max</span>
              <input
                type="file"
                accept="application/pdf,image/png,image/jpeg"
                onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <button className="button primary" type="submit" disabled={!recipientKeyId || !selectedFile || isBusy(workflow)}>
              {isBusy(workflow) ? statusLabel(workflow) : "Encrypt in browser and upload"}
            </button>
          </form>
          {error ? <p className="error" role="alert">{error}</p> : null}
        </section>

        <section className="panel evidence-panel">
          <p className="step">Live evidence</p>
          <h2>What server can inspect</h2>
          {artifact ? (
            <dl className="metadata">
              <div><dt>State</dt><dd>{workflow}</dd></div>
              <div><dt>Object</dt><dd>{artifact.metadata.storageKey}</dd></div>
              <div><dt>Encrypted bytes</dt><dd>{formatBytes(artifact.metadata.sizeBytes)}</dd></div>
              <div><dt>SHA-256</dt><dd className="digest">{artifact.metadata.sha256}</dd></div>
              <div><dt>Envelope</dt><dd>v{artifact.metadata.encryptionVersion} · RSA-OAEP-SHA256</dd></div>
            </dl>
          ) : (
            <div className="empty-state">
              <span>SBDU</span>
              <p>Upload metadata appears here. Plaintext never does.</p>
            </div>
          )}

          {artifact ? (
            <div className="decrypt-box">
              <div>
                <p className="step">Step 03</p>
                <h3>Prove local decryption</h3>
              </div>
              <button className="button secondary" type="button" onClick={decryptPreview} disabled={workflow === "decrypting"}>
                {workflow === "decrypting" ? "Decrypting locally…" : "Download ciphertext + decrypt"}
              </button>
              {previewUrl ? (
                <a className="download" href={previewUrl} download={`decrypted-${artifact.fileName}`}>
                  Download decrypted {artifact.fileName}
                </a>
              ) : null}
            </div>
          ) : null}
        </section>
      </div>

      <footer>
        <span>Local demo storage · single-use upload tokens · digest verification · no formal ZK proofs</span>
        <a href="https://github.com/GabrielMSaraiva/server-blind-document-upload">View source</a>
      </footer>
    </main>
  );
}

function StatusBadge({ state }: { state: string }) {
  return <span className={`status ${state}`}>{state}</span>;
}

function isBusy(state: WorkflowState): boolean {
  return ["validating", "encrypting", "requesting-session", "uploading", "persisting"].includes(state);
}

function statusLabel(state: WorkflowState): string {
  const labels: Partial<Record<WorkflowState, string>> = {
    validating: "Validating file bytes…",
    encrypting: "Encrypting locally…",
    "requesting-session": "Requesting upload session…",
    uploading: "Uploading ciphertext…",
    persisting: "Verifying digest…",
  };
  return labels[state] ?? "Working…";
}

function formatBytes(bytes: number): string {
  return bytes < 1_024 ? `${bytes} B` : `${(bytes / 1_024).toFixed(1)} KB`;
}
