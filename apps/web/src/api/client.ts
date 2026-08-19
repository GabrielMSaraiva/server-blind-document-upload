import type {
  ArtifactMetadata,
  BootstrapRecipientKeyResponse,
  CreateUploadSessionResponse,
  DownloadArtifactResponse,
  PersistArtifactResponse,
  UploadContentType,
} from "@zk/shared";

export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

export async function getHealth() {
  const response = await fetch(`${API_URL}/health`);

  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }

  return response.json() as Promise<{
    ok: boolean;
    service: string;
  }>;
}

export async function bootstrapRecipientKey(input: {
  organizationId: string;
  publicKeyPem: string;
}): Promise<BootstrapRecipientKeyResponse> {
  return requestJson("/recipient-keys", {
    method: "POST",
    body: JSON.stringify({ ...input, algorithm: "RSA-OAEP-SHA256" }),
  });
}

export async function createUploadSession(input: {
  organizationId: string;
  contentType: UploadContentType;
  sizeBytes: number;
}): Promise<CreateUploadSessionResponse> {
  return requestJson("/upload-sessions", { method: "POST", body: JSON.stringify(input) });
}

export async function uploadCiphertext(
  session: CreateUploadSessionResponse,
  ciphertext: Uint8Array,
): Promise<void> {
  const response = await fetch(session.uploadUrl, {
    method: session.uploadMethod,
    headers: {
      "content-type": "application/octet-stream",
      "x-upload-token": session.uploadSessionToken,
    },
    body: copyToArrayBuffer(ciphertext),
  });
  if (!response.ok) throw await apiError(response);
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function persistArtifact(input: {
  organizationId: string;
  uploadSessionToken: string;
  artifact: ArtifactMetadata;
}): Promise<PersistArtifactResponse> {
  return requestJson("/artifacts", { method: "POST", body: JSON.stringify(input) });
}

export async function getArtifactDownload(artifactId: string): Promise<DownloadArtifactResponse> {
  return requestJson(`/artifacts/${encodeURIComponent(artifactId)}/download`);
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
  if (!response.ok) throw await apiError(response);
  return response.json() as Promise<T>;
}

async function apiError(response: Response): Promise<Error> {
  const payload = (await response.json().catch(() => null)) as
    | { error?: { code?: string; message?: string } }
    | null;
  const code = payload?.error?.code ?? `HTTP_${response.status}`;
  const message = payload?.error?.message ?? "API request failed.";
  return new Error(`${code}: ${message}`);
}
