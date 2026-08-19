export const workflowStates = [
  "idle",
  "key-ready",
  "validating",
  "encrypting",
  "requesting-session",
  "uploading",
  "persisting",
  "uploaded",
  "decrypting",
  "decrypted",
  "error",
] as const;

export type WorkflowState = (typeof workflowStates)[number];

const transitions: Record<WorkflowState, readonly WorkflowState[]> = {
  idle: ["key-ready", "error"],
  "key-ready": ["key-ready", "validating", "error"],
  validating: ["encrypting", "error"],
  encrypting: ["requesting-session", "error"],
  "requesting-session": ["uploading", "error"],
  uploading: ["persisting", "error"],
  persisting: ["uploaded", "error"],
  uploaded: ["validating", "decrypting", "key-ready", "error"],
  decrypting: ["decrypted", "error"],
  decrypted: ["validating", "decrypting", "key-ready", "error"],
  error: ["key-ready", "validating", "decrypting", "error"],
};

export function transition(current: WorkflowState, next: WorkflowState): WorkflowState {
  if (!transitions[current].includes(next)) {
    throw new Error(`Invalid workflow transition: ${current} -> ${next}`);
  }
  return next;
}
