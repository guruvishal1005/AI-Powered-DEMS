import type { IntegrityStatus } from "../../lib/types";
import { labelize } from "../../lib/format";

const COPY: Record<IntegrityStatus, { label: string; className: string; meaning: string }> = {
  pending: {
    label: "Pending",
    className: "text-muted border-line bg-raised",
    meaning: "This artifact has not been verified since it was stored.",
  },
  verified: {
    label: "Verified",
    className: "text-status-verified border-status-verified/40 bg-status-verified/10",
    meaning: "Plaintext SHA-256 matches acquisition and AES-GCM authenticated the ciphertext.",
  },
  hash_mismatch: {
    label: "Hash mismatch",
    className: "text-status-critical border-status-critical/40 bg-status-critical/10",
    meaning: "Ciphertext decrypted, but the plaintext no longer matches the acquired SHA-256.",
  },
  decryption_failed: {
    label: "Storage auth failed",
    className: "text-status-critical border-status-critical/40 bg-status-critical/10",
    meaning: "AES-GCM rejected the stored ciphertext. The encrypted container was altered.",
  },
  object_missing: {
    label: "Object missing",
    className: "text-status-high border-status-high/40 bg-status-high/10",
    meaning: "The stored object is gone from disk. Restore from backup rather than re-acquire blindly.",
  },
};

export function IntegrityBadge({ status }: { status: IntegrityStatus | string }) {
  const info = COPY[status as IntegrityStatus] ?? {
    label: labelize(status),
    className: "text-muted border-line bg-raised",
    meaning: status,
  };
  return (
    <span
      title={info.meaning}
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${info.className}`}
    >
      {info.label}
    </span>
  );
}
