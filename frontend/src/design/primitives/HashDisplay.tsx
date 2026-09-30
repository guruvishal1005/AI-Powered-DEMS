import { useState } from "react";
import { truncateHash } from "../../lib/format";

export function HashDisplay({
  value,
  label = "SHA-256",
  compact = true,
}: {
  value: string | null | undefined;
  label?: string;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-muted">—</span>;

  async function copy() {
    await navigator.clipboard.writeText(value!);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  return (
    <button
      type="button"
      onClick={copy}
      title={`${label}: ${value}`}
      className="mono inline-flex max-w-full items-center gap-2 rounded px-1 py-0.5 text-left text-xs text-ink hover:bg-raised"
    >
      <span className="truncate">{compact ? truncateHash(value) : value}</span>
      <span className="text-muted">{copied ? "copied" : "copy"}</span>
    </button>
  );
}
