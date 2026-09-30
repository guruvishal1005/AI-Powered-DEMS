import type { Provenance } from "../../lib/types";

const COPY: Record<Provenance, { label: string; hint: string }> = {
  derived: {
    label: "Derived",
    hint: "Produced by deterministic rules over persisted observations and entities.",
  },
  statistical: {
    label: "Statistical",
    hint: "Produced by a recorded statistical test (method, threshold, baseline).",
  },
  llm_assisted: {
    label: "LLM assisted",
    hint: "Narrative phrasing only. This provenance cannot write forensic facts.",
  },
};

export function ProvenanceTag({ provenance }: { provenance: Provenance | string }) {
  const info = COPY[provenance as Provenance] ?? {
    label: provenance,
    hint: provenance,
  };
  return (
    <span
      title={info.hint}
      className="inline-flex items-center rounded border border-line bg-raised px-1.5 py-0.5 text-[11px] uppercase tracking-wide text-muted"
    >
      {info.label}
    </span>
  );
}
