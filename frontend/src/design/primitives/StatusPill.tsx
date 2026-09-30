import { labelize } from "../../lib/format";

export function StatusPill({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-line bg-raised px-2 py-0.5 text-xs text-ink">
      {labelize(value)}
    </span>
  );
}
