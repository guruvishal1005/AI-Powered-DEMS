import type { Severity } from "../../lib/types";
import { labelize } from "../../lib/format";

const TONE: Record<Severity, string> = {
  informational: "text-status-info border-status-info/40 bg-status-info/10",
  low: "text-status-low border-status-low/40 bg-status-low/10",
  medium: "text-status-medium border-status-medium/40 bg-status-medium/10",
  high: "text-status-high border-status-high/40 bg-status-high/10",
  critical: "text-status-critical border-status-critical/40 bg-status-critical/10",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const tone = TONE[severity as Severity] ?? "text-muted border-line bg-raised";
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${tone}`}>
      {labelize(severity)}
    </span>
  );
}
