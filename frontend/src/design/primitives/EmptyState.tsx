import type { ReactNode } from "react";

export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-line bg-canvas px-4 py-8">
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      <p className="max-w-xl text-sm text-muted">{body}</p>
      {action}
    </div>
  );
}
