export function Timestamp({
  value,
  relative = false,
}: {
  value: string | null | undefined;
  relative?: boolean;
}) {
  if (!value) return <span className="text-muted">—</span>;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return <span className="text-muted">—</span>;
  const absolute = `${date.toISOString().replace("T", " ").replace("Z", " UTC")}`;
  if (!relative) {
    return (
      <time dateTime={date.toISOString()} className="mono text-xs text-ink" title={absolute}>
        {absolute}
      </time>
    );
  }
  const delta = Date.now() - date.getTime();
  const minutes = Math.round(delta / 60_000);
  let label = "just now";
  if (Math.abs(minutes) >= 60 * 24) label = `${Math.round(minutes / (60 * 24))}d ago`;
  else if (Math.abs(minutes) >= 60) label = `${Math.round(minutes / 60)}h ago`;
  else if (Math.abs(minutes) >= 1) label = `${minutes}m ago`;
  return (
    <time dateTime={date.toISOString()} className="mono text-xs text-muted" title={absolute}>
      {label}
    </time>
  );
}
