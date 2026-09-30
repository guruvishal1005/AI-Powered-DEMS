import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Timeline, TimelineEvent } from "../lib/types";
import { Card, ErrorState, SkeletonRows, Timestamp } from "../design/primitives";

const SOURCES = ["custody", "observation", "analysis_finding", "finding", "lifecycle", "alert", "integrity"];

export function TimelinePanel({ caseId }: { caseId?: string }) {
  const [source, setSource] = useState<string>("");
  const [brush, setBrush] = useState<{ start: string; end: string } | null>(null);
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["timeline", caseId, source, brush],
    queryFn: () => {
      const params = new URLSearchParams();
      if (caseId) params.set("case_id", caseId);
      if (source) params.append("sources", source);
      if (brush) {
        params.set("window_start", brush.start);
        params.set("window_end", brush.end);
      }
      params.set("limit", "1500");
      return api<Timeline>(`/timeline?${params}`);
    },
  });

  const events = query.data?.events ?? [];
  const buckets = query.data?.buckets ?? [];
  const lanes = useMemo(() => groupBy(events, (event) => event.source), [events]);
  const peak = Math.max(1, ...buckets.map((bucket) => bucket.count), 0);

  if (query.isError) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <SkeletonRows />;
  const data = query.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select
          value={source}
          onChange={(event) => setSource(event.target.value)}
          className="rounded-md border border-line bg-surface px-3 py-2 text-sm"
        >
          <option value="">All sources</option>
          {SOURCES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        {brush ? (
          <button className="text-sm text-accent" onClick={() => setBrush(null)}>
            Clear window
          </button>
        ) : null}
      </div>
      {buckets.length > 0 ? (
        <Card title={`Density (${data.resolution})`}>
          <div className="flex h-24 items-end gap-px">
            {buckets.map((bucket) => (
              <button
                key={bucket.bucket_start}
                title={`${bucket.count} events`}
                className="flex-1 bg-accent/40 hover:bg-accent"
                style={{ height: `${Math.max(8, (bucket.count / peak) * 100)}%` }}
                onClick={() => setBrush({ start: bucket.bucket_start, end: bucket.bucket_end })}
              />
            ))}
          </div>
        </Card>
      ) : null}
      <Card title={`${data.total} events`}>
        {events.length === 0 ? (
          <p className="text-sm text-muted">No timeline events in this window.</p>
        ) : (
          <div className="space-y-6 overflow-x-auto">
            {Object.entries(lanes).map(([lane, laneEvents]) => (
              <div key={lane}>
                <h3 className="mb-2 text-xs uppercase tracking-wide text-muted">{lane}</h3>
                <ol className="relative border-l border-line pl-4">
                  {laneEvents.map((event) => (
                    <li key={`${event.source}-${event.id}`} className="mb-3">
                      <button
                        className="text-left"
                        onClick={() => event.evidence_id && navigate(`/evidence/${event.evidence_id}`)}
                      >
                        <div className="text-sm font-medium">{event.title}</div>
                        <div className="text-xs text-muted">
                          <Timestamp value={event.occurred_at} /> · {event.kind}
                          {event.timezone_assumed ? " · timezone assumed" : ""}
                        </div>
                        {event.excerpt ? <pre className="mt-1 text-xs text-muted">{event.excerpt}</pre> : null}
                      </button>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function groupBy<T>(items: T[], key: (item: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const group = key(item);
    (out[group] ??= []).push(item);
  }
  return out;
}

export function TimelinePage() {
  return (
    <div className="p-6">
      <TimelinePanel />
    </div>
  );
}

export type { TimelineEvent };
