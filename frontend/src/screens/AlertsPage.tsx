import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { AlertSummary, Page } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  SeverityBadge,
  SkeletonRows,
  StatusPill,
  Timestamp,
} from "../design/primitives";

export function AlertsPage() {
  const navigate = useNavigate();
  const { alertId } = useParams();
  const [status, setStatus] = useState("open");
  const query = useQuery({
    queryKey: ["alerts", status],
    queryFn: () => api<Page<AlertSummary>>(`/alerts?status=${status}&size=50`),
  });

  return (
    <AppShell crumbs={["Alerts"]}>
      <h1 className="mb-4 text-xl font-semibold">Alerts</h1>
      <select
        value={status}
        onChange={(event) => setStatus(event.target.value)}
        className="mb-4 rounded-md border border-line bg-surface px-3 py-2 text-sm"
      >
        {["open", "acknowledged", "resolved", "suppressed"].map((value) => (
          <option key={value}>{value}</option>
        ))}
      </select>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          {query.isError ? (
            <ErrorState error={query.error} />
          ) : !query.data ? (
            <SkeletonRows />
          ) : (
            <DataTable
              rows={query.data.items}
              onRowClick={(row) => navigate(`/alerts/${row.id}`)}
              empty={<EmptyState title="No alerts" body="Integrity failures, anomalies and security events land here." />}
              columns={[
                { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
                { key: "title", header: "Title", render: (row) => row.title },
                { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
                { key: "st", header: "Status", render: (row) => <StatusPill value={row.status} /> },
                { key: "when", header: "Last seen", render: (row) => <Timestamp value={row.last_seen_at} relative /> },
              ]}
            />
          )}
        </Card>
        <AlertDetail id={alertId} />
      </div>
    </AppShell>
  );
}

function AlertDetail({ id }: { id?: string }) {
  const { has } = useAuth();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["alert", id],
    enabled: Boolean(id),
    queryFn: () =>
      api<{
        id: string;
        title: string;
        description: string;
        recommended_action: string | null;
        status: string;
        severity: string;
      }>(`/alerts/${id}`),
  });
  const act = useMutation({
    mutationFn: (path: string) =>
      api(`/alerts/${id}/${path}`, {
        method: "POST",
        body: JSON.stringify({ note: "Triaged from the console" }),
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["alerts"] });
      void client.invalidateQueries({ queryKey: ["alert", id] });
    },
  });
  if (!id) return <Card title="Triage"><p className="text-sm text-muted">Select an alert.</p></Card>;
  if (!query.data) return <Card title="Triage"><SkeletonRows rows={4} /></Card>;
  return (
    <Card title={query.data.title}>
      <p className="text-sm">{query.data.description}</p>
      {query.data.recommended_action ? (
        <p className="mt-2 text-sm text-muted">{query.data.recommended_action}</p>
      ) : null}
      {has("alert:manage") ? (
        <div className="mt-4 flex flex-wrap gap-2">
          <Button onClick={() => act.mutate("acknowledge")}>Acknowledge</Button>
          <Button onClick={() => act.mutate("resolve")}>Resolve</Button>
          <Button onClick={() => act.mutate("suppress")}>Suppress</Button>
        </div>
      ) : null}
    </Card>
  );
}
