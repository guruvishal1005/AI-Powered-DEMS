import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../lib/api";
import { formatBytes, labelize } from "../lib/format";
import type { Dashboard } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Card,
  DataTable,
  ErrorState,
  IntegrityBadge,
  SeverityBadge,
  SkeletonRows,
  StatusPill,
  Timestamp,
} from "../design/primitives";

export function DashboardPage() {
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<Dashboard>("/dashboard"),
  });

  if (query.isError) {
    return (
      <AppShell crumbs={["Command Center"]}>
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </AppShell>
    );
  }
  const data = query.data;

  return (
    <AppShell crumbs={["Command Center"]}>
      <h1 className="mb-6 text-xl font-semibold">Command Center</h1>
      {!data ? (
        <SkeletonRows rows={8} />
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Open cases" value={String(data.cases_open)} hint={`${data.cases_total} total`} />
            <Stat label="Evidence items" value={String(data.evidence_total)} hint={formatBytes(data.storage_bytes)} />
            <Stat
              label="Integrity failures"
              value={String(data.integrity.failed)}
              hint={`${data.integrity.verified} verified · ${data.integrity.pending} pending`}
            />
            <Stat
              label="Open alerts"
              value={String(data.open_alerts.total ?? 0)}
              hint={`Queue ${data.queue_depth} · ${data.jobs_failed_24h} failed jobs (24h)`}
            />
          </div>
          <Card title="Activity">
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.activity}>
                  <XAxis dataKey="bucket_start" hide />
                  <YAxis hide />
                  <Tooltip
                    contentStyle={{ background: "#161d26", border: "1px solid #2a3440" }}
                    labelFormatter={(value) => new Date(String(value)).toLocaleString()}
                  />
                  <Area dataKey="count" stroke="#2dd4bf" fill="#134e4a" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Cases needing attention">
              <DataTable
                rows={data.attention_cases}
                onRowClick={(row) => navigate(`/cases/${row.id}`)}
                empty={<p className="text-sm text-muted">No cases currently need attention.</p>}
                columns={[
                  { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
                  { key: "title", header: "Title", render: (row) => row.title },
                  { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
                  { key: "status", header: "Status", render: (row) => <StatusPill value={row.status} /> },
                ]}
              />
            </Card>
            <Card title="Recent evidence">
              <DataTable
                rows={data.recent_evidence}
                onRowClick={(row) => navigate(`/evidence/${row.id}`)}
                empty={<p className="text-sm text-muted">No evidence in scope yet.</p>}
                columns={[
                  { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
                  { key: "title", header: "Title", render: (row) => row.title },
                  {
                    key: "int",
                    header: "Integrity",
                    render: (row) => <IntegrityBadge status={row.integrity_status} />,
                  },
                  { key: "type", header: "Type", render: (row) => labelize(row.evidence_type) },
                ]}
              />
            </Card>
          </div>
          <Card title="Recent alerts">
            <DataTable
              rows={data.recent_alerts}
              onRowClick={(row) => navigate(`/alerts/${row.id}`)}
              empty={<p className="text-sm text-muted">No alerts.</p>}
              columns={[
                { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
                { key: "title", header: "Title", render: (row) => row.title },
                { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
                { key: "when", header: "Last seen", render: (row) => <Timestamp value={row.last_seen_at} relative /> },
              ]}
            />
          </Card>
        </div>
      )}
    </AppShell>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      <div className="mt-1 text-xs text-muted">{hint}</div>
    </div>
  );
}
