import { useNavigate, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadFile } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Page, ReportSummary } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  HashDisplay,
  SkeletonRows,
  StatusPill,
  Timestamp,
} from "../design/primitives";

export function ReportsPage() {
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["reports"],
    queryFn: () => api<Page<ReportSummary>>("/reports?size=50"),
  });
  return (
    <AppShell crumbs={["Reports"]}>
      <h1 className="mb-4 text-xl font-semibold">Reports</h1>
      {query.isError ? (
        <ErrorState error={query.error} />
      ) : !query.data ? (
        <SkeletonRows />
      ) : (
        <Card>
          <DataTable
            rows={query.data.items}
            onRowClick={(row) => navigate(`/reports/${row.id}`)}
            empty={<EmptyState title="No reports" body="Capture a snapshot from a case workspace." />}
            columns={[
              { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
              { key: "title", header: "Title", render: (row) => row.title },
              { key: "st", header: "Status", render: (row) => <StatusPill value={row.status} /> },
              { key: "signed", header: "Signed", render: (row) => (row.is_signed ? "yes" : "no") },
              { key: "when", header: "Created", render: (row) => <Timestamp value={row.created_at} relative /> },
            ]}
          />
        </Card>
      )}
    </AppShell>
  );
}

export function ReportDetailPage() {
  const { reportId = "" } = useParams();
  const { has, user } = useAuth();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["report", reportId],
    queryFn: () =>
      api<
        ReportSummary & {
          executive_summary: string | null;
          conclusion: string | null;
          artifacts: Array<{ id: string; format: string; filename: string; sha256: string }>;
          prepared_by: { id: string } | null;
          review_note: string | null;
        }
      >(`/reports/${reportId}`),
  });
  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) =>
      api(`/reports/${reportId}/${path}`, {
        method: "POST",
        body: body ? JSON.stringify(body) : undefined,
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["report", reportId] }),
  });

  if (query.isError) {
    return (
      <AppShell crumbs={["Reports"]}>
        <ErrorState error={query.error} />
      </AppShell>
    );
  }
  if (!query.data) {
    return (
      <AppShell crumbs={["Reports"]}>
        <SkeletonRows />
      </AppShell>
    );
  }
  const report = query.data;
  const canSign =
    has("report:sign") && report.prepared_by && user && report.prepared_by.id !== user.id;

  return (
    <AppShell crumbs={["Reports", report.reference]}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="mono text-xs text-muted">{report.reference}</p>
          <h1 className="text-xl font-semibold">{report.title}</h1>
          <StatusPill value={report.status} />
        </div>
        <div className="flex flex-wrap gap-2">
          {report.status === "draft" && has("report:generate") ? (
            <Button onClick={() => act.mutate({ path: "submit", body: { note: "Submitted for review" } })}>
              Submit
            </Button>
          ) : null}
          {report.status === "pending_review" && canSign ? (
            <Button variant="primary" onClick={() => act.mutate({ path: "sign" })}>
              Approve and sign
            </Button>
          ) : null}
          <Button onClick={() => act.mutate({ path: "render?fmt=pdf" })}>Render PDF</Button>
          <Button onClick={() => void downloadFile(`/reports/${reportId}/download?fmt=pdf`)}>Download</Button>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Snapshot">
          <p className="text-sm">SHA-256 of the frozen snapshot:</p>
          <HashDisplay value={report.snapshot_sha256} compact={false} />
          <p className="mt-2 text-xs text-muted">
            Re-rendering reproduces this snapshot. Live case changes do not alter a signed report.
          </p>
        </Card>
        <Card title="Artifacts">
          <ul className="space-y-2 text-sm">
            {report.artifacts.map((item) => (
              <li key={item.id}>
                {item.format} · {item.filename} · <HashDisplay value={item.sha256} />
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Executive summary" className="md:col-span-2">
          <p className="whitespace-pre-wrap text-sm">{report.executive_summary || "Captured at snapshot time."}</p>
        </Card>
      </div>
    </AppShell>
  );
}
