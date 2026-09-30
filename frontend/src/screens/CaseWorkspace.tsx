import { useState, type FormEvent } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type {
  CaseDetail,
  CustodyEvent,
  EvidenceSummary,
  Finding,
  Insight,
  Page,
  ReportSummary,
} from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  HashDisplay,
  IntegrityBadge,
  ProvenanceTag,
  SeverityBadge,
  SkeletonRows,
  StatusPill,
  TabPanel,
  Tabs,
  Timestamp,
} from "../design/primitives";
import { TimelinePanel } from "./TimelinePanel";
import { GraphPanel } from "./GraphPanel";
import { UploadDialog } from "./UploadDialog";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
  { id: "graph", label: "Graph" },
  { id: "findings", label: "Findings" },
  { id: "custody", label: "Chain of Custody" },
  { id: "reports", label: "Reports" },
  { id: "activity", label: "Activity" },
];

export function CaseWorkspace() {
  const { caseId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "overview";
  const { has } = useAuth();
  const client = useQueryClient();
  const [uploadOpen, setUploadOpen] = useState(false);

  const detail = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api<CaseDetail>(`/cases/${caseId}`),
  });

  if (detail.isError) {
    return (
      <AppShell crumbs={["Cases"]}>
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </AppShell>
    );
  }
  if (!detail.data) {
    return (
      <AppShell crumbs={["Cases"]}>
        <SkeletonRows />
      </AppShell>
    );
  }
  const caseRow = detail.data;

  return (
    <AppShell crumbs={["Cases", caseRow.reference]}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="mono text-xs text-muted">{caseRow.reference}</p>
          <h1 className="text-xl font-semibold">{caseRow.title}</h1>
          <div className="mt-2 flex flex-wrap gap-2">
            <SeverityBadge severity={caseRow.severity} />
            <StatusPill value={caseRow.status} />
            {caseRow.legal_hold ? <StatusPill value="legal hold" /> : null}
          </div>
        </div>
        <div className="flex gap-2">
          {has("evidence:upload") ? (
            <Button variant="primary" onClick={() => setUploadOpen(true)}>
              Upload evidence
            </Button>
          ) : null}
          {has("case:close") && caseRow.status === "active" ? (
            <Button
              onClick={() =>
                void api(`/cases/${caseId}/status`, {
                  method: "POST",
                  body: JSON.stringify({
                    status: "pending_review",
                    reason: "Submitted for review from the workspace",
                  }),
                }).then(() => client.invalidateQueries({ queryKey: ["case", caseId] }))
              }
            >
              Request closure
            </Button>
          ) : null}
        </div>
      </div>
      <Tabs
        tabs={TABS}
        value={tab}
        onChange={(id) => {
          params.set("tab", id);
          setParams(params);
        }}
      />
      <TabPanel>
        {tab === "overview" && <Overview caseRow={caseRow} />}
        {tab === "evidence" && <EvidenceTab caseId={caseId} onUpload={() => setUploadOpen(true)} />}
        {tab === "timeline" && <TimelinePanel caseId={caseId} />}
        {tab === "graph" && <GraphPanel caseId={caseId} />}
        {tab === "findings" && <FindingsTab caseId={caseId} />}
        {tab === "custody" && <CustodyTab caseId={caseId} />}
        {tab === "reports" && <ReportsTab caseId={caseId} />}
        {tab === "activity" && <ActivityTab caseId={caseId} />}
      </TabPanel>
      <UploadDialog open={uploadOpen} caseId={caseId} onClose={() => setUploadOpen(false)} />
    </AppShell>
  );
}

function Overview({ caseRow }: { caseRow: CaseDetail }) {
  const insights = useQuery({
    queryKey: ["insights", caseRow.id],
    queryFn: () => api<Page<Insight>>(`/intelligence/insights?case_id=${caseRow.id}&size=5`),
  });
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Summary" className="xl:col-span-2">
        <p className="whitespace-pre-wrap text-sm text-ink">{caseRow.summary || "No summary recorded."}</p>
        <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <div>
            <dt className="text-muted">Lead</dt>
            <dd>{caseRow.lead_investigator?.full_name ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted">Risk</dt>
            <dd>{caseRow.risk_score ?? "not scored"}</dd>
          </div>
          <div>
            <dt className="text-muted">Occurred</dt>
            <dd>
              <Timestamp value={caseRow.incident_occurred_at} />
            </dd>
          </div>
          <div>
            <dt className="text-muted">Organization</dt>
            <dd>{caseRow.organization ?? "—"}</dd>
          </div>
        </dl>
      </Card>
      <Card title="Assignments">
        <ul className="space-y-2 text-sm">
          {caseRow.assignments.map((row) => (
            <li key={row.id}>
              {row.user.full_name} · {row.role_on_case}
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Pinned insights" className="xl:col-span-3">
        <DataTable
          rows={insights.data?.items ?? []}
          empty={<p className="text-sm text-muted">No insights yet. Analysis must finish first.</p>}
          columns={[
            { key: "title", header: "Insight", render: (row) => row.title },
            { key: "prov", header: "Provenance", render: (row) => <ProvenanceTag provenance={row.provenance} /> },
            { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
          ]}
        />
      </Card>
    </div>
  );
}

function EvidenceTab({ caseId, onUpload }: { caseId: string; onUpload: () => void }) {
  const navigate = useNavigate();
  const { has } = useAuth();
  const query = useQuery({
    queryKey: ["evidence", caseId],
    queryFn: () => api<Page<EvidenceSummary>>(`/evidence?case_id=${caseId}&size=100`),
  });
  if (query.isError) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <SkeletonRows />;
  return (
    <Card
      title="Evidence inventory"
      actions={
        has("evidence:upload") ? (
          <Button variant="primary" onClick={onUpload}>
            Upload
          </Button>
        ) : null
      }
    >
      <DataTable
        rows={query.data.items}
        onRowClick={(row) => navigate(`/evidence/${row.id}`)}
        empty={
          <EmptyState title="No evidence yet" body="Upload an artifact to open its chain of custody." />
        }
        columns={[
          { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
          { key: "title", header: "Title", render: (row) => row.title },
          { key: "hash", header: "SHA-256", render: (row) => <HashDisplay value={row.sha256} /> },
          { key: "int", header: "Integrity", render: (row) => <IntegrityBadge status={row.integrity_status} /> },
        ]}
      />
    </Card>
  );
}

function FindingsTab({ caseId }: { caseId: string }) {
  const { has } = useAuth();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["findings", caseId],
    queryFn: () => api<Finding[]>(`/cases/${caseId}/findings`),
  });
  const create = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api(`/cases/${caseId}/findings`, { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["findings", caseId] }),
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    create.mutate({
      kind: String(form.get("kind")),
      title: String(form.get("title")),
      description: String(form.get("description")),
      severity: String(form.get("severity")),
      confidence: "moderate",
    });
    event.currentTarget.reset();
  }

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Recorded findings" className="xl:col-span-2">
        {query.isError ? (
          <ErrorState error={query.error} />
        ) : (
          <DataTable
            rows={query.data ?? []}
            empty={<EmptyState title="No human findings" body="Analyst conclusions are recorded here, separate from analyzer output." />}
            columns={[
              { key: "seq", header: "#", render: (row) => row.sequence },
              { key: "title", header: "Title", render: (row) => row.title },
              { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
            ]}
          />
        )}
      </Card>
      {has("finding:create") ? (
        <Card title="Add finding">
          <form className="space-y-3" onSubmit={onSubmit}>
            <input name="title" required placeholder="Title" className="w-full rounded-md border border-line bg-canvas px-3 py-2 text-sm" />
            <textarea name="description" required rows={5} className="w-full rounded-md border border-line bg-canvas px-3 py-2 text-sm" />
            <select name="kind" className="w-full rounded-md border border-line bg-canvas px-3 py-2 text-sm">
              <option value="observation">observation</option>
              <option value="indicator_of_compromise">indicator of compromise</option>
              <option value="root_cause">root cause</option>
              <option value="recommendation">recommendation</option>
            </select>
            <select name="severity" className="w-full rounded-md border border-line bg-canvas px-3 py-2 text-sm">
              <option>medium</option>
              <option>high</option>
              <option>critical</option>
            </select>
            <Button type="submit" variant="primary">
              Save
            </Button>
          </form>
        </Card>
      ) : null}
    </div>
  );
}

function CustodyTab({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ["custody", caseId],
    queryFn: () => api<Page<CustodyEvent>>(`/custody/events?case_id=${caseId}&size=200`),
  });
  if (query.isError) return <ErrorState error={query.error} />;
  if (!query.data) return <SkeletonRows />;
  return (
    <Card title="Custody events for this case">
      <ol className="space-y-3">
        {query.data.items.map((event) => (
          <li key={event.id} className="rounded-md border border-line bg-canvas px-3 py-2 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium">
                #{event.sequence} · {event.action}
              </span>
              <Timestamp value={event.occurred_at} />
            </div>
            <p className="text-muted">{event.actor_label}</p>
            <HashDisplay value={event.entry_hash} label="Entry hash" />
          </li>
        ))}
      </ol>
    </Card>
  );
}

function ReportsTab({ caseId }: { caseId: string }) {
  const navigate = useNavigate();
  const { has } = useAuth();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["reports", caseId],
    queryFn: () => api<Page<ReportSummary>>(`/reports?case_id=${caseId}`),
  });
  const create = useMutation({
    mutationFn: () =>
        api<ReportSummary>(`/reports?case_id=${caseId}`, {
        method: "POST",
        body: JSON.stringify({
          title: "Investigation report",
          classification: "RESTRICTED",
        }),
      }),
    onSuccess: (report) => {
      void client.invalidateQueries({ queryKey: ["reports", caseId] });
      navigate(`/reports/${report.id}`);
    },
  });
  return (
    <Card
      title="Reports"
      actions={
        has("report:generate") ? (
          <Button variant="primary" onClick={() => create.mutate()}>
            Capture snapshot
          </Button>
        ) : null
      }
    >
      <DataTable
        rows={query.data?.items ?? []}
        onRowClick={(row) => navigate(`/reports/${row.id}`)}
        empty={<EmptyState title="No reports" body="A report captures a point-in-time snapshot that can be signed." />}
        columns={[
          { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
          { key: "title", header: "Title", render: (row) => row.title },
          { key: "status", header: "Status", render: (row) => <StatusPill value={row.status} /> },
        ]}
      />
    </Card>
  );
}

function ActivityTab({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ["audit", caseId],
    queryFn: () => api<Page<{ id: string; action: string; actor_label: string; recorded_at: string; detail: string | null }>>(
      `/audit?case_id=${caseId}&size=50`,
    ),
  });
  return (
    <Card title="Case activity">
      <DataTable
        rows={query.data?.items ?? []}
        empty={<p className="text-sm text-muted">No audit events for this case yet.</p>}
        columns={[
          { key: "when", header: "When", render: (row) => <Timestamp value={row.recorded_at} /> },
          { key: "action", header: "Action", render: (row) => <span className="mono">{row.action}</span> },
          { key: "actor", header: "Actor", render: (row) => row.actor_label },
        ]}
      />
    </Card>
  );
}

