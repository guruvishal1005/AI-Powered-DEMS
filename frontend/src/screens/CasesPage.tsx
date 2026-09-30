import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { qs } from "../lib/format";
import type { CaseSummary, Page } from "../lib/types";
import { useAuth } from "../lib/auth";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  Dialog,
  EmptyState,
  ErrorState,
  SeverityBadge,
  SkeletonRows,
  StatusPill,
  Timestamp,
} from "../design/primitives";

const INCIDENT_TYPES = [
  "ransomware",
  "phishing",
  "business_email_compromise",
  "insider_threat",
  "financial_fraud",
  "unauthorized_access",
  "data_breach",
  "other",
];

export function CasesPage() {
  const navigate = useNavigate();
  const { has } = useAuth();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState(false);
  const query = useQuery({
    queryKey: ["cases", search, status],
    queryFn: () =>
      api<Page<CaseSummary>>(
        `/cases${qs({ search: search || undefined, status: status || undefined, size: 50 })}`,
      ),
  });

  return (
    <AppShell crumbs={["Cases"]}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Cases</h1>
        {has("case:create") ? (
          <Button variant="primary" onClick={() => setOpen(true)}>
            Register case
          </Button>
        ) : null}
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search title or reference"
          className="rounded-md border border-line bg-surface px-3 py-2 text-sm"
        />
        <select
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          className="rounded-md border border-line bg-surface px-3 py-2 text-sm"
        >
          <option value="">All statuses</option>
          {["draft", "active", "pending_review", "on_hold", "closed", "archived"].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      {query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : !query.data ? (
        <SkeletonRows />
      ) : (
        <Card>
          <DataTable
            rows={query.data.items}
            onRowClick={(row) => navigate(`/cases/${row.id}`)}
            empty={
              <EmptyState
                title="No cases in scope"
                body="Cases you own or are assigned to will appear here. Nothing is hidden client-side — the API only returns rows you may see."
              />
            }
            columns={[
              { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
              { key: "title", header: "Title", render: (row) => row.title },
              { key: "type", header: "Type", render: (row) => row.incident_type.replaceAll("_", " ") },
              { key: "sev", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
              { key: "status", header: "Status", render: (row) => <StatusPill value={row.status} /> },
              {
                key: "activity",
                header: "Last activity",
                render: (row) => <Timestamp value={row.last_activity_at} relative />,
              },
            ]}
          />
        </Card>
      )}
      <CreateCaseDialog open={open} onClose={() => setOpen(false)} />
    </AppShell>
  );
}

function CreateCaseDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const client = useQueryClient();
  const mutation = useMutation({
    mutationFn: (payload: Record<string, string>) =>
      api<{ id: string }>("/cases", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: (created) => {
      void client.invalidateQueries({ queryKey: ["cases"] });
      onClose();
      navigate(`/cases/${created.id}`);
    },
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    mutation.mutate({
      title: String(form.get("title")),
      summary: String(form.get("summary")),
      incident_type: String(form.get("incident_type")),
      severity: String(form.get("severity")),
      classification: "RESTRICTED",
    });
  }

  return (
    <Dialog open={open} title="Register a case" onClose={onClose}>
      <form className="space-y-3" onSubmit={onSubmit}>
        <Field name="title" label="Title" required />
        <label className="block text-sm">
          Summary
          <textarea name="summary" className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2" rows={4} />
        </label>
        <label className="block text-sm">
          Incident type
          <select name="incident_type" className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2">
            {INCIDENT_TYPES.map((value) => (
              <option key={value} value={value}>
                {value.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label className="block text-sm">
          Severity
          <select name="severity" defaultValue="high" className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2">
            {["informational", "low", "medium", "high", "critical"].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        {mutation.isError ? <p className="text-sm text-status-critical">{String(mutation.error)}</p> : null}
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          Create
        </Button>
      </form>
    </Dialog>
  );
}

function Field({ name, label, required }: { name: string; label: string; required?: boolean }) {
  return (
    <label className="block text-sm">
      {label}
      <input
        name={name}
        required={required}
        className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2"
      />
    </label>
  );
}
