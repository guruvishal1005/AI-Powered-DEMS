import { useState } from "react";
import { useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Page } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  StatusPill,
  Tabs,
} from "../design/primitives";

const SECTIONS = [
  { id: "users", label: "Users" },
  { id: "roles", label: "Roles" },
  { id: "retention", label: "Retention" },
  { id: "jobs", label: "Jobs" },
  { id: "health", label: "Health" },
  { id: "backups", label: "Backups" },
  { id: "security", label: "Security" },
];

export function AdminPage() {
  const { has } = useAuth();
  const [params, setParams] = useSearchParams();
  const section = params.get("section") ?? "users";
  if (!has("system:read") && !has("user:read")) {
    return (
      <AppShell crumbs={["Administration"]}>
        <ErrorState error={new Error("Administration is not available for this role.")} />
      </AppShell>
    );
  }
  return (
    <AppShell crumbs={["Administration"]}>
      <h1 className="mb-4 text-xl font-semibold">Administration</h1>
      <Tabs
        tabs={SECTIONS}
        value={section}
        onChange={(id) => {
          params.set("section", id);
          setParams(params);
        }}
      />
      <div className="pt-4">
        {section === "users" && <Users />}
        {section === "roles" && <Roles />}
        {section === "retention" && <Retention />}
        {section === "jobs" && <Jobs />}
        {section === "health" && <Health />}
        {section === "backups" && <Backups />}
        {section === "security" && <Security />}
      </div>
    </AppShell>
  );
}

function Users() {
  const query = useQuery({
    queryKey: ["admin-users"],
    queryFn: () =>
      api<Page<{ id: string; email: string; full_name: string; status: string; roles: Array<{ name: string }> }>>(
        "/admin/users",
      ),
  });
  if (query.isError) return <ErrorState error={query.error} />;
  return (
    <Card>
      <DataTable
        rows={query.data?.items ?? []}
        empty={<EmptyState title="No users" body="" />}
        columns={[
          { key: "name", header: "Name", render: (row) => row.full_name },
          { key: "email", header: "Email", render: (row) => row.email },
          { key: "roles", header: "Roles", render: (row) => row.roles.map((role) => role.name).join(", ") },
          { key: "st", header: "Status", render: (row) => <StatusPill value={row.status} /> },
        ]}
      />
    </Card>
  );
}

function Roles() {
  const query = useQuery({
    queryKey: ["admin-roles"],
    queryFn: () =>
      api<Array<{ id: string; name: string; slug: string; description: string; user_count: number; permissions: Array<{ code: string }> }>>(
        "/admin/roles",
      ),
  });
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {(query.data ?? []).map((role) => (
        <Card key={role.id} title={`${role.name} (${role.user_count})`}>
          <p className="mb-2 text-sm text-muted">{role.description}</p>
          <p className="text-xs text-muted">{role.permissions.length} permissions, including download/sign only if granted in the database.</p>
        </Card>
      ))}
    </div>
  );
}

function Retention() {
  const query = useQuery({
    queryKey: ["retention"],
    queryFn: () => api<Array<{ id: string; name: string; retention_days: number; enabled: boolean }>>("/admin/retention"),
  });
  const holds = useQuery({
    queryKey: ["holds"],
    queryFn: () => api<Array<{ id: string; reason: string; case_id: string | null }>>("/admin/legal-holds"),
  });
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card title="Policies">
        <DataTable
          rows={query.data ?? []}
          empty={<p className="text-sm text-muted">No policies.</p>}
          columns={[
            { key: "name", header: "Name", render: (row) => row.name },
            { key: "days", header: "Days", render: (row) => row.retention_days },
            { key: "on", header: "Enabled", render: (row) => (row.enabled ? "yes" : "no") },
          ]}
        />
      </Card>
      <Card title="Legal holds">
        <DataTable
          rows={holds.data ?? []}
          empty={<p className="text-sm text-muted">No holds.</p>}
          columns={[
            { key: "reason", header: "Reason", render: (row) => row.reason },
            { key: "case", header: "Case", render: (row) => row.case_id ?? "—" },
          ]}
        />
      </Card>
    </div>
  );
}

function Jobs() {
  const client = useQueryClient();
  const stats = useQuery({
    queryKey: ["job-stats"],
    queryFn: () => api<Record<string, number>>("/admin/jobs/stats"),
  });
  const jobs = useQuery({
    queryKey: ["jobs"],
    queryFn: () =>
      api<Page<{ id: string; task: string; status: string; attempts: number; last_error: string | null }>>(
        "/admin/jobs?size=50",
      ),
  });
  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: string }) =>
      api(`/admin/jobs/${id}/${action}`, { method: "POST" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["jobs"] }),
  });
  return (
    <div className="space-y-4">
      <Card title="Queue">
        <pre className="text-xs">{JSON.stringify(stats.data ?? {}, null, 2)}</pre>
      </Card>
      <Card title="Jobs">
        <DataTable
          rows={jobs.data?.items ?? []}
          empty={<p className="text-sm text-muted">Queue is idle.</p>}
          columns={[
            { key: "name", header: "Task", render: (row) => row.task },
            { key: "st", header: "Status", render: (row) => <StatusPill value={row.status} /> },
            {
              key: "act",
              header: "",
              render: (row) => (
                <div className="flex gap-2">
                  <Button onClick={() => act.mutate({ id: row.id, action: "retry" })}>Retry</Button>
                  <Button onClick={() => act.mutate({ id: row.id, action: "cancel" })}>Cancel</Button>
                </div>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}

function Health() {
  const query = useQuery({
    queryKey: ["health"],
    queryFn: () => api<Record<string, unknown>>("/admin/health"),
  });
  return (
    <Card title="System health">
      <pre className="overflow-auto text-xs">{JSON.stringify(query.data ?? {}, null, 2)}</pre>
    </Card>
  );
}

function Backups() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["backups"],
    queryFn: () => api<Array<{ id: string; status: string; created_at: string }>>("/admin/backups"),
  });
  const run = useMutation({
    mutationFn: () => api("/admin/backups", { method: "POST" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["backups"] }),
  });
  return (
    <Card
      title="Backups"
      actions={
        <Button variant="primary" onClick={() => run.mutate()}>
          Trigger backup
        </Button>
      }
    >
      <DataTable
        rows={query.data ?? []}
        empty={<p className="text-sm text-muted">No backups yet.</p>}
        columns={[
          { key: "id", header: "ID", render: (row) => <span className="mono text-xs">{row.id}</span> },
          { key: "st", header: "Status", render: (row) => <StatusPill value={row.status} /> },
        ]}
      />
    </Card>
  );
}

function Security() {
  const [key, setKey] = useState("");
  const query = useQuery({
    queryKey: ["settings"],
    queryFn: () => api<Array<{ key: string; label: string; description: string; value: unknown; is_sensitive: boolean }>>(
      "/admin/settings",
    ),
  });
  const selected = query.data?.find((item) => item.key === key) ?? query.data?.[0];
  return (
    <Card title="Security settings">
      <select
        value={selected?.key ?? ""}
        onChange={(event) => setKey(event.target.value)}
        className="mb-3 rounded-md border border-line bg-canvas px-3 py-2 text-sm"
      >
        {(query.data ?? []).map((item) => (
          <option key={item.key} value={item.key}>
            {item.label}
          </option>
        ))}
      </select>
      {selected ? (
        <div className="text-sm">
          <p className="text-muted">{selected.description}</p>
          <pre className="mt-2 text-xs">{selected.is_sensitive ? "••••" : JSON.stringify(selected.value, null, 2)}</pre>
        </div>
      ) : null}
    </Card>
  );
}
