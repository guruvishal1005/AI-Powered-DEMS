import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AppShell } from "../shell/AppShell";
import { Button, Card, DataTable, Timestamp } from "../design/primitives";

export function SettingsPage() {
  const { user, refreshUser } = useAuth();
  const client = useQueryClient();
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: () =>
      api<Array<{ id: string; ip_address: string | null; device_label: string | null; last_seen_at: string; is_current: boolean }>>(
        "/auth/sessions",
      ),
  });
  const tokens = useQuery({
    queryKey: ["tokens"],
    queryFn: () =>
      api<Array<{ id: string; name: string; prefix: string; created_at: string; last_used_at: string | null }>>(
        "/admin/tokens",
      ),
  });
  const [secret, setSecret] = useState<string | null>(null);

  const revoke = useMutation({
    mutationFn: (id: string) => api(`/auth/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["sessions"] }),
  });
  const createToken = useMutation({
    mutationFn: (name: string) =>
      api<{ token: string }>("/admin/tokens", {
        method: "POST",
        body: JSON.stringify({ name, scopes: ["case:read"] }),
      }),
    onSuccess: (body) => {
      setSecret(body.token);
      void client.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const revokeToken = useMutation({
    mutationFn: (id: string) => api(`/admin/tokens/${id}`, { method: "DELETE" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["tokens"] }),
  });

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await api("/auth/me", {
      method: "PATCH",
      body: JSON.stringify({
        full_name: String(form.get("full_name")),
        job_title: String(form.get("job_title")),
        timezone: String(form.get("timezone")),
      }),
    });
    await refreshUser();
  }

  return (
    <AppShell crumbs={["Settings"]}>
      <h1 className="mb-4 text-xl font-semibold">Settings</h1>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Profile">
          {user ? (
            <form className="space-y-3" onSubmit={(event) => void saveProfile(event)}>
              <label className="block text-sm">
                Name
                <input name="full_name" defaultValue={user.full_name} className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2" />
              </label>
              <label className="block text-sm">
                Job title
                <input name="job_title" defaultValue={user.job_title ?? ""} className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2" />
              </label>
              <label className="block text-sm">
                Timezone
                <input name="timezone" defaultValue={user.timezone} className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2" />
              </label>
              <Button type="submit" variant="primary">
                Save
              </Button>
            </form>
          ) : null}
        </Card>
        <Card title="Active sessions">
          <DataTable
            rows={sessions.data ?? []}
            empty={<p className="text-sm text-muted">No sessions.</p>}
            columns={[
              { key: "dev", header: "Device", render: (row) => row.device_label ?? row.ip_address ?? "—" },
              { key: "seen", header: "Last seen", render: (row) => <Timestamp value={row.last_seen_at} relative /> },
              {
                key: "act",
                header: "",
                render: (row) =>
                  row.is_current ? (
                    "current"
                  ) : (
                    <Button onClick={() => revoke.mutate(row.id)}>Revoke</Button>
                  ),
              },
            ]}
          />
        </Card>
        <Card title="API tokens" className="xl:col-span-2">
          <Button onClick={() => createToken.mutate(`console-${Date.now()}`)}>Create token</Button>
          {secret ? (
            <p className="mt-2 text-sm text-status-medium">
              Copy now — it will not be shown again: <span className="mono">{secret}</span>
            </p>
          ) : null}
          <div className="mt-3">
            <DataTable
              rows={tokens.data ?? []}
              empty={<p className="text-sm text-muted">No tokens.</p>}
              columns={[
                { key: "name", header: "Name", render: (row) => row.name },
                { key: "pre", header: "Prefix", render: (row) => <span className="mono">{row.prefix}</span> },
                {
                  key: "act",
                  header: "",
                  render: (row) => <Button onClick={() => revokeToken.mutate(row.id)}>Revoke</Button>,
                },
              ]}
            />
          </div>
        </Card>
      </div>
    </AppShell>
  );
}
