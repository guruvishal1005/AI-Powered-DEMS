import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { AuditEntry, Page } from "../lib/types";
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

export function AuditPage() {
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("");
  const query = useQuery({
    queryKey: ["audit", search, action],
    queryFn: () => {
      const params = new URLSearchParams({ size: "50" });
      if (search) params.set("search", search);
      if (action) params.set("action", action);
      return api<Page<AuditEntry>>(`/audit?${params}`);
    },
  });
  const chain = useQuery({
    queryKey: ["audit-verify"],
    queryFn: () =>
      api<{ intact: boolean; summary: string; entries_checked: number; signatures_valid: number; signatures_checked: number }>(
        "/audit/verify",
      ),
  });

  return (
    <AppShell crumbs={["Audit Log"]}>
      <h1 className="mb-4 text-xl font-semibold">Audit log</h1>
      <Card title="Chain status" className="mb-4">
        {chain.data ? (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <StatusPill value={chain.data.intact ? "intact" : "broken"} />
            <span>{chain.data.summary}</span>
            <span className="text-muted">
              {chain.data.signatures_valid}/{chain.data.signatures_checked} signatures
            </span>
            <Button onClick={() => void chain.refetch()}>Re-verify</Button>
          </div>
        ) : (
          <SkeletonRows rows={2} />
        )}
      </Card>
      <div className="mb-4 flex gap-2">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search detail or resource"
          className="rounded-md border border-line bg-surface px-3 py-2 text-sm"
        />
        <input
          value={action}
          onChange={(event) => setAction(event.target.value)}
          placeholder="Action filter"
          className="rounded-md border border-line bg-surface px-3 py-2 text-sm"
        />
      </div>
      {query.isError ? (
        <ErrorState error={query.error} />
      ) : !query.data ? (
        <SkeletonRows />
      ) : (
        <Card>
          <DataTable
            rows={query.data.items}
            empty={<EmptyState title="No entries" body="Audit records are append-only and hash-chained." />}
            columns={[
              { key: "seq", header: "#", render: (row) => row.sequence },
              { key: "when", header: "When", render: (row) => <Timestamp value={row.recorded_at} /> },
              { key: "action", header: "Action", render: (row) => <span className="mono text-xs">{row.action}</span> },
              { key: "actor", header: "Actor", render: (row) => row.actor_label },
              { key: "result", header: "Result", render: (row) => <StatusPill value={row.result} /> },
              { key: "hash", header: "Entry hash", render: (row) => <HashDisplay value={row.entry_hash} /> },
            ]}
          />
        </Card>
      )}
    </AppShell>
  );
}
