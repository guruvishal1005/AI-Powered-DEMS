import { useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { formatBytes, qs } from "../lib/format";
import type { EvidenceSummary, Page } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  HashDisplay,
  IntegrityBadge,
  SkeletonRows,
  Timestamp,
} from "../design/primitives";

export function EvidencePage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const query = useQuery({
    queryKey: ["evidence", "all", search],
    queryFn: () => api<Page<EvidenceSummary>>(`/evidence${qs({ search: search || undefined, size: 50 })}`),
  });

  return (
    <AppShell crumbs={["Evidence"]}>
      <h1 className="mb-4 text-xl font-semibold">Evidence repository</h1>
      <input
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="Search filename, title, or hash"
        className="mb-4 w-full max-w-md rounded-md border border-line bg-surface px-3 py-2 text-sm"
      />
      {query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : !query.data ? (
        <SkeletonRows />
      ) : (
        <Card>
          <DataTable
            rows={query.data.items}
            onRowClick={(row) => navigate(`/evidence/${row.id}`)}
            empty={<EmptyState title="No evidence" body="Artifacts appear here after they are acquired into a case." />}
            columns={[
              { key: "ref", header: "ID", render: (row) => <span className="mono">{row.reference}</span> },
              { key: "title", header: "Title", render: (row) => row.title },
              { key: "hash", header: "SHA-256", render: (row) => <HashDisplay value={row.sha256} /> },
              { key: "size", header: "Size", render: (row) => formatBytes(row.size_bytes) },
              { key: "int", header: "Integrity", render: (row) => <IntegrityBadge status={row.integrity_status} /> },
              { key: "when", header: "Uploaded", render: (row) => <Timestamp value={row.uploaded_at} relative /> },
            ]}
          />
        </Card>
      )}
    </AppShell>
  );
}
