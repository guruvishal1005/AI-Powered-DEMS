import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, downloadFile } from "../lib/api";
import { formatBytes, labelize } from "../lib/format";
import { useAuth } from "../lib/auth";
import type {
  ChainStatus,
  CustodyEvent,
  EvidenceDetail,
  IntegrityCheck,
  Page,
} from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  DataTable,
  ErrorState,
  HashDisplay,
  IntegrityBadge,
  SkeletonRows,
  StatusPill,
  TabPanel,
  Tabs,
  Timestamp,
} from "../design/primitives";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "preview", label: "Preview" },
  { id: "analysis", label: "Analysis" },
  { id: "entities", label: "Entities" },
  { id: "relationships", label: "Relationships" },
  { id: "custody", label: "Custody" },
  { id: "versions", label: "Versions" },
];

export function EvidenceDetailPage() {
  const { evidenceId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "overview";
  const { has } = useAuth();
  const client = useQueryClient();
  const [reason, setReason] = useState("Investigative review of original artifact");

  const detail = useQuery({
    queryKey: ["evidence-detail", evidenceId],
    queryFn: () => api<EvidenceDetail>(`/evidence/${evidenceId}`),
  });
  const verify = useMutation({
    mutationFn: () => api(`/evidence/${evidenceId}/verify`, { method: "POST" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["evidence-detail", evidenceId] }),
  });

  if (detail.isError) {
    return (
      <AppShell crumbs={["Evidence"]}>
        <ErrorState error={detail.error} />
      </AppShell>
    );
  }
  if (!detail.data) {
    return (
      <AppShell crumbs={["Evidence"]}>
        <SkeletonRows />
      </AppShell>
    );
  }
  const item = detail.data;

  return (
    <AppShell crumbs={["Evidence", item.reference]}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="mono text-xs text-muted">{item.reference}</p>
          <h1 className="text-xl font-semibold">{item.title}</h1>
          <div className="mt-2 flex flex-wrap gap-2">
            <IntegrityBadge status={item.integrity_status} />
            <StatusPill value={item.status} />
            {item.mime_mismatch ? <StatusPill value="mime mismatch" /> : null}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {has("evidence:verify") ? (
            <Button onClick={() => verify.mutate()}>Verify integrity</Button>
          ) : null}
          {has("evidence:download") ? (
            <div className="flex gap-2">
              <input
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                className="w-64 rounded-md border border-line bg-surface px-2 py-1 text-xs"
                aria-label="Download reason"
              />
              <Button
                variant="primary"
                onClick={() =>
                  void downloadFile(`/evidence/${evidenceId}/download?reason=${encodeURIComponent(reason)}`)
                }
              >
                Download
              </Button>
            </div>
          ) : (
            <p className="text-xs text-muted">Raw content is not available for this role.</p>
          )}
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
        {tab === "overview" && <Overview item={item} />}
        {tab === "preview" && <Preview evidenceId={evidenceId} />}
        {tab === "analysis" && <Analysis evidenceId={evidenceId} />}
        {tab === "entities" && <Entities evidenceId={evidenceId} />}
        {tab === "relationships" && <Relationships evidenceId={evidenceId} />}
        {tab === "custody" && <Custody evidenceId={evidenceId} />}
        {tab === "versions" && <Versions evidenceId={evidenceId} item={item} />}
      </TabPanel>
    </AppShell>
  );
}

function Overview({ item }: { item: EvidenceDetail }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card title="Fingerprint">
        <dl className="space-y-2 text-sm">
          <Row label="SHA-256" value={<HashDisplay value={item.sha256} compact={false} />} />
          <Row label="SHA-1" value={<HashDisplay value={item.current_version?.sha1} label="SHA-1" />} />
          <Row label="MD5" value={<HashDisplay value={item.current_version?.md5} label="MD5" />} />
          <Row label="Size" value={formatBytes(item.size_bytes)} />
          <Row label="MIME" value={item.mime_type} />
        </dl>
      </Card>
      <Card title="Acquisition">
        <dl className="space-y-2 text-sm">
          <Row label="Case" value={item.case ? <Link className="text-accent" to={`/cases/${item.case.id}`}>{item.case.reference}</Link> : "—"} />
          <Row label="Filename" value={item.original_filename} />
          <Row label="Acquired by" value={item.acquired_by_name ?? "—"} />
          <Row label="Acquired at" value={<Timestamp value={item.acquired_at} />} />
          <Row label="Method" value={labelize(item.acquisition_method)} />
        </dl>
      </Card>
      {item.integrity_note ? (
        <Card title="Integrity note" className="md:col-span-2">
          <p className="text-sm">{item.integrity_note}</p>
        </Card>
      ) : null}
    </div>
  );
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="text-muted">{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function Preview({ evidenceId }: { evidenceId: string }) {
  const query = useQuery({
    queryKey: ["preview", evidenceId],
    queryFn: () =>
      api<{ content: string; encoding: string; truncated: boolean; note: string }>(
        `/evidence/${evidenceId}/preview`,
      ),
  });
  if (query.isError) return <ErrorState error={query.error} />;
  if (!query.data) return <SkeletonRows />;
  return (
    <Card title="Sanitised preview">
      <p className="mb-2 text-xs text-muted">{query.data.note}</p>
      {query.data.truncated ? <p className="mb-2 text-xs text-status-medium">Truncated — this is not the complete artifact.</p> : null}
      <pre className="max-h-[480px] overflow-auto rounded bg-canvas p-3 text-xs">{query.data.content}</pre>
    </Card>
  );
}

function Analysis({ evidenceId }: { evidenceId: string }) {
  const query = useQuery({
    queryKey: ["analysis-findings", evidenceId],
    queryFn: () =>
      api<Page<{ id: string; title: string; severity: string; analyzer: string; description: string }>>(
        `/analysis/findings?evidence_id=${evidenceId}`,
      ),
  });
  return (
    <Card title="Analyzer findings">
      <DataTable
        rows={query.data?.items ?? []}
        empty={<p className="text-sm text-muted">No analyzer findings yet.</p>}
        columns={[
          { key: "title", header: "Finding", render: (row) => row.title },
          { key: "an", header: "Analyzer", render: (row) => row.analyzer },
          { key: "sev", header: "Severity", render: (row) => row.severity },
        ]}
      />
    </Card>
  );
}

function Entities({ evidenceId }: { evidenceId: string }) {
  const query = useQuery({
    queryKey: ["entities", evidenceId],
    queryFn: () =>
      api<Page<{ id: string; kind: string; summary: string; actor_value: string | null; excerpt: string | null }>>(
        `/observations?evidence_id=${evidenceId}`,
      ),
  });
  return (
    <Card title="Observed entities">
      <DataTable
        rows={query.data?.items ?? []}
        empty={<p className="text-sm text-muted">No entities extracted yet.</p>}
        columns={[
            { key: "type", header: "Kind", render: (row) => row.kind },
          { key: "val", header: "Observed", render: (row) => <span className="mono text-xs">{row.actor_value ?? row.summary}</span> },
          { key: "n", header: "Excerpt", render: (row) => row.excerpt ?? "—" },
        ]}
      />
    </Card>
  );
}

function Relationships({ evidenceId }: { evidenceId: string }) {
  const query = useQuery({
    queryKey: ["correlations", evidenceId],
    queryFn: () =>
      api<Page<{ id: string; explanation: string; score: number; is_cross_case: boolean }>>(
        `/intelligence/correlations?evidence_id=${evidenceId}`,
      ),
  });
  return (
    <Card title="Correlations">
      <DataTable
        rows={query.data?.items ?? []}
        empty={<p className="text-sm text-muted">No scored links yet.</p>}
        columns={[
          { key: "why", header: "Why related", render: (row) => row.explanation },
          { key: "score", header: "Score", render: (row) => row.score.toFixed(3) },
          { key: "x", header: "Cross-case", render: (row) => (row.is_cross_case ? "yes" : "no") },
        ]}
      />
    </Card>
  );
}

function Custody({ evidenceId }: { evidenceId: string }) {
  const chain = useQuery({
    queryKey: ["chain", evidenceId],
    queryFn: () => api<ChainStatus>(`/evidence/${evidenceId}/custody/verify`),
  });
  const events = useQuery({
    queryKey: ["custody-events", evidenceId],
    queryFn: () => api<CustodyEvent[]>(`/evidence/${evidenceId}/custody`),
  });
  const checks = useQuery({
    queryKey: ["integrity-checks", evidenceId],
    queryFn: () => api<IntegrityCheck[]>(`/evidence/${evidenceId}/integrity-checks`),
  });
  return (
    <div className="space-y-4">
      <Card title="Chain verification">
        {chain.data ? (
          <div className="space-y-2 text-sm">
            <IntegrityBadge status={chain.data.trustworthy ? "verified" : "hash_mismatch"} />
            <p>{chain.data.summary}</p>
            <p className="text-muted">
              {chain.data.event_count} events · signatures {chain.data.signatures_valid}/
              {chain.data.signatures_checked}
            </p>
            {chain.data.breaks.map((item) => (
              <p key={item.record_id} className="text-status-critical">
                seq {item.sequence}: {item.detail}
              </p>
            ))}
          </div>
        ) : (
          <SkeletonRows rows={3} />
        )}
      </Card>
      <Card title="Custody timeline">
        <ol className="space-y-3">
          {(events.data ?? []).map((event) => (
            <li key={event.id} className="border-l-2 border-accent/40 pl-3 text-sm">
              <div className="font-medium">
                #{event.sequence} {event.action}
              </div>
              <div className="text-muted">
                {event.actor_label} · <Timestamp value={event.occurred_at} />
              </div>
              <HashDisplay value={event.entry_hash} label="entry hash" />
              {event.previous_hash ? <HashDisplay value={event.previous_hash} label="prev" /> : <span className="text-xs text-muted">genesis</span>}
            </li>
          ))}
        </ol>
      </Card>
      <Card title="Integrity checks">
        <DataTable
          rows={checks.data ?? []}
          empty={<p className="text-sm text-muted">No verifications recorded.</p>}
          columns={[
            { key: "st", header: "Result", render: (row) => <IntegrityBadge status={row.status} /> },
            { key: "ct", header: "Ciphertext", render: (row) => (row.ciphertext_verified ? "authenticated" : "failed") },
            { key: "when", header: "When", render: (row) => <Timestamp value={row.created_at} /> },
          ]}
        />
      </Card>
    </div>
  );
}

function Versions({ evidenceId, item }: { evidenceId: string; item: EvidenceDetail }) {
  const query = useQuery({
    queryKey: ["versions", evidenceId],
    queryFn: () => api<Array<{ id: string; version_number: number; sha256: string; reason: string; is_current: boolean; created_at: string }>>(
      `/evidence/${evidenceId}/versions`,
    ),
  });
  return (
    <Card title="Versions">
      <DataTable
        rows={query.data ?? []}
        empty={<p className="text-sm text-muted">Only the original acquisition is recorded.</p>}
        columns={[
          { key: "n", header: "v", render: (row) => row.version_number },
          { key: "hash", header: "SHA-256", render: (row) => <HashDisplay value={row.sha256} /> },
          { key: "why", header: "Reason", render: (row) => row.reason },
          { key: "cur", header: "Current", render: (row) => (row.is_current ? "yes" : "") },
        ]}
      />
      <p className="mt-3 text-xs text-muted">Head hash on the evidence row: {item.custody_head_hash ?? "—"}</p>
    </Card>
  );
}
