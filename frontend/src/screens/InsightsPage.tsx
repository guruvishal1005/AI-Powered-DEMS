import { Link, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Insight, Page } from "../lib/types";
import { AppShell } from "../shell/AppShell";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  ProvenanceTag,
  SeverityBadge,
  SkeletonRows,
} from "../design/primitives";

export function InsightsPage() {
  const [params] = useSearchParams();
  const caseId = params.get("case_id");
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ["insights", caseId],
    queryFn: () =>
      api<Page<Insight>>(`/intelligence/insights?${caseId ? `case_id=${caseId}&` : ""}size=50`),
  });
  const pin = useMutation({
    mutationFn: (id: string) =>
      api(`/intelligence/insights/${id}/pin`, { method: "POST", body: JSON.stringify({ pinned: true }) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["insights"] }),
  });

  return (
    <AppShell crumbs={["Intelligence"]}>
      <h1 className="mb-2 text-xl font-semibold">AI Insights</h1>
      <p className="mb-6 max-w-3xl text-sm text-muted">
        Observed facts are stored separately from interpretation. LLM narrative, when present, cannot
        write entities, observations, or findings.
      </p>
      {query.isError ? (
        <ErrorState error={query.error} />
      ) : !query.data ? (
        <SkeletonRows />
      ) : query.data.items.length === 0 ? (
        <EmptyState title="No insights" body="Insights appear after analysis, correlation and anomaly detection finish." />
      ) : (
        <div className="space-y-4">
          {query.data.items.map((insight) => (
            <Card
              key={insight.id}
              title={insight.title}
              actions={
                <div className="flex items-center gap-2">
                  <ProvenanceTag provenance={insight.provenance} />
                  <SeverityBadge severity={insight.severity} />
                  <Button onClick={() => pin.mutate(insight.id)}>Pin</Button>
                </div>
              }
            >
              <section className="mb-4 rounded-md border border-line bg-canvas p-3">
                <h3 className="text-xs uppercase tracking-wide text-muted">Observed</h3>
                <p className="mt-1 text-sm">{insight.observed}</p>
                <ul className="mt-2 space-y-1 text-xs">
                  {insight.evidence_refs.map((ref, index) => (
                    <li key={index}>
                      {typeof ref === "object" && ref && "evidence_id" in ref ? (
                        <Link className="text-accent" to={`/evidence/${String((ref as { evidence_id: string }).evidence_id)}`}>
                          Source locator
                        </Link>
                      ) : (
                        JSON.stringify(ref)
                      )}
                    </li>
                  ))}
                </ul>
              </section>
              <section className="rounded-md border border-dashed border-line p-3">
                <h3 className="text-xs uppercase tracking-wide text-muted">Interpretation</h3>
                <p className="mt-1 text-sm text-ink">{insight.interpretation ?? "No interpretation recorded."}</p>
                {insight.llm_narrative ? (
                  <p className="mt-2 text-xs text-muted">
                    LLM ({insight.llm_model ?? "unknown"}): {insight.llm_narrative}
                  </p>
                ) : null}
              </section>
            </Card>
          ))}
        </div>
      )}
    </AppShell>
  );
}
