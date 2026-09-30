import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { GraphNode, GraphProjection } from "../lib/types";
import { Card, ErrorState, SkeletonRows } from "../design/primitives";

export function GraphPanel({ caseId }: { caseId?: string }) {
  const container = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [layout, setLayout] = useState<"cose" | "concentric" | "breadthfirst">("cose");
  const query = useQuery({
    queryKey: ["graph", caseId],
    queryFn: () => api<GraphProjection>(`/graph?${caseId ? `case_id=${caseId}&` : ""}depth=2&max_nodes=250`),
  });

  useEffect(() => {
    if (!container.current || !query.data) return;
    const cy = cytoscape({
      container: container.current,
      elements: [
        ...query.data.nodes.map((node) => ({
          data: { ...node, id: node.id, label: node.label },
        })),
        ...query.data.edges.map((edge) => ({
          data: { id: edge.id, source: edge.source, target: edge.target, label: edge.label },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e8edf2",
            "font-size": 10,
            "background-color": "#2dd4bf",
            "text-outline-color": "#07090c",
            "text-outline-width": 2,
            width: 24,
            height: 24,
          },
        },
        {
          selector: "node[kind = 'evidence']",
          style: { "background-color": "#7dd3fc" },
        },
        {
          selector: "node[is_pivot]",
          style: { "background-color": "#f87171", width: 36, height: 36 },
        },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#2a3440",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#2a3440",
            "curve-style": "bezier",
          },
        },
      ],
      layout: { name: layout, animate: false },
    });
    cy.on("tap", "node", (event) => setSelected(event.target.data() as GraphNode));
    return () => {
      cy.destroy();
    };
  }, [query.data, layout]);

  if (query.isError) return <ErrorState error={query.error} />;
  if (!query.data) return <SkeletonRows />;

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card
        title={`${query.data.node_count} nodes · ${query.data.edge_count} edges`}
        className="xl:col-span-2"
        actions={
          <select
            value={layout}
            onChange={(event) => setLayout(event.target.value as typeof layout)}
            className="rounded border border-line bg-canvas px-2 py-1 text-xs"
          >
            <option value="cose">cose</option>
            <option value="concentric">concentric</option>
            <option value="breadthfirst">breadthfirst</option>
          </select>
        }
      >
        <div ref={container} className="h-[520px] rounded bg-canvas" />
      </Card>
      <Card title="Inspection">
        {selected ? (
          <dl className="space-y-2 text-sm">
            <div>
              <dt className="text-muted">Label</dt>
              <dd>{selected.label}</dd>
            </div>
            <div>
              <dt className="text-muted">Kind</dt>
              <dd>{selected.kind}</dd>
            </div>
            <div>
              <dt className="text-muted">Degree centrality</dt>
              <dd>{selected.degree_centrality.toFixed(3)}</dd>
            </div>
            <div>
              <dt className="text-muted">Betweenness</dt>
              <dd>{selected.betweenness_centrality.toFixed(3)}</dd>
            </div>
            <div>
              <dt className="text-muted">PageRank</dt>
              <dd>{selected.pagerank.toFixed(4)}</dd>
            </div>
            {selected.is_pivot ? <p className="text-status-critical">Pivot entity (server-ranked)</p> : null}
          </dl>
        ) : (
          <p className="text-sm text-muted">Select a node. Pivot nodes are highlighted from server-side centrality.</p>
        )}
      </Card>
    </div>
  );
}
