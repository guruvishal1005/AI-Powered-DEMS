import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../lib/api";
import { useUi } from "../lib/ui";
import type { SearchResults } from "../lib/types";

export function CommandPalette() {
  const open = useUi((s) => s.commandOpen);
  const setOpen = useUi((s) => s.setCommandOpen);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResults | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(!open);
      }
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, setOpen]);

  useEffect(() => {
    if (!open || query.trim().length < 2) {
      setResults(null);
      return;
    }
    const handle = window.setTimeout(() => {
      void api<SearchResults>(`/search?q=${encodeURIComponent(query.trim())}`).then(setResults);
    }, 200);
    return () => window.clearTimeout(handle);
  }, [open, query]);

  const hits = useMemo(() => {
    if (!results) return [];
    return [
      ...results.cases.map((hit) => ({ ...hit, group: "Cases" })),
      ...results.evidence.map((hit) => ({ ...hit, group: "Evidence" })),
      ...results.hashes.map((hit) => ({ ...hit, group: "Hashes" })),
      ...results.entities.map((hit) => ({ ...hit, group: "Entities" })),
    ];
  }, [results]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-6 pt-24">
      <div
        role="dialog"
        aria-label="Command palette"
        className="w-full max-w-xl overflow-hidden rounded-lg border border-line bg-surface"
      >
        <input
          autoFocus
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search cases, evidence, hashes, entities"
          className="w-full border-b border-line bg-transparent px-4 py-3 text-sm outline-none"
        />
        <ul className="max-h-80 overflow-y-auto py-2">
          {hits.length === 0 ? (
            <li className="px-4 py-3 text-sm text-muted">
              {query.length < 2 ? "Type at least two characters." : "No matches in your scope."}
            </li>
          ) : (
            hits.map((hit) => (
              <li key={`${hit.kind}-${hit.id}`}>
                <button
                  className="flex w-full flex-col items-start px-4 py-2 text-left hover:bg-raised"
                  onClick={() => {
                    navigate(hit.href);
                    setOpen(false);
                    setQuery("");
                  }}
                >
                  <span className="text-[11px] uppercase tracking-wide text-muted">{hit.group}</span>
                  <span className="text-sm text-ink">
                    {hit.reference ? `${hit.reference} · ` : ""}
                    {hit.title}
                  </span>
                  {hit.subtitle ? <span className="text-xs text-muted">{hit.subtitle}</span> : null}
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
