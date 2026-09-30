import { useState } from "react";
import { api } from "../lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { Button, Dialog } from "../design/primitives";

export function UploadDialog({
  open,
  caseId,
  onClose,
}: {
  open: boolean;
  caseId: string;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [hash, setHash] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function hashFile(selected: File) {
    setHash("hashing…");
    const buffer = await selected.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    setHash(hex);
  }

  async function submit() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("case_id", caseId);
      form.append("file", file);
      form.append(
        "metadata",
        JSON.stringify({
          title: file.name,
          source_category: "digital_device",
          acquisition_method: "file_export",
          acquired_by_name: "Investigator (console upload)",
          collection_notes: "Uploaded through the CYBERTRACE console.",
        }),
      );
      setProgress(60);
      await api("/evidence", { method: "POST", body: form });
      setProgress(100);
      await client.invalidateQueries({ queryKey: ["evidence"] });
      onClose();
      setFile(null);
      setHash(null);
      setProgress(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title="Acquire evidence" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p className="text-muted">
          Acquisition metadata is stored as a claim attributed to you. The SHA-256 below is computed
          in the browser so you can compare it with the server-recorded fingerprint after ingest.
        </p>
        <input
          type="file"
          onChange={(event) => {
            const selected = event.target.files?.[0] ?? null;
            setFile(selected);
            if (selected) void hashFile(selected);
          }}
        />
        {hash ? (
          <p className="mono break-all text-xs">
            Browser SHA-256: {hash}
          </p>
        ) : null}
        {progress > 0 ? (
          <div className="h-1 overflow-hidden rounded bg-raised">
            <div className="h-full bg-accent" style={{ width: `${progress}%` }} />
          </div>
        ) : null}
        {error ? <p className="text-status-critical">{error}</p> : null}
        <Button variant="primary" disabled={!file || busy} onClick={() => void submit()}>
          Register artifact
        </Button>
      </div>
    </Dialog>
  );
}
