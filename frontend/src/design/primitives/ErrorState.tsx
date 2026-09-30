import { ApiError } from "../../lib/types";
import { Button } from "./Button";

export function ErrorState({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const message =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : "The request failed.";
  return (
    <div role="alert" className="rounded-lg border border-status-critical/40 bg-status-critical/10 px-4 py-4">
      <h3 className="text-sm font-semibold text-status-critical">Unable to load this view</h3>
      <p className="mt-1 text-sm text-ink">{message}</p>
      {onRetry ? (
        <Button className="mt-3" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
