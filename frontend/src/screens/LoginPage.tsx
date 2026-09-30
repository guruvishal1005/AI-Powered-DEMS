import { useState, type FormEvent } from "react";
import { Navigate } from "react-router";
import { useAuth } from "../lib/auth";
import { ApiError } from "../lib/types";
import { Button } from "../design/primitives";

export function LoginPage() {
  const { user, ready, login } = useAuth();
  const [email, setEmail] = useState("r.mehta@cybertrace.gov");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  if (ready && user) return <Navigate to="/" replace />;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <form
        onSubmit={(event) => void onSubmit(event)}
        className="w-full max-w-md space-y-4 rounded-lg border border-line bg-surface p-8"
      >
        <div>
          <p className="text-xs tracking-[0.25em] text-accent">CYBERTRACE</p>
          <h1 className="mt-2 text-xl font-semibold">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Access tokens stay in memory. Sessions rotate on refresh.</p>
        </div>
        <label className="block text-sm">
          Email
          <input
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2"
          />
        </label>
        <label className="block text-sm">
          Password
          <input
            type="password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1 w-full rounded-md border border-line bg-canvas px-3 py-2"
          />
        </label>
        {error ? <p className="text-sm text-status-critical">{error}</p> : null}
        <Button type="submit" variant="primary" disabled={pending} className="w-full">
          {pending ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </div>
  );
}
