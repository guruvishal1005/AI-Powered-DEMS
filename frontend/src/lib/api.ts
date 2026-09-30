import { ApiError } from "./types";
import type { paths } from "./api-types";

const CSRF_COOKIE = "cybertrace_csrf";
const API = "/api/v1";

export { ApiError };
export type { paths };

let accessToken: string | null = null;
let csrfToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setSession(token: string | null, csrf?: string | null): void {
  accessToken = token;
  if (csrf) csrfToken = csrf;
}

export function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return csrfToken;
  const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : csrfToken;
}

async function parseError(response: Response): Promise<ApiError> {
  try {
    const body = (await response.json()) as {
      error?: { code?: string; message?: string; details?: Record<string, unknown> };
    };
    return new ApiError(
      response.status,
      body.error?.code ?? "http_error",
      body.error?.message ?? response.statusText,
      body.error?.details ?? {},
    );
  } catch {
    return new ApiError(response.status, "http_error", response.statusText);
  }
}

type RequestOptions = RequestInit & { skipAuth?: boolean; skipRefresh?: boolean };

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (accessToken && !options.skipAuth) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const csrf = readCsrfCookie();
  if (csrf) headers.set("X-CSRF-Token", csrf);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (response.status === 401 && !options.skipRefresh && !path.startsWith("/auth/")) {
    const refreshed = await silentRefresh();
    if (refreshed) return api<T>(path, { ...options, skipRefresh: true });
  }

  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return undefined as T;
  return (await response.json()) as T;
}

export async function apiBlob(
  path: string,
  options: RequestOptions = {},
): Promise<{ blob: Blob; filename: string; sha256: string | null }> {
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const csrf = readCsrfCookie();
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(`${API}${path}`, { ...options, headers, credentials: "include" });
  if (!response.ok) throw await parseError(response);
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="([^"]+)"/);
  return {
    blob: await response.blob(),
    filename: match?.[1] ?? "download.bin",
    sha256: response.headers.get("x-cybertrace-sha256"),
  };
}

export async function silentRefresh(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    try {
      const body = await api<{ access_token: string; csrf_token: string; expires_at: string }>(
        "/auth/refresh",
        { method: "POST", skipAuth: true, skipRefresh: true },
      );
      setSession(body.access_token, body.csrf_token);
      return true;
    } catch {
      setSession(null);
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

export async function ensureCsrf(): Promise<void> {
  if (readCsrfCookie()) return;
  await api<{ ok: boolean; message: string }>("/auth/csrf", { skipAuth: true, skipRefresh: true });
}

export async function downloadFile(path: string): Promise<void> {
  const { blob, filename } = await apiBlob(path);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
