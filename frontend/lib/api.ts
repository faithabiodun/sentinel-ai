/**
 * Typed API client.
 *
 * Auth token lives in a cookie (sentinel_token) set by setToken() after
 * login/register. The middleware reads the same cookie to gate protected
 * routes. API calls pull the token from the cookie and send it as a Bearer
 * header so FastAPI can verify it.
 */

const BASE =
  (typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_URL) ||
  "http://localhost:8000";

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

export function setToken(token: string): void {
  const maxAge = 60 * 60 * 24; // 24 h
  document.cookie = `sentinel_token=${token}; path=/; max-age=${maxAge}; SameSite=Strict`;
}

export function clearToken(): void {
  document.cookie = "sentinel_token=; path=/; max-age=0";
}

export function getToken(): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(/(?:^|;\s*)sentinel_token=([^;]+)/);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token = getToken();

  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    });
  } catch {
    // fetch() rejects on DNS/connection failure with an opaque TypeError.
    // Name the actual problem — an unreachable API is the most likely
    // misconfiguration in a fresh deployment.
    throw new ApiError(0, `Cannot reach the API at ${BASE}. Is the backend running?`);
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface TokenResponse {
  access_token: string;
  token_type: string;
  analyst_id: string;
  email: string;
  display_name: string;
  role: string;
}

export const auth = {
  register: (body: { email: string; display_name: string; password: string }) =>
    apiFetch<TokenResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  login: (body: { email: string; password: string }) =>
    apiFetch<TokenResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  me: () => apiFetch<{ analyst_id: string; email: string; display_name: string; role: string }>("/api/auth/me"),
};

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export interface IncidentSummary {
  id: string;
  ref: string;
  title: string;
  severity: string;
  status: string;
  host: string | null;
  primary_user: string | null;
  attack_technique: string | null;
  alert_count: number;
  opened_at: string;
  summary: string | null;
}

export interface HypothesisOut {
  id: string;
  statement: string;
  status: string;
  confidence: number | null;
  supporting: number;
  contradicting: number;
  note: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface TimelineEventOut {
  seq: number;
  occurred_at: string;
  actor: string | null;
  action: string;
  attack_technique: string | null;
}

export interface EvidenceOut {
  id: string;
  claim: string;
  supports: boolean;
  source_tool: string | null;
  created_at: string;
}

export interface EntityOut {
  id: string;
  kind: string;
  value: string;
  verdict: string;
  reasoning: string | null;
  risk_score: number | null;
  times_seen: number;
  first_seen: string;
  cleared_count: number;
}

export interface SimilarIncident {
  ref: string;
  title: string;
  similarity: number;
}

export interface IncidentDetail extends IncidentSummary {
  root_cause: string | null;
  report: string | null;
  closed_at: string | null;
  hypotheses: HypothesisOut[];
  timeline: TimelineEventOut[];
  evidence: EvidenceOut[];
  entities: EntityOut[];
  similar: SimilarIncident | null;
}

export interface QueueStats {
  open: number;
  investigating: number;
  closed: number;
  auto_cleared: number;
  total_alerts: number;
  total_events: number;
}

export const incidents = {
  list: () => apiFetch<IncidentSummary[]>("/api/incidents"),
  stats: () => apiFetch<QueueStats>("/api/incidents/stats"),
  get: (id: string) => apiFetch<IncidentDetail>(`/api/incidents/${id}`),
  investigate: (id: string) =>
    apiFetch<{ status: string; incident_id: string; ref: string }>(
      `/api/incidents/${id}/investigate`,
      { method: "POST" },
    ),
};

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

export interface EntityMemory {
  id: string;
  kind: string;
  value: string;
  verdict: string;
  reasoning: string | null;
  riskScore: number | null;
  timesSeen: number;
  firstSeen: string | null;
  lastSeen: string | null;
  clearedCount: number;
}

export interface EntityStats {
  total: number;
  malicious: number;
  suspicious: number;
  benign: number;
  unknown: number;
}

export const entities = {
  list: (params?: { verdict?: string; kind?: string }) => {
    const q = new URLSearchParams();
    if (params?.verdict) q.set("verdict", params.verdict);
    if (params?.kind) q.set("kind", params.kind);
    const qs = q.toString();
    return apiFetch<EntityMemory[]>(`/api/entities${qs ? `?${qs}` : ""}`);
  },
  stats: () => apiFetch<EntityStats>("/api/entities/stats"),
};
