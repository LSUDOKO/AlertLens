// One typed client for the AlertLens API. Types for the core models come from the API's own OpenAPI schema.
import type { components } from "./api-schema";

export type AnalysisResult = components["schemas"]["AnalysisResult"];
export type Claim = components["schemas"]["Claim"];
export type Action = components["schemas"]["Action"];
export type Explanation = components["schemas"]["Explanation"];

export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit & { json?: unknown }, timeoutMs = 90_000): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_URL}${path}`, {
      method: init?.json !== undefined ? "POST" : init?.method ?? "GET",
      headers: init?.json !== undefined ? { "content-type": "application/json" } : undefined,
      body: init?.json !== undefined ? JSON.stringify(init.json) : init?.body,
      signal: ctrl.signal,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new ApiError(res.status, body.error ?? "http_error", body.detail ?? res.statusText);
    return body as T;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if ((e as Error).name === "AbortError") throw new ApiError(0, "timeout", "The API took too long to answer.");
    throw new ApiError(0, "offline", "The API is not reachable. A free server may be waking up; try again in a minute.");
  } finally {
    clearTimeout(timer);
  }
}

export type Health = { status: string; provider: string; model: string; version: string; public_demo: boolean };
export type Sample = { name: string; alert: Record<string, unknown> };
export type RedTeamOptions = {
  alerts: string[];
  families: string[];
  fields: string[];
  max_custom_payload: number;
  real_model: boolean;
  examples: Record<string, string>;
};
export type NaiveVerdict = { severity: string; verdict: string; actions: string[]; explanation: string };
export type Layer = { layer: string; detail: string };
export type AttackResult = {
  family: string;
  field: string;
  dirty_alert: Record<string, unknown>;
  naive: NaiveVerdict;
  naive_clean: NaiveVerdict;
  naive_fooled: boolean;
  alertlens: AnalysisResult;
  alertlens_fooled: boolean;
  clean: { label: string; score: number; base_score: number };
  layers: Layer[];
  model: string;
};
export type Attempt = { text: string; ops: string[]; risk: number; detected: boolean; label: string; base_score: number; triage: string };
export type AdaptiveSummary = {
  campaigns: number;
  attempts: number;
  evasion_rate: number;
  campaigns_with_an_evasion: number;
  decision_changed: number;
  labels_lowered: number;
  auto_close: number;
  evasion_by_operator: Record<string, number>;
  examples: { text: string; ops: string[] }[];
};
export type AdaptiveResult = { summary: AdaptiveSummary; clean_label: string; clean_base_score: number; attempts: Attempt[] };
export type GraphNode = { id: string; label: string; kind: string; pivot?: boolean; degree?: number };
export type GraphEdge = { source: string; target: string; label?: string };
export type TimelineRow = { ts: string; alert_id: string; rule_id: string; what: string; tactic: string; label: string; score: number; injected: boolean };
export type Incident = {
  incident_id: string;
  alert_ids: string[];
  entities: { kind: string; value: string; role?: string | null }[];
  tactics_sequence: string[];
  severity: { score: number; label: string; triage: string; reasons: string[] };
  timeline: TimelineRow[];
  graph_summary: string;
  predicted_next: { tactic: string; weight: number; example_techniques: string[]; watch_for: string; note: string }[];
  pivot?: string | null;
  graph: { nodes: GraphNode[]; edges: (GraphEdge & { alert_id?: string; action?: string })[] };
};
// Benchmark files are read as committed; each may be missing.
export type Benchmark = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const api = {
  health: () => call<Health>("/health", undefined, 75_000),
  samples: () => call<Sample[]>("/v2/samples"),
  analyze: (alert: unknown, opts: { audience?: string; lang?: string; deep?: boolean } = {}) => {
    const q = new URLSearchParams({ audience: opts.audience ?? "analyst", lang: opts.lang ?? "en", deep: String(Boolean(opts.deep)) });
    return call<AnalysisResult>(`/analyze?${q}`, { json: alert });
  },
  redteamOptions: () => call<RedTeamOptions>("/v2/redteam/options"),
  attack: (body: { alert_id: string; field: string; family?: string; payload?: string; model?: "simulated" | "configured" }) =>
    call<AttackResult>("/v2/redteam/attack", { json: body }, 600_000),
  adaptive: (body: { alert_id: string; field: string; seed_text: string; steps: number; seed?: number }) =>
    call<AdaptiveResult>("/v2/redteam/adaptive", { json: body }),
  heroDemo: () => call<{ incident_id: string; alert_ids: string[]; incident: Incident | null }>("/v2/demo/hero", { json: {} }),
  incident: (id: string) => call<Incident>(`/incidents/${encodeURIComponent(id)}`),
  benchmark: () => call<Benchmark>("/v2/benchmark"),
  approve: (instanceId: string, approver: string, confirm = false) =>
    call<Action>(`/actions/${encodeURIComponent(instanceId)}/approve`, { json: { approver, confirm } }),
};

export const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;
export const pct = (v: number | null | undefined, d = 1) => (v === null || v === undefined ? "n/a" : `${(v * 100).toFixed(d)}%`);
