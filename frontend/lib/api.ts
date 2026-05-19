"use client";

import { getAdminToken } from "./auth";

const RAW_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL?.trim() || "http://localhost:8000";
export const API_BASE = RAW_BASE.replace(/\/+$/, "");

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let body: unknown = null;
  let message = `HTTP ${res.status}`;
  try {
    body = await res.json();
    if (body && typeof body === "object" && "detail" in body) {
      const d = (body as { detail: unknown }).detail;
      message = typeof d === "string" ? d : JSON.stringify(d);
    }
  } catch {
    try {
      message = await res.text();
    } catch {
      /* swallow */
    }
  }
  return new ApiError(res.status, message, body);
}

function authHeaders(extra?: HeadersInit): HeadersInit {
  const tok = getAdminToken();
  const h: Record<string, string> = { ...(extra as Record<string, string>) };
  if (tok) h["Authorization"] = `Bearer ${tok}`;
  return h;
}

export async function apiGet<T>(path: string, params?: Record<string, string | undefined>): Promise<T> {
  const url = new URL(`${API_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, v);
    }
  }
  const res = await fetch(url.toString(), {
    method: "GET",
    headers: authHeaders({ Accept: "application/json" }),
    cache: "no-store",
  });
  if (!res.ok) throw await parseError(res);
  return res.json() as Promise<T>;
}

export async function apiPostJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json", Accept: "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw await parseError(res);
  return res.json() as Promise<T>;
}

export async function apiPostForm<T>(path: string, form: FormData): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders({ Accept: "application/json" }),
    body: form,
  });
  if (!res.ok) throw await parseError(res);
  return res.json() as Promise<T>;
}

// -----------------------------------------------------------------------
// Typed shapes (mirror backend pydantic models)
// -----------------------------------------------------------------------
export interface Tenant {
  id: string;
  name: string;
  created_at: string;
}
export interface User {
  id: string;
  tenant_id: string;
  email: string;
  created_at: string;
}
export interface Device {
  id: string;
  tenant_id: string;
  user_id: string;
  hostname: string;
  os: string;
  created_at: string;
}
export interface SessionRow {
  token: number;
  token_hex: string;
  tenant_id: string;
  user_id: string;
  device_id: string;
  issued_at: string;
  expires_at: string;
}
export interface Extraction {
  id: string;
  tenant_id: string | null;
  investigator_email: string;
  case_id: string;
  image_sha256: string;
  result_summary: string | null;
  ts: string;
}
export interface AuditEvent {
  id: string;
  tenant_id: string | null;
  event_type: string;
  actor: string | null;
  target: string | null;
  payload: string | null;
  ts: string;
}
export interface ExtractResp {
  success: boolean;
  strategy: string;
  ber_estimate: number;
  token_hex: string | null;
  tenant_id: string | null;
  user_email: string | null;
  device_hostname: string | null;
  time_window_start: string | null;
  time_window_end: string | null;
  failure_reason: string | null;
  audit_id: string | null;
  session_kind: string | null;
  asset_id: string | null;
  asset_type: string | null;
  asset_status: string | null;
  asset_case_id: string | null;
  asset_description: string | null;
  asset_recipient_name: string | null;
  asset_recipient_email: string | null;
  asset_recipient_ref: string | null;
  asset_created_at: string | null;
}

export interface Asset {
  id: string;
  tenant_id: string;
  asset_type: string;
  case_id: string | null;
  description: string | null;
  recipient_user_id: string | null;
  recipient_name: string | null;
  recipient_email: string | null;
  recipient_ref: string | null;
  issued_by_email: string | null;
  token: number;
  token_hex: string;
  original_sha256: string;
  original_mime: string;
  original_w: number;
  original_h: number;
  status: string;
  created_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export function assetMarkedUrl(assetId: string): string {
  return `${API_BASE}/v1/assets/${assetId}/marked`;
}

/** Fetch a binary asset with the admin bearer and trigger a browser download. */
export async function downloadAssetMarked(assetId: string, filename: string): Promise<void> {
  const tok = getAdminToken();
  const res = await fetch(`${API_BASE}/v1/assets/${assetId}/marked`, {
    headers: tok ? { Authorization: `Bearer ${tok}` } : undefined,
  });
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`, null);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
export interface CreateTenantResp {
  tenant_id: string;
  user_id: string;
}
export interface EnrollDeviceResp {
  device_id: string;
  enroll_secret: string;
}
