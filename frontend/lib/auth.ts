"use client";

const KEY = "watermark.adminToken";

export function getAdminToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(KEY);
}

export function setAdminToken(tok: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, tok);
}

export function clearAdminToken(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
}
