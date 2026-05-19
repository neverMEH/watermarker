"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  apiGet,
  type Asset,
  type AuditEvent,
  type Device,
  type Extraction,
  type SessionRow,
  type Tenant,
  type User,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";

interface Counts {
  tenants: number;
  users: number;
  devices: number;
  assets: number;
  sessions: number;
  extractions: number;
}

export default function DashboardPage() {
  const [counts, setCounts] = useState<Counts | null>(null);
  const [recent, setRecent] = useState<AuditEvent[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [tenants, users, devices, assets, sessions, extractions, audit] = await Promise.all([
          apiGet<Tenant[]>("/v1/tenants"),
          apiGet<User[]>("/v1/users"),
          apiGet<Device[]>("/v1/devices"),
          apiGet<Asset[]>("/v1/assets"),
          apiGet<SessionRow[]>("/v1/sessions"),
          apiGet<Extraction[]>("/v1/extractions"),
          apiGet<AuditEvent[]>("/v1/audit", { limit: "10" }),
        ]);
        setCounts({
          tenants: tenants.length,
          users: users.length,
          devices: devices.length,
          assets: assets.length,
          sessions: sessions.length,
          extractions: extractions.length,
        });
        setRecent(audit.slice(0, 10));
      } catch (e: any) {
        setErr(e.message ?? String(e));
      }
    })();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Overview of tenants, devices, and recent activity.
        </p>
      </div>

      {err && (
        <Card className="border-destructive/40">
          <CardContent className="pt-6 text-sm text-destructive">{err}</CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
        <Stat label="Assets" value={counts?.assets} href="/assets" />
        <Stat label="Tenants" value={counts?.tenants} href="/tenants" />
        <Stat label="Users" value={counts?.users} href="/users" />
        <Stat label="Devices" value={counts?.devices} href="/devices" />
        <Stat label="Sessions" value={counts?.sessions} href="/sessions" />
        <Stat label="Extractions" value={counts?.extractions} href="/investigator" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent activity</CardTitle>
          <CardDescription>Latest audit events from the backend.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {recent.length === 0 && (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          )}
          {recent.map((evt) => (
            <div
              key={evt.id}
              className="flex flex-wrap items-baseline gap-2 border-b py-2 text-sm last:border-0"
            >
              <Badge variant="secondary" className="font-mono">
                {evt.event_type}
              </Badge>
              <span className="text-muted-foreground">{evt.actor ?? "—"}</span>
              {evt.target && (
                <span className="font-mono text-xs text-muted-foreground truncate">
                  → {evt.target}
                </span>
              )}
              <span className="ml-auto text-xs text-muted-foreground">
                {new Date(evt.ts).toLocaleString()}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function Stat({ label, value, href }: { label: string; value?: number; href: string }) {
  return (
    <Link href={href}>
      <Card className="transition-colors hover:bg-accent">
        <CardHeader className="pb-2">
          <CardDescription>{label}</CardDescription>
          <CardTitle className="text-3xl">{value ?? "—"}</CardTitle>
        </CardHeader>
      </Card>
    </Link>
  );
}
