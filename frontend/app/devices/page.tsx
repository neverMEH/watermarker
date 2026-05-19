"use client";

import { useEffect, useMemo, useState } from "react";
import {
  apiGet,
  apiPostJSON,
  type Device,
  type EnrollDeviceResp,
  type Tenant,
  type User,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function DevicesPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [userId, setUserId] = useState("");
  const [hostname, setHostname] = useState("");
  const [os, setOs] = useState("macos");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [enrolled, setEnrolled] = useState<EnrollDeviceResp | null>(null);

  async function loadBase() {
    try {
      const ts = await apiGet<Tenant[]>("/v1/tenants");
      setTenants(ts);
      if (!tenantId && ts.length > 0) setTenantId(ts[0].id);
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  }
  async function loadScoped() {
    if (!tenantId) {
      setUsers([]);
      setDevices([]);
      return;
    }
    try {
      const [us, ds] = await Promise.all([
        apiGet<User[]>("/v1/users", { tenant_id: tenantId }),
        apiGet<Device[]>("/v1/devices", { tenant_id: tenantId }),
      ]);
      setUsers(us);
      setDevices(ds);
      if (!us.find((u) => u.id === userId)) setUserId(us[0]?.id ?? "");
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  }

  useEffect(() => {
    loadBase();
  }, []);
  useEffect(() => {
    loadScoped();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  const userById = useMemo(
    () => Object.fromEntries(users.map((u) => [u.id, u.email])),
    [users]
  );

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId || !userId) return;
    setBusy(true);
    setErr(null);
    setEnrolled(null);
    try {
      const resp = await apiPostJSON<EnrollDeviceResp>("/v1/devices/enroll", {
        tenant_id: tenantId,
        user_id: userId,
        hostname,
        os,
      });
      setEnrolled(resp);
      setHostname("");
      await loadScoped();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Devices</h1>
        <p className="text-sm text-muted-foreground">
          Enroll a desktop so its agent can request watermark sessions.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Enroll device</CardTitle>
          <CardDescription>
            Returns a one-time enrollment secret — copy it before leaving this page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid gap-3 md:grid-cols-4 md:items-end">
            <div className="space-y-1.5">
              <Label htmlFor="tenant">Tenant</Label>
              <select
                id="tenant"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                required
              >
                <option value="">— pick one —</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="user">User</Label>
              <select
                id="user"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                required
                disabled={users.length === 0}
              >
                <option value="">— pick one —</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="host">Hostname</Label>
              <Input
                id="host"
                required
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="alice-mbp"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="os">OS</Label>
              <select
                id="os"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={os}
                onChange={(e) => setOs(e.target.value)}
              >
                <option value="macos">macOS</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="unknown">unknown</option>
              </select>
            </div>
            <div className="md:col-span-4">
              <Button type="submit" disabled={busy || !userId}>
                {busy ? "Enrolling…" : "Enroll device"}
              </Button>
            </div>
          </form>
          {enrolled && (
            <div className="mt-4 space-y-1 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm">
              <div className="font-medium">Enrollment secret — shown once</div>
              <div>
                <span className="text-muted-foreground">device_id: </span>
                <span className="font-mono">{enrolled.device_id}</span>
              </div>
              <div>
                <span className="text-muted-foreground">enroll_secret: </span>
                <span className="font-mono break-all">{enrolled.enroll_secret}</span>
              </div>
              <div className="text-xs text-muted-foreground">
                Paste this into the desktop agent config; it acts as the device bearer
                token when requesting sessions.
              </div>
            </div>
          )}
          {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Devices</CardTitle>
        </CardHeader>
        <CardContent>
          {devices.length === 0 ? (
            <p className="text-sm text-muted-foreground">No devices enrolled.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Device ID</TableHead>
                  <TableHead>Enrolled</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-medium">{d.hostname}</TableCell>
                    <TableCell>{d.os}</TableCell>
                    <TableCell>{userById[d.user_id] ?? d.user_id}</TableCell>
                    <TableCell className="font-mono text-xs">{d.id}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(d.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
