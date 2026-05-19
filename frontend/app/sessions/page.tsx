"use client";

import { useEffect, useMemo, useState } from "react";
import {
  API_BASE,
  apiGet,
  type Device,
  type SessionRow,
  type Tenant,
  type User,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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

interface IssueResp {
  token: number;
  token_hex: string;
  issued_at: string;
  expires_at: string;
  watermark_w: number;
  watermark_h: number;
  symbol_size: number;
  encoded_symbols: number[];
}

export default function SessionsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [sessions, setSessions] = useState<SessionRow[]>([]);

  const [deviceId, setDeviceId] = useState("");
  const [enrollSecret, setEnrollSecret] = useState("");
  const [issueErr, setIssueErr] = useState<string | null>(null);
  const [issueBusy, setIssueBusy] = useState(false);
  const [issued, setIssued] = useState<IssueResp | null>(null);

  async function refresh() {
    try {
      const [ts, us, ds, ss] = await Promise.all([
        apiGet<Tenant[]>("/v1/tenants"),
        apiGet<User[]>("/v1/users"),
        apiGet<Device[]>("/v1/devices"),
        apiGet<SessionRow[]>("/v1/sessions", { limit: "100" }),
      ]);
      setTenants(ts);
      setUsers(us);
      setDevices(ds);
      setSessions(ss);
    } catch (e: any) {
      setIssueErr(e.message ?? String(e));
    }
  }
  useEffect(() => {
    refresh();
  }, []);

  const tenantById = useMemo(
    () => Object.fromEntries(tenants.map((t) => [t.id, t.name])),
    [tenants]
  );
  const userById = useMemo(
    () => Object.fromEntries(users.map((u) => [u.id, u.email])),
    [users]
  );
  const deviceById = useMemo(
    () => Object.fromEntries(devices.map((d) => [d.id, d.hostname])),
    [devices]
  );

  async function issue(e: React.FormEvent) {
    e.preventDefault();
    setIssueBusy(true);
    setIssueErr(null);
    setIssued(null);
    try {
      const res = await fetch(`${API_BASE}/v1/sessions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${enrollSecret}`,
          "X-Device-Id": deviceId,
        },
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const j = await res.json();
          if (j?.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
        } catch {
          /* swallow */
        }
        throw new Error(msg);
      }
      const j = (await res.json()) as IssueResp;
      setIssued(j);
      await refresh();
    } catch (e: any) {
      setIssueErr(e.message ?? String(e));
    } finally {
      setIssueBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Watermarks</h1>
        <p className="text-sm text-muted-foreground">
          Sessions are 40-bit tokens encoded into the screen overlay; they rotate every 5
          minutes per the build spec.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Issue test watermark</CardTitle>
          <CardDescription>
            Uses the device enrollment secret as a bearer token, the same as the desktop agent
            does in production. Paste the values shown at enrollment time.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={issue}
            className="grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end"
          >
            <div className="space-y-1.5">
              <Label htmlFor="did">Device</Label>
              <select
                id="did"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                required
              >
                <option value="">— pick a device —</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.hostname} — {userById[d.user_id] ?? d.user_id}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="secret">Enrollment secret</Label>
              <Input
                id="secret"
                type="password"
                required
                value={enrollSecret}
                onChange={(e) => setEnrollSecret(e.target.value)}
                placeholder="paste from device enrollment"
              />
            </div>
            <Button type="submit" disabled={issueBusy || !deviceId}>
              {issueBusy ? "Issuing…" : "Issue watermark"}
            </Button>
          </form>

          {issued && (
            <div className="mt-4 grid gap-2 rounded-md border bg-muted/50 p-3 text-sm md:grid-cols-2">
              <div>
                <span className="text-muted-foreground">token: </span>
                <span className="font-mono">{issued.token_hex}</span>
              </div>
              <div>
                <span className="text-muted-foreground">expires: </span>
                {new Date(issued.expires_at).toLocaleString()}
              </div>
              <div>
                <span className="text-muted-foreground">grid: </span>
                {issued.watermark_w}×{issued.watermark_h}, symbol {issued.symbol_size}px
              </div>
              <div>
                <span className="text-muted-foreground">symbols: </span>
                {issued.encoded_symbols.length}
              </div>
            </div>
          )}
          {issueErr && <p className="mt-3 text-sm text-destructive">{issueErr}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent sessions</CardTitle>
        </CardHeader>
        <CardContent>
          {sessions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No sessions issued yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Token</TableHead>
                  <TableHead>Tenant</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Issued</TableHead>
                  <TableHead>Expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => {
                  const exp = new Date(s.expires_at).getTime();
                  const expired = exp < Date.now();
                  return (
                    <TableRow key={s.token}>
                      <TableCell>
                        {expired ? (
                          <Badge variant="secondary">expired</Badge>
                        ) : (
                          <Badge variant="success">active</Badge>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{s.token_hex}</TableCell>
                      <TableCell>{tenantById[s.tenant_id] ?? s.tenant_id}</TableCell>
                      <TableCell>{userById[s.user_id] ?? s.user_id}</TableCell>
                      <TableCell>{deviceById[s.device_id] ?? s.device_id}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(s.issued_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(s.expires_at).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
