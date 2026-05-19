"use client";

import { useEffect, useMemo, useState } from "react";
import { apiGet, apiPostJSON, type Tenant, type User } from "@/lib/api";
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

export default function UsersPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      const [ts, us] = await Promise.all([
        apiGet<Tenant[]>("/v1/tenants"),
        apiGet<User[]>("/v1/users", selectedTenant ? { tenant_id: selectedTenant } : {}),
      ]);
      setTenants(ts);
      setUsers(us);
      if (!selectedTenant && ts.length > 0) setSelectedTenant(ts[0].id);
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedTenant]);

  const tenantById = useMemo(
    () => Object.fromEntries(tenants.map((t) => [t.id, t.name])),
    [tenants]
  );

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedTenant) return;
    setBusy(true);
    setErr(null);
    try {
      await apiPostJSON<User>("/v1/users", {
        tenant_id: selectedTenant,
        email,
      });
      setEmail("");
      await load();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Users</h1>
        <p className="text-sm text-muted-foreground">
          Watermarks are attributed to users via their devices.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Add user</CardTitle>
          <CardDescription>Adds a new user under the selected tenant.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={submit}
            className="grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end"
          >
            <div className="space-y-1.5">
              <Label htmlFor="tenant">Tenant</Label>
              <select
                id="tenant"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={selectedTenant}
                onChange={(e) => setSelectedTenant(e.target.value)}
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
              <Label htmlFor="uemail">Email</Label>
              <Input
                id="uemail"
                required
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="person@acme.com"
              />
            </div>
            <Button type="submit" disabled={busy || !selectedTenant}>
              {busy ? "Adding…" : "Add user"}
            </Button>
          </form>
          {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>
            {selectedTenant ? `Filtered to ${tenantById[selectedTenant] ?? "tenant"}` : "All tenants"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {users.length === 0 ? (
            <p className="text-sm text-muted-foreground">No users.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Tenant</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium">{u.email}</TableCell>
                    <TableCell>{tenantById[u.tenant_id] ?? u.tenant_id}</TableCell>
                    <TableCell className="font-mono text-xs">{u.id}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(u.created_at).toLocaleString()}
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
