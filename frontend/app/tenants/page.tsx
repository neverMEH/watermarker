"use client";

import { useEffect, useState } from "react";
import {
  apiGet,
  apiPostJSON,
  type CreateTenantResp,
  type Tenant,
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

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [createdInfo, setCreatedInfo] = useState<CreateTenantResp | null>(null);

  async function refresh() {
    setLoading(true);
    setErr(null);
    try {
      setTenants(await apiGet<Tenant[]>("/v1/tenants"));
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const out = await apiPostJSON<CreateTenantResp>("/v1/tenants", {
        tenant_name: name,
        user_email: email,
      });
      setCreatedInfo(out);
      setName("");
      setEmail("");
      await refresh();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Tenants</h1>
        <p className="text-sm text-muted-foreground">
          Each tenant gets its own master key; users and devices live under a tenant.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Create tenant</CardTitle>
          <CardDescription>
            Provisions a tenant + initial user in one call.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={submit}
            className="grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end"
          >
            <div className="space-y-1.5">
              <Label htmlFor="tname">Tenant name</Label>
              <Input
                id="tname"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Acme Inc"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="temail">Initial user email</Label>
              <Input
                id="temail"
                required
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@acme.com"
              />
            </div>
            <Button type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create tenant"}
            </Button>
          </form>
          {createdInfo && (
            <div className="mt-4 rounded-md border bg-emerald-50 p-3 text-sm">
              Tenant created.{" "}
              <span className="font-mono">tenant_id={createdInfo.tenant_id}</span>{" "}
              <span className="font-mono">user_id={createdInfo.user_id}</span>
            </div>
          )}
          {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>All tenants</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : tenants.length === 0 ? (
            <p className="text-sm text-muted-foreground">No tenants yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenants.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell className="font-mono text-xs">{t.id}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(t.created_at).toLocaleString()}
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
