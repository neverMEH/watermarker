"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Asset,
  Tenant,
  User,
  apiGet,
  apiPostForm,
  apiPostJSON,
  assetMarkedUrl,
  downloadAssetMarked,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { AuthImage } from "@/components/auth-image";

const ASSET_TYPES = [
  { value: "id_card", label: "ID card" },
  { value: "sim_card", label: "SIM card" },
  { value: "document", label: "Document" },
  { value: "other", label: "Other" },
];

export default function AssetsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  // form state
  const [tenantId, setTenantId] = useState("");
  const [assetType, setAssetType] = useState("id_card");
  const [caseId, setCaseId] = useState("");
  const [description, setDescription] = useState("");
  const [recipientMode, setRecipientMode] = useState<"internal" | "external">("internal");
  const [recipientUserId, setRecipientUserId] = useState("");
  const [recipientName, setRecipientName] = useState("");
  const [recipientEmail, setRecipientEmail] = useState("");
  const [recipientRef, setRecipientRef] = useState("");
  const [issuedByEmail, setIssuedByEmail] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [lastIssued, setLastIssued] = useState<Asset | null>(null);

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
      setAssets([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [us, as] = await Promise.all([
        apiGet<User[]>("/v1/users", { tenant_id: tenantId }),
        apiGet<Asset[]>("/v1/assets", { tenant_id: tenantId, limit: "200" }),
      ]);
      // Skip the synthetic asset-issuer user in the recipient dropdown.
      setUsers(us.filter((u) => u.email !== "asset-issuer@unseen.local"));
      setAssets(as);
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadBase();
  }, []);
  useEffect(() => {
    loadScoped();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  function pickFile(f: File | null) {
    setFile(f);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(f ? URL.createObjectURL(f) : null);
  }

  const userById = useMemo(
    () => Object.fromEntries(users.map((u) => [u.id, u.email])),
    [users]
  );

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId || !file) return;
    setBusy(true);
    setErr(null);
    setLastIssued(null);
    try {
      const fd = new FormData();
      fd.set("tenant_id", tenantId);
      fd.set("asset_type", assetType);
      if (caseId) fd.set("case_id", caseId);
      if (description) fd.set("description", description);
      if (issuedByEmail) fd.set("issued_by_email", issuedByEmail);
      if (recipientMode === "internal") {
        if (!recipientUserId) throw new Error("Pick a recipient user");
        fd.set("recipient_user_id", recipientUserId);
      } else {
        if (!recipientName && !recipientEmail && !recipientRef) {
          throw new Error("Provide at least one of name / email / ref");
        }
        if (recipientName) fd.set("recipient_name", recipientName);
        if (recipientEmail) fd.set("recipient_email", recipientEmail);
        if (recipientRef) fd.set("recipient_ref", recipientRef);
      }
      fd.set("image", file);

      const asset = await apiPostForm<Asset>("/v1/assets", fd);
      setLastIssued(asset);

      // Download the marked image immediately so the operator has the artifact.
      const baseName = file.name.replace(/\.[^.]+$/, "");
      await downloadAssetMarked(asset.id, `${baseName}-watermarked-${asset.token_hex}.png`);

      // Reset for next issue
      setFile(null);
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
        setPreviewUrl(null);
      }
      setCaseId("");
      setDescription("");
      setRecipientName("");
      setRecipientEmail("");
      setRecipientRef("");
      await loadScoped();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(asset: Asset) {
    const reason = window.prompt(
      `Revoke this ${asset.asset_type} issued to ${asset.recipient_name ?? asset.recipient_ref ?? "—"}?\n\nReason (optional):`,
      ""
    );
    if (reason === null) return;
    try {
      await apiPostJSON(`/v1/assets/${asset.id}/revoke`, { reason });
      await loadScoped();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  }

  async function download(asset: Asset) {
    try {
      await downloadAssetMarked(asset.id, `asset-${asset.id}-${asset.token_hex}.png`);
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Assets</h1>
        <p className="text-sm text-muted-foreground">
          Issue a watermarked artifact (ID card, SIM card, document) bound to a
          recipient. When a leaked copy surfaces, the Investigator console will
          identify who it was issued to.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Issue asset</CardTitle>
          <CardDescription>
            Upload the source image — it gets a deterministic, invisible watermark
            tied to the recipient you choose. The marked image downloads automatically.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-5">
            <div className="grid gap-3 md:grid-cols-3">
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
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="atype">Asset type</Label>
                <select
                  id="atype"
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value)}
                >
                  {ASSET_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="case">Case ID (optional)</Label>
                <Input
                  id="case"
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                  placeholder="EMP-2026-019"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Recipient</Label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setRecipientMode("internal")}
                  className={`rounded-md border px-3 py-1.5 text-sm ${
                    recipientMode === "internal"
                      ? "border-primary bg-primary text-primary-foreground"
                      : "bg-background hover:bg-accent"
                  }`}
                >
                  Internal user
                </button>
                <button
                  type="button"
                  onClick={() => setRecipientMode("external")}
                  className={`rounded-md border px-3 py-1.5 text-sm ${
                    recipientMode === "external"
                      ? "border-primary bg-primary text-primary-foreground"
                      : "bg-background hover:bg-accent"
                  }`}
                >
                  External
                </button>
              </div>

              {recipientMode === "internal" ? (
                <select
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={recipientUserId}
                  onChange={(e) => setRecipientUserId(e.target.value)}
                  required={recipientMode === "internal"}
                >
                  <option value="">— pick a user —</option>
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>{u.email}</option>
                  ))}
                </select>
              ) : (
                <div className="grid gap-3 md:grid-cols-3">
                  <Input
                    placeholder="Recipient name"
                    value={recipientName}
                    onChange={(e) => setRecipientName(e.target.value)}
                  />
                  <Input
                    type="email"
                    placeholder="Email (optional)"
                    value={recipientEmail}
                    onChange={(e) => setRecipientEmail(e.target.value)}
                  />
                  <Input
                    placeholder="Reference (ICCID, employee #, …)"
                    value={recipientRef}
                    onChange={(e) => setRecipientRef(e.target.value)}
                  />
                </div>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="desc">Description (optional)</Label>
              <Textarea
                id="desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. employee badge front side"
                rows={2}
              />
            </div>

            <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
              <div className="space-y-1.5">
                <Label htmlFor="img">Source image</Label>
                <Input
                  id="img"
                  type="file"
                  accept="image/*"
                  required
                  onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="iby" className="opacity-70">Issued by (optional)</Label>
                <Input
                  id="iby"
                  type="email"
                  value={issuedByEmail}
                  onChange={(e) => setIssuedByEmail(e.target.value)}
                  placeholder="you@example.com"
                />
              </div>
            </div>
            {previewUrl && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={previewUrl}
                alt="preview"
                className="max-h-48 rounded border"
              />
            )}

            <Button type="submit" disabled={busy || !file || !tenantId}>
              {busy ? "Watermarking…" : "Issue & download"}
            </Button>

            {lastIssued && (
              <div className="rounded-md border border-emerald-300 bg-emerald-50 p-3 text-sm">
                <div className="font-medium">Asset issued.</div>
                <div className="mt-1 grid gap-y-0.5 md:grid-cols-2">
                  <div><span className="text-muted-foreground">id: </span><span className="font-mono">{lastIssued.id}</span></div>
                  <div><span className="text-muted-foreground">token: </span><span className="font-mono">{lastIssued.token_hex}</span></div>
                  <div><span className="text-muted-foreground">recipient: </span>{lastIssued.recipient_name || lastIssued.recipient_email || lastIssued.recipient_ref || "—"}</div>
                  <div><span className="text-muted-foreground">case: </span>{lastIssued.case_id ?? "—"}</div>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  The marked image was downloaded to your machine. Distribute that file.
                </div>
              </div>
            )}
            {err && <p className="text-sm text-destructive">{err}</p>}
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Issued assets</CardTitle>
          <CardDescription>
            {loading ? "Loading…" : `${assets.length} asset(s)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {assets.length === 0 && !loading ? (
            <p className="text-sm text-muted-foreground">None yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20"></TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Recipient</TableHead>
                  <TableHead>Case</TableHead>
                  <TableHead>Token</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Issued</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell>
                      <AuthImage
                        src={assetMarkedUrl(a.id)}
                        alt="thumbnail"
                        className="h-12 w-20 rounded border object-cover"
                      />
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{a.asset_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        {a.recipient_name || a.recipient_email || "—"}
                      </div>
                      {a.recipient_ref && (
                        <div className="text-xs text-muted-foreground font-mono">
                          {a.recipient_ref}
                        </div>
                      )}
                      {a.recipient_user_id && (
                        <div className="text-xs text-muted-foreground">
                          {userById[a.recipient_user_id] ?? "internal"}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>{a.case_id ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{a.token_hex}</TableCell>
                    <TableCell>
                      {a.status === "active" ? (
                        <Badge variant="success">active</Badge>
                      ) : (
                        <Badge variant="destructive">revoked</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(a.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="outline" onClick={() => download(a)}>
                          Download
                        </Button>
                        {a.status === "active" && (
                          <Button size="sm" variant="destructive" onClick={() => revoke(a)}>
                            Revoke
                          </Button>
                        )}
                      </div>
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
