"use client";

import { useEffect, useRef, useState } from "react";
import { apiGet, apiPostForm, type Extraction, type ExtractResp } from "@/lib/api";
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

export default function InvestigatorPage() {
  const [caseId, setCaseId] = useState("");
  const [investigatorEmail, setInvestigatorEmail] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [screenW, setScreenW] = useState<number | "">("");
  const [screenH, setScreenH] = useState<number | "">("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<ExtractResp | null>(null);
  const [recent, setRecent] = useState<Extraction[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);

  async function refreshRecent() {
    try {
      setRecent(await apiGet<Extraction[]>("/v1/extractions", { limit: "20" }));
    } catch {
      /* ignore — could be empty */
    }
  }
  useEffect(() => {
    refreshRecent();
  }, []);

  function pickFile(f: File | null) {
    setFile(f);
    setResult(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    if (!f) {
      setPreviewUrl(null);
      return;
    }
    const url = URL.createObjectURL(f);
    setPreviewUrl(url);
    // Auto-fill screen dimensions from the image — /v1/extract requires they match.
    const img = new Image();
    img.onload = () => {
      setScreenW(img.naturalWidth);
      setScreenH(img.naturalHeight);
    };
    img.src = url;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!file || !screenW || !screenH) return;
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const fd = new FormData();
      fd.set("case_id", caseId);
      fd.set("investigator_email", investigatorEmail);
      fd.set("screen_w", String(screenW));
      fd.set("screen_h", String(screenH));
      fd.set("image", file);
      const resp = await apiPostForm<ExtractResp>("/v1/extract", fd);
      setResult(resp);
      await refreshRecent();
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Investigator console</h1>
        <p className="text-sm text-muted-foreground">
          Upload a suspect screenshot. The backend decodes the watermark and attributes it
          to the user, device, and session that issued it.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>New extraction</CardTitle>
            <CardDescription>
              Image dimensions must match the original screen resolution.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="case">Case ID</Label>
                  <Input
                    id="case"
                    required
                    value={caseId}
                    onChange={(e) => setCaseId(e.target.value)}
                    placeholder="INC-2026-019"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="iemail">Investigator email</Label>
                  <Input
                    id="iemail"
                    type="email"
                    required
                    value={investigatorEmail}
                    onChange={(e) => setInvestigatorEmail(e.target.value)}
                    placeholder="you@example.com"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="img">Screenshot</Label>
                <Input
                  id="img"
                  ref={fileRef}
                  type="file"
                  accept="image/*"
                  required
                  onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
                />
                {previewUrl && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={previewUrl}
                    alt="preview"
                    className="mt-2 max-h-64 w-auto rounded border"
                  />
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="sw">Screen width (px)</Label>
                  <Input
                    id="sw"
                    type="number"
                    required
                    value={screenW}
                    onChange={(e) =>
                      setScreenW(e.target.value === "" ? "" : Number(e.target.value))
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="sh">Screen height (px)</Label>
                  <Input
                    id="sh"
                    type="number"
                    required
                    value={screenH}
                    onChange={(e) =>
                      setScreenH(e.target.value === "" ? "" : Number(e.target.value))
                    }
                  />
                </div>
              </div>

              <Button type="submit" disabled={busy || !file}>
                {busy ? "Decoding…" : "Extract watermark"}
              </Button>
              {err && <p className="text-sm text-destructive">{err}</p>}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Result</CardTitle>
            <CardDescription>
              MAC-verified attribution if successful; failure reason otherwise.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!result ? (
              <p className="text-sm text-muted-foreground">No extraction yet.</p>
            ) : (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2">
                  {result.success ? (
                    <Badge variant="success">Verified</Badge>
                  ) : (
                    <Badge variant="destructive">No match</Badge>
                  )}
                  <span className="text-muted-foreground">
                    strategy: <span className="font-mono">{result.strategy}</span>
                  </span>
                  <span className="text-muted-foreground">
                    BER: {result.ber_estimate.toFixed(3)}
                  </span>
                </div>
                {result.success ? (
                  <dl className="grid grid-cols-[140px_1fr] gap-y-1">
                    <Term>Token</Term>
                    <Val mono>{result.token_hex}</Val>
                    <Term>Tenant</Term>
                    <Val mono>{result.tenant_id}</Val>
                    <Term>User</Term>
                    <Val>{result.user_email}</Val>
                    <Term>Device</Term>
                    <Val>{result.device_hostname}</Val>
                    <Term>Issued at</Term>
                    <Val>
                      {result.time_window_start
                        ? new Date(result.time_window_start).toLocaleString()
                        : "—"}
                    </Val>
                    <Term>Expires</Term>
                    <Val>
                      {result.time_window_end
                        ? new Date(result.time_window_end).toLocaleString()
                        : "—"}
                    </Val>
                    <Term>Audit ID</Term>
                    <Val mono>{result.audit_id}</Val>
                  </dl>
                ) : (
                  <p className="text-muted-foreground">{result.failure_reason}</p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent extractions</CardTitle>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">No extractions yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Case</TableHead>
                  <TableHead>Investigator</TableHead>
                  <TableHead>Image SHA256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="text-muted-foreground">
                      {new Date(r.ts).toLocaleString()}
                    </TableCell>
                    <TableCell className="font-medium">{r.case_id}</TableCell>
                    <TableCell>{r.investigator_email}</TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-[24ch]">
                      {r.image_sha256}
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

function Term({ children }: { children: React.ReactNode }) {
  return <dt className="text-muted-foreground">{children}</dt>;
}
function Val({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return <dd className={mono ? "font-mono break-all" : ""}>{children}</dd>;
}
