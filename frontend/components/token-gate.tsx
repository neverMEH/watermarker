"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { clearAdminToken, getAdminToken, setAdminToken } from "@/lib/auth";
import { API_BASE } from "@/lib/api";
import { LogoMark } from "@/components/logo";

export function TokenGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [hasToken, setHasToken] = useState(false);
  const [input, setInput] = useState("");
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setHasToken(!!getAdminToken());
    setReady(true);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setChecking(true);
    try {
      const res = await fetch(`${API_BASE}/v1/tenants`, {
        method: "GET",
        headers: { Authorization: `Bearer ${input}` },
      });
      if (res.status === 401 || res.status === 403) {
        setError("Admin token rejected by the API.");
        return;
      }
      if (res.status >= 500) {
        setError(`Backend error ${res.status}. Is WATERMARK_ADMIN_TOKEN set on the server?`);
        return;
      }
      setAdminToken(input);
      setHasToken(true);
    } catch (err) {
      setError(
        `Could not reach API at ${API_BASE}. Set NEXT_PUBLIC_API_BASE_URL or check CORS.`
      );
    } finally {
      setChecking(false);
    }
  }

  if (!ready) return null;

  if (!hasToken) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-muted/30 px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-3">
            <div className="flex items-center gap-2">
              <LogoMark className="h-7 w-7" />
              <span className="text-lg font-semibold tracking-tight">unseen</span>
            </div>
            <div className="space-y-1.5">
              <CardTitle>Sign in</CardTitle>
              <CardDescription>
                Paste the <code className="font-mono text-xs">WATERMARK_ADMIN_TOKEN</code>{" "}
                from your backend to access the console.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="token">Admin token</Label>
                <Input
                  id="token"
                  type="password"
                  autoComplete="off"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="hex string"
                  required
                />
              </div>
              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}
              <p className="text-xs text-muted-foreground break-all">
                API base: <span className="font-mono">{API_BASE}</span>
              </p>
              <Button type="submit" className="w-full" disabled={checking || !input}>
                {checking ? "Verifying…" : "Continue"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <>
      {children}
      <SignOutFab onSignOut={() => { clearAdminToken(); setHasToken(false); }} />
    </>
  );
}

function SignOutFab({ onSignOut }: { onSignOut: () => void }) {
  return (
    <button
      onClick={onSignOut}
      className="fixed bottom-4 right-4 rounded-full border bg-background px-3 py-1.5 text-xs text-muted-foreground shadow hover:bg-accent"
    >
      Sign out
    </button>
  );
}
