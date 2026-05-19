"use client";

import { useEffect, useState } from "react";
import { apiGet, type AuditEvent } from "@/lib/api";
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

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        setEvents(await apiGet<AuditEvent[]>("/v1/audit", { limit: "200" }));
      } catch (e: any) {
        setErr(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  function variantFor(type: string) {
    if (type.endsWith(".failed")) return "destructive" as const;
    if (type.endsWith(".completed") || type.endsWith(".issued")) return "success" as const;
    return "secondary" as const;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Audit log</h1>
        <p className="text-sm text-muted-foreground">
          Every tenant creation, device enrollment, session issuance, and extraction.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>Most recent 200.</CardDescription>
        </CardHeader>
        <CardContent>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : events.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Payload</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">
                      {new Date(e.ts).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Badge variant={variantFor(e.event_type)} className="font-mono">
                        {e.event_type}
                      </Badge>
                    </TableCell>
                    <TableCell>{e.actor ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{e.target ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground max-w-[40ch] truncate">
                      {e.payload ?? "—"}
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
