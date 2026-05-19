"use client";

import { useEffect, useState } from "react";
import { getAdminToken } from "@/lib/auth";
import { cn } from "@/lib/utils";

export function AuthImage({
  src,
  alt,
  className,
}: {
  src: string;
  alt: string;
  className?: string;
}) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let blobUrl: string | null = null;
    (async () => {
      try {
        const tok = getAdminToken();
        const res = await fetch(src, {
          headers: tok ? { Authorization: `Bearer ${tok}` } : undefined,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const blob = await res.blob();
        blobUrl = URL.createObjectURL(blob);
        if (!cancelled) setObjectUrl(blobUrl);
      } catch {
        if (!cancelled) setErr(true);
      }
    })();
    return () => {
      cancelled = true;
      if (blobUrl) URL.revokeObjectURL(blobUrl);
    };
  }, [src]);

  if (err) {
    return (
      <div className={cn("flex items-center justify-center bg-muted text-xs text-muted-foreground", className)}>
        load failed
      </div>
    );
  }
  if (!objectUrl) {
    return <div className={cn("animate-pulse bg-muted", className)} />;
  }
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={objectUrl} alt={alt} className={className} />;
}
