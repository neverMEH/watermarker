"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Building2,
  Users,
  MonitorSmartphone,
  KeyRound,
  Search,
  ScrollText,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { LogoMark } from "@/components/logo";

const nav = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/tenants", label: "Tenants", icon: Building2 },
  { href: "/users", label: "Users", icon: Users },
  { href: "/devices", label: "Devices", icon: MonitorSmartphone },
  { href: "/sessions", label: "Watermarks", icon: KeyRound },
  { href: "/investigator", label: "Investigator", icon: Search },
  { href: "/audit", label: "Audit log", icon: ScrollText },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 border-r bg-muted/30 md:flex md:flex-col">
        <Link
          href="/"
          className="flex items-center gap-2 border-b px-5 py-4 hover:bg-background/40"
        >
          <LogoMark className="h-6 w-6" />
          <div>
            <div className="font-semibold tracking-tight leading-none">unseen</div>
            <div className="mt-1 text-xs text-muted-foreground leading-none">
              Forensic console
            </div>
          </div>
        </Link>
        <nav className="flex-1 space-y-0.5 px-2 py-3">
          {nav.map((item) => {
            const Icon = item.icon;
            const active =
              item.href === "/"
                ? pathname === "/"
                : pathname === item.href || pathname.startsWith(item.href + "/");
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                  active
                    ? "bg-background font-medium text-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-background/60 hover:text-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="flex-1 min-w-0">
        <div className="mx-auto max-w-6xl px-4 py-6 md:px-8 md:py-10">{children}</div>
      </main>
    </div>
  );
}
