import type { Metadata } from "next";
import "./globals.css";
import { TokenGate } from "@/components/token-gate";
import { AppShell } from "@/components/app-shell";

export const metadata: Metadata = {
  title: "Unseen",
  description: "Unseen — forensic watermark management & investigator console",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <TokenGate>
          <AppShell>{children}</AppShell>
        </TokenGate>
      </body>
    </html>
  );
}
