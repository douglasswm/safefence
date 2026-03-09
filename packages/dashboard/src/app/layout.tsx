import type { Metadata } from "next";
import { Shell } from "./shell";

export const metadata: Metadata = {
  title: "SafeFence Dashboard",
  description: "Centralized control plane for SafeFence guardrails",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, -apple-system, sans-serif", background: "#0a0a0a", color: "#e0e0e0" }}>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
