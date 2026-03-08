import type { Metadata } from "next";

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
        <div style={{ display: "flex", minHeight: "100vh" }}>
          <nav style={{
            width: 240,
            borderRight: "1px solid #1e1e1e",
            padding: "24px 16px",
            background: "#111",
          }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 32, color: "#fff" }}>
              SafeFence
            </h2>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {[
                { href: "/", label: "Overview" },
                { href: "/instances", label: "Instances" },
                { href: "/policies", label: "Policies" },
                { href: "/rbac", label: "RBAC" },
                { href: "/audit", label: "Audit Log" },
              ].map((item) => (
                <li key={item.href} style={{ marginBottom: 8 }}>
                  <a
                    href={item.href}
                    style={{
                      display: "block",
                      padding: "8px 12px",
                      borderRadius: 6,
                      color: "#b0b0b0",
                      textDecoration: "none",
                      fontSize: 14,
                    }}
                  >
                    {item.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <main style={{ flex: 1, padding: "32px 40px" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
