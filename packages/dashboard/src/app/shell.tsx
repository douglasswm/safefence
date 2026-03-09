"use client";

import { AuthProvider, useAuth } from "../lib/auth-context";
import type { ReactNode } from "react";

export function Shell({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <ShellInner>{children}</ShellInner>
    </AuthProvider>
  );
}

function ShellInner({ children }: { children: ReactNode }) {
  const { logout } = useAuth();

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <nav style={{
        width: 240,
        borderRight: "1px solid #1e1e1e",
        padding: "24px 16px",
        background: "#111",
        display: "flex",
        flexDirection: "column",
      }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 32, color: "#fff" }}>
          SafeFence
        </h2>
        <ul style={{ listStyle: "none", padding: 0, margin: 0, flex: 1 }}>
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
        <button
          onClick={logout}
          style={{
            padding: "8px 12px",
            borderRadius: 6,
            border: "1px solid #333",
            background: "transparent",
            color: "#888",
            fontSize: 13,
            cursor: "pointer",
            textAlign: "left",
          }}
        >
          Sign Out
        </button>
      </nav>
      <main style={{ flex: 1, padding: "32px 40px" }}>
        {children}
      </main>
    </div>
  );
}
