"use client";

import type { ReactNode } from "react";

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div style={{
      padding: "12px 16px",
      background: "#2d1515",
      border: "1px solid #5c2020",
      borderRadius: 6,
      marginBottom: 16,
      fontSize: 13,
      color: "#f87171",
    }}>
      {message}
    </div>
  );
}

export function StatusBadge({
  value,
  colorMap,
}: {
  value: string;
  colorMap: Record<string, string>;
}) {
  const color = colorMap[value] ?? "#888";
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 10px",
      borderRadius: 12,
      fontSize: 12,
      fontWeight: 600,
      color,
      background: color + "1a",
    }}>
      {value}
    </span>
  );
}

export function TableEmptyRow({
  colSpan,
  children,
}: {
  colSpan: number;
  children: ReactNode;
}) {
  return (
    <tr>
      <td colSpan={colSpan} style={{ padding: "32px 16px", textAlign: "center", color: "#666" }}>
        {children}
      </td>
    </tr>
  );
}
