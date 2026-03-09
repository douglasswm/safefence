"use client";

import { useState } from "react";
import { useApiClient } from "../../lib/auth-context";
import { useFetch } from "../../lib/use-fetch";
import { ErrorBanner, StatusBadge, TableHeader, TableEmptyRow } from "../../components/ui";
import { AUDIT_DECISION } from "../../lib/types";
import type { AuditDecision } from "../../lib/types";

const decisionColors: Record<AuditDecision, string> = {
  [AUDIT_DECISION.ALLOW]: "#22c55e",
  [AUDIT_DECISION.DENY]: "#ef4444",
};

export default function AuditPage() {
  const api = useApiClient();
  const { data, error, loading } = useFetch(() => api.listAuditEvents({ limit: 100 }));

  const [typeFilter, setTypeFilter] = useState("");
  const [instanceFilter, setInstanceFilter] = useState("");

  const filtered = data?.filter((e) => {
    if (typeFilter && !e.eventType.toLowerCase().includes(typeFilter.toLowerCase())) return false;
    if (instanceFilter && !e.instanceId.toLowerCase().includes(instanceFilter.toLowerCase())) return false;
    return true;
  });

  const inputStyle = {
    padding: "8px 16px",
    borderRadius: 6,
    border: "1px solid #333",
    background: "#161616",
    color: "#e0e0e0",
    fontSize: 14,
    width: 240,
  };

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Audit Log</h1>
      <ErrorBanner message={error} />
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <input
          type="text"
          placeholder="Filter by event type..."
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={inputStyle}
        />
        <input
          type="text"
          placeholder="Filter by instance..."
          value={instanceFilter}
          onChange={(e) => setInstanceFilter(e.target.value)}
          style={inputStyle}
        />
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <TableHeader columns={["Timestamp", "Instance", "Event Type", "Decision", "Actor", "Details"]} />
        <tbody>
          {loading && <TableEmptyRow colSpan={6}>Loading...</TableEmptyRow>}
          {filtered && filtered.length === 0 && (
            <TableEmptyRow colSpan={6}>
              {data && data.length > 0
                ? "No events match the current filters."
                : "No audit events yet. Events will appear here as connected instances report them."}
            </TableEmptyRow>
          )}
          {filtered?.map((event) => (
            <tr key={event.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
              <td style={{ padding: "12px 16px", fontSize: 12, color: "#888" }}>
                {new Date(event.timestamp).toLocaleString()}
              </td>
              <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 12 }}>
                {event.instanceId.slice(0, 8)}...
              </td>
              <td style={{ padding: "12px 16px" }}>{event.eventType}</td>
              <td style={{ padding: "12px 16px" }}>
                {event.decision && (
                  <StatusBadge value={event.decision} colorMap={decisionColors} />
                )}
              </td>
              <td style={{ padding: "12px 16px", fontSize: 12 }}>
                {event.actorUserId ?? event.actorPlatformId ?? "—"}
              </td>
              <td style={{ padding: "12px 16px", fontSize: 12, color: "#888", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                {event.details ? JSON.stringify(event.details) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
