export default function AuditPage() {
  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Audit Log</h1>
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <input
          type="text"
          placeholder="Filter by event type..."
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "1px solid #333",
            background: "#161616",
            color: "#e0e0e0",
            fontSize: 14,
            width: 240,
          }}
        />
        <input
          type="text"
          placeholder="Filter by instance..."
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "1px solid #333",
            background: "#161616",
            color: "#e0e0e0",
            fontSize: 14,
            width: 240,
          }}
        />
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["Timestamp", "Instance", "Event Type", "Decision", "Actor", "Details"].map((h) => (
              <th key={h} style={{ padding: "12px 16px", textAlign: "left", color: "#888", fontWeight: 500 }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          <tr>
            <td colSpan={6} style={{ padding: "32px 16px", textAlign: "center", color: "#666" }}>
              No audit events yet. Events will appear here as connected instances report them.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
