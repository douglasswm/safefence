export default function InstancesPage() {
  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Instance Fleet</h1>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["Instance ID", "Group", "Version", "Status", "Last Heartbeat", "Policy Ver", "RBAC Ver"].map((h) => (
              <th key={h} style={{ padding: "12px 16px", textAlign: "left", color: "#888", fontWeight: 500 }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          <tr>
            <td colSpan={7} style={{ padding: "32px 16px", textAlign: "center", color: "#666" }}>
              No instances connected. Configure <code>controlPlane.enabled: true</code> in your SafeFence plugin.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
