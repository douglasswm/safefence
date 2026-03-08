export default function OverviewPage() {
  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Organization Overview</h1>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
        {[
          { label: "Connected Instances", value: "—" },
          { label: "Total Evaluations (24h)", value: "—" },
          { label: "Denied Requests (24h)", value: "—" },
          { label: "Avg Latency", value: "—" },
        ].map((stat) => (
          <div
            key={stat.label}
            style={{
              background: "#161616",
              border: "1px solid #1e1e1e",
              borderRadius: 8,
              padding: "20px 24px",
            }}
          >
            <div style={{ fontSize: 12, color: "#888", marginBottom: 8 }}>{stat.label}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: "#fff" }}>{stat.value}</div>
          </div>
        ))}
      </div>
      <p style={{ color: "#666", fontSize: 14 }}>
        Connect your SafeFence dashboard to the control plane API to see live data.
      </p>
    </div>
  );
}
