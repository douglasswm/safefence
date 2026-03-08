export default function PoliciesPage() {
  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Policy Management</h1>
      <p style={{ color: "#888", fontSize: 14, marginBottom: 24 }}>
        Configure guardrail policies centrally. Changes propagate to all connected instances in real-time.
      </p>
      <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
        <h3 style={{ fontSize: 16, marginBottom: 16 }}>Mutable Policy Fields</h3>
        <p style={{ color: "#666", fontSize: 14 }}>
          Connect to the control plane API to load and edit policy fields.
        </p>
      </div>
    </div>
  );
}
