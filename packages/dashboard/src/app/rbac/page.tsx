export default function RbacPage() {
  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>RBAC Management</h1>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
          <h3 style={{ fontSize: 16, marginBottom: 16 }}>Roles</h3>
          <p style={{ color: "#666", fontSize: 14 }}>
            Define roles and permissions that sync across all instances.
          </p>
        </div>
        <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
          <h3 style={{ fontSize: 16, marginBottom: 16 }}>Users &amp; Assignments</h3>
          <p style={{ color: "#666", fontSize: 14 }}>
            Manage user identities and role assignments centrally.
          </p>
        </div>
      </div>
    </div>
  );
}
