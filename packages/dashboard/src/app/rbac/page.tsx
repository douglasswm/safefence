"use client";

import { useState } from "react";
import { useApiClient } from "../../lib/auth-context";
import { useFetch } from "../../lib/use-fetch";
import { RoleForm } from "../../components/role-form";
import { ConfirmButton } from "../../components/confirm-button";
import { ErrorBanner } from "../../components/ui";

export default function RbacPage() {
  const api = useApiClient();
  const roles = useFetch(() => api.listRoles());
  const users = useFetch(() => api.listUsers());

  const [showRoleForm, setShowRoleForm] = useState(false);
  const [showUserForm, setShowUserForm] = useState(false);
  const [newUserName, setNewUserName] = useState("");

  const [mutationError, setMutationError] = useState<string | null>(null);
  const error = roles.error || users.error || mutationError;

  const handleCreateRole = async (name: string, description: string) => {
    await api.createRole(name, description || undefined);
    roles.refetch();
    setShowRoleForm(false);
  };

  const handleDeleteRole = async (roleId: string) => {
    setMutationError(null);
    try {
      await api.deleteRole(roleId);
      roles.refetch();
    } catch (err) {
      setMutationError(err instanceof Error ? err.message : "Failed to delete role");
    }
  };

  const handleCreateUser = async () => {
    if (!newUserName.trim()) return;
    setMutationError(null);
    try {
      await api.createUser(newUserName.trim());
      users.refetch();
      setNewUserName("");
      setShowUserForm(false);
    } catch (err) {
      setMutationError(err instanceof Error ? err.message : "Failed to create user");
    }
  };

  const handleAssignRole = async (userId: string, roleId: string) => {
    setMutationError(null);
    try {
      await api.assignRole(userId, roleId);
    } catch (err) {
      setMutationError(err instanceof Error ? err.message : "Failed to assign role");
    }
  };

  const inputStyle = {
    padding: "8px 12px",
    borderRadius: 6,
    border: "1px solid #333",
    background: "#161616",
    color: "#e0e0e0",
    fontSize: 13,
  };

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>RBAC Management</h1>
      <ErrorBanner message={error} />
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        {/* Roles Panel */}
        <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h3 style={{ fontSize: 16 }}>Roles</h3>
            <button
              onClick={() => setShowRoleForm(!showRoleForm)}
              style={{
                padding: "6px 12px",
                borderRadius: 6,
                border: "none",
                background: showRoleForm ? "#333" : "#2563eb",
                color: "#fff",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              {showRoleForm ? "Cancel" : "Add Role"}
            </button>
          </div>

          {showRoleForm && (
            <div style={{ marginBottom: 16 }}>
              <RoleForm onSubmit={handleCreateRole} />
            </div>
          )}

          {roles.loading && <p style={{ color: "#666", fontSize: 13 }}>Loading...</p>}
          {roles.data?.length === 0 && <p style={{ color: "#666", fontSize: 13 }}>No roles defined.</p>}
          {roles.data && roles.data.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
                  {["Name", "Description", ""].map((h) => (
                    <th key={h} style={{ padding: "8px 8px", textAlign: "left", color: "#888", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {roles.data.map((role) => (
                  <tr key={role.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
                    <td style={{ padding: "8px" }}>
                      {role.name}
                      {role.isSystem && (
                        <span style={{ marginLeft: 6, fontSize: 10, color: "#888", background: "#222", padding: "1px 6px", borderRadius: 4 }}>system</span>
                      )}
                    </td>
                    <td style={{ padding: "8px", color: "#888" }}>{role.description ?? "—"}</td>
                    <td style={{ padding: "8px" }}>
                      {!role.isSystem && (
                        <ConfirmButton label="Delete" onConfirm={() => handleDeleteRole(role.id)} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Users Panel */}
        <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h3 style={{ fontSize: 16 }}>Users &amp; Assignments</h3>
            <button
              onClick={() => setShowUserForm(!showUserForm)}
              style={{
                padding: "6px 12px",
                borderRadius: 6,
                border: "none",
                background: showUserForm ? "#333" : "#2563eb",
                color: "#fff",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              {showUserForm ? "Cancel" : "Add User"}
            </button>
          </div>

          {showUserForm && (
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              <input
                type="text"
                value={newUserName}
                onChange={(e) => setNewUserName(e.target.value)}
                placeholder="Display name"
                style={{ ...inputStyle, flex: 1 }}
              />
              <button
                onClick={handleCreateUser}
                style={{
                  padding: "8px 14px",
                  borderRadius: 6,
                  border: "none",
                  background: "#2563eb",
                  color: "#fff",
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                Create
              </button>
            </div>
          )}

          {users.loading && <p style={{ color: "#666", fontSize: 13 }}>Loading...</p>}
          {users.data?.length === 0 && <p style={{ color: "#666", fontSize: 13 }}>No users registered.</p>}
          {users.data && users.data.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
                  {["User", "Created", "Assign Role"].map((h) => (
                    <th key={h} style={{ padding: "8px", textAlign: "left", color: "#888", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.data.map((user) => (
                  <tr key={user.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
                    <td style={{ padding: "8px" }}>{user.displayName ?? user.id.slice(0, 8)}</td>
                    <td style={{ padding: "8px", color: "#888", fontSize: 12 }}>
                      {new Date(user.createdAt).toLocaleDateString()}
                    </td>
                    <td style={{ padding: "8px" }}>
                      {roles.data && roles.data.length > 0 && (
                        <select
                          onChange={(e) => {
                            if (e.target.value) {
                              handleAssignRole(user.id, e.target.value);
                              e.target.value = "";
                            }
                          }}
                          style={{
                            ...inputStyle,
                            padding: "4px 8px",
                            fontSize: 12,
                          }}
                        >
                          <option value="">Assign...</option>
                          {roles.data.map((r) => (
                            <option key={r.id} value={r.id}>{r.name}</option>
                          ))}
                        </select>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
