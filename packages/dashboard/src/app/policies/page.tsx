"use client";

import { useState } from "react";
import { useApiClient } from "../../lib/auth-context";
import { useFetch } from "../../lib/use-fetch";
import { PolicyEditor } from "../../components/policy-editor";
import { ConfirmButton } from "../../components/confirm-button";
import { ErrorBanner, TableHeader, TableEmptyRow } from "../../components/ui";

export default function PoliciesPage() {
  const api = useApiClient();
  const policies = useFetch(() => api.listPolicies());
  const versions = useFetch(() => api.listPolicyVersions());
  const [showEditor, setShowEditor] = useState(false);

  const [mutationError, setMutationError] = useState<string | null>(null);
  const error = policies.error || versions.error || mutationError;

  const handleSave = async (key: string, value: unknown) => {
    await api.setPolicy(key, value, "dashboard");
    policies.refetch();
    versions.refetch();
    setShowEditor(false);
  };

  const handleDelete = async (key: string) => {
    setMutationError(null);
    try {
      await api.deletePolicy(key);
      policies.refetch();
      versions.refetch();
    } catch (err) {
      setMutationError(err instanceof Error ? err.message : "Failed to delete policy");
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700 }}>Policy Management</h1>
        <button
          onClick={() => setShowEditor(!showEditor)}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: showEditor ? "#333" : "#2563eb",
            color: "#fff",
            fontSize: 13,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          {showEditor ? "Cancel" : "Add Policy"}
        </button>
      </div>
      <ErrorBanner message={error} />

      {showEditor && (
        <div style={{ marginBottom: 24 }}>
          <PolicyEditor onSave={handleSave} />
        </div>
      )}

      <p style={{ color: "#888", fontSize: 14, marginBottom: 16 }}>
        Configure guardrail policies centrally. Changes propagate to all connected instances in real-time.
      </p>

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14, marginBottom: 32 }}>
        <TableHeader columns={["Key", "Value", "Scope", "Version", "Updated", ""]} />
        <tbody>
          {policies.loading && <TableEmptyRow colSpan={6}>Loading...</TableEmptyRow>}
          {policies.data?.length === 0 && <TableEmptyRow colSpan={6}>No policies configured.</TableEmptyRow>}
          {policies.data?.map((p) => (
            <tr key={p.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
              <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 12 }}>{p.key}</td>
              <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 12, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>
                {JSON.stringify(p.value)}
              </td>
              <td style={{ padding: "12px 16px" }}>{p.scope}</td>
              <td style={{ padding: "12px 16px" }}>{p.version}</td>
              <td style={{ padding: "12px 16px", fontSize: 12, color: "#888" }}>
                {new Date(p.updatedAt).toLocaleString()}
              </td>
              <td style={{ padding: "12px 16px" }}>
                <ConfirmButton label="Delete" onConfirm={() => handleDelete(p.key)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ background: "#161616", border: "1px solid #1e1e1e", borderRadius: 8, padding: 24 }}>
        <h3 style={{ fontSize: 16, marginBottom: 16 }}>Version History</h3>
        {versions.data?.length === 0 && (
          <p style={{ color: "#666", fontSize: 14 }}>No version history yet.</p>
        )}
        {versions.data && versions.data.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <TableHeader columns={["Key", "Value", "Version", "Changed By", "Changed At"]} padding="8px 12px" />
            <tbody>
              {versions.data.map((v) => (
                <tr key={v.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
                  <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 12 }}>{v.key}</td>
                  <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 12, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                    {JSON.stringify(v.value)}
                  </td>
                  <td style={{ padding: "8px 12px" }}>{v.version}</td>
                  <td style={{ padding: "8px 12px" }}>{v.changedBy ?? "—"}</td>
                  <td style={{ padding: "8px 12px", color: "#888" }}>{new Date(v.changedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
