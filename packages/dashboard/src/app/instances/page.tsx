"use client";

import { useApiClient } from "../../lib/auth-context";
import { useFetch } from "../../lib/use-fetch";
import { ErrorBanner, StatusBadge, TableHeader, TableEmptyRow } from "../../components/ui";

const statusColors: Record<string, string> = {
  active: "#22c55e",
  registered: "#3b82f6",
  deregistered: "#ef4444",
  stale: "#eab308",
};

export default function InstancesPage() {
  const api = useApiClient();
  const { data, error, loading } = useFetch(() => api.listInstances());

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Instance Fleet</h1>
      <ErrorBanner message={error} />
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <TableHeader columns={["Instance ID", "Group", "Version", "Status", "Last Heartbeat", "Policy Ver", "RBAC Ver"]} />
        <tbody>
          {loading && <TableEmptyRow colSpan={7}>Loading...</TableEmptyRow>}
          {data && data.length === 0 && (
            <TableEmptyRow colSpan={7}>
              No instances connected. Configure <code>controlPlane.enabled: true</code> in your SafeFence plugin.
            </TableEmptyRow>
          )}
          {data?.map((inst) => (
            <tr key={inst.id} style={{ borderBottom: "1px solid #1a1a1a" }}>
              <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 12 }}>
                {inst.id.slice(0, 8)}...
              </td>
              <td style={{ padding: "12px 16px" }}>{inst.groupId ?? "—"}</td>
              <td style={{ padding: "12px 16px" }}>{inst.pluginVersion ?? "—"}</td>
              <td style={{ padding: "12px 16px" }}>
                <StatusBadge value={inst.status} colorMap={statusColors} />
              </td>
              <td style={{ padding: "12px 16px", fontSize: 12, color: "#888" }}>
                {inst.lastHeartbeatAt ? new Date(inst.lastHeartbeatAt).toLocaleString() : "—"}
              </td>
              <td style={{ padding: "12px 16px" }}>{inst.policyVersion}</td>
              <td style={{ padding: "12px 16px" }}>{inst.rbacVersion}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
