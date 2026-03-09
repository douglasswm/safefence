"use client";

import { useApiClient } from "../lib/auth-context";
import { useFetch } from "../lib/use-fetch";
import { INSTANCE_STATUS } from "../lib/types";
import { ErrorBanner } from "../components/ui";

export default function OverviewPage() {
  const api = useApiClient();
  const instances = useFetch(() => api.listInstances());
  const stats = useFetch(() => api.getAuditStats());

  const cards = [
    { label: "Connected Instances", value: instances.data?.filter((i) => i.status === INSTANCE_STATUS.ACTIVE).length ?? "—" },
    { label: "Total Evaluations", value: stats.data?.total ?? "—" },
    { label: "Denied Requests", value: stats.data?.denied ?? "—" },
    { label: "Allowed Requests", value: stats.data?.allowed ?? "—" },
  ];

  const error = instances.error || stats.error;

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Organization Overview</h1>
      <ErrorBanner message={error} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
        {cards.map((stat) => (
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
      {instances.loading && <p style={{ color: "#666", fontSize: 14 }}>Loading...</p>}
    </div>
  );
}
