"use client";

import { useState, type FormEvent } from "react";

interface RoleFormProps {
  onSubmit: (name: string, description: string) => Promise<void>;
}

export function RoleForm({ onSubmit }: RoleFormProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setError("");
    setSaving(true);
    try {
      await onSubmit(name.trim(), description.trim());
      setName("");
      setDescription("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create role");
    } finally {
      setSaving(false);
    }
  };

  const inputStyle = {
    width: "100%",
    padding: "8px 12px",
    borderRadius: 6,
    border: "1px solid #333",
    background: "#161616",
    color: "#e0e0e0",
    fontSize: 13,
    boxSizing: "border-box" as const,
  };

  return (
    <form onSubmit={handleSubmit} style={{ background: "#111", border: "1px solid #252525", borderRadius: 6, padding: 16 }}>
      <div style={{ marginBottom: 10 }}>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Role name"
          style={inputStyle}
        />
      </div>
      <div style={{ marginBottom: 10 }}>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description (optional)"
          rows={2}
          style={{ ...inputStyle, resize: "vertical" }}
        />
      </div>
      {error && <p style={{ color: "#f87171", fontSize: 12, marginBottom: 8 }}>{error}</p>}
      <button
        type="submit"
        disabled={saving}
        style={{
          padding: "6px 14px",
          borderRadius: 6,
          border: "none",
          background: "#2563eb",
          color: "#fff",
          fontSize: 12,
          fontWeight: 600,
          cursor: saving ? "not-allowed" : "pointer",
          opacity: saving ? 0.6 : 1,
        }}
      >
        {saving ? "Creating..." : "Create Role"}
      </button>
    </form>
  );
}
