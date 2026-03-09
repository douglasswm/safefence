"use client";

import { useState, type FormEvent } from "react";

interface PolicyEditorProps {
  onSave: (key: string, value: unknown) => Promise<void>;
}

export function PolicyEditor({ onSave }: PolicyEditorProps) {
  const [key, setKey] = useState("");
  const [valueStr, setValueStr] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    if (!key.trim()) {
      setError("Key is required");
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(valueStr);
    } catch {
      setError("Value must be valid JSON");
      return;
    }

    setSaving(true);
    try {
      await onSave(key.trim(), parsed);
      setKey("");
      setValueStr("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
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
    <form onSubmit={handleSubmit} style={{ background: "#111", border: "1px solid #1e1e1e", borderRadius: 8, padding: 20 }}>
      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontSize: 12, color: "#888", marginBottom: 4 }}>Policy Key</label>
        <input
          type="text"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="e.g. guardrails.maxTokens"
          style={inputStyle}
        />
      </div>
      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontSize: 12, color: "#888", marginBottom: 4 }}>Value (JSON)</label>
        <textarea
          value={valueStr}
          onChange={(e) => setValueStr(e.target.value)}
          placeholder='e.g. 1000 or {"enabled": true}'
          rows={3}
          style={{ ...inputStyle, fontFamily: "monospace", resize: "vertical" }}
        />
      </div>
      {error && <p style={{ color: "#f87171", fontSize: 12, marginBottom: 8 }}>{error}</p>}
      <button
        type="submit"
        disabled={saving}
        style={{
          padding: "8px 16px",
          borderRadius: 6,
          border: "none",
          background: "#2563eb",
          color: "#fff",
          fontSize: 13,
          fontWeight: 600,
          cursor: saving ? "not-allowed" : "pointer",
          opacity: saving ? 0.6 : 1,
        }}
      >
        {saving ? "Saving..." : "Save Policy"}
      </button>
    </form>
  );
}
