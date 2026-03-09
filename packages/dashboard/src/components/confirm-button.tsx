"use client";

import { useState } from "react";

interface ConfirmButtonProps {
  label: string;
  onConfirm: () => Promise<void> | void;
}

export function ConfirmButton({ label, onConfirm }: ConfirmButtonProps) {
  const [confirming, setConfirming] = useState(false);
  const [running, setRunning] = useState(false);

  const handleConfirm = async () => {
    setRunning(true);
    try {
      await onConfirm();
    } finally {
      setRunning(false);
      setConfirming(false);
    }
  };

  if (confirming) {
    return (
      <span style={{ display: "inline-flex", gap: 4 }}>
        <button
          onClick={handleConfirm}
          disabled={running}
          style={{
            padding: "3px 8px",
            borderRadius: 4,
            border: "none",
            background: "#dc2626",
            color: "#fff",
            fontSize: 11,
            fontWeight: 600,
            cursor: running ? "not-allowed" : "pointer",
          }}
        >
          {running ? "..." : "Confirm"}
        </button>
        <button
          onClick={() => setConfirming(false)}
          disabled={running}
          style={{
            padding: "3px 8px",
            borderRadius: 4,
            border: "1px solid #333",
            background: "transparent",
            color: "#888",
            fontSize: 11,
            cursor: "pointer",
          }}
        >
          Cancel
        </button>
      </span>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      style={{
        padding: "3px 8px",
        borderRadius: 4,
        border: "1px solid #333",
        background: "transparent",
        color: "#888",
        fontSize: 11,
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}
