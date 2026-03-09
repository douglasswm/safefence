"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useMemo,
  useCallback,
  type ReactNode,
  type FormEvent,
} from "react";
import { ApiClient } from "./api-client";

interface AuthState {
  orgId: string;
  apiKey: string;
  isAuthenticated: boolean;
  login: (orgId: string, apiKey: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

// sessionStorage (not sessionStorage) so credentials clear when tab closes,
// reducing exposure if page is XSS-compromised.
const STORAGE_KEY = "safefence_auth";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [orgId, setOrgId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) {
        const { orgId: o, apiKey: k } = JSON.parse(stored);
        if (o && k) {
          setOrgId(o);
          setApiKey(k);
        }
      }
    } catch {
      // ignore
    }
    setLoaded(true);
  }, []);

  const login = useCallback((o: string, k: string) => {
    setOrgId(o);
    setApiKey(k);
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ orgId: o, apiKey: k }));
  }, []);

  const logout = useCallback(() => {
    setOrgId("");
    setApiKey("");
    sessionStorage.removeItem(STORAGE_KEY);
  }, []);

  const isAuthenticated = !!(orgId && apiKey);

  const contextValue = useMemo(
    () => ({ orgId, apiKey, isAuthenticated, login, logout }),
    [orgId, apiKey, isAuthenticated, login, logout],
  );

  // Don't render until we've checked sessionStorage to avoid hydration mismatch
  if (!loaded) return null;

  if (!isAuthenticated) {
    return <LoginForm onLogin={login} />;
  }

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export function useApiClient(): ApiClient {
  const { orgId, apiKey } = useAuth();
  return useMemo(() => new ApiClient(orgId, apiKey), [orgId, apiKey]);
}

function LoginForm({ onLogin }: { onLogin: (orgId: string, apiKey: string) => void }) {
  const [orgId, setOrgId] = useState("");
  const [apiKey, setApiKey] = useState("");

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (orgId.trim() && apiKey.trim()) {
      onLogin(orgId.trim(), apiKey.trim());
    }
  };

  const inputStyle = {
    width: "100%",
    padding: "10px 14px",
    borderRadius: 6,
    border: "1px solid #333",
    background: "#161616",
    color: "#e0e0e0",
    fontSize: 14,
    boxSizing: "border-box" as const,
  };

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      minHeight: "100vh",
      background: "#0a0a0a",
    }}>
      <form onSubmit={handleSubmit} style={{
        background: "#111",
        border: "1px solid #1e1e1e",
        borderRadius: 12,
        padding: 32,
        width: 380,
      }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#fff", marginBottom: 8 }}>
          SafeFence Dashboard
        </h2>
        <p style={{ fontSize: 13, color: "#888", marginBottom: 24 }}>
          Enter your organization credentials to continue.
        </p>
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: "block", fontSize: 13, color: "#aaa", marginBottom: 6 }}>
            Organization ID
          </label>
          <input
            type="text"
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            style={inputStyle}
          />
        </div>
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: 13, color: "#aaa", marginBottom: 6 }}>
            API Key
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="sf_..."
            style={inputStyle}
          />
        </div>
        <button
          type="submit"
          style={{
            width: "100%",
            padding: "10px 0",
            borderRadius: 6,
            border: "none",
            background: "#2563eb",
            color: "#fff",
            fontSize: 14,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Sign In
        </button>
      </form>
    </div>
  );
}
