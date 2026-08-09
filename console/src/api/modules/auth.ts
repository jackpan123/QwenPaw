import { getApiUrl } from "../config";
import { buildAuthHeaders } from "../authHeaders";

export interface LoginResponse {
  token: string;
  username: string;
  message?: string;
}

export interface AuthStatusResponse {
  enabled: boolean;
  mode?: string;
}

export interface VerifyResponse {
  valid: boolean;
  username: string;
  roles: string[];
  can_mutate: boolean;
}

export const authApi = {
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const res = await fetch(getApiUrl("/auth/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Login failed");
    }
    return res.json();
  },

  getStatus: async (): Promise<AuthStatusResponse> => {
    const res = await fetch(getApiUrl("/auth/status"));
    if (!res.ok) throw new Error("Failed to check auth status");
    return res.json();
  },

  verify: async (): Promise<VerifyResponse> => {
    const res = await fetch(getApiUrl("/auth/verify"), {
      method: "GET",
      headers: buildAuthHeaders(),
    });
    if (!res.ok) throw new Error("Invalid or expired token");
    return res.json();
  },
};
