import axios from "axios";

// ─────────────────────────────────────────────────────────────────────────────
// Base client
// ─────────────────────────────────────────────────────────────────────────────
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5001";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // default 30s — overridden per-call for uploads
  headers: {
    "Content-Type": "application/json",
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// JWT helper — retrieve the stored token from sessionStorage or localStorage
// ─────────────────────────────────────────────────────────────────────────────
export function getStoredToken() {
  return sessionStorage.getItem("trace_token") || localStorage.getItem("trace_token") || null;
}

export function storeToken(token, remember = false) {
  if (remember) {
    localStorage.setItem("trace_token", token);
  } else {
    sessionStorage.setItem("trace_token", token);
  }
}

export function clearToken() {
  sessionStorage.removeItem("trace_token");
  localStorage.removeItem("trace_token");
  sessionStorage.removeItem("trace_user");
  localStorage.removeItem("trace_user");
}

export function storeUsername(username, remember = false) {
  if (remember) {
    localStorage.setItem("trace_user", username);
  } else {
    sessionStorage.setItem("trace_user", username);
  }
}

export function getStoredUsername() {
  return sessionStorage.getItem("trace_user") || localStorage.getItem("trace_user") || null;
}

/** Decode JWT payload without verifying signature (client-side only). */
export function decodeJwtPayload(token) {
  try {
    const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}

/** Returns true if the JWT is expired (or unparseable). */
export function isTokenExpired(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || !payload.exp) return true;
  return Date.now() / 1000 > payload.exp;
}

// ─────────────────────────────────────────────────────────────────────────────
// Request interceptor — attach Authorization header automatically
// ─────────────────────────────────────────────────────────────────────────────
apiClient.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) {
    config.headers["Authorization"] = `Bearer ${token}`;
  }
  return config;
});

// ─────────────────────────────────────────────────────────────────────────────
// Response interceptor — consistent error handling
// ─────────────────────────────────────────────────────────────────────────────
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.code === "ECONNABORTED" || error.message?.includes("timeout")) {
      return Promise.reject({
        ...error,
        message:
          "Analysis could not be completed.\n\nPossible reasons:\n" +
          "• Unsupported memory image\n" +
          "• Corrupted memory dump\n" +
          "• Missing Volatility symbols\n" +
          "• Analysis timed out\n\n" +
          "Please upload another supported memory image.",
      });
    }
    const message =
      error.response?.data?.error ||
      error.response?.data?.message ||
      error.message ||
      "Neural link failure";
    return Promise.reject({
      ...error,
      message,
      response: error.response,
    });
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// Auth API
// ─────────────────────────────────────────────────────────────────────────────
export const authApi = {
  login: (credentials) => apiClient.post("/login", credentials),
  signup: (userData) => apiClient.post("/signup", userData),
  validateToken: () => apiClient.post("/validate-token"),
  forgotPassword: (identifier) => apiClient.post("/forgot-password", { identifier }),
  verifyOtp: (identifier, otp) => apiClient.post("/verify-otp", { identifier, otp }),
  resetPassword: (username, resetToken, newPassword) =>
    apiClient.post("/reset-password", { username, reset_token: resetToken, new_password: newPassword }),
};

// ─────────────────────────────────────────────────────────────────────────────
// Forensics API — 10-minute timeout for Volatility
// ─────────────────────────────────────────────────────────────────────────────
export const forensicsApi = {
  upload: (formData) =>
    apiClient.post("/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
      timeout: 600000, // 10 minutes
    }),
  getHistory: (username) => apiClient.get(`/history/${username}`),
};

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard, intel, lab, profile APIs
// ─────────────────────────────────────────────────────────────────────────────
export const dashboardApi = {
  getStats: (username) => apiClient.get(`/dashboard/stats/${username}`),
  getActivities: (username) => apiClient.get(`/activities/${username}`),
};

export const intelApi = {
  getAggregate: (username) => apiClient.get(`/intel/aggregate/${username}`),
};

export const labApi = {
  getSamples: (username) => apiClient.get(`/lab/samples/${username}`),
};

export const profileApi = {
  getProfile: (username) => apiClient.get(`/profile/${username}`),
  updateProfile: (data) => apiClient.post("/profile/update", data),
};

export default apiClient;
