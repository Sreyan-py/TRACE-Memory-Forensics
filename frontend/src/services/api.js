import axios from "axios";

// Environment-based API URL with fallback
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5001";

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 second timeout for deep scans
  headers: {
    "Content-Type": "application/json",
  },
});

// Response interceptor for consistent error handling
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    const message = error.response?.data?.error || error.message || "Neural link failure";
    console.error("API_ERROR:", message);
    return Promise.reject({ ...error, message });
  }
);

export const authApi = {
  login: (credentials) => apiClient.post("/login", credentials),
  signup: (userData) => apiClient.post("/signup", userData),
};

export const forensicsApi = {
  upload: (formData) => apiClient.post("/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  }),
  getHistory: (username) => apiClient.get(`/history/${username}`),
};

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
