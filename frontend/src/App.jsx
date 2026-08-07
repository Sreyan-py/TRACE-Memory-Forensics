import { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Analysis from "./pages/Analysis";
import Profile from "./pages/Profile";
import ThreatIntel from "./pages/ThreatIntel";
import MalwareLab from "./pages/MalwareLab";
import ScanHistory from "./pages/ScanHistory";
import Auth from "./pages/Auth";
import {
  getStoredToken,
  isTokenExpired,
  clearToken,
  decodeJwtPayload,
  authApi,
} from "./services/api";

const Placeholder = ({ title }) => (
  <div className="flex flex-col items-center justify-center min-h-[60vh] text-gray-600 font-mono italic">
    <ShieldAlert size={48} className="mb-4 opacity-20" />
    <p className="uppercase tracking-[0.5em] text-xs">Section Under Construction: {title}</p>
    <p className="text-[10px] mt-2 opacity-40 uppercase tracking-widest">Awaiting SOC Alpha Clearance</p>
  </div>
);

function App() {
  const [user, setUser] = useState(null);
  const [sessionLoading, setSessionLoading] = useState(true);

  // ── Session restore on app start ──────────────────────────────────────────
  useEffect(() => {
    const restoreSession = async () => {
      const token = getStoredToken();

      if (!token) {
        setSessionLoading(false);
        return;
      }

      // Client-side expiry check — fast path
      if (isTokenExpired(token)) {
        clearToken();
        setSessionLoading(false);
        return;
      }

      // Server-side validation (checks token_version for password-reset invalidation)
      try {
        const res = await authApi.validateToken();
        if (res.success && res.username) {
          setUser(res.username);
        } else {
          clearToken();
        }
      } catch {
        // If server is unreachable but token is not expired yet, allow offline use
        const payload = decodeJwtPayload(token);
        if (payload?.sub) {
          setUser(payload.sub);
        } else {
          clearToken();
        }
      } finally {
        setSessionLoading(false);
      }
    };

    restoreSession();
  }, []);

  const handleLogin = (username, token, remember = false) => {
    // Token is already stored by Auth.jsx before calling this
    setUser(username);
  };

  const handleLogout = () => {
    clearToken();
    // Also clear the legacy username key if present
    localStorage.removeItem("trace_user");
    setUser(null);
  };

  // Show nothing while restoring session to avoid flash
  if (sessionLoading) {
    return (
      <div className="min-h-screen bg-[#06080e] flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-[10px] text-gray-500 font-black uppercase tracking-widest">
            Restoring Secure Session...
          </p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Auth onLogin={handleLogin} />;
  }

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout user={user} onLogout={handleLogout} />}>
          <Route index element={<Dashboard />} />
          <Route path="analysis" element={<Analysis />} />
          <Route path="profile" element={<Profile user={user} />} />
          <Route path="intel" element={<ThreatIntel />} />
          <Route path="lab" element={<MalwareLab />} />
          <Route path="history" element={<ScanHistory />} />
          <Route path="monitoring" element={<Placeholder title="Live Monitoring" />} />
          <Route path="ioc" element={<Placeholder title="IOC Explorer" />} />
          <Route path="reports" element={<Placeholder title="Threat Reports" />} />
          <Route path="quarantine" element={<Placeholder title="Quarantine" />} />
          <Route path="settings" element={<Placeholder title="System Settings" />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;