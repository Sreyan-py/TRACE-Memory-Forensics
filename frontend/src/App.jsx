import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Analysis from "./pages/Analysis";
import Profile from "./pages/Profile";
import ThreatIntel from "./pages/ThreatIntel";
import MalwareLab from "./pages/MalwareLab";
import Auth from "./pages/Auth";

const Placeholder = ({ title }) => (
  <div className="flex flex-col items-center justify-center min-h-[60vh] text-gray-600 font-mono italic">
    <ShieldAlert size={48} className="mb-4 opacity-20" />
    <p className="uppercase tracking-[0.5em] text-xs">Section Under Construction: {title}</p>
    <p className="text-[10px] mt-2 opacity-40 uppercase tracking-widest">Awaiting SOC Alpha Clearance</p>
  </div>
);

function App() {
  const [user, setUser] = useState(() => localStorage.getItem("trace_user") || null);

  const handleLogin = (username) => {
    localStorage.setItem("trace_user", username);
    setUser(username);
  };

  const handleLogout = () => {
    localStorage.removeItem("trace_user");
    setUser(null);
  };

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
          <Route path="history" element={<Placeholder title="Scan History" />} />
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