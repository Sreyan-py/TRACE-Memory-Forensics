import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Analysis from "./pages/Analysis";
import Profile from "./pages/Profile";
import Auth from "./pages/Auth";

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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;