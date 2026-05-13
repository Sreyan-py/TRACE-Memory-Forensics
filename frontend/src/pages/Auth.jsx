import { useState } from "react";
import axios from "axios";
import { Shield, Lock, User, KeyRound, AlertTriangle, ArrowRight } from "lucide-react";

export default function Auth({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    const endpoint = isLogin ? "/login" : "/signup";
    
    try {
      const API_URL = import.meta.env.VITE_API_URL || "https://trace-memory-forensics.onrender.com";
      const response = await axios.post(`${API_URL}${endpoint}`, {
        username,
        password
      });

      if (isLogin) {
        // Trigger login sequence
        onLogin(response.data.username);
      } else {
        // Successfully created account, switch to login
        setIsLogin(true);
        setUsername("");
        setPassword("");
        // Show a brief success message using the error state but styled differently, or just let them login.
        // For simplicity, we just switch tabs.
      }
    } catch (err) {
      setError(err.response?.data?.error || "Authentication failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#06080e] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background decorations */}
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-[0_0_30px_rgba(34,211,238,0.4)] mb-6">
            <Shield className="text-white" size={40} />
          </div>
          <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 tracking-wider">TRACE</h1>
          <p className="text-cyan-500/80 font-mono text-sm tracking-widest uppercase mt-2">Authorized Access Only</p>
        </div>

        <div className="bg-[#0b1020]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
          {/* Subtle grid pattern inside card */}
          <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none"></div>

          <h2 className="text-2xl font-bold text-white text-center mb-8 relative z-10">
            {isLogin ? "System Login" : "Create Account"}
          </h2>

          <form onSubmit={handleSubmit} className="relative z-10">
            <div className="space-y-5">
              <div>
                <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <User size={14} /> Agent ID
                </label>
                <div className="relative">
                  <input 
                    type="text" 
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    className="w-full bg-black/40 border border-gray-700 focus:border-cyan-500 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
                    placeholder="Enter clearance ID"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2 flex items-center gap-2">
                  <KeyRound size={14} /> Passphrase
                </label>
                <div className="relative">
                  <input 
                    type="password" 
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full bg-black/40 border border-gray-700 focus:border-cyan-500 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono tracking-widest"
                    placeholder="••••••••••••"
                  />
                </div>
              </div>
            </div>

            {error && (
              <div className="mt-6 bg-red-500/10 border border-red-500/20 p-3 rounded-lg flex items-start gap-3">
                <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
                <p className="text-sm text-red-300">{error}</p>
              </div>
            )}

            <button 
              type="submit"
              disabled={isLoading}
              className={`w-full mt-8 flex items-center justify-center gap-2 px-6 py-4 rounded-xl font-bold text-white transition shadow-[0_0_20px_rgba(34,211,238,0.2)] 
                ${isLoading ? "bg-gray-600 cursor-not-allowed" : "bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500"}`}
            >
              {isLoading ? (
                "Authenticating..."
              ) : (
                <>
                  {isLogin ? "Initialize Session" : "Create Account"} <ArrowRight size={18} />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center relative z-10">
            {isLogin ? (
              <p className="text-gray-400 text-sm">
                New agent?{" "}
                <button 
                  onClick={() => { setIsLogin(false); setError(""); }}
                  className="text-cyan-400 hover:text-cyan-300 font-bold hover:underline transition-all"
                >
                  Create an account
                </button>
              </p>
            ) : (
              <p className="text-gray-400 text-sm">
                Already have clearance?{" "}
                <button 
                  onClick={() => { setIsLogin(true); setError(""); }}
                  className="text-cyan-400 hover:text-cyan-300 font-bold hover:underline transition-all"
                >
                  Sign in
                </button>
              </p>
            )}
          </div>
        </div>
        
        <p className="text-center text-gray-600 text-xs mt-6 uppercase tracking-widest">
          TRACE Memory Forensics Core v2.0 <br/> Unauthorized access is strictly prohibited.
        </p>
      </div>
    </div>
  );
}
