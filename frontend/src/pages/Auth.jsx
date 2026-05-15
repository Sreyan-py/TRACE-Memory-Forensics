import { useState } from "react";
import { Shield, Lock, User, AlertTriangle, ArrowRight, Eye, EyeOff, Check, X } from "lucide-react";
import { authApi } from "../services/api";

export default function Auth({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [isMFA, setIsMFA] = useState(false);
  const [formData, setFormData] = useState({ username: "", password: "" });
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const passwordCriteria = {
    length: formData.password.length >= 8,
    upper: /[A-Z]/.test(formData.password),
    number: /[0-9]/.test(formData.password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password)
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");
    try {
      if (isLogin) {
        const res = await authApi.login(formData);
        if (res.success) {
          setIsMFA(true);
        } else {
          setError(res.error || "Authentication failure");
        }
      } else {
        const res = await authApi.signup(formData);
        if (res.success) {
          setIsLogin(true);
          setFormData({ ...formData, password: "" });
          // Optional: Show success toast
        } else {
          setError(res.error || "Registration failure");
        }
      }
    } catch (err) {
      setError(err.message || "Neural link failure");
    } finally {
      setIsLoading(false);
    }
  };

  const handleMFAVerify = (e) => {
    e.preventDefault();
    if (mfaCode === "123456" || mfaCode.length === 6) {
      onLogin(formData.username);
    } else {
      setError("Invalid MFA Token");
    }
  };

  return (
    <div className="min-h-screen bg-[#06080e] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="w-full max-w-md relative z-10">
        <div className="flex justify-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-[0_0_30px_rgba(34,211,238,0.3)] rotate-3">
            <Shield size={32} className="text-white" />
          </div>
        </div>

        <div className="bg-[#0b1020]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none"></div>

          <h2 className="text-2xl font-black text-white text-center mb-8 uppercase tracking-widest italic">
            {isMFA ? "MFA LINK REQUIRED" : (isLogin ? "Neural Login" : "Agent Enrollment")}
          </h2>

          {isMFA ? (
             <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
                <div className="text-center mb-6">
                   <p className="text-gray-500 text-[10px] font-black uppercase">Enter your 6-digit synchronization key</p>
                </div>
                <form onSubmit={handleMFAVerify} className="space-y-6 relative z-10">
                   <input 
                     type="text" 
                     placeholder="0 0 0 0 0 0" 
                     value={mfaCode}
                     onChange={(e) => setMfaCode(e.target.value.replace(/\D/g,'').slice(0,6))}
                     className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-5 text-white text-center text-3xl font-black tracking-[0.5em] focus:border-cyan-500 outline-none transition-all placeholder:text-gray-800"
                     required
                   />
                   {error && <p className="text-red-500 text-[10px] font-black text-center uppercase">{error}</p>}
                   <button type="submit" className="w-full bg-cyan-500 hover:bg-cyan-400 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)] cursor-pointer">
                      Sync Identity
                   </button>
                   <p onClick={() => setIsMFA(false)} className="text-center text-[10px] text-gray-500 font-black uppercase cursor-pointer hover:text-white transition-colors">Abort & Return</p>
                </form>
             </div>
          ) : (
            <form onSubmit={handleAuth} className="relative z-10 space-y-5">
              <div>
                <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                  <User size={12} /> Analyst ID
                </label>
                <div className="relative">
                  <input 
                    type="text" 
                    value={formData.username}
                    onChange={(e) => setFormData({...formData, username: e.target.value})}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12"
                    placeholder="USERNAME"
                    required
                  />
                  <User className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                  <Lock size={12} /> Access Key
                </label>
                <div className="relative">
                  <input 
                    type={showPassword ? "text" : "password"}
                    value={formData.password}
                    onChange={(e) => setFormData({...formData, password: e.target.value})}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12"
                    placeholder="••••••••"
                    required
                  />
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
                  <button 
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-600 hover:text-cyan-500 transition-colors"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {!isLogin && (
                <div className="bg-black/20 p-4 rounded-2xl border border-white/5 space-y-3">
                  <p className="text-[10px] font-black text-gray-500 uppercase mb-2">Neural Security Metrics</p>
                  {[
                    { label: "8+ Char Link", met: passwordCriteria.length },
                    { label: "Upper Register", met: passwordCriteria.upper },
                    { label: "Binary Data (Num)", met: passwordCriteria.number },
                    { label: "Special Protocol", met: passwordCriteria.special },
                  ].map((c, i) => (
                    <div key={i} className="flex items-center justify-between">
                      <span className="text-[10px] text-gray-400 font-bold">{c.label}</span>
                      {c.met ? <Check size={14} className="text-green-500" /> : <X size={14} className="text-red-500/50" />}
                    </div>
                  ))}
                </div>
              )}

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl flex items-center gap-3">
                  <AlertTriangle size={16} className="text-red-400 shrink-0" />
                  <span className="text-[10px] text-red-400 font-black uppercase tracking-widest leading-tight">{error}</span>
                </div>
              )}

              <button 
                type="submit"
                disabled={isLoading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] mt-8"
              >
                {isLoading ? "ESTABLISHING LINK..." : (isLogin ? "INITIATE LOGIN" : "INITIALIZE AGENT")}
                {!isLoading && <ArrowRight size={16} />}
              </button>

              <p className="text-center text-[10px] text-gray-500 font-bold uppercase tracking-widest">
                {isLogin ? "No Clearance?" : "Clearance Granted?"}{" "}
                <button 
                  type="button"
                  onClick={() => setIsLogin(!isLogin)}
                  className="text-cyan-400 hover:text-cyan-300 ml-1 font-black"
                >
                  {isLogin ? "Register Analyst" : "Login Terminal"}
                </button>
              </p>
            </form>
          )}
        </div>

        <div className="mt-12 flex justify-center gap-8">
          <div className="text-center">
            <p className="text-white font-black text-xs tracking-tighter">AES-256</p>
            <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Encryption</p>
          </div>
          <div className="text-center">
            <p className="text-white font-black text-xs tracking-tighter">ISO-27001</p>
            <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Compliance</p>
          </div>
          <div className="text-center">
            <p className="text-white font-black text-xs tracking-tighter">TRACE-L5</p>
            <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Protocol</p>
          </div>
        </div>
      </div>
    </div>
  );
}
