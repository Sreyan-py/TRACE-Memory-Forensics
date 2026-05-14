import { Settings as SettingsIcon, Shield, Bell, Eye, Database, Lock, Save, Zap, Terminal } from "lucide-react";
import { useState } from "react";

export default function Settings() {
  const [scansEnabled, setScansEnabled] = useState(true);
  const [realTimeMonitor, setRealTimeMonitor] = useState(false);
  const [stealthMode, setStealthMode] = useState(true);

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8 animate-in fade-in duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SettingsIcon size={14} className="text-gray-500" />
            <span className="text-[10px] text-gray-500 uppercase font-black tracking-[0.4em]">Core Configuration</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">System Prefs</h1>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8">
        {/* Appearance & Interface */}
        <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white mb-8 uppercase tracking-widest flex items-center gap-2">
            <Eye size={20} className="text-cyan-400" /> Interface Aesthetics
          </h3>
          <div className="space-y-8">
            <div className="flex items-center justify-between group">
              <div>
                <p className="text-white font-bold mb-1 group-hover:text-cyan-400 transition-colors">Cyberpunk UI Effects</p>
                <p className="text-xs text-gray-500">Enable neon glows, animated borders, and futuristic backgrounds.</p>
              </div>
              <button 
                onClick={() => setStealthMode(!stealthMode)}
                className={`w-14 h-7 rounded-full p-1 transition-colors duration-500 ${stealthMode ? 'bg-cyan-500 shadow-[0_0_15px_rgba(34,211,238,0.5)]' : 'bg-gray-800'}`}
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform duration-500 ${stealthMode ? 'translate-x-7' : 'translate-x-0'}`}></div>
              </button>
            </div>
          </div>
        </div>

        {/* Scan & Logic Preferences */}
        <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white mb-8 uppercase tracking-widest flex items-center gap-2">
            <Terminal size={20} className="text-green-400" /> Forensic Engine Settings
          </h3>
          <div className="space-y-8">
            <div className="flex items-center justify-between group">
              <div>
                <p className="text-white font-bold mb-1">Deep Heuristic Scan</p>
                <p className="text-xs text-gray-500">Perform exhaustive signature matching on unknown file formats.</p>
              </div>
              <button 
                onClick={() => setScansEnabled(!scansEnabled)}
                className={`w-14 h-7 rounded-full p-1 transition-colors duration-500 ${scansEnabled ? 'bg-cyan-500' : 'bg-gray-800'}`}
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform duration-500 ${scansEnabled ? 'translate-x-7' : 'translate-x-0'}`}></div>
              </button>
            </div>

            <div className="flex items-center justify-between group">
              <div>
                <p className="text-white font-bold mb-1">Live Memory Monitoring</p>
                <p className="text-xs text-gray-500">Hook system processes for real-time memory leak analysis (Experimental).</p>
              </div>
              <button 
                onClick={() => setRealTimeMonitor(!realTimeMonitor)}
                className={`w-14 h-7 rounded-full p-1 transition-colors duration-500 ${realTimeMonitor ? 'bg-cyan-500' : 'bg-gray-800'}`}
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform duration-500 ${realTimeMonitor ? 'translate-x-7' : 'translate-x-0'}`}></div>
              </button>
            </div>
          </div>
        </div>

        {/* Security & Access */}
        <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white mb-8 uppercase tracking-widest flex items-center gap-2">
            <Lock size={20} className="text-red-500" /> Access Controls
          </h3>
          <div className="space-y-6">
             <div className="bg-black/40 border border-white/5 p-6 rounded-2xl">
                <p className="text-xs text-gray-500 uppercase font-black mb-4">Security API Key</p>
                <div className="flex gap-4">
                  <input type="password" value="TRC_SECRET_88129930" readOnly className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-cyan-500 font-mono text-sm" />
                  <button className="px-6 py-3 bg-white/10 border border-white/10 text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-white/20 transition-all">Rotate Key</button>
                </div>
             </div>
          </div>
        </div>

        <div className="flex justify-end gap-4">
          <button className="px-8 py-4 bg-white/5 border border-white/10 text-gray-400 rounded-2xl font-black text-xs uppercase tracking-widest hover:text-white transition-all">Discard Changes</button>
          <button className="px-10 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-2xl font-black text-xs uppercase tracking-widest flex items-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)]">
            <Save size={18} /> Commit Configuration
          </button>
        </div>
      </div>
    </div>
  );
}
