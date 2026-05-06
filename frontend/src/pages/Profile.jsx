import { useState } from "react";
import { User, Mail, Shield, Key, Bell, Save } from "lucide-react";

export default function Profile({ user }) {
  const [autoGen, setAutoGen] = useState(true);
  const [deepScan, setDeepScan] = useState(false);
  const [threatAlerts, setThreatAlerts] = useState(true);
  return (
    <div className="p-10 max-w-5xl mx-auto">
      <header className="mb-10">
        <h1 className="text-4xl font-bold text-white mb-2">Agent Profile</h1>
        <p className="text-gray-400">Manage your TRACE credentials and analysis settings.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Profile Card */}
        <div className="lg:col-span-1">
          <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl flex flex-col items-center text-center">
            <div className="w-32 h-32 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 p-1 mb-6 shadow-[0_0_20px_rgba(34,211,238,0.3)]">
              <div className="w-full h-full bg-[#0b1020] rounded-full flex items-center justify-center">
                <User size={64} className="text-cyan-400" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-white mb-1">Agent {user}</h2>
            <p className="text-cyan-400 font-mono mb-4 text-sm">ID: TRC-{Math.floor(Math.random() * 9000) + 1000}-X</p>
            
            <div className="flex items-center gap-2 bg-indigo-500/20 text-indigo-300 px-4 py-1.5 rounded-full text-sm font-semibold mb-8">
              <Shield size={16} /> Level 5 Clearance
            </div>

            <div className="w-full text-left space-y-4 border-t border-white/5 pt-6">
              <div>
                <div className="text-xs text-gray-500 uppercase font-bold mb-1">Email</div>
                <div className="text-gray-300 text-sm flex items-center gap-2"><Mail size={16}/> alpha@trace.sec</div>
              </div>
              <div>
                <div className="text-xs text-gray-500 uppercase font-bold mb-1">Role</div>
                <div className="text-gray-300 text-sm">Senior Forensics Analyst</div>
              </div>
            </div>
          </div>
        </div>

        {/* Settings */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
            <h3 className="text-xl font-bold text-white mb-6 border-b border-white/5 pb-4">Analysis Preferences</h3>
            
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-white font-medium mb-1">Auto-Generate PDF Reports</div>
                  <div className="text-sm text-gray-400">Automatically create a downloadable PDF after every scan.</div>
                </div>
                <div 
                  onClick={() => setAutoGen(!autoGen)}
                  className={`w-12 h-6 rounded-full flex items-center p-1 cursor-pointer transition-colors duration-300 ${autoGen ? 'bg-cyan-500' : 'bg-gray-700'}`}
                >
                  <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${autoGen ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="text-white font-medium mb-1">Deep Scan Mode</div>
                  <div className="text-sm text-gray-400">Run extended heuristic analysis on memory dumps (takes longer).</div>
                </div>
                <div 
                  onClick={() => setDeepScan(!deepScan)}
                  className={`w-12 h-6 rounded-full flex items-center p-1 cursor-pointer transition-colors duration-300 ${deepScan ? 'bg-cyan-500' : 'bg-gray-700'}`}
                >
                  <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${deepScan ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <div className="text-white font-medium mb-1 flex items-center gap-2"><Bell size={16}/> Threat Alerts</div>
                  <div className="text-sm text-gray-400">Receive email notifications for HIGH severity threats.</div>
                </div>
                <div 
                  onClick={() => setThreatAlerts(!threatAlerts)}
                  className={`w-12 h-6 rounded-full flex items-center p-1 cursor-pointer transition-colors duration-300 ${threatAlerts ? 'bg-cyan-500' : 'bg-gray-700'}`}
                >
                  <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 ${threatAlerts ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
            <h3 className="text-xl font-bold text-white mb-6 border-b border-white/5 pb-4 flex items-center gap-2"><Key size={20}/> API Access</h3>
            <p className="text-sm text-gray-400 mb-4">Your personal API key for programmatic access to the TRACE backend.</p>
            
            <div className="flex gap-4">
              <input 
                type="password" 
                value="trc_sk_8923470987234987234" 
                readOnly
                className="flex-1 bg-black/40 border border-gray-700 rounded-xl px-4 py-3 text-gray-300 focus:outline-none"
              />
              <button className="bg-white/5 border border-white/10 hover:bg-white/10 text-white px-6 py-3 rounded-xl font-medium transition">
                Reveal
              </button>
            </div>
          </div>

          <div className="flex justify-end mt-8">
            <button className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-8 py-3 rounded-xl font-bold transition shadow-[0_0_20px_rgba(34,211,238,0.2)]">
              <Save size={20} />
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
