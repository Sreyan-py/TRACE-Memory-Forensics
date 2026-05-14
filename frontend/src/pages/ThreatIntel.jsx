import { Globe, Search, ShieldAlert, Target, Database, FileCode, Zap } from "lucide-react";

export default function ThreatIntel() {
  const cves = [
    { id: "CVE-2024-38063", title: "Windows TCP/IP RCE", severity: "CRITICAL", score: "9.8" },
    { id: "CVE-2024-38077", title: "Windows RDP RCE", severity: "CRITICAL", score: "9.8" },
    { id: "CVE-2024-30080", title: "Microsoft MSHTML RCE", severity: "HIGH", score: "8.8" },
    { id: "CVE-2024-30103", title: "Outlook RCE Bypass", severity: "HIGH", score: "7.5" },
  ];

  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Globe size={14} className="text-cyber-cyan animate-cyber-pulse" />
            <span className="text-[10px] text-cyber-cyan uppercase font-black tracking-[0.4em]">CTI Intelligence Feed</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Threat Intel</h1>
        </div>
        <div className="relative group">
          <input 
            type="text" 
            placeholder="Search IOCs, Hashes, CVEs..." 
            className="bg-white/5 border border-white/10 rounded-2xl px-12 py-4 w-[400px] outline-none focus:border-cyber-cyan transition-all font-mono text-sm"
          />
          <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-cyber-cyan transition-colors" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Trending CVEs */}
        <div className="lg:col-span-8 space-y-8">
          <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-8 rounded-3xl">
            <h3 className="text-xl font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
              <Zap size={20} className="text-yellow-500" /> Trending Threats
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {cves.map((cve, i) => (
                <div key={i} className="bg-white/5 border border-white/5 p-6 rounded-2xl hover:bg-white/10 transition-all group">
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-cyber-cyan font-mono text-sm font-bold">{cve.id}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-black ${cve.severity === 'CRITICAL' ? 'bg-red-500 text-white' : 'bg-orange-500 text-white'}`}>
                      {cve.severity}
                    </span>
                  </div>
                  <h4 className="text-white font-bold mb-4">{cve.title}</h4>
                  <div className="flex items-center justify-between text-[10px] text-gray-500 font-black uppercase">
                    <span>CVSS Score: <span className="text-white">{cve.score}</span></span>
                    <button className="text-cyber-cyan hover:underline">Full Report →</button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl">
            <h3 className="text-xl font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
              <Target size={20} className="text-cyber-red" /> MITRE ATT&CK Matrix (Top Techs)
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { id: "T1059", name: "Command & Scripting" },
                { id: "T1055", name: "Process Injection" },
                { id: "T1003", name: "OS Credential Dumping" },
                { id: "T1027", name: "Obfuscated Files" },
              ].map((tech, i) => (
                <div key={i} className="bg-black/40 border border-white/5 p-4 rounded-xl text-center">
                  <div className="text-red-500 font-mono text-xs font-bold mb-1">{tech.id}</div>
                  <div className="text-white text-[10px] font-black uppercase leading-tight">{tech.name}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: IOC Feed */}
        <div className="lg:col-span-4 bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl h-fit">
          <h3 className="text-sm font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
            <ShieldAlert size={16} className="text-cyber-red" /> Critical Indicators
          </h3>
          <div className="space-y-4">
            {[
              "8.8.8.8 (Known Botnet C2)",
              "b3d2...f9a1 (Lockbit Signature)",
              "powershell.exe -enc ... (Encoded)",
              "192.168.1.105 (Suspicious Lat-Mov)",
            ].map((ioc, i) => (
              <div key={i} className="bg-white/5 p-3 rounded-xl border border-white/5 flex items-center gap-3">
                <div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse"></div>
                <span className="text-[10px] font-mono text-gray-300 truncate">{ioc}</span>
              </div>
            ))}
          </div>
          <button className="w-full mt-8 bg-cyber-cyan/20 border border-cyber-cyan/30 text-cyber-cyan py-3 rounded-xl font-black text-[10px] uppercase tracking-widest hover:bg-cyber-cyan/30 transition-all">
            Download Blacklist
          </button>
        </div>
      </div>
    </div>
  );
}
