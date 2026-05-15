import { History, Search, Filter, Download, Shield, Clock, FileText, AlertTriangle } from "lucide-react";
import { useState, useEffect } from "react";
import { forensicsApi } from "../services/api";

export default function ScanHistory() {
  const [searchTerm, setSearchTerm] = useState("");
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const username = localStorage.getItem("trace_user");

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await forensicsApi.getHistory(username);
        if (res.success) setHistory(res.data);
      } catch (err) {
        console.error("Failed to load history");
      } finally {
        setIsLoading(false);
      }
    };
    if (username) fetchHistory();
  }, [username]);

  const filteredHistory = history.filter(s => 
    s.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
    s.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <History size={14} className="text-cyan-500" />
            <span className="text-[10px] text-cyan-500 uppercase font-black tracking-[0.4em]">Forensic Audit Trail</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Operation History</h1>
        </div>
        <div className="flex gap-4">
          <div className="relative">
            <input 
              type="text" 
              placeholder="Filter by filename or ID..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-2xl px-6 py-3 pl-12 text-sm text-white focus:outline-none focus:border-cyan-500/50 w-80 font-mono"
            />
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
          </div>
          <button className="px-6 py-3 bg-white/5 border border-white/10 rounded-2xl text-white text-xs font-black uppercase tracking-widest flex items-center gap-2 hover:bg-white/10 transition-all">
            <Filter size={16} /> Advanced Filters
          </button>
        </div>
      </div>

      <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 rounded-3xl overflow-hidden shadow-2xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-black/40 border-b border-white/5">
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Operation ID</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Target Artifact</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Timestamp</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest text-center">Threat Score</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Severity</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {isLoading ? (
               <tr><td colSpan="6" className="py-20 text-center text-cyan-500 font-mono animate-pulse uppercase tracking-widest">Retrieving Forensic Logs...</td></tr>
            ) : filteredHistory.length > 0 ? filteredHistory.map((scan, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                <td className="px-8 py-6 font-mono text-xs text-cyan-500 font-bold">{scan.id}</td>
                <td className="px-8 py-6">
                  <div className="flex flex-col">
                    <span className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors">{scan.name}</span>
                    <span className="text-[10px] text-gray-500 font-mono">{scan.size}</span>
                  </div>
                </td>
                <td className="px-8 py-6 text-xs text-gray-400 flex items-center gap-2 italic">
                  <Clock size={14} className="text-gray-600" /> {scan.date}
                </td>
                <td className="px-8 py-6">
                  <div className="flex flex-col items-center gap-1">
                    <div className="text-lg font-black text-white leading-none">{scan.score}</div>
                    <div className="w-16 h-1 bg-gray-800 rounded-full overflow-hidden">
                      <div className={`h-full ${scan.score > 70 ? 'bg-red-500' : scan.score > 40 ? 'bg-orange-500' : 'bg-cyan-500'}`} style={{ width: `${scan.score}%` }}></div>
                    </div>
                  </div>
                </td>
                <td className="px-8 py-6">
                  <span className={`text-[10px] font-black uppercase px-3 py-1 rounded-full border ${
                    scan.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/20 text-red-500' : 
                    scan.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/20 text-orange-500' :
                    scan.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500' :
                    'bg-cyan-500/10 border-cyan-500/20 text-cyan-500'
                  }`}>
                    {scan.severity}
                  </span>
                </td>
                <td className="px-8 py-6">
                  <div className="flex gap-2">
                    <button className="p-2 bg-white/5 border border-white/10 rounded-lg hover:bg-cyan-500/20 hover:text-cyan-400 transition-all shadow-sm">
                      <FileText size={16} />
                    </button>
                    <a 
                      href={scan.report_url}
                      download
                      className="p-2 bg-white/5 border border-white/10 rounded-lg hover:bg-blue-500/20 hover:text-blue-400 transition-all shadow-sm"
                    >
                      <Download size={16} />
                    </a>
                  </div>
                </td>
              </tr>
            )) : (
              <tr><td colSpan="6" className="py-20 text-center text-gray-600 font-black uppercase text-xs tracking-widest italic">No matching records in forensic database</td></tr>
            )}
          </tbody>
        </table>
        
        <div className="p-8 bg-black/20 flex items-center justify-between">
          <p className="text-xs text-gray-600 font-black uppercase tracking-widest italic">Encrypted forensic logs - Authorized access only</p>
          <div className="flex gap-2">
             <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-gray-400 hover:text-white transition-all">Previous</button>
             <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-gray-400 hover:text-white transition-all">Next</button>
          </div>
        </div>
      </div>
    </div>
  );
}
