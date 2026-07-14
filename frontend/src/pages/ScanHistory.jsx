import { History, Search, Download, Shield, Clock, FileText, AlertTriangle, ChevronDown, ChevronUp, Calendar, Activity, Crosshair, File } from "lucide-react";
import { useState, useEffect } from "react";
import { forensicsApi } from "../services/api";

const FILTERS = [
  { label: "All Scans", value: "all" },
  { label: "Today", value: "today" },
  { label: "Last 7 Days", value: "7days" },
  { label: "Last 30 Days", value: "30days" },
];

function parseDate(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  return isNaN(d.getTime()) ? null : d;
}

function filterByTime(scans, filterValue) {
  if (filterValue === "all") return scans;
  const now = new Date();
  const cutoffs = {
    today: new Date(now.getFullYear(), now.getMonth(), now.getDate()),
    "7days": new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
    "30days": new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000),
  };
  const cutoff = cutoffs[filterValue];
  if (!cutoff) return scans;
  return scans.filter((s) => {
    const d = parseDate(s.date);
    return d && d >= cutoff;
  });
}

export default function ScanHistory() {
  const [searchTerm, setSearchTerm] = useState("");
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [timeFilter, setTimeFilter] = useState("all");
  const [expandedId, setExpandedId] = useState(null);
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

  const timeFiltered = filterByTime(history, timeFilter);
  const filteredHistory = timeFiltered.filter(
    (s) =>
      s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Stats
  const totalScans = history.length;
  const highRiskScans = history.filter((s) => s.severity === "CRITICAL" || s.severity === "HIGH").length;
  const lastScanDate = history.length > 0 ? history[0].date : "—";

  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <History size={14} className="text-cyan-500" />
            <span className="text-[10px] text-cyan-500 uppercase font-black tracking-[0.4em]">
              Forensic Audit Trail
            </span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">
            Operation History
          </h1>
        </div>
        <div className="flex gap-4 flex-wrap">
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
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-xl">
            <Crosshair size={22} className="text-cyan-400" />
          </div>
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-black">Total Scans</p>
            <p className="text-2xl font-black text-white">{totalScans}</p>
          </div>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 bg-red-500/10 rounded-xl">
            <AlertTriangle size={22} className="text-red-400" />
          </div>
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-black">High Risk Scans</p>
            <p className="text-2xl font-black text-red-400">{highRiskScans}</p>
          </div>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/5 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 bg-indigo-500/10 rounded-xl">
            <Calendar size={22} className="text-indigo-400" />
          </div>
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-black">Last Scan</p>
            <p className="text-sm font-mono text-gray-300 truncate max-w-[180px]">{lastScanDate}</p>
          </div>
        </div>
      </div>

      {/* Time Filters */}
      <div className="flex gap-2 flex-wrap">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setTimeFilter(f.value)}
            className={`px-5 py-2 rounded-xl text-xs font-black uppercase tracking-widest border transition-all ${
              timeFilter === f.value
                ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-400"
                : "bg-white/5 border-white/10 text-gray-500 hover:text-white hover:bg-white/10"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 rounded-3xl overflow-hidden shadow-2xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-black/40 border-b border-white/5">
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Operation ID</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Target Artifact</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Timestamp</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest text-center">Threat Score</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Severity</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Type</th>
              <th className="px-8 py-5 text-[10px] text-gray-500 uppercase font-black tracking-widest">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {isLoading ? (
              <tr>
                <td colSpan="7" className="py-20 text-center text-cyan-500 font-mono animate-pulse uppercase tracking-widest">
                  Retrieving Forensic Logs...
                </td>
              </tr>
            ) : filteredHistory.length > 0 ? (
              filteredHistory.map((scan, i) => (
                <tr key={i} className="group">
                  <td colSpan="7" className="p-0">
                    {/* Main Row */}
                    <div className="flex items-center hover:bg-white/[0.02] transition-colors cursor-pointer" onClick={() => setExpandedId(expandedId === scan.id ? null : scan.id)}>
                      <div className="px-8 py-6 font-mono text-xs text-cyan-500 font-bold w-[140px] shrink-0">{scan.id}</div>
                      <div className="px-8 py-6 flex-1 min-w-0">
                        <div className="flex flex-col">
                          <span className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors truncate">{scan.name}</span>
                          <span className="text-[10px] text-gray-500 font-mono">{scan.size}</span>
                        </div>
                      </div>
                      <div className="px-8 py-6 text-xs text-gray-400 flex items-center gap-2 italic w-[200px] shrink-0">
                        <Clock size={14} className="text-gray-600" /> {scan.date}
                      </div>
                      <div className="px-8 py-6 w-[120px] shrink-0">
                        <div className="flex flex-col items-center gap-1">
                          <div className="text-lg font-black text-white leading-none">{scan.score}</div>
                          <div className="w-16 h-1 bg-gray-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${scan.score > 70 ? "bg-red-500" : scan.score > 40 ? "bg-orange-500" : "bg-cyan-500"}`}
                              style={{ width: `${scan.score}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                      <div className="px-8 py-6 w-[120px] shrink-0">
                        <span
                          className={`text-[10px] font-black uppercase px-3 py-1 rounded-full border ${
                            scan.severity === "CRITICAL"
                              ? "bg-red-500/10 border-red-500/20 text-red-500"
                              : scan.severity === "HIGH"
                              ? "bg-orange-500/10 border-orange-500/20 text-orange-500"
                              : scan.severity === "MEDIUM"
                              ? "bg-yellow-500/10 border-yellow-500/20 text-yellow-500"
                              : "bg-cyan-500/10 border-cyan-500/20 text-cyan-500"
                          }`}
                        >
                          {scan.severity}
                        </span>
                      </div>
                      <div className="px-8 py-6 w-[90px] shrink-0">
                        <span className="text-[10px] font-black text-gray-400 uppercase bg-white/5 px-2 py-1 rounded-md border border-white/10">
                          {scan.file_type || "RAW"}
                        </span>
                      </div>
                      <div className="px-8 py-6 w-[120px] shrink-0">
                        <div className="flex gap-2 items-center">
                          <button
                            onClick={(e) => { e.stopPropagation(); setExpandedId(expandedId === scan.id ? null : scan.id); }}
                            className="p-2 bg-white/5 border border-white/10 rounded-lg hover:bg-cyan-500/20 hover:text-cyan-400 transition-all shadow-sm"
                            title="View Details"
                          >
                            {expandedId === scan.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                          </button>
                          <a
                            href={scan.report_url}
                            download
                            onClick={(e) => e.stopPropagation()}
                            className="p-2 bg-white/5 border border-white/10 rounded-lg hover:bg-blue-500/20 hover:text-blue-400 transition-all shadow-sm"
                            title="Download Report"
                          >
                            <Download size={16} />
                          </a>
                        </div>
                      </div>
                    </div>

                    {/* Expanded Details Panel */}
                    {expandedId === scan.id && (
                      <div className="bg-black/30 border-t border-white/5 px-10 py-6 animate-in slide-in-from-top-2 fade-in duration-300">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                          <div className="md:col-span-2">
                            <div className="flex items-center gap-2 mb-3">
                              <Shield size={14} className="text-cyan-500" />
                              <span className="text-[10px] text-cyan-500 uppercase font-black tracking-widest">AI Forensic Summary</span>
                            </div>
                            <p className="text-sm text-gray-300 leading-relaxed bg-black/30 border border-white/5 rounded-xl p-4 font-mono">
                              {scan.forensic_summary || "No forensic summary available for this scan."}
                            </p>
                          </div>
                          <div className="space-y-3">
                            <div className="flex items-center gap-2 mb-3">
                              <Activity size={14} className="text-cyan-500" />
                              <span className="text-[10px] text-cyan-500 uppercase font-black tracking-widest">Scan Metadata</span>
                            </div>
                            <div className="bg-black/30 border border-white/5 rounded-xl p-4 space-y-3">
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-500 font-bold uppercase">File Type</span>
                                <span className="text-white font-mono">{scan.file_type || "RAW"}</span>
                              </div>
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-500 font-bold uppercase">Dump Size</span>
                                <span className="text-white font-mono">{scan.size}</span>
                              </div>
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-500 font-bold uppercase">Suspicious Procs</span>
                                <span className="text-orange-400 font-mono font-bold">{scan.suspicious_process_count || 0}</span>
                              </div>
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-500 font-bold uppercase">Scan ID</span>
                                <span className="text-cyan-400 font-mono">{scan.id}</span>
                              </div>
                            </div>
                            <a
                              href={scan.report_url}
                              download
                              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 text-xs font-black uppercase tracking-widest hover:bg-cyan-500/20 transition-all"
                            >
                              <FileText size={14} /> Open Full Report
                            </a>
                          </div>
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="7" className="py-20 text-center">
                  <div className="flex flex-col items-center gap-4">
                    <File size={48} className="text-gray-700" />
                    <p className="text-gray-600 font-black uppercase text-xs tracking-widest italic">
                      No scans found for this analyst.
                    </p>
                    <p className="text-[10px] text-gray-700 uppercase tracking-widest">
                      Upload a memory dump in the Analysis tab to begin.
                    </p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="p-8 bg-black/20 flex items-center justify-between">
          <p className="text-xs text-gray-600 font-black uppercase tracking-widest italic">
            Encrypted forensic logs — Authorized access only
          </p>
          <p className="text-xs text-gray-600 font-mono">
            {filteredHistory.length} of {history.length} records displayed
          </p>
        </div>
      </div>
    </div>
  );
}
