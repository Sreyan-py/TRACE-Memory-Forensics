import { useState, useRef, useEffect } from "react";
import axios from "axios";
import { UploadCloud, File, AlertTriangle, Activity, Download, CheckCircle, Shield, Loader2, EyeOff, Code, Database, Network, Search, Zap } from "lucide-react";

export default function Analysis() {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [analysisData, setAnalysisData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = () => {
    setIsDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a file first.");
      return;
    }

    const ext = file.name.split('.').pop().toLowerCase();
    if (!['raw', 'mem', 'dmp', 'img'].includes(ext)) {
      setMessage("Invalid memory dump format");
      return;
    }


    setIsLoading(true);
    setScanProgress(0);
    setMessage("");
    setAnalysisData(null);

    // Realistic scanning progress simulation
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + Math.floor(Math.random() * 5) + 2;
      });
    }, 250);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("username", localStorage.getItem("trace_user"));

    try {
      const response = await axios.post("https://trace-memory-forensics.onrender.com/upload", formData);
      clearInterval(progressInterval);
      setScanProgress(100);
      
      setTimeout(() => {
        setMessage(response.data.message);
        setAnalysisData(response.data);
        setIsLoading(false);
      }, 800);

    } catch (error) {
      clearInterval(progressInterval);
      setMessage(error.response?.data?.error || "Upload Failed");
      setIsLoading(false);
    }
  };

  return (
    <div className="p-10 max-w-6xl mx-auto">
      <header className="mb-10">
        <h1 className="text-4xl font-bold text-white mb-2">Deep Memory Inspection</h1>
        <p className="text-gray-400">Upload a raw memory dump to identify zero-days, rootkits, and fileless malware via Volatility emulation.</p>
      </header>

      {/* Upload Zone */}
      {!analysisData && (
        <div 
          className={`relative w-full rounded-3xl border-2 border-dashed transition-all duration-300 p-12 text-center flex flex-col items-center justify-center min-h-[350px] mb-8
            ${isDragActive ? 'border-cyan-400 bg-cyan-400/10' : 'border-gray-700 bg-white/[0.02] hover:bg-white/[0.04] hover:border-gray-500'}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            className="hidden" 
            onChange={handleFileChange} 
          />
          
          {file ? (
            <div className="flex flex-col items-center animate-in fade-in zoom-in duration-300 w-full max-w-md">
              <div className="w-24 h-24 bg-indigo-500/20 text-indigo-400 rounded-3xl flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                <File size={48} />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">{file.name}</h3>
              <p className="text-gray-400 font-mono mb-8">{(file.size / (1024 * 1024)).toFixed(2)} MB RAW IMAGE</p>
              
              {isLoading ? (
                <div className="w-full bg-[#0b1020] p-6 rounded-2xl border border-gray-800 shadow-xl">
                  <div className="flex justify-between text-sm mb-4">
                    <span className="text-cyan-400 font-bold tracking-widest uppercase flex items-center gap-3">
                      <Loader2 size={18} className="animate-spin"/> Initiating Volatility Scan...
                    </span>
                    <span className="text-white font-mono">{scanProgress}%</span>
                  </div>
                  <div className="h-3 w-full bg-black rounded-full overflow-hidden border border-gray-800">
                    <div 
                      className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 transition-all duration-200 ease-out relative"
                      style={{ width: `${scanProgress}%` }}
                    >
                      <div className="absolute top-0 right-0 bottom-0 left-0 bg-[linear-gradient(45deg,transparent_25%,rgba(255,255,255,0.2)_25%,rgba(255,255,255,0.2)_50%,transparent_50%,transparent_75%,rgba(255,255,255,0.2)_75%,rgba(255,255,255,0.2)_100%)] bg-[length:1rem_1rem] animate-[progress-bar-stripes_1s_linear_infinite]"></div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex gap-4 w-full">
                  <button 
                    onClick={() => setFile(null)}
                    className="flex-1 px-6 py-4 rounded-xl font-bold text-gray-400 bg-white/5 hover:text-white hover:bg-white/10 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleUpload}
                    className="flex-[2] flex items-center justify-center gap-2 px-8 py-4 rounded-xl font-bold text-white transition shadow-[0_0_30px_rgba(34,211,238,0.4)] bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500"
                  >
                    <Search size={20} /> Launch Deep Scan
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center cursor-pointer group" onClick={() => fileInputRef.current?.click()}>
              <div className="w-24 h-24 bg-cyan-500/10 text-cyan-400 rounded-full flex items-center justify-center mb-6 shadow-[0_0_40px_rgba(34,211,238,0.15)] group-hover:scale-110 group-hover:bg-cyan-500/20 transition-all duration-500">
                <UploadCloud size={48} />
              </div>
              <h3 className="text-3xl font-bold text-white mb-3">Drag & Drop Memory Dump</h3>
              <p className="text-gray-400 mb-2 max-w-md">Supported formats: .raw, .img, .mem, .dmp. Analysis engine will automatically detect the memory profile.</p>
              <div className="bg-orange-500/10 border border-orange-500/30 text-orange-400 text-sm p-3 rounded-xl mb-8 max-w-md text-center">
                <span className="font-bold">Note:</span> Cloud deployment supports files up to 200MB. Large memory dumps ({'>'}200MB) must be analyzed using a local TRACE forensic node.
              </div>
              <button className="bg-white/5 border border-white/10 group-hover:border-cyan-500/50 group-hover:bg-white/10 text-white px-8 py-3 rounded-xl font-bold transition-all">
                Browse Files
              </button>
            </div>
          )}
        </div>
      )}

      {message && !analysisData && !isLoading && (
        <div className={`p-4 rounded-xl text-center font-bold ${message.includes("Failed") || message.includes("valid") ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"}`}>
          {message}
        </div>
      )}

      {/* Massive Results Dashboard */}
      {analysisData && analysisData.analysis && (
        <div className="animate-in slide-in-from-bottom-8 fade-in duration-700">
          
          {/* Header Summary Card */}
          <div className="bg-[#0d1326] border border-gray-800 rounded-3xl p-8 shadow-2xl relative overflow-hidden mb-8">
            <div className={`absolute top-0 right-0 w-[600px] h-[600px] rounded-full blur-[180px] opacity-20 pointer-events-none ${analysisData.analysis.severity === "CRITICAL" ? "bg-red-600" : analysisData.analysis.severity === "HIGH" ? "bg-orange-500" : analysisData.analysis.severity === "MEDIUM" ? "bg-yellow-500" : "bg-green-500"}`}></div>

            <div className="relative z-10 flex flex-col lg:flex-row justify-between items-center gap-8">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className={analysisData.analysis.severity === "CRITICAL" || analysisData.analysis.severity === "HIGH" ? "text-red-500" : "text-green-500"} size={40} />
                  <h2 className="text-4xl font-black text-white tracking-tight">Scan Complete</h2>
                </div>
                <p className="text-gray-400 flex items-center gap-2 mb-6 font-mono text-sm">
                  <CheckCircle size={16} className="text-cyan-400" />
                  Target: {analysisData.filename} | Time: {analysisData.analysis.timestamps?.scan_end}
                </p>
                
                {/* AI Summary Block */}
                <div className="bg-black/40 border border-gray-800 rounded-2xl p-5 border-l-4 border-l-cyan-500">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap size={16} className="text-cyan-400"/>
                    <span className="text-cyan-400 font-bold text-xs uppercase tracking-widest">AI Analyst Summary</span>
                  </div>
                  <p className="text-gray-300 leading-relaxed text-sm">
                    {analysisData.analysis.forensic_summary}
                  </p>
                </div>
              </div>
              
              {/* Threat Meter */}
              <div className="bg-black/60 backdrop-blur-md border border-gray-700 p-8 rounded-3xl text-center min-w-[250px] shadow-[inset_0_0_30px_rgba(0,0,0,0.5)]">
                <div className="text-xs text-gray-400 uppercase tracking-widest font-black mb-3">Threat Score</div>
                <div className={`text-7xl font-black tracking-tighter mb-2 ${
                  analysisData.analysis.severity === "CRITICAL" ? "text-red-500 drop-shadow-[0_0_20px_rgba(239,68,68,0.6)]" : 
                  analysisData.analysis.severity === "HIGH" ? "text-orange-500 drop-shadow-[0_0_20px_rgba(249,115,22,0.6)]" : 
                  analysisData.analysis.severity === "MEDIUM" ? "text-yellow-500 drop-shadow-[0_0_20px_rgba(234,179,8,0.6)]" : 
                  "text-green-500 drop-shadow-[0_0_20px_rgba(34,197,94,0.6)]"
                }`}>
                  {analysisData.analysis.threat_score}
                </div>
                <div className={`inline-block px-4 py-1 rounded-full text-xs font-bold uppercase tracking-widest ${
                  analysisData.analysis.severity === "CRITICAL" ? "bg-red-500/20 text-red-400 border border-red-500/50" : 
                  analysisData.analysis.severity === "HIGH" ? "bg-orange-500/20 text-orange-400 border border-orange-500/50" : 
                  analysisData.analysis.severity === "MEDIUM" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/50" : 
                  "bg-green-500/20 text-green-400 border border-green-500/50"
                }`}>
                  {analysisData.analysis.severity} RISK
                </div>
              </div>
            </div>
          </div>

          {/* Detailed Forensic Indicators Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            
            {/* Malware Indicators */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <AlertTriangle size={20} className="text-red-500" /> Forensic Indicators
              </h3>
              {analysisData.analysis.malware_indicators?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.malware_indicators.map((ind, idx) => (
                    <li key={idx} className="bg-red-500/10 border border-red-500/20 px-4 py-3 rounded-xl text-sm text-red-200 font-mono">
                      ! {ind}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No critical indicators detected.</div>
              )}
            </div>

            {/* Suspicious Processes */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Activity size={20} className="text-orange-400" /> Suspicious Processes
              </h3>
              {analysisData.analysis.suspicious_processes?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.suspicious_processes.map((proc, idx) => (
                    <li key={idx} className="bg-black/40 border border-gray-800 px-4 py-3 rounded-xl text-sm text-gray-300 font-mono flex items-center justify-between">
                      <div className="flex items-center">
                        <span className="w-2 h-2 bg-orange-500 rounded-full mr-3 shadow-[0_0_8px_rgba(249,115,22,0.8)]"></span>
                        {proc}
                      </div>
                      <span className="text-xs text-gray-500">Flagged</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">Process tree clean.</div>
              )}
            </div>

            {/* Hidden Processes / Rootkits */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <EyeOff size={20} className="text-purple-400" /> Unlinked / Hidden Processes
              </h3>
              {analysisData.analysis.hidden_processes?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.hidden_processes.map((proc, idx) => (
                    <li key={idx} className="bg-purple-500/10 border border-purple-500/20 px-4 py-3 rounded-xl text-sm text-purple-200 font-mono flex items-center justify-between">
                      <div className="flex items-center">
                        <span className="w-2 h-2 bg-purple-500 rounded-full mr-3 shadow-[0_0_8px_rgba(168,85,247,0.8)]"></span>
                        {proc}
                      </div>
                      <span className="text-xs text-purple-400/50">DKOM Detected</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No DKOM hidden processes found.</div>
              )}
            </div>

            {/* Network Connections */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Network size={20} className="text-cyan-400" /> Anomalous Network Connections
              </h3>
              {analysisData.analysis.network_connections?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.network_connections.map((conn, idx) => (
                    <li key={idx} className="bg-black/40 border border-gray-800 px-4 py-3 rounded-xl text-sm text-cyan-200 font-mono">
                      {conn}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No malicious external IPs detected.</div>
              )}
            </div>

            {/* DLL Injections */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Code size={20} className="text-yellow-400" /> Injected DLLs
              </h3>
              {analysisData.analysis.dll_injections?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.dll_injections.map((dll, idx) => (
                    <li key={idx} className="bg-yellow-500/10 border border-yellow-500/20 px-4 py-3 rounded-xl text-sm text-yellow-200 font-mono">
                      {dll}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No unbacked DLL modules.</div>
              )}
            </div>

            {/* Registry Anomalies */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Database size={20} className="text-blue-400" /> Registry Persistence
              </h3>
              {analysisData.analysis.registry_anomalies?.length > 0 ? (
                <ul className="space-y-3">
                  {analysisData.analysis.registry_anomalies.map((reg, idx) => (
                    <li key={idx} className="bg-black/40 border border-gray-800 px-4 py-3 rounded-xl text-xs text-blue-200 font-mono break-all">
                      {reg}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No suspicious autoruns found.</div>
              )}
            </div>

          </div>

          {/* Download Report Button */}
          {analysisData.report_url && (
            <div className="flex justify-center mt-8">
              <a 
                href={analysisData.report_url}
                download
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 bg-white/5 border border-white/10 hover:bg-white/10 hover:border-cyan-500/50 text-white px-10 py-5 rounded-2xl font-black text-lg transition-all duration-300 hover:shadow-[0_0_30px_rgba(34,211,238,0.2)] group"
              >
                <Download size={24} className="text-cyan-400 group-hover:scale-110 group-hover:-translate-y-1 transition-transform" />
                DOWNLOAD OFFICIAL FORENSIC REPORT (PDF)
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
