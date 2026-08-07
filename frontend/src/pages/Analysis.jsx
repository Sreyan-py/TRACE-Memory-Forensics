import { useState, useRef } from "react";
import { forensicsApi, getStoredUsername } from "../services/api";
import {
  UploadCloud, File, AlertTriangle, Activity, Download, CheckCircle,
  Loader2, EyeOff, Code, Database, Network, Search, Zap,
  Clock, List,
} from "lucide-react";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SUPPORTED_EXTENSIONS = ["raw", "mem", "dmp", "img", "vmem", "pdf"];

const EXTENSION_LABELS = {
  vmem: "VMware Memory Dump",
  raw:  "Raw Memory Image",
  mem:  "Memory Dump",
  dmp:  "Windows Crash Dump",
  img:  "Disk/Memory Image",
  pdf:  "PDF Forensic Report",
};

const SCAN_STAGES = [
  "Uploading File...",
  "Validating Memory Image...",
  "Detecting Operating System...",
  "Building Memory Profile...",
  "Launching Volatility...",
  "Enumerating Processes...",
  "Scanning Hidden Processes...",
  "Scanning DLL Injection...",
  "Scanning Network Connections...",
  "Scanning Registry...",
  "Calculating Threat Score...",
  "Generating AI Report...",
  "Analysis Complete.",
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function getFileExt(filename) {
  return filename?.split(".").pop().toLowerCase() || "";
}

function getFileTypeLabel(filename) {
  if (!filename) return "";
  const ext = getFileExt(filename);
  return EXTENSION_LABELS[ext] || ext.toUpperCase() + " FILE";
}

function formatFileSize(bytes) {
  if (!bytes) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function isMemoryDump(filename) {
  return SUPPORTED_EXTENSIONS.includes(getFileExt(filename));
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress bar with stage labels
// ─────────────────────────────────────────────────────────────────────────────

function ScanProgressBar({ stage, progress }) {
  return (
    <div className="w-full bg-[#0b1020] p-6 rounded-2xl border border-gray-800 shadow-xl">
      <div className="flex justify-between text-sm mb-2">
        <span className="text-cyan-400 font-bold tracking-widest uppercase flex items-center gap-3">
          <Loader2 size={16} className="animate-spin shrink-0" />
          <span className="truncate max-w-[260px]">{stage}</span>
        </span>
        <span className="text-white font-mono shrink-0 ml-2">{progress}%</span>
      </div>
      <div className="h-3 w-full bg-black rounded-full overflow-hidden border border-gray-800 mb-3">
        <div
          className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 transition-all duration-500 ease-out relative"
          style={{ width: `${progress}%` }}
        >
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(255,255,255,0.15)_25%,rgba(255,255,255,0.15)_50%,transparent_50%,transparent_75%,rgba(255,255,255,0.15)_75%)] bg-[length:1rem_1rem] animate-[progress-bar-stripes_1s_linear_infinite]" />
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {SCAN_STAGES.map((s, i) => {
          const stageProgress = Math.round(((i + 1) / SCAN_STAGES.length) * 100);
          const active = progress >= stageProgress;
          return (
            <div
              key={i}
              className={`text-[8px] font-black uppercase tracking-widest px-2 py-0.5 rounded transition-all ${
                active
                  ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                  : "text-gray-700 border border-gray-800"
              }`}
            >
              {i + 1}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// File metadata card (shown after file selection)
// ─────────────────────────────────────────────────────────────────────────────

function FileMetaCard({ file }) {
  const label = getFileTypeLabel(file.name);
  const isValid = isMemoryDump(file.name);
  const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
  const isOverLimit = parseFloat(sizeMB) > 200;

  return (
    <div className="w-full bg-black/20 border border-white/5 rounded-2xl p-4 mb-4 grid grid-cols-3 gap-4 text-center">
      <div>
        <p className="text-[9px] text-gray-500 font-black uppercase tracking-widest mb-1">Filename</p>
        <p className="text-white text-xs font-mono truncate" title={file.name}>{file.name}</p>
      </div>
      <div>
        <p className="text-[9px] text-gray-500 font-black uppercase tracking-widest mb-1">Size</p>
        <p className={`text-xs font-mono font-bold ${isOverLimit ? "text-red-400" : "text-white"}`}>
          {formatFileSize(file.size)}
          {isOverLimit && <span className="text-red-400 ml-1 text-[9px]">(&gt;200MB)</span>}
        </p>
      </div>
      <div>
        <p className="text-[9px] text-gray-500 font-black uppercase tracking-widest mb-1">Detected Type</p>
        <p className={`text-xs font-mono font-bold ${isValid ? "text-cyan-400" : "text-gray-500"}`}>{label}</p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Analysis component
// ─────────────────────────────────────────────────────────────────────────────

export default function Analysis() {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [analysisData, setAnalysisData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState("");
  const [isDragActive, setIsDragActive] = useState(false);
  const [isError, setIsError] = useState(false);
  const fileInputRef = useRef(null);
  const progressIntervalRef = useRef(null);
  const stageTimerRef = useRef(null);

  // ── Stage/progress simulation ──────────────────────────────────────────────
  function startProgressSimulation() {
    let stageIdx = 0;
    setScanProgress(0);
    setCurrentStage(SCAN_STAGES[0]);

    // Advance stages at realistic intervals (each ~7s for 13 stages over ~90s)
    stageTimerRef.current = setInterval(() => {
      stageIdx = Math.min(stageIdx + 1, SCAN_STAGES.length - 2); // stop at second-to-last
      setCurrentStage(SCAN_STAGES[stageIdx]);
    }, 8000);

    // Smooth progress that moves toward 92% then stops
    progressIntervalRef.current = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 92) return 92;
        const delta = prev < 50 ? 3 : prev < 80 ? 1.5 : 0.5;
        return Math.min(prev + delta, 92);
      });
    }, 300);
  }

  function stopProgressSimulation(success = true) {
    clearInterval(progressIntervalRef.current);
    clearInterval(stageTimerRef.current);
    if (success) {
      setCurrentStage(SCAN_STAGES[SCAN_STAGES.length - 1]);
      setScanProgress(100);
    } else {
      setScanProgress(0);
      setCurrentStage("");
    }
  }

  // ── Event handlers ─────────────────────────────────────────────────────────
  const handleDragOver  = (e) => { e.preventDefault(); setIsDragActive(true); };
  const handleDragLeave = () => setIsDragActive(false);
  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files?.length > 0) setFile(e.dataTransfer.files[0]);
  };
  const handleFileChange = (e) => {
    if (e.target.files?.length > 0) setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsLoading(true);
    setIsError(false);
    setMessage("");
    setAnalysisData(null);
    startProgressSimulation();

    const formData = new FormData();
    formData.append("file", file);
    formData.append("username", getStoredUsername() || "");

    try {
      const response = await forensicsApi.upload(formData);
      stopProgressSimulation(true);

      setTimeout(() => {
        setMessage(response.message || "Analysis Complete");
        setAnalysisData(response);
        setIsLoading(false);
      }, 800);
    } catch (err) {
      stopProgressSimulation(false);
      const msg = err.message || err.response?.data?.error || "Analysis Pipeline Failure";
      setMessage(msg);
      setIsError(true);
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setAnalysisData(null);
    setMessage("");
    setIsError(false);
    setScanProgress(0);
    setCurrentStage("");
  };

  const analysis = analysisData?.analysis;

  return (
    <div className="p-10 max-w-6xl mx-auto">
      <header className="mb-10">
        <h1 className="text-4xl font-bold text-white mb-2">Deep Memory Inspection</h1>
        <p className="text-gray-400">
          {file && !analysisData
            ? `Ready to inspect ${getFileTypeLabel(file.name)} for hidden threats and malicious indicators.`
            : "Upload a forensic memory image to perform real Volatility analysis."}
        </p>
      </header>

      {/* ── Upload Zone ──────────────────────────────────────────────────── */}
      {!analysisData && (
        <div
          className={`relative w-full rounded-3xl border-2 border-dashed transition-all duration-300 p-12 text-center flex flex-col items-center justify-center min-h-[350px] mb-8
            ${isDragActive
              ? "border-cyan-400 bg-cyan-400/10"
              : "border-gray-700 bg-white/[0.02] hover:bg-white/[0.04] hover:border-gray-500"}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileChange}
            accept=".raw,.mem,.dmp,.img,.vmem,.pdf" />

          {file ? (
            <div className="flex flex-col items-center animate-in fade-in zoom-in duration-300 w-full max-w-md">
              <div className="w-24 h-24 bg-indigo-500/20 text-indigo-400 rounded-3xl flex items-center justify-center mb-4 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                <File size={48} />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">{file.name}</h3>

              <FileMetaCard file={file} />

              {isLoading ? (
                <ScanProgressBar stage={currentStage} progress={scanProgress} />
              ) : (
                <div className="flex flex-col gap-3 w-full">
                  {!isMemoryDump(file.name) ? (
                    <>
                      <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl">
                        <p className="text-red-400 text-xs font-bold uppercase tracking-widest text-center">
                          Unsupported file format.
                        </p>
                        <p className="text-red-400/60 text-[10px] text-center mt-1 uppercase tracking-widest">
                          Supported: .vmem · .raw · .mem · .img · .dmp · .pdf
                        </p>
                      </div>
                      <button onClick={handleReset}
                        className="w-full px-6 py-4 rounded-xl font-bold text-gray-400 bg-white/5 hover:text-white hover:bg-white/10 transition">
                        Choose Another File
                      </button>
                    </>
                  ) : (
                    <div className="flex gap-3 w-full">
                      <button onClick={handleReset}
                        className="flex-1 px-6 py-4 rounded-xl font-bold text-gray-400 bg-white/5 hover:text-white hover:bg-white/10 transition">
                        Cancel
                      </button>
                      <button onClick={handleUpload}
                        className="flex-[2] flex items-center justify-center gap-2 px-8 py-4 rounded-xl font-bold text-white transition shadow-[0_0_30px_rgba(34,211,238,0.4)] bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 cursor-pointer">
                        <Search size={20} /> {getFileExt(file.name) === 'pdf' ? 'Launch Document Inspection' : 'Launch Memory Forensics'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center cursor-pointer group" onClick={() => fileInputRef.current?.click()}>
              <div className="w-24 h-24 bg-cyan-500/10 text-cyan-400 rounded-full flex items-center justify-center mb-6 shadow-[0_0_40px_rgba(34,211,238,0.15)] group-hover:scale-110 group-hover:bg-cyan-500/20 transition-all duration-500">
                <UploadCloud size={48} />
              </div>
              <h3 className="text-3xl font-bold text-white mb-3">Drag &amp; Drop Memory Dump / PDF Report</h3>
              <p className="text-gray-400 mb-2 max-w-md text-sm">
                Supported formats: <span className="text-cyan-400 font-mono font-bold">.vmem · .raw · .mem · .img · .dmp · .pdf</span>
              </p>
              <p className="text-gray-600 text-xs mb-6 max-w-md text-center">
                Automated OS detection, Volatility 3 kernel profiling, and PDF document triage engine.
              </p>
              <button className="bg-white/5 border border-white/10 group-hover:border-cyan-500/50 group-hover:bg-white/10 text-white px-8 py-3 rounded-xl font-bold transition-all">
                Browse Files
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Error Message ────────────────────────────────────────────────── */}
      {message && !analysisData && !isLoading && (
        <div className={`rounded-2xl p-6 mb-8 border ${
          isError
            ? "bg-red-500/10 border-red-500/20"
            : "bg-green-500/10 border-green-500/20"
        }`}>
          <div className="flex items-start gap-4">
            {isError
              ? <AlertTriangle size={24} className="text-red-400 shrink-0 mt-0.5" />
              : <CheckCircle size={24} className="text-green-400 shrink-0" />}
            <div className="flex-1">
              <p className={`font-black uppercase tracking-widest text-sm mb-2 ${isError ? "text-red-400" : "text-green-400"}`}>
                {isError ? "Analysis Failed" : "Success"}
              </p>
              <p className={`text-sm leading-relaxed whitespace-pre-line ${isError ? "text-red-300/80" : "text-green-300/80"}`}>
                {message}
              </p>
            </div>
          </div>
          <button onClick={handleReset}
            className="mt-4 w-full bg-white/5 border border-white/10 hover:bg-white/10 text-white py-3 rounded-xl font-bold text-xs uppercase tracking-widest transition cursor-pointer">
            Upload Another File
          </button>
        </div>
      )}

      {/* ── Analysis Results ─────────────────────────────────────────────── */}
      {analysisData && analysis && (
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">

          {/* New scan button */}
          <div className="flex justify-end mb-6">
            <button onClick={handleReset}
              className="flex items-center gap-2 text-xs font-black uppercase tracking-widest text-gray-400 hover:text-cyan-400 bg-white/5 hover:bg-white/10 border border-white/10 px-5 py-2.5 rounded-xl transition cursor-pointer">
              <UploadCloud size={14} /> New Scan
            </button>
          </div>

          {/* Score + Summary card */}
          <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-8 mb-8">
            <div className="flex flex-col lg:flex-row gap-8 items-start">

              {/* Threat score */}
              <div className="flex flex-col items-center shrink-0">
                <div className={`w-32 h-32 rounded-full flex flex-col items-center justify-center border-4 shadow-2xl ${
                  analysis.severity === "CRITICAL"
                    ? "border-red-500 shadow-red-500/30"
                    : analysis.severity === "HIGH"
                    ? "border-orange-500 shadow-orange-500/30"
                    : analysis.severity === "MEDIUM"
                    ? "border-yellow-500 shadow-yellow-500/30"
                    : "border-green-500 shadow-green-500/30"
                }`}>
                  <span className={`text-4xl font-black ${
                    analysis.severity === "CRITICAL" ? "text-red-400"
                      : analysis.severity === "HIGH" ? "text-orange-400"
                      : analysis.severity === "MEDIUM" ? "text-yellow-400"
                      : "text-green-400"
                  }`}>{analysis.threat_score}</span>
                  <span className="text-xs text-gray-500 font-bold">/100</span>
                </div>
                <p className="text-[10px] text-gray-500 font-black uppercase tracking-widest mt-3">Threat Score</p>
                <div className={`mt-2 inline-block px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest ${
                  analysis.severity === "CRITICAL" ? "bg-red-500/20 text-red-400 border border-red-500/50"
                    : analysis.severity === "HIGH" ? "bg-orange-500/20 text-orange-400 border border-orange-500/50"
                    : analysis.severity === "MEDIUM" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/50"
                    : "bg-green-500/20 text-green-400 border border-green-500/50"
                }`}>
                  {analysis.severity} RISK
                </div>
              </div>

              {/* Meta + Summary */}
              <div className="flex-1">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
                  {[
                    { label: "SHA-256 Hash",  value: analysis.file_hash ? `${analysis.file_hash.slice(0, 12)}...` : "N/A" },
                    { label: "Detected OS",   value: (analysis.detected_os || "Windows").toUpperCase() },
                    { label: "Architecture",  value: analysis.architecture || "x64" },
                    { label: "File Type",     value: analysis.file_type_label || getFileTypeLabel(file?.name || "") },
                    { label: "File Size",     value: `${analysis.file_size_mb || "?"} MB` },
                    { label: "Analysis Mode", value: (analysis.analysis_mode || "VOLATILITY").toUpperCase() },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-black/20 p-3 rounded-xl">
                      <p className="text-[9px] text-gray-500 font-black uppercase tracking-widest mb-1">{label}</p>
                      <p className="text-white text-xs font-mono font-bold truncate" title={value}>{value}</p>
                    </div>
                  ))}
                </div>
                <div className="bg-black/20 p-4 rounded-xl border-l-2 border-cyan-500">
                  <p className="text-[9px] text-cyan-400 font-black uppercase tracking-widest mb-2 flex items-center gap-2">
                    <Zap size={10} /> AI Analyst Summary
                  </p>
                  <p className="text-gray-300 text-sm leading-relaxed">{analysis.forensic_summary}</p>
                </div>
              </div>
            </div>
          </div>

          {/* PDF Analysis Mode Special Sections */}
          {analysis.analysis_mode === "PDF Analysis Mode" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Key Findings */}
              <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
                <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                  <Search size={20} className="text-cyan-400" /> Key Findings &amp; Stream Analysis
                </h3>
                {analysis.key_findings?.length > 0 ? (
                  <ul className="space-y-3">
                    {analysis.key_findings.map((item, idx) => (
                      <li key={idx} className="bg-cyan-500/10 border border-cyan-500/20 px-4 py-3 rounded-xl text-sm text-cyan-200 font-mono">
                        &bull; {item}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">Structure inspection clean.</div>
                )}
              </div>

              {/* Risk Assessment */}
              <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
                <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                  <AlertTriangle size={20} className="text-yellow-400" /> Risk Assessment
                </h3>
                <div className="bg-black/40 border border-gray-800 p-4 rounded-xl text-sm text-gray-300 font-mono leading-relaxed mb-4">
                  {analysis.risk_assessment || "Standard document security baseline."}
                </div>
                {analysis.document_summary && (
                  <div className="bg-black/20 p-4 rounded-xl border-l-2 border-indigo-500 text-xs font-mono text-gray-400 max-h-36 overflow-y-auto">
                    <p className="text-[9px] text-indigo-400 font-black uppercase tracking-widest mb-1">Document Stream Sample</p>
                    {analysis.document_summary}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Forensic indicators grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

            {/* Malware Indicators */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <AlertTriangle size={20} className="text-red-500" /> Forensic Indicators
              </h3>
              {analysis.malware_indicators?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.malware_indicators.map((ind, idx) => (
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
              {analysis.suspicious_processes?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.suspicious_processes.map((proc, idx) => (
                    <li key={idx} className="bg-black/40 border border-gray-800 px-4 py-3 rounded-xl text-sm text-gray-300 font-mono flex items-center justify-between">
                      <div className="flex items-center">
                        <span className="w-2 h-2 bg-orange-500 rounded-full mr-3 shadow-[0_0_8px_rgba(249,115,22,0.8)]" />
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

            {/* Hidden / DKOM Processes */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <EyeOff size={20} className="text-purple-400" /> Unlinked / Hidden Processes
              </h3>
              {analysis.hidden_processes?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.hidden_processes.map((proc, idx) => (
                    <li key={idx} className="bg-purple-500/10 border border-purple-500/20 px-4 py-3 rounded-xl text-sm text-purple-200 font-mono flex items-center justify-between">
                      <div className="flex items-center">
                        <span className="w-2 h-2 bg-purple-500 rounded-full mr-3 shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
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
              {analysis.network_connections?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.network_connections.map((conn, idx) => (
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
                <Code size={20} className="text-yellow-400" /> Injected DLLs / Malfind
              </h3>
              {analysis.dll_injections?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.dll_injections.map((dll, idx) => (
                    <li key={idx} className="bg-yellow-500/10 border border-yellow-500/20 px-4 py-3 rounded-xl text-sm text-yellow-200 font-mono break-all">
                      {dll}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-gray-500 bg-black/20 p-4 rounded-xl text-center text-sm font-mono">No code injection detected.</div>
              )}
            </div>

            {/* Registry Anomalies */}
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Database size={20} className="text-blue-400" /> Registry Persistence
              </h3>
              {analysis.registry_anomalies?.length > 0 ? (
                <ul className="space-y-3">
                  {analysis.registry_anomalies.map((reg, idx) => (
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

          {/* IOC List */}
          {analysis.ioc_list?.length > 0 && (
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6 mb-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <List size={20} className="text-red-400" /> Indicators of Compromise (IOC)
              </h3>
              <div className="flex flex-wrap gap-2">
                {analysis.ioc_list.map((ioc, idx) => (
                  <span key={idx} className="bg-red-500/10 border border-red-500/20 text-red-300 text-xs font-mono px-3 py-1.5 rounded-lg">
                    {ioc}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Timeline */}
          {analysis.timeline?.length > 0 && (
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6 mb-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Clock size={20} className="text-indigo-400" /> Forensic Event Timeline
              </h3>
              <div className="space-y-3">
                {analysis.timeline.map((entry, idx) => (
                  <div key={idx} className="flex gap-4 items-start bg-black/20 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 font-mono shrink-0 mt-0.5">
                      {typeof entry === "object" ? entry.timestamp?.slice(11, 19) : ""}
                    </span>
                    <span className="text-sm text-gray-300 font-mono">
                      {typeof entry === "object" ? entry.event : entry}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {analysis.recommendations?.length > 0 && (
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-6 mb-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-3">
                <Zap size={20} className="text-cyan-400" /> Action Plan &amp; Recommendations
              </h3>
              <ul className="space-y-3">
                {analysis.recommendations.map((rec, idx) => (
                  <li key={idx} className="bg-black/40 border border-gray-800 px-4 py-3 rounded-xl text-sm text-gray-300 font-mono flex items-center gap-3">
                    <span className="w-2 h-2 bg-cyan-400 rounded-full shrink-0" />
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Download Report */}
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
