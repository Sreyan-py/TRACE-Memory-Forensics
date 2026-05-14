import { Database, Search, Filter, Shield, Zap } from "lucide-react";

export default function IOCExplorer() {
  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
       <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Database size={14} className="text-blue-500" />
            <span className="text-[10px] text-blue-500 uppercase font-black tracking-[0.4em]">Indicator Database</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">IOC Explorer</h1>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
         {[1,2,3].map(i => (
           <div key={i} className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-8 rounded-3xl animate-pulse">
              <div className="w-12 h-12 bg-white/5 rounded-2xl mb-6"></div>
              <div className="h-4 bg-white/5 rounded w-3/4 mb-2"></div>
              <div className="h-4 bg-white/5 rounded w-1/2"></div>
           </div>
         ))}
      </div>
      <div className="bg-cyan-500/5 border border-cyan-500/10 p-10 rounded-3xl text-center">
         <Shield size={48} className="mx-auto text-cyan-500/50 mb-4" />
         <p className="text-cyan-500 font-mono text-sm uppercase tracking-widest font-bold">Synchronizing with global malware repositories...</p>
      </div>
    </div>
  );
}
