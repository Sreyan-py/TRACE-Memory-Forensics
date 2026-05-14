import { Activity, Zap, Cpu, Search, Database } from "lucide-react";

export default function LiveMonitoring() {
  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Activity size={14} className="text-green-500 animate-pulse" />
            <span className="text-[10px] text-green-500 uppercase font-black tracking-[0.4em]">Real-time Telemetry Stream</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Live Monitoring</h1>
        </div>
      </div>
      <div className="bg-[#0b1020]/40 backdrop-blur-xl border border-cyan-500/10 p-12 rounded-3xl text-center border-dashed">
        <Cpu size={48} className="mx-auto text-cyan-400 mb-6 animate-spin-slow" />
        <h2 className="text-2xl font-black text-white uppercase tracking-widest mb-4">Establishing Secure Stream</h2>
        <p className="text-gray-500 max-w-md mx-auto font-mono text-sm">Deploying TRACE agents to monitored endpoints. Expecting incoming telemetry in T-minus 10s.</p>
        <div className="mt-8 flex justify-center gap-2">
          {[1,2,3,4].map(i => <div key={i} className="w-2 h-8 bg-cyan-500/20 rounded-full animate-bounce" style={{ animationDelay: `${i*0.2}s` }}></div>)}
        </div>
      </div>
    </div>
  );
}
