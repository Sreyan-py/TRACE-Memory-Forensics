import { ShieldAlert, Lock, Zap, Search, ShieldCheck } from "lucide-react";

export default function Quarantine() {
  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
       <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert size={14} className="text-red-500" />
            <span className="text-[10px] text-red-500 uppercase font-black tracking-[0.4em]">Vault & Isolation</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Quarantine</h1>
        </div>
      </div>
      
      <div className="bg-red-500/10 border border-red-500/20 p-20 rounded-3xl text-center border-dashed">
         <Lock size={64} className="mx-auto text-red-500 mb-8 animate-bounce" />
         <h2 className="text-3xl font-black text-white uppercase tracking-widest mb-4">Isolation Chamber Empty</h2>
         <p className="text-gray-500 max-w-lg mx-auto font-mono text-sm leading-relaxed">No high-risk artifacts currently residing in the isolation vault. All system nodes reporting within safe operational parameters.</p>
         <button className="mt-10 px-8 py-3 bg-red-500 text-white rounded-xl font-black text-xs uppercase tracking-widest shadow-[0_0_20px_rgba(239,68,68,0.3)]">Emergency Lockout</button>
      </div>
    </div>
  );
}
