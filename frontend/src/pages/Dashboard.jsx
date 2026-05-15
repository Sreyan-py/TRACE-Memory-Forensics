import { Activity, HardDrive, ShieldAlert, Cpu, Zap, Search, Clock, Target, Database, Globe, ArrowUpRight, TrendingUp } from "lucide-react";
import { useState, useEffect } from "react";
import axios from "axios";
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  BarChart, Bar, Cell
} from "recharts";

import { dashboardApi } from "../services/api";

export default function Dashboard() {
  const [statsData, setStatsData] = useState(null);
  const [activities, setActivities] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const username = localStorage.getItem("trace_user");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, activityRes] = await Promise.all([
          dashboardApi.getStats(username),
          dashboardApi.getActivities(username)
        ]);
        if (statsRes.success) setStatsData(statsRes.data);
        if (activityRes.success) setActivities(activityRes.data);
      } catch (err) {
        setError(err.message || "Failed to synchronize with SOC telemetry feed.");
      } finally {
        setIsLoading(false);
      }
    };
    if (username) fetchData();
  }, [username]);

  if (isLoading) return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-cyber-cyan font-mono tracking-widest gap-4">
      <div className="w-16 h-16 border-4 border-cyber-cyan/20 border-t-cyber-cyan rounded-full animate-spin shadow-[0_0_20px_rgba(34,211,238,0.3)]"></div>
      <p className="animate-pulse">SYNCHRONIZING NEURAL LINK...</p>
    </div>
  );

  if (error || !statsData) return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-cyber-red font-mono p-8 text-center">
      <ShieldAlert size={48} className="mb-4 animate-bounce" />
      <h2 className="text-2xl font-black uppercase tracking-tighter italic">Connection Terminated</h2>
      <p className="text-xs text-gray-500 mt-2 max-w-md">The secure telemetry tunnel was closed. Re-establish local link protocol.</p>
    </div>
  );

  const { total_dumps, critical_threats, health_score, distribution_data, activity_data } = statsData;

  const mainStats = [
    { title: "Analysis Throughput", value: total_dumps, sub: "Total Images", icon: <HardDrive size={20} />, color: "text-cyber-cyan", bg: "bg-cyber-cyan/10" },
    { title: "Critical Breaches", value: critical_threats, sub: "L5 Alerts", icon: <ShieldAlert size={20} />, color: "text-cyber-red", bg: "bg-cyber-red/10" },
    { title: "System Resilience", value: health_score + "%", sub: "Score Delta", icon: <Activity size={20} />, color: "text-cyber-green", bg: "bg-cyber-green/10" },
    { title: "Active Intel", value: "1.2k", sub: "Global IOCs", icon: <Database size={20} />, color: "text-cyber-purple", bg: "bg-cyber-purple/10" },
  ];

  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-8 animate-in fade-in duration-700">
      {/* Dashboard Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8 relative overflow-hidden">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Zap size={14} className="text-cyber-cyan animate-pulse" />
            <span className="text-[10px] text-cyber-cyan uppercase font-black tracking-[0.4em]">Operations Overview</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Analyst Terminal</h1>
        </div>
        <div className="flex gap-4">
          <div className="bg-white/5 border border-white/5 p-4 rounded-2xl flex items-center gap-4">
            <div className="text-right">
              <p className="text-[10px] text-gray-500 font-black uppercase">Session Health</p>
              <p className="text-cyber-green font-mono font-bold">STABLE</p>
            </div>
            <div className="w-10 h-10 rounded-full border-2 border-cyber-green/20 border-t-cyber-green animate-spin-slow"></div>
          </div>
        </div>
      </div>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {mainStats.map((stat, i) => (
          <div key={i} className="bg-[#0b1020]/40 backdrop-blur-xl border border-white/5 p-6 rounded-3xl group hover:border-cyber-cyan/30 transition-all duration-500 relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
              {stat.icon}
            </div>
            <div className={`${stat.bg} ${stat.color} w-10 h-10 rounded-xl flex items-center justify-center mb-4 border border-white/5`}>
              {stat.icon}
            </div>
            <p className="text-xs text-gray-500 font-black uppercase tracking-widest mb-1">{stat.title}</p>
            <div className="flex items-baseline gap-2">
              <h3 className="text-3xl font-black text-white">{stat.value}</h3>
              <span className="text-[10px] text-gray-600 font-bold uppercase">{stat.sub}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Primary Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Global Threat Pulse */}
        <div className="lg:col-span-8 bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-cyber-cyan/5 blur-3xl rounded-full"></div>
          <div className="flex justify-between items-center mb-10">
            <div>
              <h3 className="text-xl font-black text-white uppercase tracking-widest flex items-center gap-2">
                <Globe size={20} className="text-cyber-cyan" /> Global Threat Pulse
              </h3>
              <p className="text-xs text-gray-500 font-mono mt-1">Real-time heuristic anomaly detection</p>
            </div>
            <div className="flex gap-2">
              <button className="bg-cyber-cyan/10 text-cyber-cyan text-[10px] px-4 py-2 rounded-full font-black uppercase border border-cyber-cyan/20">LIVE</button>
            </div>
          </div>
          <div className="h-[350px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activity_data}>
                <defs>
                  <linearGradient id="colorPulse" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                <XAxis dataKey="time" hide />
                <YAxis hide />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#02040a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '16px' }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Area type="monotone" dataKey="value" stroke="#22d3ee" strokeWidth={4} fillOpacity={1} fill="url(#colorPulse)" animationDuration={2000} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Radar */}
        <div className="lg:col-span-4 bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
            <Target size={20} className="text-cyber-red" /> Severity Radar
          </h3>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="80%" data={distribution_data}>
                <PolarGrid stroke="#ffffff10" />
                <PolarAngleAxis dataKey="name" stroke="#666" fontSize={10} tick={{ fill: '#666', fontWeight: 'bold' }} />
                <Radar name="Threats" dataKey="value" stroke="#ef4444" fill="#ef4444" fillOpacity={0.5} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-8 space-y-4">
            {distribution_data.map((item, i) => (
              <div key={i} className="flex justify-between items-center text-xs">
                <span className="text-gray-500 font-bold uppercase tracking-widest">{item.name}</span>
                <span className="text-white font-mono">{item.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Secondary Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Live Activity Feed */}
        <div className="lg:col-span-1 bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl h-[450px] flex flex-col">
          <h3 className="text-sm font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
            <Clock size={18} className="text-cyber-purple" /> Active Pipeline
          </h3>
          <div className="flex-1 overflow-y-auto custom-scrollbar space-y-6 pr-4">
            {activities.length > 0 ? activities.map((log, i) => (
              <div key={i} className="flex gap-4 group cursor-default">
                <div className="flex flex-col items-center">
                  <div className={`w-2 h-2 rounded-full mt-1.5 shadow-[0_0_8px] transition-all duration-300 ${
                    log.type === 'threat' ? 'bg-cyber-red shadow-cyber-red/50' : 
                    log.type === 'auth' ? 'bg-cyber-green shadow-cyber-green/50' : 
                    'bg-cyber-cyan shadow-cyber-cyan/50'
                  }`}></div>
                  <div className="w-[1px] flex-1 bg-white/5 my-2"></div>
                </div>
                <div>
                  <p className="text-[8px] text-gray-600 font-mono mb-1">{log.time}</p>
                  <p className="text-[11px] text-gray-400 group-hover:text-white transition-colors leading-relaxed font-bold uppercase tracking-tight">{log.msg}</p>
                </div>
              </div>
            )) : (
              <div className="text-center py-20 text-gray-600 font-black uppercase text-[10px] tracking-widest">Awaiting system events...</div>
            )}
          </div>
        </div>

        {/* Threat Distribution Chart */}
        <div className="lg:col-span-2 bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl h-[450px]">
          <div className="flex justify-between items-center mb-10">
            <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
              <TrendingUp size={18} className="text-cyber-green" /> Malware Family Distribution
            </h3>
            <span className="text-[10px] text-gray-600 font-mono">Real-time Metrics</span>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distribution_data}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#666', fontSize: 10, fontWeight: 'bold' }} />
                <YAxis hide />
                <Tooltip 
                   cursor={{ fill: '#ffffff05' }}
                   contentStyle={{ backgroundColor: '#02040a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }}
                />
                <Bar dataKey="value" radius={[8, 8, 0, 0]} animationDuration={1500}>
                  {distribution_data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={index % 2 === 0 ? '#22d3ee' : '#a855f7'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
