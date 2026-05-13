import { Activity, HardDrive, ShieldAlert, Cpu } from "lucide-react";
import { useState, useEffect } from "react";
import axios from "axios";
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  Legend
} from "recharts";

const COLORS = ['#ef4444', '#f97316', '#22d3ee', '#8b5cf6'];

export default function Dashboard() {
  const [statsData, setStatsData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const username = localStorage.getItem("trace_user");

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get(`http://127.0.0.1:5001/dashboard/stats/${username}`);
        setStatsData(response.data);
      } catch (err) {
        setError("Failed to load dashboard data. Ensure the backend is running.");
      } finally {
        setIsLoading(false);
      }
    };

    if (username) {
      fetchStats();
    }
  }, [username]);

  if (isLoading) {
    return <div className="p-10 max-w-7xl mx-auto text-white flex items-center justify-center min-h-[50vh] font-mono tracking-widest animate-pulse">Initializing Interface...</div>;
  }

  if (error) {
    return <div className="p-10 max-w-7xl mx-auto text-red-500 font-bold bg-red-500/10 border border-red-500/20 rounded-xl mt-10 p-6">{error}</div>;
  }

  const { total_dumps, critical_threats, health_score, distribution_data, activity_data } = statsData;

  const stats = [
    { title: "Total Dumps Analyzed", value: total_dumps, icon: <HardDrive size={24} className="text-cyan-400" />, trend: "Active" },
    { title: "Critical Threats Found", value: critical_threats, icon: <ShieldAlert size={24} className="text-red-400" />, trend: "Tracked" },
    { title: "System Health Score", value: health_score, icon: <Activity size={24} className="text-green-400" />, trend: "Real-time" },
    { title: "Active Nodes", value: "1", icon: <Cpu size={24} className="text-indigo-400" />, trend: "Local" },
  ];

  return (
    <div className="p-10 max-w-7xl mx-auto">
      <header className="mb-10">
        <h1 className="text-4xl font-bold text-white mb-2">SOC Command Center</h1>
        <p className="text-gray-400">Enterprise Memory Forensics Overview & Threat Intelligence.</p>
      </header>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-10">
        {stats.map((stat, idx) => (
          <div key={idx} className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-6 rounded-2xl shadow-xl transition-all hover:bg-white/[0.05] hover:border-white/20">
            <div className="flex justify-between items-start mb-4">
              <div className="p-3 bg-white/5 rounded-xl">
                {stat.icon}
              </div>
              <span className="text-sm font-semibold text-gray-400">
                {stat.trend}
              </span>
            </div>
            <h3 className="text-gray-400 text-sm font-medium mb-1">{stat.title}</h3>
            <div className="text-3xl font-bold text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Line Chart - Activity */}
        <div className="lg:col-span-2 bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
          <h2 className="text-xl font-bold text-white mb-6">Recent Analysis Activity</h2>
          <div className="h-[300px] w-full">
            {activity_data && activity_data.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activity_data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                  <XAxis dataKey="name" stroke="#ffffff50" axisLine={false} tickLine={false} />
                  <YAxis stroke="#ffffff50" axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px' }} itemStyle={{ color: '#fff' }} />
                  <Legend />
                  <Area type="monotone" name="Threat Score" dataKey="score" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorThreats)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500 font-mono">No recent activity found. Execute a scan.</div>
            )}
          </div>
        </div>

        {/* Pie Chart */}
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
          <h2 className="text-xl font-bold text-white mb-6">Threat Distribution</h2>
          <div className="h-[300px] w-full flex items-center justify-center">
            {distribution_data && distribution_data.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distribution_data}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {distribution_data.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: 'none', borderRadius: '8px' }} />
                  <Legend verticalAlign="bottom" height={36} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500 font-mono">No data available.</div>
            )}
          </div>
        </div>
      </div>

      {/* Live SOC Metrics */}
      <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">Agent Status</p>
            <p className="text-white font-mono font-bold">{username}</p>
          </div>
          <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(34,197,94,0.5)]"></div>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">Database Sync</p>
          <p className="text-white font-mono font-bold text-xl">Online</p>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">High Severity Alerts</p>
          <p className="text-red-400 font-mono font-bold text-xl">{critical_threats}</p>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">Forensic Engine</p>
          <p className="text-cyan-400 font-mono font-bold text-xl">Volatility3</p>
        </div>
      </div>
    </div>
  );
}
