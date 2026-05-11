import { Activity, HardDrive, ShieldAlert, Cpu } from "lucide-react";
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar, Legend
} from "recharts";

const activityData = [
  { day: "Mon", threats: 8, resolved: 6 },
  { day: "Tue", threats: 12, resolved: 9 },
  { day: "Wed", threats: 7, resolved: 5 },
  { day: "Thu", threats: 18, resolved: 14 },
  { day: "Fri", threats: 10, resolved: 8 },
  { day: "Sat", threats: 4, resolved: 3 },
  { day: "Sun", threats: 6, resolved: 5 },
];

const distributionData = [
  { name: "Trojans", value: 35 },
  { name: "Spyware", value: 25 },
  { name: "Rootkits", value: 20 },
  { name: "Worms", value: 20 },
];

const COLORS = ['#ef4444', '#f97316', '#22d3ee', '#8b5cf6'];

const trendData = [
  { name: 'Week 1', Critical: 4, High: 10, Medium: 20 },
  { name: 'Week 2', Critical: 2, High: 8, Medium: 15 },
  { name: 'Week 3', Critical: 7, High: 14, Medium: 25 },
  { name: 'Week 4', Critical: 1, High: 5, Medium: 12 },
];

export default function Dashboard() {
  const stats = [
    { title: "Total Dumps Analyzed", value: "1,284", icon: <HardDrive size={24} className="text-cyan-400" />, trend: "+5.2%" },
    { title: "Critical Threats Found", value: "37", icon: <ShieldAlert size={24} className="text-red-400" />, trend: "-12%" },
    { title: "System Health Score", value: "96%", icon: <Activity size={24} className="text-green-400" />, trend: "+0.5%" },
    { title: "Active Nodes", value: "12", icon: <Cpu size={24} className="text-indigo-400" />, trend: "0%" },
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
              <span className={`text-sm font-semibold ${stat.trend.startsWith('+') ? 'text-green-400' : stat.trend.startsWith('-') ? 'text-red-400' : 'text-gray-400'}`}>
                {stat.trend}
              </span>
            </div>
            <h3 className="text-gray-400 text-sm font-medium mb-1">{stat.title}</h3>
            <div className="text-3xl font-bold text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Line Chart */}
        <div className="lg:col-span-2 bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
          <h2 className="text-xl font-bold text-white mb-6">Threat Activity Overview</h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="day" stroke="#ffffff50" axisLine={false} tickLine={false} />
                <YAxis stroke="#ffffff50" axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px' }} itemStyle={{ color: '#fff' }} />
                <Legend />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorThreats)" />
                <Area type="monotone" dataKey="resolved" stroke="#22d3ee" strokeWidth={3} fillOpacity={1} fill="url(#colorScans)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pie Chart */}
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl">
          <h2 className="text-xl font-bold text-white mb-6">Threat Distribution</h2>
          <div className="h-[300px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distributionData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {distributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: 'none', borderRadius: '8px' }} />
                <Legend verticalAlign="bottom" height={36} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bar Chart */}
        <div className="lg:col-span-3 bg-white/[0.03] backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-xl mb-10">
          <h2 className="text-xl font-bold text-white mb-6">Severity Trends (Past 4 Weeks)</h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trendData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="name" stroke="#ffffff50" axisLine={false} tickLine={false} />
                <YAxis stroke="#ffffff50" axisLine={false} tickLine={false} />
                <Tooltip cursor={{fill: '#ffffff05'}} contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px' }} />
                <Legend />
                <Bar dataKey="Critical" stackId="a" fill="#ef4444" radius={[0, 0, 4, 4]} />
                <Bar dataKey="High" stackId="a" fill="#f97316" />
                <Bar dataKey="Medium" stackId="a" fill="#eab308" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live SOC Metrics */}
      <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl flex items-center justify-between">
          <div>
            <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">Last Scan</p>
            <p className="text-white font-mono font-bold">2 mins ago</p>
          </div>
          <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_10px_rgba(34,197,94,0.5)]"></div>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">IOCs Detected</p>
          <p className="text-white font-mono font-bold text-xl">14</p>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">High Severity Alerts</p>
          <p className="text-red-400 font-mono font-bold text-xl">3</p>
        </div>
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/10 p-5 rounded-2xl">
          <p className="text-gray-400 text-xs uppercase tracking-widest font-bold mb-1">Processes Analyzed</p>
          <p className="text-cyan-400 font-mono font-bold text-xl">412</p>
        </div>
      </div>
    </div>
  );
}
