import { NavLink, Outlet } from "react-router-dom";
import { 
  Shield, LayoutDashboard, Search, User, LogOut, Activity, Database, 
  Globe, FlaskConical, History, ShieldAlert, Settings, ChevronLeft, 
  ChevronRight, Zap, FileText, Lock
} from "lucide-react";
import { useState } from "react";

export default function Layout({ user, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { section: "Operational", items: [
      { name: "Dashboard", path: "/", icon: <LayoutDashboard size={20} /> },
      { name: "Deep Analysis", path: "/analysis", icon: <Search size={20} /> },
    ]},
    { section: "Intelligence", items: [
      { name: "Threat Intel", path: "/intel", icon: <Globe size={20} /> },
      { name: "Malware Lab", path: "/lab", icon: <FlaskConical size={20} /> },
      { name: "Live Monitoring", path: "/monitoring", icon: <Activity size={20} /> },
      { name: "IOC Explorer", path: "/ioc", icon: <Database size={20} /> },
    ]},
    { section: "Archives", items: [
      { name: "Threat Reports", path: "/reports", icon: <FileText size={20} /> },
      { name: "Scan History", path: "/history", icon: <History size={20} /> },
      { name: "Quarantine", path: "/quarantine", icon: <ShieldAlert size={20} /> },
    ]},
    { section: "Identity", items: [
      { name: "Profile", path: "/profile", icon: <User size={20} /> },
      { name: "Settings", path: "/settings", icon: <Settings size={20} /> },
    ]}
  ];

  return (
    <div className="flex h-screen bg-void-black text-white overflow-hidden font-sans cyber-grid">
      {/* Sidebar */}
      <aside 
        className={`${collapsed ? "w-20" : "w-72"} bg-[#0b1020]/60 backdrop-blur-3xl border-r border-white/5 flex flex-col z-50 transition-all duration-500 ease-in-out relative group`}
      >
        {/* Toggle Button */}
        <button 
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-24 w-6 h-12 bg-cyber-cyan rounded-md flex items-center justify-center text-black hover:bg-white transition-all shadow-[0_0_20px_rgba(34,211,238,0.4)] z-50 cursor-pointer"
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>

        {/* Logo Section */}
        <div className={`p-8 mb-4 flex items-center gap-4 ${collapsed ? "justify-center" : ""}`}>
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyber-cyan to-cyber-blue flex items-center justify-center shadow-[0_0_25px_rgba(34,211,238,0.4)] relative z-10 animate-cyber-pulse">
              <Shield className="text-white" size={24} />
            </div>
            <div className="absolute inset-0 bg-cyber-cyan/20 blur-xl rounded-full animate-pulse"></div>
          </div>
          {!collapsed && (
            <div className="animate-in fade-in slide-in-from-left-4 duration-500">
              <h1 className="text-xl font-black tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan to-white">TRACE</h1>
              <p className="text-[8px] text-cyber-cyan/60 uppercase tracking-[0.4em] font-black mt-0.5">Forensics Core</p>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 space-y-8 overflow-y-auto custom-scrollbar">
          {navItems.map((group) => (
            <div key={group.section} className="space-y-2">
              {!collapsed && (
                <p className="text-[10px] text-gray-600 uppercase tracking-[0.3em] font-black px-4 mb-4">{group.section}</p>
              )}
              {group.items.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-4 px-4 py-3 rounded-2xl transition-all duration-300 relative group/item ${
                      isActive
                        ? "bg-cyber-cyan/10 text-cyber-cyan"
                        : "text-gray-500 hover:text-white hover:bg-white/5"
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <div className={`relative z-10 transition-transform duration-300 group-hover/item:scale-110 ${isActive ? "glow-cyan" : ""}`}>
                        {item.icon}
                      </div>
                      {!collapsed && (
                        <span className="font-bold text-sm tracking-tight relative z-10">{item.name}</span>
                      )}
                      {isActive && (
                        <div className="absolute left-0 w-1 h-6 bg-cyber-cyan rounded-r-full shadow-[0_0_15px_rgba(34,211,238,0.6)]" />
                      )}
                      {isActive && !collapsed && (
                        <div className="absolute inset-0 bg-gradient-to-r from-cyber-cyan/5 to-transparent rounded-2xl" />
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* User Profile / Status */}
        <div className="p-6 border-t border-white/5 bg-black/40">
          {!collapsed ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-3 rounded-2xl bg-white/5 border border-white/5 relative overflow-hidden group/profile">
                <div className="absolute inset-0 bg-gradient-to-r from-cyber-cyan/5 to-transparent opacity-0 group-hover/profile:opacity-100 transition-opacity"></div>
                <div className="w-10 h-10 rounded-xl bg-cyber-cyan/10 flex items-center justify-center border border-cyber-cyan/20 relative z-10">
                  <User size={18} className="text-cyber-cyan" />
                </div>
                <div className="overflow-hidden relative z-10">
                  <p className="text-[10px] text-gray-500 uppercase font-black tracking-widest">Analyst-L5</p>
                  <p className="text-white font-bold text-xs truncate">{user}</p>
                </div>
              </div>
              <button 
                onClick={onLogout}
                className="flex items-center gap-3 px-4 py-3 w-full text-gray-500 hover:text-cyber-red hover:bg-cyber-red/10 rounded-xl transition-all duration-300 group/logout cursor-pointer"
              >
                <LogOut size={18} className="group-hover/logout:-translate-x-1 transition-transform" />
                <span className="font-black text-xs uppercase tracking-widest">End Session</span>
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-6">
              <div className="w-10 h-10 rounded-xl bg-cyber-cyan/10 flex items-center justify-center border border-cyber-cyan/20">
                <User size={18} className="text-cyber-cyan" />
              </div>
              <button 
                onClick={onLogout}
                className="w-10 h-10 flex items-center justify-center text-gray-500 hover:text-cyber-red hover:bg-cyber-red/10 rounded-xl transition-all cursor-pointer"
              >
                <LogOut size={18} />
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 relative overflow-y-auto custom-scrollbar">
        {/* Background glow effects */}
        <div className="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-cyan/10 rounded-full blur-[120px] pointer-events-none"></div>
        <div className="fixed bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-cyber-purple/10 rounded-full blur-[100px] pointer-events-none"></div>
        
        <div className="relative z-10 min-h-screen">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
