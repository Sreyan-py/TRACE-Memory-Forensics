import { NavLink, Outlet } from "react-router-dom";
import { Shield, LayoutDashboard, Search, User, LogOut } from "lucide-react";

export default function Layout({ user, onLogout }) {
  const navItems = [
    { name: "Dashboard", path: "/", icon: <LayoutDashboard size={20} /> },
    { name: "Analysis", path: "/analysis", icon: <Search size={20} /> },
    { name: "Profile", path: "/profile", icon: <User size={20} /> },
  ];

  return (
    <div className="flex h-screen bg-[#06080e] text-white overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0b1020] border-r border-gray-800 flex flex-col z-20 shadow-2xl relative">
        <div className="p-6 flex items-center gap-3 border-b border-gray-800">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-[0_0_15px_rgba(34,211,238,0.4)]">
            <Shield className="text-white" size={24} />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">TRACE</h1>
            <p className="text-[10px] text-cyan-500 uppercase tracking-widest font-semibold mt-0.5">Forensics Core</p>
          </div>
        </div>

        <nav className="flex-1 py-8 px-4 space-y-2">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                  isActive
                    ? "bg-gradient-to-r from-cyan-500/20 to-transparent text-cyan-400 border-l-2 border-cyan-400 shadow-[inset_4px_0_0_0_rgba(34,211,238,1)]"
                    : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
                }`
              }
            >
              {item.icon}
              <span className="font-medium">{item.name}</span>
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <div className="mb-4 px-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest font-bold">Active Agent</p>
            <p className="text-cyan-400 font-mono text-sm truncate">{user}</p>
          </div>
          <button 
            onClick={onLogout}
            className="flex items-center gap-3 px-4 py-3 w-full text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-colors"
          >
            <LogOut size={20} />
            <span className="font-medium">End Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 relative overflow-y-auto">
        {/* Decorative background glow */}
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none"></div>
        <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none"></div>
        
        <div className="relative z-10 w-full h-full">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
