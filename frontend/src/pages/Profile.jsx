import { User, Shield, Target, Activity, Database, Globe, Calendar, Award, Zap, Edit3, Save, MapPin, Briefcase, ChevronRight } from "lucide-react";
import { useState, useEffect } from "react";
import { profileApi, getStoredUsername } from "../services/api";

export default function Profile() {
  const [profile, setProfile] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({});
  const [isLoading, setIsLoading] = useState(true);
  const username = getStoredUsername();

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const res = await profileApi.getProfile(username);
        if (res.success) {
          setProfile(res.data);
          setFormData(res.data);
        }
      } catch (err) {
        // Handle failure silently
      } finally {
        setIsLoading(false);
      }
    };
    if (username) fetchProfile();
  }, [username]);

  const handleUpdate = async () => {
    try {
      await profileApi.updateProfile({ ...formData, username });
      setProfile(formData);
      setIsEditing(false);
    } catch (err) {
      alert(err.message || "Failed to synchronize profile data.");
    }
  };

  if (isLoading || !profile) return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-cyber-cyan font-mono animate-pulse">
      DECRYPTING ANALYST DOSSIER...
    </div>
  );

  const getRankColor = (rank) => {
    if (rank?.includes("Elite")) return "text-cyber-purple border-cyber-purple/30 bg-cyber-purple/10";
    if (rank?.includes("Specialist")) return "text-cyber-red border-cyber-red/30 bg-cyber-red/10";
    if (rank?.includes("Hunter")) return "text-cyber-cyan border-cyber-cyan/30 bg-cyber-cyan/10";
    return "text-cyber-green border-cyber-green/30 bg-cyber-green/10";
  };

  const avatars = ["agent_1", "agent_2", "agent_3", "agent_4", "agent_5"];

  return (
    <div className="p-8 max-w-[1400px] mx-auto space-y-8 animate-in fade-in duration-700">
      {/* Profile Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/5 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Award size={14} className="text-cyber-purple animate-cyber-pulse" />
            <span className="text-[10px] text-cyber-purple uppercase font-black tracking-[0.4em]">Identity Synchronization</span>
          </div>
          <h1 className="text-5xl font-black text-white tracking-tighter uppercase italic">Analyst Terminal</h1>
        </div>
        <button 
          onClick={() => isEditing ? handleUpdate() : setIsEditing(true)}
          className={`flex items-center gap-3 px-8 py-3 rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(34,211,238,0.2)] ${
            isEditing ? "bg-cyber-green text-black hover:bg-white" : "bg-white/5 border border-white/10 text-white hover:bg-white/10"
          }`}
        >
          {isEditing ? <><Save size={16} /> Save Dossier</> : <><Edit3 size={16} /> Edit Identity</>}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Holographic Card */}
        <div className="lg:col-span-4 space-y-8">
          <div className="bg-[#0b1020]/40 backdrop-blur-3xl border border-white/5 rounded-3xl p-8 relative overflow-hidden group">
            {/* Visual Deco */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-cyber-cyan/5 blur-3xl rounded-full"></div>
            <div className="absolute bottom-0 left-0 w-24 h-24 bg-cyber-purple/5 blur-2xl rounded-full"></div>
            
            <div className="relative z-10 flex flex-col items-center text-center">
              <div className="relative mb-8 group/avatar cursor-pointer">
                <div className="w-40 h-40 rounded-3xl bg-gradient-to-br from-cyber-cyan to-cyber-blue p-1 shadow-[0_0_40px_rgba(34,211,238,0.3)] group-hover/avatar:scale-105 transition-transform duration-500">
                  <div className="w-full h-full bg-[#02040a] rounded-2xl flex items-center justify-center overflow-hidden">
                    <img 
                      src={`https://api.dicebear.com/7.x/bottts/svg?seed=${profile.avatar_preset}&backgroundColor=02040a`}
                      alt="Avatar"
                      className="w-full h-full opacity-80 group-hover:opacity-100 transition-opacity"
                    />
                  </div>
                </div>
                <div className="absolute -bottom-2 -right-2 bg-cyber-cyan text-black p-2 rounded-xl shadow-lg border-4 border-[#02040a]">
                  <Shield size={16} />
                </div>
              </div>

              {isEditing ? (
                <div className="w-full space-y-4">
                  <input 
                    type="text" 
                    value={formData.display_name} 
                    onChange={(e) => setFormData({...formData, display_name: e.target.value})}
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-center font-black uppercase text-lg outline-none focus:border-cyber-cyan transition-colors"
                  />
                  <div className="flex justify-center gap-2">
                    {avatars.map(a => (
                      <button 
                        key={a}
                        onClick={() => setFormData({...formData, avatar_preset: a})}
                        className={`w-10 h-10 rounded-lg border-2 transition-all ${formData.avatar_preset === a ? 'border-cyber-cyan bg-cyber-cyan/20' : 'border-white/5 bg-white/5'}`}
                      >
                        <img src={`https://api.dicebear.com/7.x/bottts/svg?seed=${a}`} className="w-full h-full opacity-60" />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <>
                  <h2 className="text-3xl font-black text-white uppercase italic tracking-tight mb-2">{profile.display_name}</h2>
                  <div className={`px-4 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border ${getRankColor(profile.rank)}`}>
                    {profile.rank}
                  </div>
                </>
              )}

              <div className="mt-8 pt-8 border-t border-white/5 w-full space-y-4 text-left">
                <div className="flex items-center gap-3 text-xs">
                  <Zap size={14} className="text-cyber-cyan" />
                  <span className="text-gray-500 font-bold uppercase w-24">Codename</span>
                  {isEditing ? (
                    <input 
                      type="text" 
                      value={formData.codename} 
                      onChange={(e) => setFormData({...formData, codename: e.target.value})}
                      className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-white font-mono"
                    />
                  ) : (
                    <span className="text-white font-mono">{profile.codename}</span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <MapPin size={14} className="text-cyber-cyan" />
                  <span className="text-gray-500 font-bold uppercase w-24">Location</span>
                  {isEditing ? (
                    <input 
                      type="text" 
                      value={formData.location} 
                      onChange={(e) => setFormData({...formData, location: e.target.value})}
                      className="flex-1 bg-white/5 border border-white/10 rounded px-2 py-1 text-white"
                    />
                  ) : (
                    <span className="text-white font-bold">{profile.location}</span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <Calendar size={14} className="text-cyber-cyan" />
                  <span className="text-gray-500 font-bold uppercase w-24">Enrolled</span>
                  <span className="text-white font-bold">{profile.joined_at}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-cyber-cyan/5 border border-cyber-cyan/10 p-6 rounded-3xl">
             <div className="flex items-center gap-3 mb-4">
               <Shield className="text-cyber-cyan" size={18} />
               <h3 className="text-[10px] font-black text-white uppercase tracking-widest">Analyst Clearance</h3>
             </div>
             <div className="space-y-4">
                <div className="flex justify-between items-center text-[10px] font-black uppercase">
                  <span className="text-gray-600 tracking-widest">Verification Status</span>
                  <span className="text-cyber-green">VERIFIED AGENT</span>
                </div>
                <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                   <div className="h-full bg-cyber-green w-[85%] animate-pulse"></div>
                </div>
             </div>
          </div>
        </div>

        {/* Right Column: Bio & Stats */}
        <div className="lg:col-span-8 space-y-8">
          <div className="bg-[#0b1020]/40 backdrop-blur-3xl border border-white/5 rounded-3xl p-8">
            <h3 className="text-sm font-black text-white uppercase tracking-widest mb-6 flex items-center gap-2">
              <Edit3 size={16} className="text-cyber-purple" /> Operational Mandate
            </h3>
            {isEditing ? (
              <textarea 
                value={formData.bio}
                onChange={(e) => setFormData({...formData, bio: e.target.value})}
                className="w-full h-32 bg-white/5 border border-white/10 rounded-2xl p-6 text-gray-400 font-bold leading-relaxed outline-none focus:border-cyber-purple transition-colors resize-none"
              />
            ) : (
              <p className="text-gray-400 font-bold leading-relaxed text-sm">
                {profile.bio}
              </p>
            )}
          </div>

          {/* Detailed Stats Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl relative group">
               <h3 className="text-xs font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
                 <Target size={18} className="text-cyber-red" /> Forensic Telemetry
               </h3>
               <div className="grid grid-cols-2 gap-8">
                  <div>
                    <p className="text-[10px] text-gray-600 font-black uppercase mb-1">Total Scans</p>
                    <h4 className="text-3xl font-black text-white">{profile.stats.total_scans}</h4>
                  </div>
                  <div>
                    <p className="text-[10px] text-gray-600 font-black uppercase mb-1">Threats Found</p>
                    <h4 className="text-3xl font-black text-cyber-red">{profile.stats.critical_threats}</h4>
                  </div>
                  <div>
                    <p className="text-[10px] text-gray-600 font-black uppercase mb-1">IOCs Extracted</p>
                    <h4 className="text-3xl font-black text-cyber-cyan">{profile.stats.ioc_count}</h4>
                  </div>
                  <div>
                    <p className="text-[10px] text-gray-600 font-black uppercase mb-1">Data Scanned</p>
                    <h4 className="text-3xl font-black text-cyber-purple">{profile.stats.data_analyzed} GB</h4>
                  </div>
               </div>
            </div>

            <div className="bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl">
               <h3 className="text-xs font-black text-white uppercase tracking-widest mb-8 flex items-center gap-2">
                 <Activity size={18} className="text-cyber-green" /> Progression Metrics
               </h3>
               <div className="space-y-6">
                  <div>
                    <div className="flex justify-between text-[10px] font-black uppercase mb-2">
                      <span className="text-gray-600">Next Rank Progress</span>
                      <span className="text-cyber-cyan">750 / 1000 XP</span>
                    </div>
                    <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden p-0.5">
                      <div className="h-full bg-gradient-to-r from-cyber-cyan to-cyber-blue rounded-full w-[75%] shadow-[0_0_10px_rgba(34,211,238,0.5)]"></div>
                    </div>
                  </div>
                  <div className="p-4 bg-white/5 rounded-2xl border border-white/5 flex items-center justify-between">
                     <div className="flex items-center gap-3">
                       <Award className="text-cyber-purple" size={20} />
                       <div>
                         <p className="text-[10px] text-gray-500 font-black uppercase">Current Tier</p>
                         <p className="text-white font-bold text-xs uppercase tracking-tight">{profile.rank}</p>
                       </div>
                     </div>
                     <ChevronRight className="text-gray-700" size={16} />
                  </div>
               </div>
            </div>
          </div>

          {/* Active Sessions - Placeholder */}
          <div className="bg-[#0b1020]/40 border border-white/5 p-8 rounded-3xl">
             <h3 className="text-xs font-black text-white uppercase tracking-widest mb-6 flex items-center gap-2">
               <Globe size={18} className="text-cyber-cyan" /> Connected Neural Links
             </h3>
             <div className="space-y-4">
                {[
                  { device: "SOC-Alpha Terminal (MacOS)", ip: "192.168.1.42", status: "Current" },
                  { device: "Mobile Ops Hub (iOS)", ip: "10.0.0.15", status: "Active" },
                ].map((session, i) => (
                  <div key={i} className="flex justify-between items-center bg-white/5 p-4 rounded-2xl border border-white/5 group hover:bg-white/10 transition-all cursor-default">
                    <div className="flex items-center gap-4">
                       <div className="w-1.5 h-1.5 rounded-full bg-cyber-green shadow-[0_0_5px_#10b981]"></div>
                       <div>
                         <p className="text-xs font-bold text-white">{session.device}</p>
                         <p className="text-[10px] text-gray-600 font-mono">{session.ip}</p>
                       </div>
                    </div>
                    <span className="text-[8px] font-black uppercase px-2 py-1 rounded bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20 tracking-widest">{session.status}</span>
                  </div>
                ))}
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
