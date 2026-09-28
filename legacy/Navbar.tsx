import React from 'react';
import { ClientOrg, User } from '../types';
import { 
  Building2, 
  BarChart3, 
  FileText, 
  Crosshair, 
  ShieldCheck,
  Calculator, 
  Presentation, 
  Grid3X3,
  SlidersHorizontal
} from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  clients: ClientOrg[];
  currentClient: ClientOrg;
  setCurrentClient: (client: ClientOrg) => void;
  currentUser: User;
  setCurrentUser: (user: User) => void;
  users: User[];
  onOpenClientModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  clients,
  currentClient,
  setCurrentClient,
  currentUser,
  setCurrentUser,
  users,
  onOpenClientModal,
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Main Dashboard', icon: BarChart3 },
    { id: 'reports', label: 'Hunt Reports', icon: FileText },
    { id: 'todays-hunts', label: "Today's Hunt", icon: Crosshair },
    { id: 'detection-coverage', label: 'Detection Coverage', icon: ShieldCheck },
    { id: 'severity', label: 'Severity Scoring', icon: Calculator },
    { id: 'decks', label: 'Executive Decks', icon: Presentation },
    { id: 'mitre', label: 'ATT&CK Heatmap', icon: Grid3X3 },
  ];

  return (
    <header className="no-print bg-[#070b14]/95 border-b border-[#1e293b] sticky top-0 z-40 backdrop-blur-md">
      {/* Top tier brand and contextual selectors */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18 py-2">
          {/* Typographic Emblem Logo: Name itself is the logo */}
          <button
            onClick={() => setCurrentTab('dashboard')}
            className="flex flex-col text-left group cursor-pointer select-none focus:outline-none py-0.5"
            title="Blindspot by Optiv — Threat Hunting & Detection Platform"
          >
            <div className="flex items-center gap-2">
              {/* Outer Cyber Tactical Housing */}
              <div className="relative flex items-center px-3 py-1 rounded-md bg-gradient-to-r from-[#0c1220] via-[#0f172a] to-[#070b14] border border-[#1e293b] group-hover:border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.08)] group-hover:shadow-[0_0_22px_rgba(6,182,212,0.25)] transition-all duration-300">
                {/* Tech Bracket Left */}
                <span className="font-mono text-cyan-500/40 text-sm font-light select-none mr-1.5 transition-colors group-hover:text-cyan-400">
                  [
                </span>

                {/* Brand Name Typography with Optical Target Lock */}
                <div className="flex items-center tracking-[0.24em] font-extrabold font-mono text-lg select-none">
                  <span className="text-white drop-shadow-[0_1px_2px_rgba(0,0,0,0.8)] transition-all duration-300 group-hover:tracking-[0.28em]">
                    BLIND
                  </span>

                  {/* Optical Reticle Glyph incorporated directly into the logo name */}
                  <span className="relative flex items-center justify-center mx-1 w-5 h-5 text-cyan-400 group-hover:text-cyan-300 transition-colors">
                    <svg 
                      className="w-4 h-4 transition-transform duration-700 ease-out group-hover:rotate-90 animate-[spin_12s_linear_infinite]" 
                      viewBox="0 0 24 24" 
                      fill="none" 
                      stroke="currentColor" 
                      strokeWidth="2"
                    >
                      <circle cx="12" cy="12" r="9" className="opacity-40 stroke-cyan-500" strokeDasharray="3 3" />
                      <circle cx="12" cy="12" r="4" className="stroke-cyan-400" />
                      <path d="M12 2v4M12 18v4M2 12h4M18 12h4" strokeLinecap="round" />
                    </svg>
                    <span className="absolute w-1 h-1 rounded-full bg-cyan-300 shadow-[0_0_6px_#22d3ee] animate-ping" />
                  </span>

                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 group-hover:from-cyan-300 group-hover:to-emerald-300 drop-shadow-[0_0_12px_rgba(34,211,238,0.35)]">
                    SPOT
                  </span>
                </div>

                {/* Tech Bracket Right */}
                <span className="font-mono text-cyan-500/40 text-sm font-light select-none ml-1.5 transition-colors group-hover:text-cyan-400">
                  ]
                </span>
              </div>
            </div>

            {/* Tool One-Liner Subtitle */}
            <div className="flex items-center gap-1.5 mt-0.5 ml-0.5 text-[11px] font-sans">
              <span className="text-cyan-400/90 font-mono text-[10.5px] font-semibold tracking-tight hidden sm:inline">
                Proactive Threat Hunting & Detection Engineering Platform
              </span>
            </div>
          </button>

          {/* Client & User Controls - Popping High Visibility Compact Chips */}
          <div className="flex items-center gap-2.5">
            {/* Active Client Org Switcher (Popping Electric Cyan/Blue) */}
            <div className="relative flex items-center bg-gradient-to-r from-cyan-950/90 via-[#091b33] to-[#0c1626] border-2 border-cyan-400 shadow-[0_0_16px_rgba(6,182,212,0.35)] rounded-md px-2.5 py-1 text-xs">
              <Building2 className="w-3.5 h-3.5 text-cyan-300 mr-2 shrink-0 animate-pulse" />
              <div className="flex flex-col text-left mr-1.5">
                <span className="text-[9px] text-cyan-300 font-mono uppercase tracking-wider font-extrabold flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping inline-block" />
                  Active Client
                </span>
                <select
                  aria-label="Active Client"
                  value={currentClient.id}
                  onChange={(e) => {
                    const found = clients.find((c) => c.id === e.target.value);
                    if (found) setCurrentClient(found);
                  }}
                  className="bg-transparent text-white font-bold focus:outline-none cursor-pointer pr-3 text-xs leading-tight"
                >
                  {clients.map((c) => (
                    <option key={c.id} value={c.id} className="bg-slate-900 text-white font-medium">
                      {c.name} ({c.industry.toUpperCase()})
                    </option>
                  ))}
                </select>
              </div>
              <button 
                onClick={onOpenClientModal}
                title="Manage Clients & Telemetry"
                className="text-cyan-300 hover:text-white transition-colors p-1 hover:bg-cyan-900/60 rounded cursor-pointer"
              >
                <SlidersHorizontal className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Hunter Identity / Role Switcher (Popping Neon Violet/Fuchsia) */}
            <div className="flex items-center bg-gradient-to-r from-violet-950/90 via-[#200d3a] to-[#130b24] border-2 border-fuchsia-400 shadow-[0_0_16px_rgba(217,70,239,0.35)] rounded-md px-2.5 py-1 text-xs">
              <div className="w-5.5 h-5.5 rounded-full bg-gradient-to-tr from-violet-600 to-fuchsia-500 flex items-center justify-center font-black text-[9.5px] text-white mr-2 border border-fuchsia-300 shadow-[0_0_8px_rgba(217,70,239,0.6)] shrink-0">
                {currentUser.avatar || currentUser.name.slice(0, 2).toUpperCase()}
              </div>
              <div className="flex flex-col text-left mr-2">
                <span className="text-[9px] text-fuchsia-300 font-mono uppercase tracking-wider font-extrabold flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-400 inline-block" />
                  Hunter Role
                </span>
                <select
                  aria-label="Hunter Role"
                  value={currentUser.id}
                  onChange={(e) => {
                    const u = users.find((usr) => usr.id === e.target.value);
                    if (u) setCurrentUser(u);
                  }}
                  className="bg-transparent text-white font-bold focus:outline-none cursor-pointer text-xs pr-2 leading-tight"
                >
                  {users.map((u) => (
                    <option key={u.id} value={u.id} className="bg-slate-900 text-white font-medium">
                      {u.name} ({u.role.toUpperCase()})
                    </option>
                  ))}
                </select>
              </div>
              <span className="text-[9px] px-2 py-0.5 rounded font-mono font-black uppercase tracking-wider bg-fuchsia-400 text-slate-950 shadow-[0_0_10px_rgba(217,70,239,0.7)] shrink-0">
                {currentUser.role.toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        {/* Primary Navigation Tabs */}
        <div className="flex space-x-1 overflow-x-auto py-1 scrollbar-none border-t border-[#1e293b]">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setCurrentTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-md whitespace-nowrap transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-[#131f37] text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#0c1220]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
